# hunting/similar_email_hunt.py
import time
import requests
from datetime import datetime, UTC
from typing import Dict, Any, List, Optional, Tuple

from analysis.header_analyzer import analyze_headers

GRAPH_URL = "https://graph.microsoft.com/v1.0"
REQUEST_TIMEOUT = 15

# mailboxes that should never be searched
EXCLUDED_HUNT_MAILBOXES = {
    "phishingreports@tenant.onmicrosoft.com",
    "phishinginbox@tenant.onmicrosoft.com",
}


# URL-encode user/mailbox for safe insertion into Graph URL path segments
def _encode_user(user: str) -> str:
    return requests.utils.quote(user or "", safe="")


# ISO-8601 compliance SOC-grade logging time format
def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


# generic Graph GET wrapper returning (status_code, json_payload, response_headers)
def _graph_get(
    token: str,
    url: str,
    params: Optional[dict] = None,
    headers_extra: Optional[dict] = None,
) -> Tuple[int, dict, dict]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if headers_extra:
        headers.update(headers_extra)

    r = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)

    try:
        j = r.json()
    except Exception:
        j = {"raw": r.text}

    return r.status_code, j, dict(r.headers)


# sleep using Retry-After (when present) with same bounds for backoff control
def _sleep_backoff(headers: dict) -> None:
    ra = headers.get("Retry-After")
    try:
        s = int(ra) if ra else 5
    except Exception:
        s = 5
    time.sleep(min(max(s, 1), 30))


# produce a compact error string from a Graph error payload
def _graph_error_brief(payload: dict) -> str:
    if not isinstance(payload, dict):
        return str(payload)
    err = payload.get("error")
    if isinstance(err, dict):
        code = err.get("code")
        msg = err.get("message")
        return f"{code}: {msg}"
    return str(payload)


# enumerate user UPNs via Graph /users for org-wide hunts, returning (upns, diag_metadata)
# in a proper enterprise environment, instead of querying all user's it would be more effective to run a query in MS Defender for o365
def list_users_upns(token: str, max_users: int = 500) -> Tuple[List[str], Dict[str, Any]]:

    diag: Dict[str, Any] = {
        "endpoint": "/users",
        "max_users": max_users,
        "status": None,
        "error": None,
        "returned": 0,
        "notes": [],
    }

    url = f"{GRAPH_URL}/users"
    params = {"$select": "userPrincipalName", "$top": 50}

    upns: List[str] = []
    while url and len(upns) < max_users:
        status, data, hdrs = _graph_get(token, url, params=params)
        params = None
        diag["status"] = status

        if status == 429:
            diag["notes"].append("throttled_429")
            _sleep_backoff(hdrs)
            continue

        if status != 200:
            diag["error"] = _graph_error_brief(data)
            diag["notes"].append("enumeration_failed")
            return [], diag

        vals = data.get("value", []) or []
        diag["returned"] += len(vals)

        for u in vals:
            upn = (u.get("userPrincipalName") or "").strip().lower()
            if upn and "@" in upn:
                if upn in EXCLUDED_HUNT_MAILBOXES:
                    continue
                upns.append(upn)
                if len(upns) >= max_users:
                    break

        url = data.get("@odata.nextLink")

    if not upns:
        diag["notes"].append("enumeration_succeeded_but_empty")

    return upns, diag


# escape embedded quotes for safe insertion into AQS strings
def _aqs_escape(v: str) -> str:
    return (v or "").replace('"', '\\"').strip()


# wrap AQS query as a quoted phrase for Graph $search, escaping internal quotes
def _wrap_search_phrase(aqs_query: str) -> str:
    safe = (aqs_query or "").replace('"', '\\"')
    return f"\"{safe}\""


# search a mailbox using Graph $search (AQS), returning candidate message metadata objects
def _search_mailbox_candidates_aqs(
    token: str,
    mailbox: str,
    aqs_query: str,
    top: int = 25
) -> List[Dict[str, Any]]:
    mbx = (mailbox or "").strip().lower()
    if mbx in EXCLUDED_HUNT_MAILBOXES:
        return []

    user_seg = _encode_user(mbx)
    url = f"{GRAPH_URL}/users/{user_seg}/messages"

    params = {
        "$top": int(top),
        "$search": _wrap_search_phrase(aqs_query),
        "$select": "id,subject,receivedDateTime,from,internetMessageId",
    }

    status, data, hdrs = _graph_get(
        token, url, params=params, headers_extra={"ConsistencyLevel": "eventual"}
    )

    if status == 429:
        _sleep_backoff(hdrs)
        return _search_mailbox_candidates_aqs(token, mailbox, aqs_query, top=top)

    if status != 200:
        return []

    return data.get("value", []) or []


# fetch message's headers for later IP matching against original sender IP set
def _fetch_headers_for_message(token: str, mailbox: str, message_id: str) -> Optional[Dict[str, Any]]:
    mbx = (mailbox or "").strip().lower()
    if mbx in EXCLUDED_HUNT_MAILBOXES:
        return None

    user_seg = _encode_user(mbx)
    url = (
        f"{GRAPH_URL}/users/{user_seg}/messages/{message_id}"
        "?$select=id,subject,from,receivedDateTime,internetMessageHeaders"
    )

    status, data, hdrs = _graph_get(token, url, params=None)
    if status == 429:
        _sleep_backoff(hdrs)
        return _fetch_headers_for_message(token, mailbox, message_id)

    if status != 200:
        return None

    return data


# extract sender email address from a Graph message object
def _sender_addr(msg: Dict[str, Any]) -> str:
    return (((msg.get("from") or {}).get("emailAddress") or {}).get("address") or "").strip().lower()


# extract the raw subject from a Graph message object
def _subject_raw(msg: Dict[str, Any]) -> str:
    return (msg.get("subject") or "").strip()


# perform org-wide hunt by enumerating mailboxes and searching for exact subject and sender matches
def hunt_similar_emails_orgwide(
    token: str,
    *,
    original_subject: str,
    original_sender_email: str,
    original_sender_ips: List[str],
    max_users: int = 5,
    candidates_per_mailbox: int = 25,
    max_hits_total: int = 5
) -> Dict[str, Any]:
    started = now()

    subj_raw = (original_subject or "").strip()
    subj_cmp = subj_raw.lower()

    sender = (original_sender_email or "").strip().lower()
    ips_set = set([str(x).strip() for x in (original_sender_ips or []) if str(x).strip()])

    targets, enum_diag = list_users_upns(token, max_users=max_users)
    targets_mode = "all"

    targets = [t for t in targets if t and "@" in t and t not in EXCLUDED_HUNT_MAILBOXES]
    q_subject_exact = f'subject:"{_aqs_escape(subj_raw)}"' if subj_raw else ""
    q_sender_exact = f"from:{sender}" if sender else ""

    matches: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    per_mailbox_stats: List[Dict[str, Any]] = []

    for mbx in targets:
        if len(matches) >= max_hits_total:
            break

        if mbx in EXCLUDED_HUNT_MAILBOXES:
            continue

        try:
            candidate_map: Dict[str, Dict[str, Any]] = {}

            stats = {"mailbox": mbx, "subject_exact_hits": 0, "sender_exact_hits": 0}

            if q_subject_exact:
                r1 = _search_mailbox_candidates_aqs(token, mbx, q_subject_exact, top=candidates_per_mailbox)
                stats["subject_exact_hits"] = len(r1)

                for c in r1:
                    mid = c.get("id")
                    if not mid:
                        continue

                    if _subject_raw(c).lower() != subj_cmp:
                        continue

                    if mid not in candidate_map:
                        candidate_map[mid] = {"msg": c, "reasons": set()}
                    candidate_map[mid]["reasons"].add("subject_exact")

            if q_sender_exact:
                r2 = _search_mailbox_candidates_aqs(token, mbx, q_sender_exact, top=candidates_per_mailbox)
                stats["sender_exact_hits"] = len(r2)

                for c in r2:
                    mid = c.get("id")
                    if not mid:
                        continue

                    if _sender_addr(c) != sender:
                        continue

                    if mid not in candidate_map:
                        candidate_map[mid] = {"msg": c, "reasons": set()}
                    candidate_map[mid]["reasons"].add("sender_exact")

            per_mailbox_stats.append(stats)

            for mid, entry in candidate_map.items():
                if len(matches) >= max_hits_total:
                    break

                c = entry["msg"]
                reasons = entry.get("reasons") or set()

                c_sender = _sender_addr(c)
                c_subject = _subject_raw(c)

                sender_ip_matches: List[str] = []
                full = _fetch_headers_for_message(token, mbx, mid)
                if full:
                    findings = analyze_headers(full.get("internetMessageHeaders") or [])
                    received_ips = set(findings.get("all_received_ips") or findings.get("sender_ips") or [])
                    if ips_set:
                        sender_ip_matches = sorted(list(received_ips.intersection(ips_set)))

                matches.append({
                    "mailbox": mbx,
                    "message_id": mid,
                    "subject": c_subject,
                    "sender_address": c_sender,
                    "sender_ip_matches": sender_ip_matches,
                    "match_type": "+".join(sorted(list(reasons))) if reasons else "unknown",
                    "receivedDateTime": c.get("receivedDateTime"),
                })

        except Exception as e:
            errors.append({"mailbox": mbx, "error": str(e)})

    dedup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for m in matches:
        mbx = (m.get("mailbox") or "").strip().lower()
        mid = (m.get("message_id") or "").strip()
        if not mbx or not mid:
            continue
        if mbx in EXCLUDED_HUNT_MAILBOXES:
            continue
        dedup[(mbx, mid)] = m
    matches = list(dedup.values())

    finished = now()

    return {
        "started": started,
        "finished": finished,
        "targets_mode": targets_mode,
        "targets_count": len(targets),
        "fallback_used": False,
        "excluded_mailboxes": sorted(list(EXCLUDED_HUNT_MAILBOXES)),
        "enumeration_diag": enum_diag,
        "search": {
            "subject": subj_raw,
            "sender_email": sender,
            "queries": {
                "subject_exact": q_subject_exact,
                "sender_exact": q_sender_exact,
            }
        },
        "per_mailbox_stats": per_mailbox_stats,
        "matches_count": len(matches),
        "matches": sorted(matches, key=lambda x: (x.get("mailbox") or "", x.get("receivedDateTime") or "")),
        "errors": errors,
    }


# format hunt results into a readable "Affected Users" block for console output or ticket notes
def format_affected_users(hunt: Dict[str, Any]) -> str:
    hunt = hunt or {}
    matches = hunt.get("matches") or []
    queries = ((hunt.get("search") or {}).get("queries") or {})
    excluded = hunt.get("excluded_mailboxes") or []

    lines = []
    lines.append("========================================= AFFECTED USERS ===========================================")
    lines.append(f"Org Hunt Started (UTC): {hunt.get('started')}")
    lines.append(f"Org Hunt Finished(UTC): {hunt.get('finished')}")
    lines.append(f"Targets Mode          : {hunt.get('targets_mode')}")
    lines.append(f"Targets Count         : {hunt.get('targets_count')}")
    lines.append(f"Search Sender         : {((hunt.get('search') or {}).get('sender_email'))}")
    lines.append(f"Search Subject        : {((hunt.get('search') or {}).get('subject'))}")
    lines.append(f"Matches Found         : {hunt.get('matches_count')}")
    lines.append("")

    lines.append("Search Queries Used:")
    lines.append(f"  - subject_exact : {queries.get('subject_exact')}")
    lines.append(f"  - sender_exact  : {queries.get('sender_exact')}")
    lines.append("")

    if not matches:
        lines.append("Affected Users: none")
    else:
        lines.append("Affected Users:")

        by_user: Dict[str, List[Dict[str, Any]]] = {}
        for m in matches:
            by_user.setdefault(m.get("mailbox") or "unknown", []).append(m)

        for user in sorted(by_user.keys()):
            lines.append(f"\n- {user}")
            for hit in by_user[user]:
                ips = hit.get("sender_ip_matches") or []
                ip_str = ", ".join(ips) if ips else "NO_IP_MATCH_DATA"
                lines.append(f"    Message ID    : {hit.get('message_id')}")
                lines.append(f"    Subject       : {hit.get('subject')}")
                lines.append(f"    Sender Address: {hit.get('sender_address')}")
                lines.append(f"    Match Type    : {hit.get('match_type')}")
                lines.append(f"    Sender IP     : {ip_str}")
                lines.append("")

    errs = hunt.get("errors") or []
    if errs:
        lines.append("\nHunt Errors (partial):")
        for e in errs[:25]:
            lines.append(f"  - {e.get('mailbox')}: {e.get('error')}")
        if len(errs) > 25:
            lines.append(f"  ... ({len(errs) - 25} more)")
    return "\n".join(lines)
