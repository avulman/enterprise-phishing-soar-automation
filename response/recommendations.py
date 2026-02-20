# response/recommendations.py
from typing import Dict, Any, List, Optional


# normalize an email-like string to a consistent lowercase/trimmed form
def _norm_email(s: str) -> str:
    return (s or "").strip().lower()


# safely convert potentially-None values into a trimmed string
def _safe(s: str) -> str:
    return (s or "").strip()


# read VirusTotal detection count (mal+sus)
def _vt_reported_from_summary(summary: Dict[str, Any]) -> int:
    try:
        p = (summary or {}).get("pretty") or {}
        return int(p.get("vt_reported", 0) or 0)
    except Exception:
        return 0


# convert an attachment processor verdict into a detection-like number for gating decisions
def _attachment_vt_reported(att: Dict[str, Any]) -> int:
    v = (att or {}).get("verdict") or ""
    return 10 if v.strip().upper() == "MALICIOUS" else 0


# build a list of "Delete Email" action dicts for the reporter and any affected users from the org-wide hunt
def build_delete_email_actions(
    *,
    reporter_upn: str,
    reporter_message_id: str,
    reporter_subject: str,
    reporter_received: str,
    hunt: Dict[str, Any],
) -> List[Dict[str, str]]:
    actions: List[Dict[str, str]] = []

    # reporter copy
    if reporter_upn and reporter_message_id:
        actions.append({
            "mailbox": _norm_email(reporter_upn),
            "received": _safe(reporter_received),
            "subject": _safe(reporter_subject),
            "msg_id": _safe(reporter_message_id),
        })

    # affected matches
    matches = (hunt or {}).get("matches") or []
    for m in matches:
        mbx = _norm_email(m.get("mailbox") or "")
        mid = _safe(m.get("message_id") or "")
        subj = _safe(m.get("subject") or "")
        rcv = _safe(m.get("receivedDateTime") or "")

        if not mbx or not mid:
            continue

        actions.append({
            "mailbox": mbx,
            "received": rcv,
            "subject": subj,
            "msg_id": mid,
        })

    # dedup by mailbox+msg_id
    dedup = {}
    for a in actions:
        dedup[(a.get("mailbox"), a.get("msg_id"))] = a

    # stable ordering (mailbox then received)
    out = list(dedup.values())
    out.sort(key=lambda x: (x.get("mailbox") or "", x.get("received") or ""))
    return out


# build a unified "recommended actions" object used for console output and ServiceNow ticket content
def build_recommended_actions(
    *,
    sender_address: str,
    ip_rep_summaries: Optional[List[Dict[str, Any]]] = None,
    url_vt_summaries: Optional[List[Dict[str, Any]]] = None,
    domain_vt_summaries: Optional[List[Dict[str, Any]]] = None,
    att_results: Optional[List[Dict[str, Any]]] = None,
    delete_email_actions: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    ip_rep_summaries = ip_rep_summaries or []
    url_vt_summaries = url_vt_summaries or []
    domain_vt_summaries = domain_vt_summaries or []
    att_results = att_results or []
    delete_email_actions = delete_email_actions or []

    block_senders: List[str] = []
    block_domains: List[str] = []

    # Sender (always if present)
    s = _norm_email(sender_address)
    if s and "@" in s:
        block_senders.append(s)

    for d in domain_vt_summaries:
        dom = _safe(d.get("domain") or "").lower()
        if not dom:
            continue
        if _vt_reported_from_summary(d) >= 10:
            block_domains.append(dom)

    block_senders = sorted(set([x for x in block_senders if x]))
    block_domains = sorted(set([x for x in block_domains if x]))

    return {
        "block_senders": block_senders,
        "block_domains": block_domains,
        "delete_emails": delete_email_actions,
    }


# render the recommended actions object into the exact multi-line section used in output/tickets
def format_recommended_actions_section(actions: Dict[str, Any]) -> str:
    actions = actions or {}
    senders = actions.get("block_senders") or []
    domains = actions.get("block_domains") or []
    deletes = actions.get("delete_emails") or []

    lines: List[str] = []
    lines.append("======================================= RECOMMENDED ACTIONS ========================================")
    lines.append("")
    any_item = False

    for s in senders:
        lines.append(f"- Block Sender: {s}")
        lines.append("")
        any_item = True

    for d in domains:
        lines.append(f"- Block Domain: {d}")
        lines.append("")
        any_item = True

    for e in deletes:
        mbx = _safe(e.get("mailbox"))
        rcv = _safe(e.get("received"))
        subj = _safe(e.get("subject"))
        mid = _safe(e.get("msg_id"))

        lines.append(
            f"- Delete Email: mailbox={mbx} received={rcv} subject={subj} msg_id={mid}"
        )
        lines.append("")
        any_item = True

    if not any_item:
        lines.append("- none")
        lines.append("")

    lines.append("====================================================================================================")
    return "\n".join(lines)


# build conensed one-line "Actions: ..." snippet
def shortdesc_recommended_actions_snippet(actions: Dict[str, Any], max_delete: int = 1) -> str:
    actions = actions or {}
    senders = actions.get("block_senders") or []
    domains = actions.get("block_domains") or []
    deletes = actions.get("delete_emails") or []

    parts: List[str] = []

    if senders:
        parts.append("Block Sender=" + ",".join(senders[:2]) + ("" if len(senders) <= 2 else ",..."))

    if domains:
        parts.append("Block Domain=" + ",".join(domains[:2]) + ("" if len(domains) <= 2 else ",..."))

    if deletes:
        shown = deletes[:max_delete]
        # show mailbox + msg_id only (shortdesc space)
        dd = []
        for e in shown:
            mbx = _safe(e.get("mailbox"))
            mid = _safe(e.get("msg_id"))
            if mbx and mid:
                dd.append(f"{mbx}:{mid}")
        if dd:
            parts.append("Delete Email=" + ",".join(dd) + ("" if len(deletes) <= max_delete else ",..."))

    if not parts:
        return "Actions: none"

    return "Actions: " + "; ".join(parts)
