# main.py
import os
import time
import requests
import io
import contextlib
from datetime import datetime, UTC
from typing import Dict, Any, List

from auth.graph_auth import get_access_token

from ingest.fetch_message import fetch_full_message
from ingest.move_message import move_message_to_folder
from ingest.reporter_original_finder import (
    parse_wrapper_subject,
    extract_wrapper_from_address,
    find_original_in_reporter_deleted_items,
)

from analysis.header_analyzer import analyze_headers
from analysis.ioc_extractor import extract_iocs_from_body
from analysis.url_filter import filter_urls, WHITELIST_DOMAINS
from analysis.scoring_engine import score_email

from processors.ip_processor import process_ips
from processors.url_processor import process_urls
from processors.domain_processor import process_domains
from processors.attachment_processor import process_attachments_for_email

from state.servicenow_state import load_ticket_map, save_ticket_map
from integrations.servicenow import create_incident

from hunting.similar_email_hunt import hunt_similar_emails_orgwide, format_affected_users

from response.recommendations import (
    build_delete_email_actions,
    build_recommended_actions,
    format_recommended_actions_section,
    shortdesc_recommended_actions_snippet,
)

POLL_INTERVAL_SECONDS = 5
REQUEST_TIMEOUT = 15
GRAPH_URL = "https://graph.microsoft.com/v1.0"

PHISHING_MAILBOX = "phishinginbox@tenant.onmicrosoft.com"
REPORTED_FOLDER = "Reported Emails"
PROCESSED_FOLDER = "Processed"

# whietlist mailbox from similar email hunt
HUNT_EXCLUDE_MAILBOXES = {
    "phishinginbox@tenant.onmicrosoft.com",
}

# ISO-8601 compliance SOC-grade logging time format
def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

# url encode user/email so that it can safely be used in MS Graph API request paths
def _encode_user(user: str) -> str:
    return requests.utils.quote(user or "", safe="")

# send authenticated GET request to MS Graph and return JSON response, printing status code on failure
def _graph_get_json(token: str, url: str, params: dict = None) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    r = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)

    if r.status_code != 200:
        print(f"Graph request failed with status code: {r.status_code}")
        return {}

    return r.json()

# retrieve all paginated results from a MS Graph endpoint by following @odata.nextLink until complete
def _graph_get_all_pages(token: str, url: str, params: dict = None) -> List[dict]:
    all_items: List[dict] = []
    next_url = url
    next_params = params

    while next_url:
        data = _graph_get_json(token, next_url, params=next_params)
        next_params = None
        all_items.extend(data.get("value", []) or [])
        next_url = data.get("@odata.nextLink")

    return all_items

# resolve and return the MS Graph ID of a specified top-level mailbox folder by matching its display name (e.g. ReportedEmails@tenant.com > Folder: 'Reported Emails')
def resolve_top_level_folder_id(token: str, mailbox: str, folder_name: str) -> str:
    user_seg = _encode_user(mailbox)
    url = f"{GRAPH_URL}/users/{user_seg}/mailFolders"
    folders = _graph_get_all_pages(token, url, params={"$select": "id,displayName", "$top": 200})

    target = (folder_name or "").strip().lower()
    for f in folders:
        if (f.get("displayName") or "").strip().lower() == target:
            return f.get("id") or ""
    return ""

# retrieve and return all messages from a specified top-level mailbox folder, sorted by newest first
def list_messages_in_folder(token: str, mailbox: str, folder_name: str) -> List[dict]:
    folder_id = resolve_top_level_folder_id(token, mailbox, folder_name)
    if not folder_id:
        print(f"[{now()}] [WARN] Folder '{folder_name}' not found as TOP-LEVEL in mailbox={mailbox}")
        return []

    user_seg = _encode_user(mailbox)
    url = f"{GRAPH_URL}/users/{user_seg}/mailFolders/{folder_id}/messages"
    messages = _graph_get_all_pages(token, url, params={"$select": "id,subject,receivedDateTime,from", "$top": 50})

    messages.sort(key=lambda m: m.get("receivedDateTime") or "", reverse=True)
    return messages

# format email authentication results into a readable output
def _fmt_auth_results(auth: dict) -> str:
    auth = auth or {}
    spf = str(auth.get("spf", "not found")).upper()
    dkim = str(auth.get("dkim", "not found")).upper()
    dmarc = str(auth.get("dmarc", "not found")).upper()
    return (
        f"SPF Result   : {spf}\n"
        f"DKIM Result  : {dkim}\n"
        f"DMARC Result : {dmarc}"
    )

# output received email hops and associated IPs to show message delivery path
def _print_received_hops(hops: List[Dict[str, Any]]) -> None:
    print("========================================== RECEIVED HOPS ===========================================\n")
    if not hops:
        print("  - NONE FOUND")
        return

    for h in hops:
        index = h.get("index")
        ips = h.get("ips") or []

        index_str = f"{index:>2}" if index is not None else "??"
        ip_str = ", ".join(ips) if ips else "NONE"

        print(f"  - Hop {index_str}: {ip_str}")

    print(f"\n  Total hops: {len(hops)}")

# print VirusTotal reputation verdicts and detection counts for all extracted IPs
def _print_scanned_ips(ip_rep_summaries: List[Dict[str, Any]]) -> None:
    print("\n=========================================== SCANNED IPS ============================================\n")
    if not ip_rep_summaries:
        print("  - none")
        return

    for ipr in ip_rep_summaries:
        ip = ipr.get("ip")
        pretty = ipr.get("pretty") or {}
        vt_tier = pretty.get("vt_tier", "NO_DATA")
        vt_reported = pretty.get("vt_reported", 0)
        vt_total = pretty.get("vt_total", 0)
        abuse_score = pretty.get("abuse_score", 0)
        abuse = ipr.get("abuseipdb") or {}
        abuse_reports = abuse.get("totalReports", 0)
        country = pretty.get("country", "Unknown")
        isp = pretty.get("isp", "Unknown")
        print(f"{ip} [VirusTotal]: {vt_tier} - Detections: {vt_reported}/{vt_total}")
        print(f"{ip} [AbuseIPDB ]: Score: {abuse_score} - Reports: {abuse_reports} - Country: {country} - ISP: {isp}")


# print VirusTotal reputation verdicts and detection counts for all extracted URLs
def _print_scanned_urls(url_vt_summaries: List[Dict[str, Any]]) -> None:
    print("\n========================================== SCANNED URLS ============================================\n")
    if not url_vt_summaries:
        print("  - none")
        return

    for u in url_vt_summaries:
        url = u.get("url")
        p = u.get("pretty") or {}
        tier = p.get("vt_tier", "NO_DATA")
        rep = p.get("vt_reported", 0)
        tot = p.get("vt_total", 0)
        print(f"{url} [VirusTotal]: {tier} - Detections: {rep}/{tot}")


# print VirusTotal reputation verdicts and detection counts for all extracted domains
def _print_scanned_domains(domain_vt_summaries: List[Dict[str, Any]]) -> None:
    print("\n========================================= SCANNED DOMAINS ==========================================\n")
    if not domain_vt_summaries:
        print("  - none")
        return

    for i, d in enumerate(domain_vt_summaries):
        dom = d.get("domain")
        p = d.get("pretty") or {}
        tier = p.get("vt_tier", "NO_DATA")
        rep = p.get("vt_reported", 0)
        tot = p.get("vt_total", 0)
        print(f"{dom} - [VirusTotal]: {tier} - Detections: {rep}/{tot}")


# print VirusTotal reputation verdicts and detection counts for all extracted domains, and attachment information
def _print_scanned_attachments(att_results: List[Dict[str, Any]]) -> None:
    print("\n======================================= SCANNED ATTACHMENTS ========================================\n")
    if not att_results:
        print("No attachments identified")
        return

    for i, r in enumerate(att_results):
        print("File    :", r.get("filename"))
        print("Type    :", r.get("contentType"))
        print("Size    :", r.get("size"))
        print("SHA256  :", r.get("sha256"))
        print("[VT Verdict (gated)] :", r.get("verdict"))
        if i != len(att_results) - 1:
            print("")


# format email scoring results into structured block
def _format_scoring_block(verdict_obj: dict) -> str:
    verdict_obj = verdict_obj or {}
    lines: List[str] = []
    lines.append("############################################ SCORING ###############################################")
    lines.append("")
    lines.append(f"Overall Score: {verdict_obj.get('score')}")
    lines.append(f"Verdict      : {verdict_obj.get('verdict')}")
    lines.append(f"Confidence   : {verdict_obj.get('confidence')}")
    lines.append("Reasons      :")
    reasons = verdict_obj.get("reasons") or []
    if reasons:
        for r in reasons:
            lines.append(f"- {r}")
    else:
        lines.append("")
    lines.append("")
    lines.append("####################################################################################################")
    return "\n".join(lines)


# extract and normalize the sender's email address from a MS Graph message object
def _sender_addr(msg: dict) -> str:
    return (((msg.get("from") or {}).get("emailAddress") or {}).get("address") or "").strip().lower()

# generates a concise summary string listing impacted user mailboxes from hunt results, truncating if necessary
def _impacted_users_summary(hunt: Dict[str, Any], max_users_in_title: int = 6) -> str:
    hunt = hunt or {}
    matches = hunt.get("matches") or []
    users = sorted({(m.get("mailbox") or "").strip().lower() for m in matches if (m.get("mailbox") or "").strip()})

    if not users:
        return "Affected=0"

    shown = users[:max_users_in_title]
    extra = max(0, len(users) - len(shown))
    if extra > 0:
        return f"Affected={len(users)}: " + ", ".join(shown) + f", ... (+{extra} more)"
    return f"Affected={len(users)}: " + ", ".join(shown)


# capture printed output from a function and return it as a string (SNow/Terminal output helper)
def _capture_print(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue().rstrip()

def main():
    print(f"[{now()}] Phish SOAR worker starting...")

    # load previously processed wrapper email IDs mapped to ServiceNow ticket IDs to prevent duplication
    ticket_map = load_ticket_map()
    print(f"[{now()}] Loaded {len(ticket_map)} ServiceNow ticket map entries")

    # acquire MS Graph OAuth token for API authentication
    token = get_access_token()

    # continuously poll for newly reported phishing emails
    while True:
        try:
            # retrieve all messages in 'Reported Emails' folder
            messages = list_messages_in_folder(token, PHISHING_MAILBOX, REPORTED_FOLDER)

            # if no messages found, wait and retry polling
            if not messages:
                print(f"[{now()}] No new reported emails. Listening...")
                time.sleep(POLL_INTERVAL_SECONDS)
                continue
            
            print(f"[{now()}] Found {len(messages)} message(s) in folder: '{REPORTED_FOLDER}'. Processing email...")

            # process each wrapper email found
            for msg in messages:
                # extract message ID and Subject
                wrapper_id = msg.get("id")
                wrapper_subject = msg.get("subject", "") or ""

                # skip invalid messages without an ID
                if not wrapper_id:
                    continue
                
                # skip messages already processed and ticketed (in case move fails)
                if wrapper_id in ticket_map:
                    continue

                # retrieve full wrapper email metadata from MS Graph
                wrapper_full = fetch_full_message(token, PHISHING_MAILBOX, wrapper_id)
                if not wrapper_full:
                    continue

                # extract reporter email address
                reporter = extract_wrapper_from_address(wrapper_full)

                # extract reporter and original subject
                subject_reporter, subject_guess = parse_wrapper_subject(wrapper_subject)

                # use subject-derived reporter if header extraction failed
                if not reporter:
                    reporter = subject_reporter

                # skip if reporter or subject guess could not be determined
                if not reporter or not subject_guess:
                    continue

                # locate original reported email in reporter's 'Deleted Items' folder (emails are moved here after being reported)
                meta = find_original_in_reporter_deleted_items(token, reporter, subject_guess)
                if not meta or not meta.get("id"):
                    continue

                # fetch full original email including headers, body, attachments
                original = fetch_full_message(token, reporter, meta["id"])
                if not original:
                    continue

                print("\n" + "=" * 101)
                print(f"[{now()}]")
                print("======================================== NEW REPORTED PHISH ========================================\n")
                print("Original Subject      : " + (original.get("subject") or ""))
                print("Original From         : " + _sender_addr(original))
                print("Original Received     : " + str(original.get("receivedDateTime") or ""))
                print("Original Message ID   : " + str(original.get("id") or "") + "\n")

                print("Wrapper Email Subject : " + wrapper_subject)
                print("Reported by           : " + reporter)
                print("Wrapper Email ID      : " + wrapper_id + "\n")

                # extract and analyze internet message headers
                headers = original.get("internetMessageHeaders") or []
                header_findings = analyze_headers(headers)

                # extract authentication results
                auth_results = header_findings.get("auth_results") or {}

                # extract hops
                hops = header_findings.get("received_hops") or []

                # extract all IP addresses found in headers
                all_header_ips = header_findings.get("all_ips") or []
                sender_ips_for_hunt = header_findings.get("all_received_ips") or header_findings.get("sender_ips") or []

                print("========================================= HEADER ANALYSIS ==========================================\n")
                print(_fmt_auth_results(auth_results))
                print("")
                _print_received_hops(hops)

                # enrich all header IPs with threat intelligence (VirusTotal, AbuseIPDB)
                ip_rep_summaries: List[Dict[str, Any]] = []
                for ip in all_header_ips:
                    try:
                        res = process_ips(ip)
                        if res:
                            ip_rep_summaries.append(res)
                    except Exception as e:
                        print(f"[WARN] IP enrichment failed for {ip}: {e}")

                _print_scanned_ips(ip_rep_summaries)

                # extract email body content
                body_content = ""
                body = original.get("body")
                if isinstance(body, dict):
                    body_content = body.get("content") or ""

                # extract indicators of compromise (URLs, domains, etc.) from body
                iocs = extract_iocs_from_body(body_content)
                raw_urls = list(iocs.get("urls", []))
                urls = sorted(filter_urls(set(raw_urls)))
                domains_in = list(iocs.get("domains", []) or [])

                domains = []
                for d in domains_in:
                    dd = (d or "").strip().lower().rstrip(".")
                    if dd.startswith("www."):
                        dd = dd[4:]
                    if not dd:
                        continue
                    whitelisted = False
                    for wd in WHITELIST_DOMAINS:
                        w = (wd or "").strip().lower().rstrip(".")
                        if w.startswith("www."):
                            w = w[4:]
                        if dd == w or dd.endswith("." + w):
                            whitelisted = True
                            break
                    if not whitelisted:
                        domains.append(dd)
                domains = sorted(set(domains))

                # enrich URLs with VirusTotal
                url_vt_summaries: List[Dict[str, Any]] = []
                for u in urls:
                    try:
                        r = process_urls(u)
                        if r:
                            url_vt_summaries.append(r)
                    except Exception as e:
                        print(f"[WARN] URL enrichment failed for {u}: {e}")

                _print_scanned_urls(url_vt_summaries)

                # enrich domains with VirusTotal
                domain_vt_summaries: List[Dict[str, Any]] = []
                for d in domains:
                    try:
                        r = process_domains(d)
                        if r:
                            domain_vt_summaries.append(r)
                    except Exception as e:
                        print(f"[WARN] Domain enrichment failed for {d}: {e}")

                _print_scanned_domains(domain_vt_summaries)

                # analyze email attachments and enrich with VirusTotal
                try:
                    att_results = process_attachments_for_email(
                        token=token,
                        mailbox=reporter,
                        email=original,
                    )
                except Exception as e:
                    print(f"[WARN] Attachment processing failed: {e}")
                    att_results = []

                _print_scanned_attachments(att_results)

                # score email using collected threat intelligence indicators
                verdict_obj = score_email(
                    att_results=att_results,
                    url_vt_summaries=url_vt_summaries,
                    domain_vt_summaries=domain_vt_summaries,
                    ip_rep_summaries=ip_rep_summaries,
                )

                scoring_block = _format_scoring_block(verdict_obj)

                # initialize organization-wide hunt tracking
                hunt: Dict[str, Any] = {}
                impacted_block = ""
                impacted_summary = "Affected=0"

                # if malicious, perform organization-wide search for similar emails
                if verdict_obj.get("verdict") == "malicious":

                    hunt = hunt_similar_emails_orgwide(
                        token=token,
                        original_subject=(original.get("subject") or ""),
                        original_sender_email=_sender_addr(original),
                        original_sender_ips=sender_ips_for_hunt,
                        max_users=int(os.getenv("HUNT_ALL_USERS_MAX", "500") or "500"),
                        candidates_per_mailbox=int(os.getenv("HUNT_CANDIDATES_PER_MAILBOX", "25") or "25"),
                        max_hits_total=int(os.getenv("HUNT_MAX_HITS_TOTAL", "250") or "250"),
                    )

                    # filter out whitelisted mailboxes from matches
                    matches = hunt.get("matches") or []
                    filtered_matches = []
                    for m in matches:
                        mbx = (m.get("mailbox") or "").strip().lower()
                        if mbx and mbx in HUNT_EXCLUDE_MAILBOXES:
                            continue
                        filtered_matches.append(m)

                    hunt["matches"] = filtered_matches
                    hunt["matches_count"] = len(filtered_matches)

                    impacted_block = format_affected_users(hunt)
                    impacted_summary = _impacted_users_summary(hunt, max_users_in_title=6)

                    print("\n" + impacted_block + "\n")

                recommended_actions: Dict[str, Any] = {}
                actions_snippet = "Actions: none"

                # generate recommended remediation actions for malicious emails
                if verdict_obj.get("verdict") == "malicious":
                    delete_email_actions = build_delete_email_actions(
                        reporter_upn=reporter,
                        reporter_message_id=(original.get("id") or ""),
                        reporter_subject=(original.get("subject") or ""),
                        reporter_received=str(original.get("receivedDateTime") or ""),
                        hunt=hunt,
                    )

                    recommended_actions = build_recommended_actions(
                        sender_address=_sender_addr(original),
                        ip_rep_summaries=ip_rep_summaries,
                        url_vt_summaries=url_vt_summaries,
                        domain_vt_summaries=domain_vt_summaries,
                        att_results=att_results,
                        delete_email_actions=delete_email_actions,
                    )

                    print("\n" + format_recommended_actions_section(recommended_actions) + "\n")

                    actions_snippet = shortdesc_recommended_actions_snippet(recommended_actions, max_delete=1)

                # build ServiceNow incident short description
                short_desc = (
                    f"[PhishSOAR] {verdict_obj['verdict'].upper()} "
                    f"(score={verdict_obj['score']}, conf={verdict_obj['confidence']}) "
                    f"Subject: {original.get('subject','')}"
                )

                desc_parts: List[str] = []

                def _sn_new_reported_phish():
                    print("======================================== NEW REPORTED PHISH ========================================\n")
                    print("Original Subject      : " + (original.get("subject") or ""))
                    print("Original From         : " + _sender_addr(original))
                    print("Original Received     : " + str(original.get("receivedDateTime") or ""))
                    print("Original Message ID   : " + str(original.get("id") or "") + "\n")
                    print("Wrapper Email Subject : " + wrapper_subject)
                    print("Reported by           : " + reporter)
                    print("Wrapper Email ID      : " + wrapper_id)

                def _sn_header_analysis():
                    print("========================================= HEADER ANALYSIS ==========================================\n")
                    print(_fmt_auth_results(auth_results))

                desc_parts.append(_capture_print(_sn_new_reported_phish))
                desc_parts.append(_capture_print(_sn_header_analysis))
                desc_parts.append(_capture_print(_print_received_hops, hops))
                desc_parts.append(_capture_print(_print_scanned_ips, ip_rep_summaries))
                desc_parts.append(_capture_print(_print_scanned_urls, url_vt_summaries))
                desc_parts.append(_capture_print(_print_scanned_domains, domain_vt_summaries))
                desc_parts.append(_capture_print(_print_scanned_attachments, att_results))

                if impacted_block:
                    desc_parts.append(impacted_block)

                if verdict_obj.get("verdict") == "malicious" and recommended_actions:
                    desc_parts.append(format_recommended_actions_section(recommended_actions))

                desc_parts.append(scoring_block)

                desc = "\n\n".join([p for p in desc_parts if (p or "").strip()])

                # create incident ticket in ServiceNow
                sn = create_incident(
                    short_description=short_desc,
                    description=desc,
                    severity=verdict_obj["verdict"]
                )

                sys_id = sn.get("sys_id")
                number = sn.get("number")

                # save processed wrapper ID to prevent duplicate processing
                ticket_map[wrapper_id] = sys_id or number or "created"
                save_ticket_map(ticket_map)

                print(f"[{now()}] [ServiceNow] Created incident: {number}")

                # move processed wrapper email to the 'Processed Folder' to prevent reprocessing
                processed_folder_id = resolve_top_level_folder_id(token, PHISHING_MAILBOX, PROCESSED_FOLDER)
                if processed_folder_id:
                    try:
                        move_message_to_folder(token, PHISHING_MAILBOX, wrapper_id, processed_folder_id)
                        print(f"[{now()}] [Graph] Moved wrapper email to folder: '{PROCESSED_FOLDER}'")
                    except Exception as e:
                        print(f"[{now()}] [WARN] Failed moving wrapper to processed folder: {e}")

                print("\n" + scoring_block + "\n")

        # catch unexpected errors, refresh tokens, and reload state
        except Exception as e:
            print(f"[{now()}] [ERROR] Loop exception: {e}")
            token = get_access_token()
            ticket_map = load_ticket_map()
            print(f"[{now()}] Reloaded ticket map entries={len(ticket_map)}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()