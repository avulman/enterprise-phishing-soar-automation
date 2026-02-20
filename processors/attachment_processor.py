# processors/attachment_processor.py
import base64
import hashlib
from typing import Dict, Any, List, Optional

import requests

from core.enrich import enrich_hash

GRAPH_URL = "https://graph.microsoft.com/v1.0"
REQUEST_TIMEOUT = 15
VT_DETECTIONS_MALICIOUS_THRESHOLD = 10


# URL-encode mailbox/UPN to safely use Graph API URL
def _encode_user(user: str) -> str:
    return requests.utils.quote(user or "", safe="")


# determine whether a Graph attachment object represents a real life attachment to process
def _is_file_attachment(att: Dict[str, Any]) -> bool:
    odata_type = (att.get("@odata.type") or "").lower()
    if "fileattachment" in odata_type:
        return True
    if "itemattachment" in odata_type or "referenceattachment" in odata_type:
        return False
    return True  # unknown/missing type -> allow and validate later


# compute sha256 hex digest for raw bytes
def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


# perform an authenticated GET request to Graph and return JSON payload, handling throttling and errors
def _graph_get_json(token: str, url: str, params: Optional[dict] = None) -> Optional[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)

        # handle rate limiting
        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", "5") or "5")
            raise RuntimeError(f"Graph throttled (429). Retry-After={retry_after}s")

        if r.status_code != 200:
            try:
                detail = r.json()
            except Exception:
                detail = {"raw": r.text}
            print(f"[Graph] GET failed: status={r.status_code} url={url} params={params} detail={detail}")
            return None

        return r.json()
    except Exception as e:
        print(f"[Graph] GET exception: url={url} params={params} err={e}")
        return None


# get original attachment object directly from Graph
def _fetch_attachment_raw(token: str, mailbox: str, message_id: str, attachment_id: str) -> Optional[Dict[str, Any]]:
    user_seg = _encode_user(mailbox)
    url = f"{GRAPH_URL}/users/{user_seg}/messages/{message_id}/attachments/{attachment_id}"
    return _graph_get_json(token, url, params=None)


# extract VirusTotal detection count (malicious + suspicious) from a VT stats dict safely
def _vt_reported(stats: Any) -> int:
    if not isinstance(stats, dict):
        return 0
    try:
        mal = int(stats.get("malicious", 0) or 0)
        sus = int(stats.get("suspicious", 0) or 0)
        return mal + sus
    except Exception:
        return 0


# process all attachments for a given email: hash file bytes, enrich hashes, and return structure
def process_attachments_for_email(
    token: str,
    mailbox: str,
    email: Dict[str, Any],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    msg_id = email.get("id")
    attachments = email.get("attachments") or []
    if not msg_id or not attachments:
        return results

    for att in attachments:
        if not _is_file_attachment(att):
            continue

        att_id = att.get("id")
        name = att.get("name")
        size = att.get("size")
        ctype = att.get("contentType")

        content_b64 = att.get("contentBytes")

        if not content_b64 and att_id:
            raw_att = _fetch_attachment_raw(token, mailbox, msg_id, att_id)
            if raw_att:
                name = raw_att.get("name") or name
                size = raw_att.get("size") or size
                ctype = raw_att.get("contentType") or ctype
                content_b64 = raw_att.get("contentBytes")

                otype = (raw_att.get("@odata.type") or "").lower()
                if not content_b64 and otype and ("referenceattachment" in otype or "itemattachment" in otype):
                    results.append({
                        "filename": name,
                        "contentType": ctype,
                        "size": size,
                        "sha256": None,
                        "virustotal": None,
                        "score": None,
                        "verdict": "NON_FILE_ATTACHMENT"
                    })
                    continue

        if not content_b64:
            results.append({
                "filename": name,
                "contentType": ctype,
                "size": size,
                "sha256": None,
                "virustotal": None,
                "score": None,
                "verdict": "NO_BYTES"
            })
            continue

        try:
            raw = base64.b64decode(content_b64)
        except Exception:
            results.append({
                "filename": name,
                "contentType": ctype,
                "size": size,
                "sha256": None,
                "virustotal": None,
                "score": None,
                "verdict": "DECODE_ERROR"
            })
            continue

        sha256 = _sha256_bytes(raw)

        enriched = enrich_hash(sha256)
        vt_stats = (enriched.get("virustotal") or {}).get("stats")
        vt_score = (enriched.get("virustotal") or {}).get("score") or {}
        vt_raw = (enriched.get("virustotal") or {}).get("raw")

        reported = _vt_reported(vt_stats)
        verdict = "MALICIOUS" if reported >= VT_DETECTIONS_MALICIOUS_THRESHOLD else "CLEAN"

        results.append({
            "filename": name,
            "contentType": ctype,
            "size": size,
            "sha256": sha256,
            "virustotal": vt_raw,
            "score": vt_score,
            "verdict": verdict
        })

    # return attachment results for scoring and ticket output
    return results
