# ingest/reporter_original_finder.py
import re
from typing import Optional, Dict, Any, List, Tuple
import requests

GRAPH_URL = "https://graph.microsoft.com/v1.0"
REQUEST_TIMEOUT = 15


# URL-encode the mailbox/UP so it can safely be used in Graph API URL
def _encode_user(user: str) -> str:
    return requests.utils.quote(user or "", safe="")

WRAPPER_SUBJECT_RE = re.compile(
    r"^\s*(?:Phishing:|Junk:)\s*[^|]*\|(?P<reporter>[^|]+)\|\((?P<orig_subject>.+?)\)\s*.*$",
    re.IGNORECASE,
)


# extract (reporter_email, original_subject_guess), and if present, else (None, None)
def parse_wrapper_subject(wrapper_subject: str) -> Tuple[Optional[str], Optional[str]]:
    s = wrapper_subject or ""
    m = WRAPPER_SUBJECT_RE.match(s)
    if not m:
        return None, None

    reporter = (m.group("reporter") or "").strip()
    orig_subject = (m.group("orig_subject") or "").strip()

    if not reporter or "@" not in reporter:
        reporter = None
    if not orig_subject:
        orig_subject = None

    return reporter, orig_subject


# extract wrapper email's From address to identify the reporting user
def extract_wrapper_from_address(wrapper_msg: Dict[str, Any]) -> Optional[str]:
    from_obj = (wrapper_msg or {}).get("from") or {}
    from_email_obj = from_obj.get("emailAddress") or {}
    addr = (from_email_obj.get("address") or "").strip()
    if addr and "@" in addr:
        return addr.lower()
    return None


# when email's get reported, they are relocated to the 'Deleted Items' folder. here we access it
def search_deleted_items_by_subject(
    token: str,
    reporter_mailbox: str,
    subject_guess: str,
    top: int = 15
) -> List[Dict[str, Any]]:
    # encode for safety
    user_seg = _encode_user(reporter_mailbox)
    url = f"{GRAPH_URL}/users/{user_seg}/mailFolders/deleteditems/messages"

    headers = {
        "Authorization": f"Bearer {token}",
        "ConsistencyLevel": "eventual",
    }

    params = {
        "$top": int(top),
        "$search": f"\"{subject_guess}\"",
        "$select": "id,subject,receivedDateTime,from,internetMessageId",
    }

    r = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)

    # handle rate limiting
    if r.status_code == 429:
        retry_after = int(r.headers.get("Retry-After", "5") or "5")
        raise RuntimeError(f"Graph throttled (429) searching Deleted Items. Retry-After={retry_after}s")

    if r.status_code != 200:
        try:
            detail = r.json()
        except Exception:
            detail = {"raw": r.text}
        print(f"[Graph] DeletedItems search failed: status={r.status_code} reporter={reporter_mailbox} detail={detail}")
        return []

    return r.json().get("value", []) or []


# choose the best candidate message based on subject similarity and recency
def pick_best_subject_match(candidates: List[Dict[str, Any]], subject_guess: str) -> Optional[Dict[str, Any]]:
    if not candidates:
        return None

    guess = (subject_guess or "").strip().lower()

    scored = []
    for c in candidates:
        subj = (c.get("subject") or "").strip().lower()
        score = 0

        if subj == guess:
            score += 100
        elif guess and guess in subj:
            score += 50
        elif subj and subj in guess:
            score += 25

        received = c.get("receivedDateTime") or ""
        scored.append((score, received, c))

    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return scored[0][2]


# high-level helper that searches reporter Deleted Items and returns the best match for the original email
def find_original_in_reporter_deleted_items(token: str, reporter_mailbox: str, subject_guess: str) -> Optional[Dict[str, Any]]:
    if not reporter_mailbox or not subject_guess:
        return None

    # return most likely match based on similarity scoring and recency
    candidates = search_deleted_items_by_subject(token, reporter_mailbox, subject_guess, top=15)
    return pick_best_subject_match(candidates, subject_guess)
