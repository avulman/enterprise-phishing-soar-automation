# ingest/move_message.py
import requests
from typing import Optional, Dict, Any

GRAPH_URL = "https://graph.microsoft.com/v1.0"
REQUEST_TIMEOUT = 15

# URL-encode mailbox UPN so it can safely use Graph API URL paths
def _encode_user(user: str) -> str:
    return requests.utils.quote(user or "", safe="")


# move an email message from current folder to destination folder within the same mailbox
def move_message_to_folder(
    token: str,
    mailbox: str,
    message_id: str,
    destination_folder_id: str,
) -> Optional[Dict[str, Any]]:
    # validate required parameters before attempting move operation
    if not token or not mailbox or not message_id or not destination_folder_id:
        return None

    # encode mailbox identifier for safe inclusion in Graph API URL
    user_seg = _encode_user(mailbox)
    url = f"{GRAPH_URL}/users/{user_seg}/messages/{message_id}/move"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    payload = {"destinationId": destination_folder_id}

    r = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)

    # handle rate limiting
    if r.status_code == 429:
        retry_after = int(r.headers.get("Retry-After", "5") or "5")
        raise RuntimeError(f"Graph throttled (429) move message. Retry-After={retry_after}s")

    if r.status_code not in (200, 201):
        try:
            detail = r.json()
        except Exception:
            detail = {"raw": r.text}
        print(f"[Graph] move_message_to_folder failed: status={r.status_code} id={message_id} detail={detail}")
        return None

    return r.json()
