import requests
from typing import Dict, Any, Optional

GRAPH_URL = "https://graph.microsoft.com/v1.0"
REQUEST_TIMEOUT = 15


# URL-encode the mailxbox UPN so it can safely be used in Graph API URL path
def _encode_user(user: str) -> str:
    return requests.utils.quote(user or "", safe="")


# fetch the full email message object from Microsoft Graph including headers, body, and attachments
def fetch_full_message(
    token: str,
    mailbox: str,
    message_id: str,
) -> Optional[Dict[str, Any]]:
    # validate required parameters before making API request
    if not token or not mailbox or not message_id:
        return None

    # build authorization header with OAuth access token
    headers = {"Authorization": f"Bearer {token}"}
    # encode mailbox identifier for safe inclusion in URL
    user_seg = _encode_user(mailbox)

    url = (
        f"{GRAPH_URL}/users/{user_seg}/messages/{message_id}"
        "?$select="
        "id,"
        "subject,"
        "from,"
        "receivedDateTime,"
        "body,"
        "internetMessageHeaders"
        "&$expand=attachments($select=id,name,contentType,size)"
    )

    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        # handle rate limiting
        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", "5") or "5")
            raise RuntimeError(f"Graph throttled (429) fetch message. Retry-After={retry_after}s")

        if r.status_code != 200:
            try:
                detail = r.json()
            except Exception:
                detail = {"raw": r.text}
            print(f"[Graph] fetch_full_message failed: status={r.status_code} message_id={message_id} detail={detail}")
            return None

        return r.json()

    except Exception as e:
        print(f"[Graph] fetch_full_message exception: message_id={message_id} err={e}")
        return None
