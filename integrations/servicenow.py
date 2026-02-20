# integrations/servicenow.py
import os
import time
import requests
from dotenv import load_dotenv

# load .env
load_dotenv()

SN_INSTANCE = os.getenv("SN_INSTANCE")  # e.g. https://dev12345.service-now.com

# OAuth 2.0 (Client Credentials)
SN_CLIENT_ID = os.getenv("SN_CLIENT_ID")
SN_CLIENT_SECRET = os.getenv("SN_CLIENT_SECRET")
SN_OAUTH_SCOPE = (os.getenv("SN_OAUTH_SCOPE") or "").strip()  # optional

# token endpoint (default ServiceNow)
SN_OAUTH_TOKEN_URL = os.getenv(
    "SN_OAUTH_TOKEN_URL",
    f"{SN_INSTANCE.rstrip('/')}/oauth_token.do" if SN_INSTANCE else ""
)

REQUEST_TIMEOUT = 15

_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0,
}


# validate required environment variables are present before attempting ServiceNow API calls
def _require_env():
    if not SN_INSTANCE:
        raise RuntimeError("SN_INSTANCE is not set (e.g. https://dev12345.service-now.com)")
    if not SN_CLIENT_ID:
        raise RuntimeError("SN_CLIENT_ID is not set (OAuth Client ID)")
    if not SN_CLIENT_SECRET:
        raise RuntimeError("SN_CLIENT_SECRET is not set (OAuth Client Secret)")
    if not SN_OAUTH_TOKEN_URL:
        raise RuntimeError("SN_OAUTH_TOKEN_URL could not be determined (set SN_INSTANCE or SN_OAUTH_TOKEN_URL)")


# mask secrets for safe error reporting
def _mask(s: str, keep: int = 4) -> str:
    if not s:
        return ""
    s = str(s)
    if len(s) <= keep:
        return "*" * len(s)
    return ("*" * (len(s) - keep)) + s[-keep:]


# request (or reuse cached) OAuth access token from ServiceNow using client credentials grant
def _get_oauth_token() -> str:
    _require_env()

    now = int(time.time())
    cached = _TOKEN_CACHE.get("access_token")
    expires_at = int(_TOKEN_CACHE.get("expires_at") or 0)

    if cached and now < (expires_at - 30):
        return cached

    data = {
        "grant_type": "client_credentials",
        "client_id": SN_CLIENT_ID,
        "client_secret": SN_CLIENT_SECRET,
    }

    if SN_OAUTH_SCOPE:
        data["scope"] = SN_OAUTH_SCOPE

    r = requests.post(
        SN_OAUTH_TOKEN_URL,
        data=data,
        headers={"Accept": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )

    if r.status_code not in (200, 201):
        try:
            err_json = r.json()
        except Exception:
            err_json = {"raw": r.text}

        raise RuntimeError(
            "ServiceNow OAuth token failed:\n"
            f"- token_url: {SN_OAUTH_TOKEN_URL}\n"
            f"- client_id: {_mask(SN_CLIENT_ID)}\n"
            f"- http_status: {r.status_code}\n"
            f"- response: {err_json}\n"
        )

    j = r.json()
    access_token = j.get("access_token")
    expires_in = int(j.get("expires_in") or 3600)

    if not access_token:
        raise RuntimeError(f"ServiceNow OAuth token response missing access_token: {j}")

    _TOKEN_CACHE["access_token"] = access_token
    _TOKEN_CACHE["expires_at"] = int(time.time()) + expires_in

    return access_token


# leverage Table API to create a ServiceNow incident
def create_incident(
    short_description: str,
    description: str,
    severity: str = "clean",
    category: str = "Security",
    subcategory: str = "Email",
) -> dict:
    _require_env()

    url = f"{SN_INSTANCE.rstrip('/')}/api/now/table/incident"

    sev = (severity or "").lower().strip()
    if sev == "malicious":
        impact = "1"
        urgency = "1"
    else:
        # clean
        impact = "3"
        urgency = "3"

    payload = {
        "short_description": short_description,
        "description": description,
        "category": category,
        "subcategory": subcategory,
        "impact": impact,
        "urgency": urgency,
    }

    token = _get_oauth_token()

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    r = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)

    if r.status_code not in (200, 201):
        raise RuntimeError(f"ServiceNow create incident failed: HTTP {r.status_code} - {r.text}")

    data = r.json().get("result", {}) or {}

    return {"sys_id": data.get("sys_id"), "number": data.get("number"), "raw": data}


# kept for future use; main.py does NOT call this now
def append_work_notes(sys_id: str, work_notes: str) -> dict:
    _require_env()
    if not sys_id or not work_notes:
        return {"updated": False, "reason": "missing_sys_id_or_notes"}

    url = f"{SN_INSTANCE.rstrip('/')}/api/now/table/incident/{sys_id}"

    token = _get_oauth_token()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    payload = {"work_notes": work_notes}

    r = requests.patch(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)

    if r.status_code not in (200, 204):
        raise RuntimeError(f"ServiceNow append work_notes failed: HTTP {r.status_code} - {r.text}")

    if r.status_code == 204:
        return {"updated": True, "raw": None}

    data = r.json().get("result", {}) or {}
    return {"updated": True, "raw": data}
