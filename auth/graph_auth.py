import msal
import os
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")          # Azure AD tenant (Directory) ID
CLIENT_ID = os.getenv("CLIENT_ID")          # App Registration client ID
CLIENT_SECRET = os.getenv("CLIENT_SECRET")  # App Registration secret value

if not TENANT_ID:
    raise RuntimeError("TENANT_ID is not set")
if not CLIENT_ID:
    raise RuntimeError("CLIENT_ID is not set")
if not CLIENT_SECRET:
    raise RuntimeError("CLIENT_SECRET is not set")

# OAuth2 authority endpoint - token issuing endpoint
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}" 
# ".default" means use the statically configured API permissions granted to this app
SCOPE = ["https://graph.microsoft.com/.default"]

def get_access_token():
    # use MSAL (Microsoft Authentication Library) to perform OAuth2 Client Credentials flow to return access_token (string)
    app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
        validate_authority=False
    )
    
    result = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in result:
        raise RuntimeError(f"Token acquisition failed: {result}")
    return result["access_token"]
