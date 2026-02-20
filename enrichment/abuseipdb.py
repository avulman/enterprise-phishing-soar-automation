import requests
import os

ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT = 10

# query AbuseIPDB to retrieve abuse reputation and metadata for a given IP address
def abuseipdb_lookup(ip):
    try:
        headers = {
            "Key": ABUSE_API_KEY,        # API key authentication
            "Accept": "application/json" # request JSON response
        }
        params = {
            "ipAddress": ip,    # IP to check
            "maxAgeInDays": 90, # only consider reports within last N days
            "verbose": True     # include extra metadata (categories, usageType, etc.)
        }

        # send GET request with headers and query parameters
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None
        
        # parse JSON and extract "data" object
        data = response.json().get("data", {})

        # return only selected fields
        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "totalReports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "isp": data.get("isp")
        }
    except Exception:
        return None
