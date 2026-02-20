import os
import base64
import requests
from dotenv import load_dotenv

# load .env file
load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 10

if not VT_API_KEY:
    raise RuntimeError("VIRUSTOTAL_API_KEY is not set (check .env)")

VT_HEADERS = {"x-apikey": VT_API_KEY}


# query URL in VirusTotal
def vt_lookup_url(url: str):
    try:
        # VT expects a URL identifier: base64(url) with urlsafe alphabet and stripped "=" padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # construct endpoint: /urls/{url_id}
        api_url = f"{VT_BASE_URL}/urls/{url_id}"

        # send request with auth header and timeout
        response = requests.get(api_url, headers=VT_HEADERS, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None
        
        # parse response JSON
        data = response.json()

        # return the nested analysis stats dict, or None if missing
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    
    except Exception:
        return None


# query domain in VirusTotal
def vt_lookup_domain(domain: str):
    try:
        api_url = f"{VT_BASE_URL}/domains/{domain}"
        response = requests.get(api_url, headers=VT_HEADERS, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None
        data = response.json()
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    except Exception:
        return None


# query IP in VirusTotal
def vt_lookup_ip(ip: str):
    try:
        api_url = f"{VT_BASE_URL}/ip_addresses/{ip}"
        response = requests.get(api_url, headers=VT_HEADERS, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None
        data = response.json()
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    except Exception:
        return None


# query file hash in VirusTotal
def vt_lookup_file_hash(file_hash: str):
    try:
        api_url = f"{VT_BASE_URL}/files/{file_hash}"
        response = requests.get(api_url, headers=VT_HEADERS, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None

        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})

        return {
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "meaningful_name": attrs.get("meaningful_name"),
            "type_description": attrs.get("type_description"),
            "size": attrs.get("size"),
        }
    except Exception:
        return None


# convert VirusTotal analysis stats into normalized verdict object
def vt_score_verdict(stats: dict):
    if not stats or not isinstance(stats, dict):
        return {
            "verdict": "NO_DATA",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    # extract detection counts
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    # verdict scoring
    if malicious >= 2:
        verdict = "MALICIOUS"
    elif suspicious >= 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    # return structured verdict object
    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected
    }
