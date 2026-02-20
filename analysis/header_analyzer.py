import re
import ipaddress
from typing import Dict, Any, List, Set

IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_CANDIDATE_REGEX = re.compile(r"\b[a-fA-F0-9:]{2,}\b")

AUTH_REGEX = {
    "spf": re.compile(r"spf=(pass|fail|softfail|neutral|none)", re.IGNORECASE),
    "dkim": re.compile(r"dkim=(pass|fail|neutral|none)", re.IGNORECASE),
    "dmarc": re.compile(r"dmarc=(pass|fail|bestguesspass|none)", re.IGNORECASE),
}


# use Python's built-in ipaddress module to formally parse a string as an IP address, boolean for whether it is valid or not
def _is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


# extract and return a set of valid IPv4 and IPv6 addresses found within an arbitrary text blob
def _extract_ips_from_text(text: str) -> Set[str]:

    ips: Set[str] = set()

    # IPv4 candidates
    for m in IPV4_REGEX.findall(text or ""):
        if _is_valid_ip(m):
            ips.add(m)

    # IPv6 candidates
    for cand in IPV6_CANDIDATE_REGEX.findall(text or ""):
        if ":" in cand and _is_valid_ip(cand):
            ips.add(cand)

    return ips


# analyze email headers to extract IPs, Received hop chain, relay domains, and SPF/DKIM/DMARC results
def analyze_headers(headers: List[Dict[str, Any]]) -> Dict[str, Any]:

    all_ips: Set[str] = set()
    all_received_ips: Set[str] = set()
    header_domains: Set[str] = set()

    auth_results = {"spf": "not found", "dkim": "not found", "dmarc": "not found"}

    received_hops: List[Dict[str, Any]] = []

    # iterate headers and extract relevant data
    for header in headers or []:
        name = (header.get("name") or "").lower()
        value = header.get("value") or ""

        # extract IPs from every header value (not just received)
        all_ips.update(_extract_ips_from_text(value))

        # parse received headers into hop objects and track all IPs seen in the chain
        if name == "received":
            hop_ips = sorted(_extract_ips_from_text(value))
            if hop_ips:
                all_received_ips.update(hop_ips)

            # store hop index, hop IPs, and raw Received header text
            received_hops.append({
                "index": len(received_hops),
                "ips": hop_ips,
                "raw": value
            })

            # relay domain tokenization
            tokens = value.split()
            for token in tokens:
                if "." in token and not token.startswith("["):
                    header_domains.add(token.strip("();"))

        # parse SPF/DKIM/DMARC results
        if name == "authentication-results":
            lower_value = value.lower()
            for auth_type, regex in AUTH_REGEX.items():
                match = regex.search(lower_value)
                if match:
                    auth_results[auth_type] = match.group(1).lower()

    # return a structured summary
    return {
        "all_ips": sorted(all_ips),
        "all_received_ips": sorted(all_received_ips),
        "received_hops": received_hops,
        "sender_ips": sorted(all_received_ips),
        "header_domains": sorted(header_domains),
        "auth_results": auth_results
    }
