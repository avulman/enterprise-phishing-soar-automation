# core/enrich.py
from typing import Dict, Any, Optional

from enrichment.virustotal import (
    vt_lookup_ip,
    vt_lookup_url,
    vt_lookup_domain,
    vt_lookup_file_hash,
    vt_score_verdict,
)
from enrichment.abuseipdb import abuseipdb_lookup


# enrich an IP address by querying VirusTotal and AbuseIPDB for threat intelligence
def enrich_ip(ip: str) -> Dict[str, Any]:
    stats = vt_lookup_ip(ip)
    score = vt_score_verdict(stats)
    abuse = abuseipdb_lookup(ip) or {}

    return {
        "type": "ip",
        "value": ip,
        "virustotal": {"stats": stats, "score": score},
        "abuseipdb": abuse,
    }

# enrich a URL by querying VirusTotal for threat intelligence
def enrich_url(url: str) -> Dict[str, Any]:
    stats = vt_lookup_url(url)
    score = vt_score_verdict(stats)

    return {
        "type": "url",
        "value": url,
        "virustotal": {"stats": stats, "score": score},
    }


# enrich a domain by querying VirusTotal for threat intelligence
def enrich_domain(domain: str) -> Dict[str, Any]:
    stats = vt_lookup_domain(domain)
    score = vt_score_verdict(stats)

    return {
        "type": "domain",
        "value": domain,
        "virustotal": {"stats": stats, "score": score},
    }


# enrich a file hash (SHA256) by querying VirusTotal for file analysis results
def enrich_hash(sha256: str) -> Dict[str, Any]:
    vt = vt_lookup_file_hash(sha256)
    stats = vt.get("last_analysis_stats") if vt else None
    score = vt_score_verdict(stats)

    return {
        "type": "hash",
        "value": sha256,
        "virustotal": {"stats": stats, "score": score, "raw": vt},
    }


# enrich a generic observable object dynamically based on its declared type
def enrich_observable(observable: Dict[str, Any]) -> Dict[str, Any]:
    obs = observable or {}
    obs_type = (obs.get("type") or "").strip().lower()
    value = (obs.get("value") or "").strip()

    if not obs_type or not value:
        return {
            "type": obs_type or None,
            "value": value or None,
            "error": "missing_type_or_value",
        }

    if obs_type == "ip":
        return enrich_ip(value)

    if obs_type == "url":
        return enrich_url(value)

    if obs_type == "domain":
        return enrich_domain(value)

    # allow a few common aliases for hash in demo pipelines
    if obs_type in ("hash", "sha256", "file_hash"):
        return enrich_hash(value)

    return {
        "type": obs_type,
        "value": value,
        "error": f"unsupported_observable_type:{obs_type}",
    }

# safely retrieve nested dictionary values without raising exceptions if keys are missing
def safe_get(d: Optional[dict], *path, default=None):
    cur = d or {}
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default
