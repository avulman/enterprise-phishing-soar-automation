# processors/ip_processor.py
from enrichment.virustotal import vt_lookup_ip, vt_score_verdict
from enrichment.abuseipdb import abuseipdb_lookup

VT_DETECTIONS_MALICIOUS_THRESHOLD = 10


# extract and compute useful totals from VirusTotal stats object
def _vt_totals(stats: dict):
    if not stats or not isinstance(stats, dict):
        return 0, 0, 0, 0

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    timeout = int(stats.get("timeout", 0) or 0)

    total = malicious + suspicious + harmless + undetected + timeout
    reported = malicious + suspicious
    return total, reported, malicious, suspicious


# determine final VirusTotal tier label based on detection count threshold
def _vt_label(reported: int) -> str:
    return "MALICIOUS" if reported >= VT_DETECTIONS_MALICIOUS_THRESHOLD else "CLEAN"


# main IP enrichment processor used
def process_ips(ip: str):
    vt_stats = vt_lookup_ip(ip)
    vt_score = vt_score_verdict(vt_stats)

    total, reported, malicious, suspicious = _vt_totals(vt_stats)
    vt_tier = _vt_label(reported)

    abuse = abuseipdb_lookup(ip) or {}
    abuse_score = abuse.get("abuseConfidenceScore", 0) or 0

    country = abuse.get("country") or "Unknown"
    isp = abuse.get("isp") or "Unknown"

    return {
        "ip": ip,
        "virustotal": vt_stats,
        "vt_score": vt_score,
        "abuseipdb": abuse,
        "pretty": {
            "country": country,
            "isp": isp,
            "vt_tier": vt_tier,         # CLEAN or MALICIOUS (VT gated)
            "vt_reported": reported,    # malicious+suspicious
            "vt_total": total,
            "abuse_score": abuse_score, # informational only
        }
    }
