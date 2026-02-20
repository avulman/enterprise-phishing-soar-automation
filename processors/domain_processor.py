# processors/domain_processor.py
from enrichment.virustotal import vt_lookup_domain, vt_score_verdict

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


# main domain enrichment processor
def process_domains(domain: str):
    stats = vt_lookup_domain(domain)
    score = vt_score_verdict(stats)

    total, reported, malicious, suspicious = _vt_totals(stats)
    vt_tier = _vt_label(reported)

    return {
        "domain": domain,
        "stats": stats,
        "score": score,
        "pretty": {
            "vt_tier": vt_tier,      # CLEAN or MALICIOUS
            "vt_reported": reported, # malicious+suspicious
            "vt_total": total,
        }
    }
