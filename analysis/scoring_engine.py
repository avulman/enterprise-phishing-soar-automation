# analysis/scoring_engine.py
from typing import List, Dict, Any, Optional

# if final score is >= this integer, classify the email as malicious
MALICIOUS_THRESHOLD_SCORE = 10

# VirusTotal "detections" threshold: malicious + suspicious counts >= 10 indicates high risk
VT_DETECTIONS_MALICIOUS_THRESHOLD = 10


# convert score to an int and clamp it into a min/max range of [0, 100]
def _clamp_score(score: int) -> int:
    try:
        s = int(score)
    except Exception:
        s = 0
    return max(0, min(s, 100))

# convert a numeric score and reasons into a final veridct object (malicious vs clean) with confidence
def _finalize_clean_or_malicious(score: int, reasons: List[str]) -> Dict[str, Any]:
    score = _clamp_score(score)

    if score >= MALICIOUS_THRESHOLD_SCORE:
        return {
            "score": score,
            "verdict": "malicious",
            "confidence": 95,
            "reasons": reasons or [],
        }

    return {
        "score": score,
        "verdict": "clean",
        "confidence": 70,
        "reasons": reasons or [],
    }


# return VirusTotal detection count = malicious + suspicious from VT stats dict (safe against bad input)
def _vt_reported_from_stats(stats: Any) -> int:
    if not isinstance(stats, dict):
        return 0
    try:
        mal = int(stats.get("malicious", 0) or 0)
        sus = int(stats.get("suspicious", 0) or 0)
        return mal + sus
    except Exception:
        return 0


# extract VirusTotal detection count from a summary object
def _vt_reported_from_summary(obj: Dict[str, Any]) -> int:
    return _vt_reported_from_stats((obj or {}).get("stats"))


# score an email using enrichment results (attachments/URLs/domains/IPs) and return verdict+reasons
def score_email(
    att_results: Optional[List[Dict[str, Any]]] = None,
    url_vt_summaries: Optional[List[Dict[str, Any]]] = None,
    domain_vt_summaries: Optional[List[Dict[str, Any]]] = None,
    ip_rep_summaries: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    att_results = att_results or []
    url_vt_summaries = url_vt_summaries or []
    domain_vt_summaries = domain_vt_summaries or []
    ip_rep_summaries = ip_rep_summaries or []

    score = 0
    reasons: List[str] = []

    # attachment scoring
    for a in att_results:
        verdict = (a.get("verdict") or "").upper().strip()
        if verdict == "MALICIOUS":
            score += 50
            reasons.append("+50: Attachment VT detections >= 10 (malicious)")

    # URL scoring
    for u in url_vt_summaries:
        url_val = u.get("url") or "(url)"
        reported = _vt_reported_from_summary(u)

        if reported >= VT_DETECTIONS_MALICIOUS_THRESHOLD:
            score += 40
            reasons.append(f"+40: URL VT detections={reported} (>=10) ({url_val})")

    # domain scoring
    for d in domain_vt_summaries:
        dom_val = d.get("domain") or "(domain)"
        reported = _vt_reported_from_summary(d)

        if reported >= VT_DETECTIONS_MALICIOUS_THRESHOLD:
            score += 35
            reasons.append(f"+35: Domain VT detections={reported} (>=10) ({dom_val})")

    # IP scoring
    for ipr in ip_rep_summaries:
        try:
            ip = (ipr.get("ip") or "").strip()
            vt_stats = ipr.get("virustotal")
            reported = _vt_reported_from_stats(vt_stats)

            if ip and reported >= VT_DETECTIONS_MALICIOUS_THRESHOLD:
                score += 15
                reasons.append(f"+15: IP VT detections={reported} (>=10) ({ip})")
        except Exception:
            continue

    # convert score + reasons into final verdict object
    return _finalize_clean_or_malicious(score, reasons)
