# analysis/ioc_extractor.py
import re
from urllib.parse import urlparse

URL_REGEX = re.compile(
    r'\bhttps?://[^\s<>"]+',
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(
    r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
    re.IGNORECASE
)

DOMAIN_REGEX = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
    re.IGNORECASE
)

# normalize domain name by lowercasing, stripping whitespace, removing trailing dots, and removing 'www.' prefix
def _normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


# extract and normalize domain names from a set of URLs using urllib.parse.urlparse
def extract_domains_from_urls(urls: set) -> set:
    domains = set()
    for url in urls:
        try:
            # parse URL into components (scheme, hostname, path, etc.)
            parsed = urlparse(url)
            # extract hostname portion
            host = (parsed.hostname or "").strip().lower()
            if not host:
                continue
            # normalize domain for consistency
            domains.add(_normalize_domain(host))
        except Exception:
            continue
    return domains


# extract URLs, domains, and email addresses from email body text for threat intelligence enrichment
def extract_iocs_from_body(body_text: str) -> dict:

    # validate input
    if not body_text or not isinstance(body_text, str):
        return {
            "urls": [],
            "domains": [],
            "emails": []
        }

    # normalize whitespace to improve regex matching
    text = body_text.replace("\r", " ").replace("\n", " ")

    # extract URLs
    urls = set(URL_REGEX.findall(text))

    # extract email addresses
    emails = set(EMAIL_REGEX.findall(text))

    # extract domain names found directly in text
    domains_raw = set(DOMAIN_REGEX.findall(text))

    # normalize domains
    domains = set()
    for d in domains_raw:
        nd = _normalize_domain(d)
        if nd:
            domains.add(nd)

    # extract domains from URLs and merge into domain set
    domains.update(extract_domains_from_urls(urls))

    # return sorted IOC lists for consistent output
    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "emails": sorted(emails)
    }
