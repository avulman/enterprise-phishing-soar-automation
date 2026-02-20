from urllib.parse import urlparse

WHITELIST_DOMAINS = {
    # INPUT DOMAINS TO WHITELIST HERE
    "google.com",
    "gmail.com",
    "mail.gmail.com",
    "microsoft.com",
    "outlook.office365.com",
    "prod.outlook.com",
    "protection.outlook.com",
    "mx.microsoft.com",
    "john.silly",
    "lebron.james",
}


# filter trusted URLs that belong to trusted domains to reduce noise during analysis
def filter_urls(urls):
    # create empty set to store URLs NOT whitelisted
    filtered = set()
    # iterate URLs
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]

            if any(domain == wd or domain.endswith("." + wd) for wd in WHITELIST_DOMAINS):
                continue

            filtered.add(url)
        except Exception:
            continue
    return filtered
