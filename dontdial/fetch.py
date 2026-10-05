"""Fetch a brand's official contact page(s) and extract listed phone numbers.

This is the ONLY network access dontdial performs, and only when verifying a
phone number against a curated brand. Failures are silent (caller treats them
as UNKNOWN, never as a verdict).
"""

from __future__ import annotations

import re

import requests

from .extract import _normalize_phone

CONTACT_PATHS = [
    "/contact-us",
    "/contact",
    "/support",
    "/help",
    "/customer-service",
    "/us/en/contact-us",
]

USER_AGENT = "dontdial/0.1 (+https://github.com/CYPHERLYNX/dontdial; contact verification)"
TIMEOUT = 8

_phone_run_re = re.compile(r"(?<!\d)(?:\+?\d[\d .()\-\u2013\u2014]{5,}\d)(?!\d)")


def _numbers_in_html(html: str, default_region: str = "US") -> set[str]:
    found: set[str] = set()
    # Strip scripts/styles to reduce noise.
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)
    for m in _phone_run_re.finditer(text):
        digits = _normalize_phone(m.group(0), default_region)
        if 7 <= len(digits) <= 15:
            found.add(digits)
    # tel: links are high-signal.
    for m in re.finditer(r'href=["\']tel:([^"\']+)', html, re.IGNORECASE):
        digits = _normalize_phone(m.group(1), default_region)
        if 7 <= len(digits) <= 15:
            found.add(digits)
    return found


def fetch_official_numbers(
    official_domain: str,
    contact_paths: list[str] | None = None,
    timeout: int = TIMEOUT,
) -> set[str] | None:
    """Return digit-normalized numbers found on the brand's official site.

    Returns None if the site could not be reached at all (caller must treat
    this as UNKNOWN, not as evidence).
    """
    numbers: set[str] = set()
    reached = False
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    hosts = [official_domain]
    if not official_domain.startswith("www."):
        hosts.append("www." + official_domain)
    for path in contact_paths or CONTACT_PATHS:
        for host in hosts:
            url = f"https://{host}{path}"
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            if resp.status_code != 200:
                continue
            # Refuse to learn numbers from a redirect off the official domain.
            final_host = (resp.url.split("/")[2] if "://" in resp.url else "")
            if not (final_host == official_domain or final_host.endswith("." + official_domain)):
                continue
            reached = True
            numbers |= _numbers_in_html(resp.text)
            if numbers:
                break  # one good contact page is enough
        if numbers:
            break
    if not reached:
        return None
    return numbers
