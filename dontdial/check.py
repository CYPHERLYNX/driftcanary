"""Verdict logic: VERIFIED / SUSPICIOUS / UNKNOWN per entity.

URL/email checks are deterministic (domain comparison + typosquat detection).
Phone checks compare against numbers listed on the brand's official site
(see fetch.py); where ground truth is unavailable the verdict is UNKNOWN,
never a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .brands import Brand
from .extract import Entity

# Verdicts
VERIFIED = "VERIFIED"
SUSPICIOUS = "SUSPICIOUS"
UNKNOWN = "UNKNOWN"

# Multi-label public suffixes we handle when computing the registrable domain.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.in", "co.jp", "com.br", "co.kr",
    "com.mx", "co.za", "com.sg",
}


@dataclass
class Verdict:
    entity: Entity
    verdict: str
    evidence: str
    brand: str | None = None  # brand name this was checked against, if any


def levenshtein(a: str, b: str) -> int:
    """Simple DP Levenshtein distance (stdlib)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable_domain(host: str) -> str:
    """Naive registrable domain: last two labels, three for known multi-suffixes."""
    host = host.lower().strip().rstrip(".")
    # Strip port and userinfo if present.
    host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIX:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def host_of_url(raw_url: str) -> str:
    url = raw_url if "://" in raw_url else "https://" + raw_url
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _lookalike_reason(domain: str, official: str) -> str | None:
    """Return a reason string if `domain` looks like a typosquat of `official`."""
    if domain == official:
        return None
    base_official = official.split(".")[0]
    base_domain = domain.split(".")[0]
    # Punycode / IDN homograph.
    if domain.startswith("xn--") or "xn--" in domain:
        return f"uses punycode/IDN encoding resembling {official}"
    # Edit distance on the registrable domain.
    dist = levenshtein(domain, official)
    if dist <= 2:
        return f"differs from {official} by {dist} character(s) (possible typosquat)"
    # Brand name embedded with extra bits: chase-secure.com, deltahq-support.com
    if base_official and base_official in domain and domain != official:
        return f"embeds '{base_official}' but is not {official}"
    # Official domain embedded as a subdomain of another domain: delta.com.evil.com
    if official in domain and domain != official:
        return f"contains '{official}' inside a different domain (subdomain trick)"
    # Close edit distance on the brand label itself.
    if base_official and base_domain and levenshtein(base_domain, base_official) <= 2 and base_domain != base_official:
        return f"brand label '{base_domain}' is {levenshtein(base_domain, base_official)} edit(s) from '{base_official}'"
    return None


def check_url(entity: Entity, brands: list[Brand]) -> Verdict:
    host = host_of_url(entity.raw)
    domain = registrable_domain(host)
    brand_names = ", ".join(b.name for b in brands) if brands else None

    if not domain:
        return Verdict(entity, UNKNOWN, "could not parse a domain from the URL", brand_names)

    for b in brands:
        official = b.official_domain
        if domain == official:
            sub = f"subdomain of {official}" if host.lower() != official else f"the official domain {official}"
            return Verdict(entity, VERIFIED, f"{host} is {sub}", b.name)
        # Subdomain trick on the FULL host: delta.com.evil.com
        if official in host.lower() and domain != official:
            return Verdict(
                entity, SUSPICIOUS,
                f"{host}: contains '{official}' inside a different domain (subdomain trick)",
                b.name,
            )
        reason = _lookalike_reason(domain, official)
        if reason:
            return Verdict(entity, SUSPICIOUS, f"{host}: {reason}", b.name)

    if brands:
        return Verdict(
            entity, UNKNOWN,
            f"{host} is not {brand_names}' official domain; could not confirm it belongs to them",
            brand_names,
        )
    return Verdict(entity, UNKNOWN, f"{host}: no brand context to verify against")


def check_email(entity: Entity, brands: list[Brand]) -> Verdict:
    domain = entity.raw.rsplit("@", 1)[-1].lower()
    brand_names = ", ".join(b.name for b in brands) if brands else None
    for b in brands:
        official = b.official_domain
        if domain == official or domain.endswith("." + official):
            return Verdict(entity, VERIFIED, f"@{domain} is on the official domain {official}", b.name)
        reason = _lookalike_reason(domain, official)
        if reason:
            return Verdict(entity, SUSPICIOUS, f"@{domain}: {reason}", b.name)
    if brands:
        return Verdict(
            entity, UNKNOWN,
            f"@{domain} is not on {brand_names}' official domain; could not confirm the sender",
            brand_names,
        )
    return Verdict(entity, UNKNOWN, f"@{domain}: no brand context to verify against")


_PREMIUM_PATTERNS = [
    (re.compile(r"^1900\d{7}$"), "US premium-rate 1-900 number"),
    (re.compile(r"^1976\d{7}$"), "US premium-rate 1-976 number"),
    (re.compile(r"^449\d{8}$"), "UK premium-rate number (+44 9...)"),
]


def _suspicious_phone_pattern(digits: str) -> str | None:
    for rx, label in _PREMIUM_PATTERNS:
        if rx.match(digits):
            return label
    core = digits[-10:] if len(digits) > 10 else digits
    if len(core) >= 7 and len(set(core)) == 1:
        return "repeated-digit number (common in scams)"
    if len(digits) < 7:
        return "unusually short number"
    if len(digits) > 15:
        return "unusually long number"
    return None


def check_phone(
    entity: Entity,
    brands: list[Brand],
    official_numbers: dict[str, set[str]] | None = None,
) -> Verdict:
    """Check a phone number.

    official_numbers maps official_domain -> set of digit-normalized numbers
    found on that brand's official site (from fetch.py). None means the fetch
    was not attempted/failed for that brand.
    """
    digits = entity.normalized
    official_numbers = official_numbers or {}
    brand_names = ", ".join(b.name for b in brands) if brands else None

    for b in brands:
        known = official_numbers.get(b.official_domain)
        if known is None:
            continue  # fetch failed for this brand; don't guess
        if digits in known:
            return Verdict(entity, VERIFIED, f"{entity.raw} is listed on {b.official_domain}", b.name)
        # Tolerant match: compare last 10 digits (toll-free vs local formatting).
        if any(digits[-10:] == k[-10:] for k in known if len(k) >= 10 and len(digits) >= 10):
            return Verdict(entity, VERIFIED, f"{entity.raw} matches a number listed on {b.official_domain}", b.name)

    # No brand matched a fetched list: pattern heuristics, else UNKNOWN.
    pattern = _suspicious_phone_pattern(digits)
    if pattern:
        return Verdict(entity, SUSPICIOUS, f"{entity.raw}: {pattern}", brand_names)

    if brands:
        fetched_any = any(official_numbers.get(b.official_domain) is not None for b in brands)
        if fetched_any:
            return Verdict(
                entity, UNKNOWN,
                f"{entity.raw} was not found on {brand_names}' official site; could not confirm it",
                brand_names,
            )
        return Verdict(
            entity, UNKNOWN,
            f"could not reach {brand_names}' official site to verify {entity.raw}",
            brand_names,
        )
    return Verdict(entity, UNKNOWN, f"{entity.raw}: no brand context to verify against")


def check_entity(
    entity: Entity,
    brands: list[Brand],
    official_numbers: dict[str, set[str]] | None = None,
) -> Verdict:
    if entity.kind == "url":
        return check_url(entity, brands)
    if entity.kind == "email":
        return check_email(entity, brands)
    return check_phone(entity, brands, official_numbers)
