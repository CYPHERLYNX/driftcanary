"""Entity extraction: phone numbers, URLs, emails from free text.

Phones are found with the `phonenumbers` matcher (region US default, with
international `+` prefixes handled); URLs and emails via regex. URL/email
spans are masked before phone matching so digits inside them are not
double-counted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import phonenumbers

URL_RE = re.compile(
    r"""
    (?P<url>
        https?://[^\s<>"'()\[\]]+
      | www\.[^\s<>"'()\[\]]+
      | (?<![\w@/-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
        (?:com|net|org|io|co|ai|app|dev|info|biz|us|uk|in|edu|gov)
        (?:/[^\s<>"'()\[\]]*)?
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)

# Matches a plausible standalone phone-number-ish run of digits/separators.
# Used only as a fallback when phonenumbers finds nothing (e.g. odd spacing).
PHONE_FALLBACK_RE = re.compile(
    r"(?<!\d)(?:\+?\d[\d .()\-\u2013\u2014]{5,}\d)(?!\d)"
)

_TRAILING_PUNCT = ".,;:!?)'\""


@dataclass
class Entity:
    kind: str            # "phone" | "url" | "email"
    raw: str
    normalized: str = ""  # digits for phones, lowercased domain for url/email
    span: tuple[int, int] = (0, 0)


def _strip_trailing_punct(s: str) -> str:
    return s.rstrip(_TRAILING_PUNCT)


def _normalize_phone(raw: str, default_region: str = "US") -> str:
    """Return digit-only normalized form, E.164 digits preferred."""
    try:
        parsed = phonenumbers.parse(raw, default_region)
        if phonenumbers.is_possible_number(parsed):
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            digits = re.sub(r"\D", "", e164)
            if digits:
                return digits
    except Exception:
        pass
    digits = re.sub(r"\D", "", raw)
    return digits


def extract_phones(text: str, default_region: str = "US") -> list[Entity]:
    entities: list[Entity] = []
    seen_spans: list[tuple[int, int]] = []
    for match in phonenumbers.PhoneNumberMatcher(text, default_region):
        raw = _strip_trailing_punct(match.raw_string)
        digits = _normalize_phone(raw, default_region)
        if not (7 <= len(digits) <= 15):
            continue
        start = match.start
        end = start + len(raw)
        entities.append(Entity(kind="phone", raw=raw, normalized=digits, span=(start, end)))
        seen_spans.append((start, end))

    # Fallback for odd formats phonenumbers missed.
    masked = list(text)
    for s, e in seen_spans:
        for i in range(s, min(e, len(masked))):
            masked[i] = " "
    masked_text = "".join(masked)
    for m in PHONE_FALLBACK_RE.finditer(masked_text):
        raw = _strip_trailing_punct(m.group(0))
        digits = re.sub(r"\D", "", raw)
        if not (7 <= len(digits) <= 15):
            continue
        if any(s <= m.start() < e for s, e in seen_spans):
            continue
        entities.append(Entity(kind="phone", raw=raw, normalized=digits, span=(m.start(), m.end())))
    return entities


def extract_urls(text: str) -> list[Entity]:
    entities: list[Entity] = []
    for m in URL_RE.finditer(text):
        raw = _strip_trailing_punct(m.group("url"))
        entities.append(Entity(kind="url", raw=raw, span=(m.start(), m.start() + len(raw))))
    return entities


def extract_emails(text: str) -> list[Entity]:
    entities: list[Entity] = []
    for m in EMAIL_RE.finditer(text):
        raw = m.group(0)
        # Avoid re-matching the userinfo part of a URL like http://user@host
        entities.append(Entity(kind="email", raw=raw, span=(m.start(), m.end())))
    return entities


def extract_all(text: str, default_region: str = "US") -> list[Entity]:
    """Extract urls, emails, then phones (phones skip url/email spans)."""
    urls = extract_urls(text)
    emails = extract_emails(text)
    occupied = [(e.span[0], e.span[1]) for e in urls + emails]

    masked = list(text)
    for s, e in occupied:
        for i in range(s, min(e, len(masked))):
            masked[i] = " "
    phones = extract_phones("".join(masked), default_region)

    # Fix phone spans back to original coordinates (masking preserved length).
    all_entities = urls + emails + phones
    all_entities.sort(key=lambda e: e.span[0])
    # Drop emails that are inside a URL span (e.g. user@ in http://user@host/).
    url_spans = [(e.span[0], e.span[1]) for e in urls]
    filtered: list[Entity] = []
    for e in all_entities:
        if e.kind == "email" and any(s <= e.span[0] and e.span[1] <= en for s, en in url_spans):
            continue
        filtered.append(e)
    return filtered
