"""Curated brand data: loading, lookup, and mention detection."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

BRANDS_PATH = Path(__file__).with_name("brands.json")


@dataclass
class Brand:
    name: str
    official_domain: str
    aliases: list[str] = field(default_factory=list)


def load_brands(path: Path | None = None) -> list[Brand]:
    data = json.loads((path or BRANDS_PATH).read_text(encoding="utf-8"))
    brands: list[Brand] = []
    for entry in data:
        brands.append(
            Brand(
                name=entry["name"],
                official_domain=entry["official_domain"].lower(),
                aliases=[a for a in entry.get("aliases", [])],
            )
        )
    return brands


def find_brand(query: str, brands: list[Brand]) -> Brand | None:
    """Match a --brand query to a curated brand (name or alias, case-insensitive)."""
    q = query.strip().lower()
    if not q:
        return None
    # Exact match first.
    for b in brands:
        if q == b.name.lower() or q in (a.lower() for a in b.aliases):
            return b
    # Then substring match on name/aliases.
    for b in brands:
        candidates = [b.name, *b.aliases]
        if any(q in c.lower() or c.lower() in q for c in candidates):
            return b
    return None


def detect_brands(text: str, brands: list[Brand]) -> list[Brand]:
    """Find curated brands mentioned in free text (word-boundary, case-insensitive)."""
    found: list[Brand] = []
    for b in brands:
        for candidate in [b.name, *b.aliases]:
            # Skip very short aliases (e.g. "BA") to avoid false positives.
            if len(candidate) < 3:
                continue
            if re.search(r"\b" + re.escape(candidate) + r"\b", text, re.IGNORECASE):
                found.append(b)
                break
    return found
