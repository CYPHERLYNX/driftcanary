"""Shared probe-pack plumbing: metric aggregation and the probe registry."""
from __future__ import annotations

from typing import Dict, List


def median(values: List[float]) -> float:
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def mode(values: List[float]) -> float:
    """Most common value; ties break toward the first-seen value."""
    counts: Dict[float, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    best = values[0]
    for v in values:
        if counts[v] > counts[best]:
            best = v
    return float(best)


def aggregate(samples: List[Dict[str, float]]) -> Dict[str, float]:
    """Collapse per-sample metric dicts into one observation.

    Binary (0/1) metrics aggregate by mode; everything else by median.
    """
    out: Dict[str, float] = {}
    keys = sorted({k for s in samples for k in s})
    for k in keys:
        vals = [s[k] for s in samples if k in s]
        if not vals:
            continue
        if all(v in (0.0, 1.0) for v in vals):
            out[k] = mode(vals)
        else:
            out[k] = median(vals)
    return out
