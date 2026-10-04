"""Two-sided CUSUM change-point detection over per-probe metric series.

Method
------
For each (probe, metric) series we estimate the in-control mean mu0 and
standard deviation sigma from the first WARMUP_RUNS observations (the warmup
window). Every later observation x is standardized to z = (x - mu0) / sigma
and fed to a two-sided CUSUM:

    S_h = max(0, S_h + z - k)      (upward drift accumulator)
    S_l = max(0, S_l - z - k)      (downward drift accumulator)

A change is declared at the first index where S_h > h or S_l > h. The
change-point *estimate* is the last index where the firing accumulator was
at zero before the alarm (the standard CUSUM change-point estimator).

Defaults k=0.5, h=4.0 are the textbook compromise: they detect a sustained
~1-sigma shift within a handful of observations while keeping the in-control
average run length long. They are tunable, not magic — see the README's
"Honest statistics" section.

Honesty rules enforced here, not just documented:
  * No verdict before WARMUP_RUNS observations exist ("warming up").
  * A constant series (sigma == 0) can never alarm — there is no variation
    to detect a change in.
  * Gradual drift alarms LATER than step changes; the detector reports the
    estimated change index so the report can show it, not hide it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

DEFAULT_WARMUP_RUNS = 20
DEFAULT_K = 0.5
DEFAULT_H = 4.0


@dataclass
class CusumConfig:
    warmup_runs: int = DEFAULT_WARMUP_RUNS
    k: float = DEFAULT_K          # reference (slack) value, in sigma units
    h: float = DEFAULT_H          # decision threshold, in sigma units

    def __post_init__(self) -> None:
        if self.warmup_runs < 5:
            raise ValueError("warmup_runs must be >= 5")
        if self.k <= 0 or self.h <= 0:
            raise ValueError("k and h must be positive")


@dataclass
class DriftVerdict:
    probe: str
    metric: str
    status: str                    # 'ok' | 'warming_up' | 'drift'
    n_observations: int = 0
    warmup_runs: int = DEFAULT_WARMUP_RUNS
    # Filled when status == 'drift':
    direction: Optional[str] = None        # 'up' | 'down'
    alarm_index: Optional[int] = None      # 0-based index into the series
    change_index: Optional[int] = None     # estimated change-point index
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None
    shift_sigma: Optional[float] = None    # post-change mean shift, in sigma
    detail: str = ""


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values)


def _stdev(values: Sequence[float], mean: float) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    return math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1))


@dataclass
class _CusumState:
    s_h: float = 0.0
    s_l: float = 0.0
    # Last index where each accumulator was exactly zero (change-point est).
    zero_h: int = -1
    zero_l: int = -1


def detect_series(values: Sequence[float], probe: str, metric: str,
                  config: Optional[CusumConfig] = None) -> DriftVerdict:
    """Run two-sided CUSUM over one metric series.

    `values` must be in chronological order. Returns a DriftVerdict; never
    raises on short/constant/degenerate input.
    """
    cfg = config or CusumConfig()
    n = len(values)
    verdict = DriftVerdict(probe=probe, metric=metric, status="ok",
                           n_observations=n, warmup_runs=cfg.warmup_runs)

    if n < cfg.warmup_runs:
        verdict.status = "warming_up"
        verdict.detail = (
            "only %d of %d warmup observations collected; "
            "no drift verdict yet" % (n, cfg.warmup_runs)
        )
        return verdict

    warmup = list(values[:cfg.warmup_runs])
    mu0 = _mean(warmup)
    sigma = _stdev(warmup, mu0)
    verdict.baseline_mean = mu0
    verdict.baseline_std = sigma

    if sigma == 0.0:
        # A perfectly constant baseline cannot drift by this method's
        # definition: any future deviation is infinitely many sigma away,
        # which would be a false alarm on pure measurement noise.
        verdict.detail = "baseline has zero variance; monitoring continues"
        return verdict

    state = _CusumState(zero_h=cfg.warmup_runs - 1, zero_l=cfg.warmup_runs - 1)
    for i in range(cfg.warmup_runs, n):
        z = (values[i] - mu0) / sigma
        state.s_h = max(0.0, state.s_h + z - cfg.k)
        state.s_l = max(0.0, state.s_l - z - cfg.k)
        if state.s_h == 0.0:
            state.zero_h = i
        if state.s_l == 0.0:
            state.zero_l = i
        if state.s_h > cfg.h or state.s_l > cfg.h:
            direction = "up" if state.s_h > cfg.h else "down"
            change_idx = state.zero_h if direction == "up" else state.zero_l
            post = values[change_idx + 1:i + 1]
            shift = (_mean(post) - mu0) / sigma if post else 0.0
            verdict.status = "drift"
            verdict.direction = direction
            verdict.alarm_index = i
            verdict.change_index = change_idx + 1
            verdict.shift_sigma = shift
            verdict.detail = (
                "%s drift: CUSUM exceeded h=%.1f at observation %d "
                "(estimated change at %d, shift %+.2f sigma)"
                % (direction, cfg.h, i, change_idx + 1, shift)
            )
            return verdict

    verdict.detail = "no change-point detected in %d observations" % n
    return verdict


def detect_all(series_map: dict, config: Optional[CusumConfig] = None
               ) -> List[DriftVerdict]:
    """Run detection over {series_key: (probe, metric, values)}.

    series_key is an opaque label like "latency.latency_ms".
    """
    verdicts = []
    for _key, (probe, metric, values) in sorted(series_map.items()):
        verdicts.append(detect_series(values, probe, metric, config))
    return verdicts


def summarize(verdicts: Sequence[DriftVerdict]) -> Tuple[str, List[DriftVerdict]]:
    """Overall status: 'drift' if any drift, else 'warming_up' if any
    warming up, else 'ok'. Returns (status, drift_verdicts)."""
    drifted = [v for v in verdicts if v.status == "drift"]
    if drifted:
        return "drift", drifted
    if any(v.status == "warming_up" for v in verdicts):
        return "warming_up", []
    return "ok", []
