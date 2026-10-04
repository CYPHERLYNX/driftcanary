"""Tests for the CUSUM change-point detector.

Honesty contract under test:
  * an injected step change MUST fire within a documented window
  * flat history MUST NOT fire (false-positive guard)
  * gradual drift fires LATER than an abrupt step change
  * fewer than warmup_runs observations -> 'warming_up', never a verdict
  * a constant baseline (zero variance) can never alarm
"""

import random
import unittest

from driftcanary.detect import (
    CusumConfig, detect_series, detect_all, summarize,
)


def noisy(base, sigma, n, rng):
    return [rng.gauss(base, sigma) for _ in range(n)]


class TestStepChange(unittest.TestCase):
    def test_upward_step_fires(self):
        rng = random.Random(7)
        cfg = CusumConfig(warmup_runs=20, k=0.5, h=4.0)
        values = noisy(100.0, 5.0, 20, rng) + noisy(120.0, 5.0, 20, rng)
        v = detect_series(values, "ping", "latency_ms", cfg)
        self.assertEqual(v.status, "drift")
        self.assertEqual(v.direction, "up")
        # 4-sigma step: must fire quickly (well within 10 post-change runs)
        self.assertLessEqual(v.alarm_index - 20, 10)
        self.assertGreaterEqual(v.change_index, 18)
        self.assertLessEqual(v.change_index, 25)

    def test_downward_step_fires(self):
        rng = random.Random(11)
        cfg = CusumConfig(warmup_runs=20)
        values = noisy(50.0, 2.0, 20, rng) + noisy(40.0, 2.0, 20, rng)
        v = detect_series(values, "verbosity", "chars", cfg)
        self.assertEqual(v.status, "drift")
        self.assertEqual(v.direction, "down")

    def test_small_step_fires_later_than_large_step(self):
        rng = random.Random(3)
        cfg = CusumConfig(warmup_runs=30)
        big = noisy(0.0, 1.0, 30, rng) + noisy(3.0, 1.0, 40, rng)
        rng2 = random.Random(3)
        small = noisy(0.0, 1.0, 30, rng2) + noisy(1.2, 1.0, 40, rng2)
        vb = detect_series(big, "p", "m", cfg)
        vs = detect_series(small, "p", "m", cfg)
        self.assertEqual(vb.status, "drift")
        self.assertEqual(vs.status, "drift")
        self.assertLessEqual(vb.alarm_index, vs.alarm_index)


class TestNoFalseAlarms(unittest.TestCase):
    def test_flat_noisy_history_does_not_fire(self):
        rng = random.Random(99)
        cfg = CusumConfig(warmup_runs=20)
        values = noisy(10.0, 1.0, 60, rng)
        v = detect_series(values, "ping", "latency_ms", cfg)
        self.assertEqual(v.status, "ok")

    def test_constant_baseline_never_alarms(self):
        cfg = CusumConfig(warmup_runs=20)
        values = [5.0] * 40
        v = detect_series(values, "ping", "latency_ms", cfg)
        self.assertEqual(v.status, "ok")
        self.assertIn("zero variance", v.detail)

    def test_binary_metric_stable(self):
        # e.g. refusal_rate pinned at 1.0 for 40 runs: constant -> no alarm
        cfg = CusumConfig(warmup_runs=20)
        v = detect_series([1.0] * 40, "refusal", "refusal_rate", cfg)
        self.assertEqual(v.status, "ok")


class TestWarmup(unittest.TestCase):
    def test_short_series_is_warming_up(self):
        cfg = CusumConfig(warmup_runs=20)
        v = detect_series([1.0, 2.0, 3.0], "ping", "latency_ms", cfg)
        self.assertEqual(v.status, "warming_up")
        self.assertEqual(v.n_observations, 3)

    def test_exactly_warmup_minus_one(self):
        cfg = CusumConfig(warmup_runs=20)
        v = detect_series([float(i) for i in range(19)], "p", "m", cfg)
        self.assertEqual(v.status, "warming_up")


class TestGradualDrift(unittest.TestCase):
    def test_ramp_fires_later_than_step(self):
        rng = random.Random(5)
        cfg = CusumConfig(warmup_runs=20)
        step = noisy(0.0, 1.0, 20, rng) + noisy(4.0, 1.0, 60, rng)
        rng2 = random.Random(5)
        ramp = noisy(0.0, 1.0, 20, rng2)
        ramp += [rng2.gauss(i * 0.15, 1.0) for i in range(60)]
        vs = detect_series(step, "p", "m", cfg)
        vr = detect_series(ramp, "p", "m", cfg)
        self.assertEqual(vs.status, "drift")
        self.assertEqual(vr.status, "drift")
        # documented tradeoff: gradual drift takes longer to declare
        self.assertGreater(vr.alarm_index, vs.alarm_index)


class TestHelpers(unittest.TestCase):
    def test_detect_all_and_summarize(self):
        cfg = CusumConfig(warmup_runs=10)
        rng = random.Random(1)
        series = {
            "a.x": ("a", "x", noisy(0.0, 1.0, 30, rng)),
            "b.y": ("b", "y", noisy(0.0, 1.0, 10, rng) + noisy(5.0, 1.0, 20, rng)),
        }
        verdicts = detect_all(series, cfg)
        status, drifted = summarize(verdicts)
        self.assertEqual(status, "drift")
        self.assertEqual(len(drifted), 1)
        self.assertEqual(drifted[0].metric, "y")

    def test_summarize_warming_up(self):
        cfg = CusumConfig(warmup_runs=50)
        verdicts = detect_all({"a.x": ("a", "x", [1.0] * 10)}, cfg)
        status, drifted = summarize(verdicts)
        self.assertEqual(status, "warming_up")
        self.assertEqual(drifted, [])

    def test_bad_config_rejected(self):
        with self.assertRaises(ValueError):
            CusumConfig(warmup_runs=2)
        with self.assertRaises(ValueError):
            CusumConfig(k=0)


if __name__ == "__main__":
    unittest.main()
