"""Tests for the SQLite store: round-trips, series queries, config."""

import os
import tempfile
import unittest

from driftcanary import store as store_mod


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = store_mod.Store(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_schema_created(self):
        self.assertTrue(os.path.isfile(os.path.join(self.tmp.name, "driftcanary.db")))
        self.assertEqual(self.store.list_targets(), [])

    def test_run_lifecycle(self):
        run_id = self.store.start_run("provider", "gpt-4o-mini")
        self.store.record(run_id, "ping", "latency_ms", 120.5, samples=3)
        self.store.finish_run(run_id, "ok")
        self.assertEqual(self.store.run_count("provider", "gpt-4o-mini"), 1)
        series = self.store.series("provider", "gpt-4o-mini", "ping", "latency_ms")
        self.assertEqual(series, [(run_id, 120.5)])

    def test_error_runs_excluded_from_series(self):
        r1 = self.store.start_run("provider", "m")
        self.store.record(r1, "ping", "latency_ms", 100.0)
        self.store.finish_run(r1, "error")
        r2 = self.store.start_run("provider", "m")
        self.store.record(r2, "ping", "latency_ms", 110.0)
        self.store.finish_run(r2, "ok")
        series = self.store.series("provider", "m", "ping", "latency_ms")
        self.assertEqual(series, [(r2, 110.0)])

    def test_series_ordering(self):
        ids = []
        for i in range(5):
            r = self.store.start_run("agent", "claude")
            self.store.record(r, "sqli", "held", float(i % 2))
            self.store.finish_run(r, "ok")
            ids.append(r)
        series = self.store.series("agent", "claude", "sqli", "held")
        self.assertEqual([rid for rid, _ in series], ids)

    def test_probe_metrics_listing(self):
        r = self.store.start_run("provider", "m")
        self.store.record(r, "ping", "latency_ms", 1.0)
        self.store.record(r, "ping", "chars", 2.0)
        self.store.finish_run(r, "ok")
        self.assertEqual(
            self.store.probe_metrics("provider", "m"),
            [("ping", "chars"), ("ping", "latency_ms")])

    def test_config_roundtrip(self):
        self.assertIsNone(self.store.get_config("nope"))
        self.assertEqual(self.store.get_config("nope", "dflt"), "dflt")
        self.store.set_config("warmup_runs", "25")
        self.assertEqual(self.store.get_config("warmup_runs"), "25")
        self.store.set_config("warmup_runs", "30")
        self.assertEqual(self.store.get_config("warmup_runs"), "30")

    def test_last_run_at(self):
        self.assertIsNone(self.store.last_run_at("provider", "m"))
        r = self.store.start_run("provider", "m")
        self.store.finish_run(r, "ok")
        self.assertIsNotNone(self.store.last_run_at("provider", "m"))


if __name__ == "__main__":
    unittest.main()
