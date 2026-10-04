"""End-to-end CLI tests against a stub OpenAI-compatible endpoint.

Covers: init -> probe (xN) -> report -> alert, drift injection -> alert
exits 2, and friendly (traceback-free) failures.
"""

import http.server
import io
import json
import os
import socketserver
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout

from driftcanary.cli import main


class StubState:
    drift = False
    _n = 0  # request counter for deterministic baseline jitter


class StubHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        prompt = ""
        for m in body.get("messages", []):
            prompt += m.get("content", "") + "\n"

        if "Reply with exactly: OK" in prompt:
            text, tool_calls = "OK", []
        elif "photosynthesis" in prompt:
            # Deterministic jitter (0-10 chars) so the baseline has realistic
            # variance; a zero-variance baseline can never alarm by design.
            StubState._n += 1
            jitter = " " * (StubState._n % 11)
            text = ("Plants convert sunlight into chemical energy." + jitter
                    + (" Padding." * 200 if StubState.drift else ""))
            tool_calls = []
        elif "weather" in prompt.lower() and body.get("tools"):
            text, tool_calls = "", [{
                "id": "1", "type": "function",
                "function": {"name": "get_weather",
                             "arguments": '{"city": "Paris"}'},
            }]
        else:
            text, tool_calls = "stub reply", []

        payload = {"choices": [{
            "message": {"role": "assistant", "content": text,
                        "tool_calls": tool_calls or None},
            "finish_reason": "stop",
        }]}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class CliTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadedServer(("127.0.0.1", 0), StubHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()
        os.environ["DRIFTCANARY_TEST_KEY"] = "dummy"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        os.environ.pop("DRIFTCANARY_TEST_KEY", None)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.base = ["--dir", self.dir]
        StubState.drift = False
        StubState._n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def probe(self, extra=()):
        return self.run_cli(self.base + [
            "probe", "--target", "provider", "--model", "stub",
            "--base-url", "http://127.0.0.1:%d" % self.port,
            "--api-key-env", "DRIFTCANARY_TEST_KEY",
            "--samples", "1", "--probes", "ping,verbosity",
        ] + list(extra))

    def test_full_flow_clean(self):
        code, out, _ = self.run_cli(self.base + ["init"])
        self.assertEqual(code, 0)
        self.assertIn("initialized", out)
        for _ in range(6):
            code, _, _ = self.probe()
            self.assertEqual(code, 0)
        code, _, _ = self.run_cli(self.base + ["report"])
        self.assertEqual(code, 0)
        report = os.path.join(self.dir, "report.html")
        self.assertTrue(os.path.isfile(report))
        with open(report, encoding="utf-8") as fh:
            html_text = fh.read()
        self.assertIn("driftcanary", html_text)
        self.assertIn("WARMING UP", html_text)  # 6 < 20 default warmup
        code, out, _ = self.run_cli(self.base + ["alert"])
        self.assertEqual(code, 0)
        self.assertIn("warming up", out)

    def test_drift_injection_fires_alert(self):
        self.run_cli(self.base + ["init"])
        # verbosity only: latency is inherently noisy and would make this
        # test about the wrong metric.
        probe_args = ["--samples", "1", "--probes", "verbosity"]
        for _ in range(6):
            code, _, _ = self.run_cli(self.base + [
                "probe", "--target", "provider", "--model", "stub",
                "--base-url", "http://127.0.0.1:%d" % self.port,
                "--api-key-env", "DRIFTCANARY_TEST_KEY"] + probe_args)
            self.assertEqual(code, 0)
        StubState.drift = True  # verbosity explodes from here on
        for _ in range(6):
            code, _, _ = self.run_cli(self.base + [
                "probe", "--target", "provider", "--model", "stub",
                "--base-url", "http://127.0.0.1:%d" % self.port,
                "--api-key-env", "DRIFTCANARY_TEST_KEY"] + probe_args)
            self.assertEqual(code, 0)
        code, out, _ = self.run_cli(self.base + ["alert", "--warmup", "5"])
        self.assertEqual(code, 2, "expected exit 2 on drift, got: %s" % out)
        self.assertIn("DRIFT", out)
        self.assertIn("verbosity", out)

    def test_alert_no_history_is_clean(self):
        self.run_cli(self.base + ["init"])
        code, out, _ = self.run_cli(self.base + ["alert"])
        self.assertEqual(code, 0)
        self.assertIn("No probe history", out)

    def test_probe_without_init_is_friendly(self):
        code, _, err = self.run_cli(
            ["--dir", os.path.join(self.dir, "nope"), "probe",
             "--target", "provider", "--model", "x"])
        self.assertEqual(code, 1)
        self.assertIn("driftcanary init", err)
        self.assertNotIn("Traceback", err)

    def test_missing_api_key_is_friendly(self):
        self.run_cli(self.base + ["init"])
        os.environ.pop("DRIFTCANARY_TEST_KEY", None)
        try:
            code, _, err = self.probe()
        finally:
            os.environ["DRIFTCANARY_TEST_KEY"] = "dummy"
        self.assertEqual(code, 1)
        self.assertIn("DRIFTCANARY_TEST_KEY", err)
        self.assertNotIn("Traceback", err)

    def test_agent_mode_no_cli_is_friendly(self):
        self.run_cli(self.base + ["init"])
        code, _, err = self.run_cli(
            self.base + ["probe", "--target", "agent", "--cli", "claude"])
        # either the CLI exists (probe runs) or it doesn't (friendly error)
        self.assertIn(code, (0, 1))
        if code == 1:
            self.assertNotIn("Traceback", err)

    def test_report_empty_history(self):
        self.run_cli(self.base + ["init"])
        code, _, _ = self.run_cli(self.base + ["report"])
        self.assertEqual(code, 0)
        with open(os.path.join(self.dir, "report.html"), encoding="utf-8") as fh:
            self.assertIn("No probe history", fh.read())


if __name__ == "__main__":
    unittest.main()
