import json
import unittest

from siteseal import report as reporting
from siteseal.model import Finding


def findings():
    return [
        Finding("headers", "headers.csp-missing", "FAIL", "CSP missing",
                "No CSP.", "Add default-src 'self'."),
        Finding("secrets", "secrets.clean", "PASS", "No secrets found", "3 files scanned."),
    ]


class TestReport(unittest.TestCase):
    def test_json_schema(self):
        doc = json.loads(reporting.render_json(
            "https://x.chatgpt.site/", findings(), "C", 70.0,
            {"PASS": 1, "FAIL": 1, "WARN": 0, "UNKNOWN": 0, "INFO": 0}, 1))
        self.assertEqual(doc["tool"], "siteseal")
        self.assertEqual(doc["grade"], "C")
        self.assertEqual(doc["exit_code"], 1)
        self.assertEqual(len(doc["findings"]), 2)
        self.assertEqual(doc["findings"][0]["severity"], "FAIL")

    def test_terminal_mentions_grade(self):
        out = reporting.render_terminal("https://x.chatgpt.site/", findings(),
                                        "C", 70.0,
                                        {"PASS": 1, "FAIL": 1, "WARN": 0, "UNKNOWN": 0, "INFO": 0})
        self.assertIn("GRADE C", out)
        self.assertIn("[FAIL]", out)

    def test_terminal_error_path(self):
        out = reporting.render_terminal("https://x.chatgpt.site/", [], "?", 0.0,
                                        {"PASS": 0, "FAIL": 0, "WARN": 0, "UNKNOWN": 0, "INFO": 0},
                                        error="rate limited")
        self.assertIn("ERROR", out)

    def test_html_structure(self):
        doc = reporting.render_html("https://x.chatgpt.site/", findings(), "C", 70.0,
                                    {"PASS": 1, "FAIL": 1, "WARN": 0, "UNKNOWN": 0, "INFO": 0},
                                    "2026-10-09 00:00 UTC", "0.1.0")
        self.assertIn("<!DOCTYPE html>", doc)
        self.assertIn("--bg: #070b12", doc)          # trading-terminal tokens
        self.assertIn("chip fail", doc)
        self.assertIn("CSP missing", doc)
        for bad in ["\U0001F680", "\u2728", "\u26A1", "#6366f1"]:
            self.assertNotIn(bad, doc, "slop marker %r in HTML" % bad)

    def test_html_escapes_evidence(self):
        evil = [Finding("inject", "inject.reflected", "FAIL", "t",
                        "<script>alert(1)</script>", "")]
        doc = reporting.render_html("https://x/", evil, "F", 10.0,
                                    {"PASS": 0, "FAIL": 1, "WARN": 0, "UNKNOWN": 0, "INFO": 0},
                                    None, "0.1.0")
        self.assertNotIn("<script>alert(1)</script>", doc)
        self.assertIn("&lt;script&gt;", doc)


if __name__ == "__main__":
    unittest.main()
