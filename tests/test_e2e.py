"""End-to-end: a local fixture ChatGPT-Site-like app, audited for real.

The fixture serves: no security headers, a same-origin JS bundle containing a
(fake) embedded key and fetch() calls, an open JSON storage endpoint returning
an email field, a sign-in surface with an open auth endpoint, and a page that
reflects ?q= unescaped. Expected: FAILs across families, grade F, exit 1.
"""

import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from siteseal import cli
from siteseal.fetch import PoliteFetcher

FAKE_KEY = "sk-proj-TESTFIXTUREabcdefghij1234"


class Fixture(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            # NOTE: deliberately reflects ?q= raw — the vuln the fixture models.
            body = ("<html><head><title>fixture</title></head><body>"
                    "<button>Sign in with ChatGPT</button>"
                    "<script src=\"/assets/app.js\"></script>"
                    "<div id=\"echo\">%s</div></body></html>" % q)
            self._send(200, body)
        elif parsed.path == "/assets/app.js":
            js = ('fetch("/api/data");\nfetch("/api/auth/session");\n'
                  'const KEY = "%s";\n' % FAKE_KEY)
            self._send(200, js, "application/javascript")
        elif parsed.path == "/api/data":
            self._send(200, '{"email": "owner@example.com", "visits": 42}',
                       "application/json")
        elif parsed.path == "/api/auth/session":
            self._send(200, '{"user": null}', "application/json")
        else:
            self._send(404, "nope")

    def log_message(self, *a):
        pass


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/" % srv.server_address[1]


class TestE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.url = _serve()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_full_audit_finds_everything(self):
        findings, error = cli.audit(self.url, probe=True, delay=0,
                                    allow_private=True)
        self.assertIsNone(error)
        by_id = {f.id: f for f in findings}
        # headers: zero headers shipped -> all six FAIL
        self.assertEqual(by_id["headers.csp-missing"].severity, "FAIL")
        self.assertEqual(by_id["headers.hsts-missing"].severity, "FAIL")
        # secrets: the fake embedded key
        self.assertEqual(by_id["secrets.embedded-openai-key"].severity, "FAIL")
        self.assertIn("…", by_id["secrets.embedded-openai-key"].evidence)  # redacted
        self.assertNotIn(FAKE_KEY, by_id["secrets.embedded-openai-key"].evidence)
        # storage: open endpoint with email field
        self.assertEqual(by_id["storage.sensitive-exposed"].severity, "FAIL")
        # inject: reflected ?q= with no CSP
        self.assertEqual(by_id["inject.reflected"].severity, "FAIL")
        # auth: surface detected + open endpoint
        self.assertTrue(any(f.id == "auth.signin-surface" for f in findings))
        self.assertTrue(any(f.id == "auth.endpoint-open" for f in findings))

    def test_grade_and_exit_code(self):
        from siteseal import score as scoring
        findings, error = cli.audit(self.url, probe=True, delay=0,
                                    allow_private=True)
        letter, _ = scoring.grade(findings)
        self.assertEqual(letter, "F")
        self.assertEqual(scoring.exit_code(findings, error), 1)

    def test_cli_end_to_end(self):
        code = cli.main(["audit", self.url, "--allow-local", "--delay", "0"])
        self.assertEqual(code, 1)

    def test_cli_json_valid(self):
        import io, json
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["audit", self.url, "--allow-local", "--delay", "0",
                             "--json"])
        self.assertEqual(code, 1)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["tool"], "siteseal")
        self.assertIn("findings", doc)

    def test_no_probe_mode(self):
        findings, error = cli.audit(self.url, probe=False, delay=0,
                                    allow_private=True)
        self.assertIsNone(error)
        self.assertTrue(any(f.id == "storage.skipped" for f in findings))
        self.assertTrue(any(f.id == "inject.skipped" for f in findings))

    def test_bad_url_is_exit_2(self):
        self.assertEqual(cli.main(["audit", "not a url!!", "--allow-local"]), 2)

    def test_429_mid_audit_aborts_with_error(self):
        from siteseal.fetch import RateLimited
        from tests.helpers import FakeFetcher, FakeResponse, html_page
        f = FakeFetcher()
        calls = {"n": 0}

        def _get(url):
            calls["n"] += 1
            if calls["n"] > 2:
                raise RateLimited("429")
            return FakeResponse(url, body=html_page())

        f.get = _get
        import siteseal.cli as climod
        real = climod.PoliteFetcher
        climod.PoliteFetcher = lambda **kw: f
        try:
            findings, error = climod.audit("https://x.chatgpt.site/", probe=True)
        finally:
            climod.PoliteFetcher = real
        self.assertIsNotNone(error)
        self.assertIn("429", error)


if __name__ == "__main__":
    unittest.main()
