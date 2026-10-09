import unittest

from siteseal.checks import headers
from siteseal.fetch import FetchError

from helpers import FakeFetcher, FakeResponse, html_page

BASE = "https://example.chatgpt.site/"

STRONG = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}


def run_with(hdrs, status=200):
    f = FakeFetcher().add(BASE, FakeResponse(BASE, status=status, headers=hdrs,
                                             body=html_page()))
    return headers.run(f, BASE)


class TestHeaders(unittest.TestCase):
    def test_all_strong_is_all_pass(self):
        out = run_with(STRONG)
        self.assertEqual(len(out), 6)
        self.assertTrue(all(x.severity == "PASS" for x in out), [x.to_dict() for x in out])

    def test_all_missing_is_all_fail(self):
        out = run_with({})
        self.assertEqual(len(out), 6)
        self.assertTrue(all(x.severity == "FAIL" for x in out))

    def test_hsts_short_max_age_warns(self):
        h = dict(STRONG, **{"strict-transport-security": "max-age=1000"})
        out = run_with(h)
        hsts = [x for x in out if x.id == "headers.hsts-weak"]
        self.assertEqual(len(hsts), 1)
        self.assertEqual(hsts[0].severity, "WARN")

    def test_csp_unsafe_inline_warns(self):
        h = dict(STRONG, **{"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"})
        out = run_with(h)
        csp = [x for x in out if x.id == "headers.csp-unsafe-inline"]
        self.assertEqual(len(csp), 1)

    def test_csp_without_src_directive_warns(self):
        h = dict(STRONG, **{"content-security-policy": "upgrade-insecure-requests"})
        out = run_with(h)
        self.assertTrue(any(x.id == "headers.csp-ineffective" for x in out))

    def test_xfo_allow_from_is_weak(self):
        h = dict(STRONG, **{"x-frame-options": "ALLOW-FROM https://x.example"})
        out = run_with(h)
        self.assertTrue(any(x.id == "headers.xfo-weak" for x in out))

    def test_unreachable_is_unknown(self):
        f = FakeFetcher().add(BASE, FetchError("boom"))
        out = headers.run(f, BASE)
        self.assertEqual(out[0].severity, "UNKNOWN")

    def test_http_error_page_is_unknown(self):
        out = run_with(STRONG, status=500)
        self.assertEqual(out[0].severity, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
