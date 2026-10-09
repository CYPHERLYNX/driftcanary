import unittest

from siteseal.checks import inject

from helpers import FakeFetcher, FakeResponse, html_page

BASE = "https://example.chatgpt.site/"
STRONG_CSP = {"content-security-policy": "default-src 'self'"}


def fetcher_factory(reflect=False, headers=None):
    """FakeFetcher where the main page optionally reflects the marker."""
    def make():
        f = FakeFetcher()

        def _get(url):
            f.request_count += 1
            f.requested.append(url)
            if "?" in url and "sitesealprobe7x9" in url:
                if reflect:
                    return FakeResponse(url, headers=headers or {},
                                        body=("<html><body>hello sitesealprobe7x9</body></html>").encode())
                return FakeResponse(url, headers=headers or {},
                                    body=b"<html><body>hello</body></html>")
            return FakeResponse(BASE, headers=headers or {}, body=html_page())

        f.get = _get
        return f
    return make


class TestInject(unittest.TestCase):
    def test_no_reflection_passes(self):
        out = inject.run(fetcher_factory(reflect=False)(), BASE)
        self.assertEqual(out[0].id, "inject.no-reflection")
        self.assertEqual(out[0].severity, "PASS")

    def test_reflection_without_csp_fails(self):
        out = inject.run(fetcher_factory(reflect=True)(), BASE)
        self.assertEqual(out[0].id, "inject.reflected")
        self.assertEqual(out[0].severity, "FAIL")

    def test_reflection_with_csp_warns(self):
        out = inject.run(fetcher_factory(reflect=True, headers=STRONG_CSP)(), BASE)
        self.assertEqual(out[0].severity, "WARN")

    def test_no_probe_skips(self):
        f = fetcher_factory()()
        out = inject.run(f, BASE, probe=False)
        self.assertEqual(out[0].id, "inject.skipped")
        self.assertEqual(f.request_count, 0)

    def test_inert_marker_only(self):
        # the check must never send script payloads — assert on requested URLs
        f = fetcher_factory(reflect=False)()
        inject.run(f, BASE)
        for u in f.requested:
            self.assertNotIn("<script", u.lower())
            self.assertNotIn("alert(", u.lower())


if __name__ == "__main__":
    unittest.main()
