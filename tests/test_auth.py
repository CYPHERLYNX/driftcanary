import unittest

from siteseal.checks import auth

from helpers import FakeFetcher, FakeResponse, html_page

BASE = "https://example.chatgpt.site/"


def fetcher_with(html, js_map=None, routes=None):
    f = FakeFetcher()
    for path, resp in (routes or {}).items():
        f.add(BASE.rstrip("/") + path, resp)
    for path, js in (js_map or {}).items():
        f.add(BASE.rstrip("/") + path, FakeResponse(BASE.rstrip("/") + path, body=js))
    f.add(BASE, FakeResponse(BASE, body=html))
    return f


class TestAuth(unittest.TestCase):
    def test_no_surface_is_info_not_fail(self):
        f = fetcher_with(html_page())
        out = auth.run(f, BASE)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "INFO")
        self.assertEqual(out[0].id, "auth.no-signin-surface")

    def test_signin_text_detected(self):
        f = fetcher_with(html_page(body_extra="<button>Sign in with ChatGPT</button>"))
        out = auth.run(f, BASE)
        self.assertTrue(any(x.id == "auth.signin-surface" for x in out))

    def test_signin_marker_in_js_detected(self):
        f = fetcher_with(html_page(scripts=["/assets/a.js"]),
                         {"/assets/a.js": "init('sign-in-with-chatgpt');"})
        out = auth.run(f, BASE)
        self.assertTrue(any(x.id == "auth.signin-surface" for x in out))

    def test_open_auth_endpoint_warns(self):
        html = html_page(scripts=["/assets/a.js"],
                         body_extra="<button>Sign in with ChatGPT</button>")
        f = fetcher_with(html, {"/assets/a.js": 'fetch("/api/auth/session")'},
                         {"/api/auth/session": FakeResponse(
                             BASE.rstrip("/") + "/api/auth/session",
                             headers={"content-type": "application/json"},
                             body=b'{"user": null}')})
        out = auth.run(f, BASE)
        self.assertTrue(any(x.id == "auth.endpoint-open" for x in out))

    def test_protected_auth_endpoint_no_warn(self):
        html = html_page(scripts=["/assets/a.js"],
                         body_extra="<button>Sign in with ChatGPT</button>")
        f = fetcher_with(html, {"/assets/a.js": 'fetch("/api/auth/session")'},
                         {"/api/auth/session": FakeResponse(
                             BASE.rstrip("/") + "/api/auth/session",
                             status=401, body=b"")})
        out = auth.run(f, BASE)
        self.assertFalse(any(x.id == "auth.endpoint-open" for x in out))


if __name__ == "__main__":
    unittest.main()
