import unittest

from siteseal.checks import storage

from helpers import FakeFetcher, FakeResponse, html_page

BASE = "https://example.chatgpt.site/"


def fetcher_with(js_map=None, routes=None):
    f = FakeFetcher()
    for path, resp in (routes or {}).items():
        f.add(BASE.rstrip("/") + path, resp)
    for path, js in (js_map or {}).items():
        f.add(BASE.rstrip("/") + path, FakeResponse(BASE.rstrip("/") + path, body=js))
    f.add(BASE, FakeResponse(BASE, body=html_page(scripts=["/assets/a.js"])))
    return f


class TestStorage(unittest.TestCase):
    def test_no_probe_skips(self):
        f = fetcher_with()
        out = storage.run(f, BASE, probe=False)
        self.assertEqual(out[0].id, "storage.skipped")
        self.assertEqual(out[0].severity, "INFO")

    def test_sensitive_fields_fail(self):
        f = fetcher_with(
            {"/assets/a.js": 'fetch("/api/data")'},
            {"/api/data": FakeResponse(BASE + "api/data",
                                       headers={"content-type": "application/json"},
                                       body=b'{"email": "a@b.c", "items": []}')})
        out = storage.run(f, BASE)
        fails = [x for x in out if x.id == "storage.sensitive-exposed"]
        self.assertEqual(len(fails), 1)
        self.assertIn("email", fails[0].evidence)

    def test_open_json_warns_not_fails(self):
        f = fetcher_with(
            {"/assets/a.js": 'fetch("/api/data")'},
            {"/api/data": FakeResponse(BASE + "api/data",
                                       headers={"content-type": "application/json"},
                                       body=b'{"items": [1, 2]}')})
        out = storage.run(f, BASE)
        self.assertTrue(any(x.id == "storage.open-json" and x.severity == "WARN" for x in out))
        self.assertFalse(any(x.severity == "FAIL" for x in out))

    def test_protected_endpoint_passes(self):
        f = fetcher_with(
            {"/assets/a.js": 'fetch("/api/data")'},
            {"/api/data": FakeResponse(BASE + "api/data", status=403, body=b"")})
        out = storage.run(f, BASE)
        self.assertTrue(any(x.id == "storage.protected" and x.severity == "PASS" for x in out))

    def test_nothing_answering_is_info(self):
        f = fetcher_with({"/assets/a.js": "var x = 1;"})
        out = storage.run(f, BASE)
        self.assertEqual(out[0].id, "storage.no-signals")
        self.assertEqual(out[0].severity, "INFO")

    def test_never_writes(self):
        # only GET-shaped fetches exist; the check must not issue POST/PUT/DELETE.
        # The FakeFetcher only implements get(), so any other method would explode.
        f = fetcher_with({"/assets/a.js": 'fetch("/api/data")'},
                         {"/api/data": FakeResponse(BASE + "api/data", status=404, body=b"")})
        storage.run(f, BASE)  # must not raise


if __name__ == "__main__":
    unittest.main()
