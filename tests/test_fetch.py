import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from siteseal.fetch import FetchError, PoliteFetcher, RateLimited

from helpers import FakeResponse  # noqa: F401  (keeps helpers importable pattern)


class TestSSRFGuard(unittest.TestCase):
    def test_loopback_refused_by_default(self):
        f = PoliteFetcher(delay=0)
        with self.assertRaises(FetchError):
            f.get("http://127.0.0.1:9/")

    def test_loopback_allowed_with_flag(self):
        # allowed target, but nothing listens -> connection error, not policy error
        f = PoliteFetcher(delay=0, allow_private=True)
        with self.assertRaises(FetchError) as ctx:
            f.get("http://127.0.0.1:9/")
        self.assertNotIn("--allow-local", str(ctx.exception))

    def test_private_hostname_refused(self):
        f = PoliteFetcher(delay=0)
        with self.assertRaises(FetchError):
            f.get("http://localhost:9/")

    def test_non_http_refused(self):
        f = PoliteFetcher(delay=0)
        with self.assertRaises(FetchError):
            f.get("ftp://example.com/x")


class TestSSRFBlocklist(unittest.TestCase):
    def _check(self, ip_str, allow_private=False):
        from siteseal import fetch as fetch_mod
        real = __import__("socket").getaddrinfo
        fetch_mod.socket.getaddrinfo = lambda *a: [(2, 1, 6, "", (ip_str, 0))]
        try:
            return fetch_mod._is_public_host("x.test", allow_private)
        finally:
            fetch_mod.socket.getaddrinfo = real

    def test_rfc1918_blocked(self):
        from siteseal.fetch import FetchError as FE
        for ip in ("10.1.2.3", "172.16.5.4", "192.168.1.1", "127.0.0.1",
                   "169.254.169.254"):
            with self.assertRaises(FE, msg=ip):
                self._check(ip)

    def test_benchmarking_range_allowed(self):
        # 198.18.0.0/15 is used by DNS filtering proxies; blocking it would
        # refuse every target behind such a proxy.
        self.assertTrue(self._check("198.18.44.145"))

    def test_allow_private_bypasses(self):
        self.assertTrue(self._check("10.1.2.3", allow_private=True))


class _Handler429(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(429)
        self.send_header("Retry-After", "5")
        self.end_headers()
        self.wfile.write(b"slow down")

    def log_message(self, *a):
        pass


class _HandlerOK(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%d/" % srv.server_address[1]


class _HandlerRedirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "/landed")
        self.end_headers()

    def log_message(self, *a):
        pass


class _HandlerLanded(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"landed"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve_path(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


class TestRedirects(unittest.TestCase):
    def test_redirect_followed_and_hop_counted(self):
        # one server redirects to another server's /landed
        srv2, base2 = _serve_path(_HandlerLanded)

        class _R(_HandlerRedirect):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", base2 + "/landed")
                self.end_headers()

        srv1, base1 = _serve_path(_R)
        try:
            f = PoliteFetcher(delay=0, allow_private=True)
            r = f.get(base1 + "/start")
            self.assertEqual(r.status, 200)
            self.assertEqual(r.text, "landed")
            self.assertEqual(r.url, base2 + "/landed")
            self.assertEqual(f.request_count, 2)
        finally:
            srv1.shutdown()
            srv2.shutdown()


class TestPoliteFetcherLive(unittest.TestCase):
    def test_429_raises_ratelimited(self):
        srv, url = _serve(_Handler429)
        try:
            f = PoliteFetcher(delay=0, allow_private=True)
            with self.assertRaises(RateLimited):
                f.get(url)
        finally:
            srv.shutdown()

    def test_delay_is_enforced(self):
        srv, url = _serve(_HandlerOK)
        try:
            import time
            f = PoliteFetcher(delay=0.3, allow_private=True)
            t0 = time.monotonic()
            f.get(url)
            f.get(url + "2")
            elapsed = time.monotonic() - t0
            self.assertGreaterEqual(elapsed, 0.3)
        finally:
            srv.shutdown()

    def test_ok_response_shape(self):
        srv, url = _serve(_HandlerOK)
        try:
            f = PoliteFetcher(delay=0, allow_private=True)
            r = f.get(url)
            self.assertEqual(r.status, 200)
            self.assertIn("ok", r.text)
            self.assertEqual(f.request_count, 1)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
