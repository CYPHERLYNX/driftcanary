"""Polite-by-design HTTP layer.

- Single thread, a minimum delay between requests (default 0.7s).
- Hard stop on HTTP 429: the whole audit aborts, never retries.
- Bounded: timeouts, max body bytes, max redirects, capped asset count.
- SSRF guard: the target host (and every redirect hop) is DNS-resolved and
  refused when it lands on a private/loopback/link-local address, unless
  ``allow_private`` is set (tests and explicit ``--allow-local`` only).
- Only http/https. No cookies are persisted between requests.
"""

import ipaddress
import socket
import time
import urllib.parse
import urllib.request

USER_AGENT = "siteseal/0.1.0 (security-posture audit; passive by default)"
MAX_REDIRECTS = 5


class RateLimited(Exception):
    """The server answered 429. Audit stops; it does not retry."""


class FetchError(Exception):
    """Network, policy (SSRF guard), or protocol failure."""


class Response:
    def __init__(self, url, status, headers, body, truncated):
        self.url = url            # final URL after redirects
        self.status = status
        self.headers = headers    # dict, lowercase names
        self.body = body          # bytes (possibly truncated)
        self.truncated = truncated

    @property
    def text(self):
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")


# Explicit blocklist for the SSRF guard. Deliberately NOT Python's
# ip.is_private: that also covers 198.18.0.0/15 (benchmarking, used by DNS
# filtering proxies — blocking it would refuse every target behind such a
# proxy) and 100.64.0.0/10. What matters here is the auditor's own network.
_BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local incl. cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_public_host(host, allow_private):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise FetchError("DNS resolution failed for %s: %s" % (host, exc))
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_multicast or any(ip in net for net in _BLOCKED_NETS):
            if not allow_private:
                raise FetchError(
                    "refusing non-public target %s (%s); use --allow-local for local testing"
                    % (host, ip)
                )
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stops urllib following redirects itself; we follow manually so every
    hop is re-checked by the SSRF guard."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PoliteFetcher:
    def __init__(self, delay=0.7, timeout=10, max_bytes=512 * 1024,
                 allow_private=False):
        self.delay = delay
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.allow_private = allow_private
        self.request_count = 0
        self._last_at = 0.0

    def _pace(self):
        wait = self.delay - (time.monotonic() - self._last_at)
        if wait > 0:
            time.sleep(wait)
        self._last_at = time.monotonic()

    def get(self, url):
        """GET url politely. Raises RateLimited on 429, FetchError otherwise."""
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            parsed = urllib.parse.urlparse(current)
            if parsed.scheme not in ("http", "https"):
                raise FetchError("refusing non-http(s) URL: %s" % current)
            if not parsed.hostname:
                raise FetchError("URL has no host: %s" % current)
            _is_public_host(parsed.hostname, self.allow_private)

            self._pace()
            req = urllib.request.Request(current, headers={"User-Agent": USER_AGENT})

            opener = urllib.request.build_opener(_NoRedirect)
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    status = resp.status
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    if status == 429:
                        raise RateLimited("server returned 429 for %s" % current)
                    body = resp.read(self.max_bytes + 1)
                    truncated = len(body) > self.max_bytes
                    self.request_count += 1
                    return Response(current, status, headers, body[: self.max_bytes], truncated)
            except RateLimited:
                raise
            except FetchError:
                raise
            except urllib.error.HTTPError as exc:
                # With _NoRedirect, urllib surfaces 3xx as HTTPError; follow manually
                # so every hop is re-checked by the SSRF guard.
                if exc.code in (301, 302, 303, 307, 308):
                    loc = (exc.headers or {}).get("Location")
                    self.request_count += 1
                    if not loc:
                        raise FetchError("redirect without Location from %s" % current)
                    current = urllib.parse.urljoin(current, loc)
                    continue
                if exc.code == 429:
                    raise RateLimited("server returned 429 for %s" % current)
                # Non-429 HTTP errors are still evidence (e.g. 403 on a probe).
                headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
                self.request_count += 1
                try:
                    body = exc.read(self.max_bytes + 1)
                except Exception:
                    body = b""
                return Response(current, exc.code, headers,
                                body[: self.max_bytes], len(body) > self.max_bytes)
            except urllib.error.URLError as exc:
                raise FetchError("%s: %s" % (current, exc.reason))
            except (socket.timeout, TimeoutError):
                raise FetchError("timed out fetching %s" % current)
            except OSError as exc:
                raise FetchError("%s: %s" % (current, exc))
        raise FetchError("too many redirects fetching %s" % url)
