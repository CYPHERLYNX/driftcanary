"""Sign-in-with-ChatGPT surface detection.

ChatGPT Sites can gate content behind "Sign in with ChatGPT". When present,
the site owner receives the visitor's ChatGPT account email/name — a data
exposure the builder may not realize. This check:

- scans the main document and same-origin JS for sign-in markers;
- if a sign-in surface exists: reports what visitor data it exposes (INFO),
  and probes any auth endpoints found in JS for unauthenticated 200s (WARN);
- if none is found: a single INFO — absence is never a FAIL.

Missing surface -> informational. Never alarmist.
"""

import re
import urllib.parse
from html.parser import HTMLParser

from ..fetch import FetchError, PoliteFetcher, RateLimited
from ..model import Finding
from .secrets import _AssetCollector, _same_origin, MAX_JS_ASSETS

SIGNIN_TEXT = re.compile(r"(?i)sign[\s_-]*in[\s_-]*with[\s_-]*chatgpt")
AUTH_HINT = re.compile(r"(?i)(chatgpt|openai).{0,40}(oauth|signin|sign-in|/auth|login)|"
                       r"(oauth|signin|sign-in|/auth).{0,40}(chatgpt|openai)")
ENDPOINT = re.compile(r"""['"](/api/(?:auth|session|me|user|profile)[^'"\s]*)['"]""")


def run(fetcher: PoliteFetcher, base_url: str):
    try:
        resp = fetcher.get(base_url)
    except RateLimited:
        raise
    except FetchError as exc:
        return [Finding("auth", "auth.unreachable", "UNKNOWN",
                        "Could not fetch the site", str(exc))]
    if resp.status >= 400:
        return [Finding("auth", "auth.unreachable", "UNKNOWN",
                        "Site returned HTTP %d" % resp.status, "")]

    html = resp.text
    has_text_marker = bool(SIGNIN_TEXT.search(html) or AUTH_HINT.search(html))

    # Scan same-origin JS for auth markers too (sign-in widgets load client-side).
    collector = _AssetCollector(resp.url)
    try:
        collector.feed(html)
    except Exception:
        pass
    js_markers, endpoints = [], []
    for asset in [u for u in dict.fromkeys(collector.assets)
                  if _same_origin(u, resp.url)][:MAX_JS_ASSETS]:
        try:
            js = fetcher.get(asset)
        except FetchError:
            continue
        if js.status >= 400:
            continue
        text = js.text
        if SIGNIN_TEXT.search(text) or AUTH_HINT.search(text):
            js_markers.append(urllib.parse.urlparse(asset).path)
        endpoints.extend(ENDPOINT.findall(text))

    if not has_text_marker and not js_markers:
        return [Finding("auth", "auth.no-signin-surface", "INFO",
                        "No Sign-in-with-ChatGPT surface detected",
                        "Neither the document nor %d same-origin JS asset(s) referenced "
                        "ChatGPT sign-in. Nothing to assess here." % min(len(collector.assets), MAX_JS_ASSETS))]

    findings = [Finding(
        "auth", "auth.signin-surface", "INFO",
        "Sign-in-with-ChatGPT surface detected",
        "Markers found in: %s. When a visitor signs in, the site owner receives "
        "their ChatGPT account email and display name — make sure the site's "
        "privacy notice says so." % ", ".join(
            (["main document"] if has_text_marker else []) + js_markers[:5]))]

    seen = set()
    for ep in dict.fromkeys(endpoints):
        if ep in seen:
            continue
        seen.add(ep)
        url = urllib.parse.urljoin(resp.url, ep)
        try:
            r = fetcher.get(url)
        except FetchError:
            continue
        if r.status == 200 and r.body.strip():
            ctype = r.headers.get("content-type", "")
            if "json" in ctype or r.body.strip()[:1] in b"{[":
                findings.append(Finding(
                    "auth", "auth.endpoint-open", "WARN",
                    "Auth endpoint answers without a token: %s" % ep,
                    "GET %s -> HTTP 200 with a JSON-ish body and no Authorization "
                    "header was sent. Verify this endpoint is meant to be public." % ep,
                    "Require a session token on %s, or confirm the response is "
                    "intentionally public." % ep))
    return findings
