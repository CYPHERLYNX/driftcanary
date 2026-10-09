"""Unauthenticated storage/API endpoint probing.

ChatGPT Sites builders wire client JS to backend routes (D1/R2-backed or
otherwise). Endpoints left open without auth leak or corrupt site data. This
check:

- harvests fetch()/XHR URL strings from same-origin JS;
- adds a small list of conventional storage-route guesses;
- GETs each once (read-only, benign, never writes);
- FAILs only on concrete evidence: HTTP 200 with a JSON body containing
  sensitive field names (email, password, token, secret, api_key, ...).
- WARNs when a route returns 200 with a JSON-ish body that looks like data
  but shows no sensitive fields — "verify this is meant to be public".

Everything ambiguous stays WARN/UNKNOWN. The tool never asserts an endpoint
is private; it reports what answers without credentials.
"""

import json
import re
import urllib.parse

from ..fetch import FetchError, PoliteFetcher, RateLimited
from ..model import Finding
from .secrets import _AssetCollector, _same_origin, MAX_JS_ASSETS

FETCH_URL = re.compile(r"""(?:fetch|axios\.(?:get|post)|XMLHttpRequest|open)\s*\(\s*['"`]([^'"`\s]+)['"`]""")
GUESS_ROUTES = ["/api/data", "/api/store", "/api/kv", "/api/db", "/api/items",
                "/api/submit", "/api/form", "/api/contact", "/api/feedback",
                "/api/comments", "/api/leads", "/api/signups"]

SENSITIVE_FIELDS = re.compile(
    r"(?i)\"(email|e-mail|password|passwd|token|secret|api[_-]?key|auth|session|"
    r"phone|address|ssn|credit[_-]?card)\"\s*:")


def _looks_like_json(body: bytes):
    s = body.strip()
    if not s[:1] in b"{[":
        return None
    try:
        return json.loads(s.decode("utf-8", "replace"))
    except Exception:
        return None


def run(fetcher: PoliteFetcher, base_url: str, probe: bool = True):
    try:
        resp = fetcher.get(base_url)
    except RateLimited:
        raise
    except FetchError as exc:
        return [Finding("storage", "storage.unreachable", "UNKNOWN",
                        "Could not fetch the site", str(exc))]
    if resp.status >= 400:
        return [Finding("storage", "storage.unreachable", "UNKNOWN",
                        "Site returned HTTP %d" % resp.status, "")]
    if not probe:
        return [Finding("storage", "storage.skipped", "INFO",
                        "Storage probing skipped (--no-probe)",
                        "Passive mode: no endpoint was requested.")]

    collector = _AssetCollector(resp.url)
    try:
        collector.feed(resp.text)
    except Exception:
        pass
    routes = []
    for asset in [u for u in dict.fromkeys(collector.assets)
                  if _same_origin(u, resp.url)][:MAX_JS_ASSETS]:
        try:
            js = fetcher.get(asset)
        except FetchError:
            continue
        if js.status >= 400:
            continue
        for m in FETCH_URL.finditer(js.text):
            u = m.group(1)
            if u.startswith("/api/"):
                routes.append(u.split("?")[0])
    for g in GUESS_ROUTES:
        routes.append(g)
    routes = [r for r in dict.fromkeys(routes) if r.startswith("/api/")][:40]

    findings = []
    tested = 0
    for route in routes:
        url = urllib.parse.urljoin(resp.url, route)
        try:
            r = fetcher.get(url)
        except FetchError:
            continue
        tested += 1
        if r.status in (401, 403):
            findings.append(Finding("storage", "storage.protected", "PASS",
                                    "Endpoint requires auth: %s" % route,
                                    "GET %s -> HTTP %d." % (route, r.status)))
            continue
        if r.status == 404:
            continue
        if r.status == 200:
            data = _looks_like_json(r.body)
            if data is None:
                continue  # 200 non-JSON (HTML page etc.) — not a storage signal
            raw = r.body.decode("utf-8", "replace")
            if SENSITIVE_FIELDS.search(raw):
                fields = sorted(set(m.group(1) for m in SENSITIVE_FIELDS.finditer(raw)))
                findings.append(Finding(
                    "storage", "storage.sensitive-exposed", "FAIL",
                    "Endpoint exposes sensitive fields without auth: %s" % route,
                    "GET %s -> HTTP 200, JSON body contains: %s. No Authorization "
                    "header was sent." % (route, ", ".join(fields)),
                    "Put %s behind authentication, or stop returning sensitive fields "
                    "to unauthenticated callers." % route))
            else:
                findings.append(Finding(
                    "storage", "storage.open-json", "WARN",
                    "Endpoint answers unauthenticated with JSON: %s" % route,
                    "GET %s -> HTTP 200 with a JSON body. It may be intentionally "
                    "public — verify." % route,
                    "Confirm %s is meant to be public; otherwise require auth." % route))
    if not findings:
        return [Finding("storage", "storage.no-signals", "INFO",
                        "No storage endpoints answered (%d route(s) tested)" % tested,
                        "Tested %d /api route(s); none returned data without auth." % tested)]
    return findings
