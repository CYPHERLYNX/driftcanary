"""Reflected query-parameter injection seam check.

Appends an inert marker to a few common query parameters on the main page and
checks whether the marker is reflected into the HTML unescaped. Uses inert
alphanumeric markers only — never script payloads. One request per vector.

Verdict logic:
- marker reflected AND no effective CSP            -> FAIL (real XSS seam)
- marker reflected AND CSP present and restrictive -> WARN (reflection exists,
  CSP contains it — defense in depth still wants output encoding)
- marker not reflected                            -> PASS
"""

import urllib.parse

from ..fetch import FetchError, PoliteFetcher, RateLimited
from ..model import Finding
from .headers import _csp

PARAMS = ["q", "s", "search", "name", "query", "keyword"]
MARKER = "sitesealprobe7x9"  # inert, alphanumeric: escape() is identity on it,
                             # so any appearance in the body IS a reflection


def _csp_effective(headers):
    f = _csp(headers)
    return f.severity == "PASS"


def run(fetcher: PoliteFetcher, base_url: str, probe: bool = True):
    if not probe:
        return [Finding("inject", "inject.skipped", "INFO",
                        "Injection probing skipped (--no-probe)",
                        "Passive mode: no probe requests were sent.")]
    try:
        base = fetcher.get(base_url)
    except RateLimited:
        raise
    except FetchError as exc:
        return [Finding("inject", "inject.unreachable", "UNKNOWN",
                        "Could not fetch the site", str(exc))]
    if base.status >= 400:
        return [Finding("inject", "inject.unreachable", "UNKNOWN",
                        "Site returned HTTP %d" % base.status, "")]

    csp_ok = _csp_effective(base.headers)
    reflected = []
    probe_base = base.url  # final URL after redirects, not the raw input
    for param in PARAMS:
        url = probe_base + ("&" if "?" in probe_base else "?") + \
            urllib.parse.urlencode({param: MARKER})
        try:
            r = fetcher.get(url)
        except FetchError:
            continue
        if r.status >= 400:
            continue
        body = r.text
        if MARKER in body:
            idx = body.find(MARKER)
            context = body[max(0, idx - 60): idx + 60].strip().replace("\n", " ")
            reflected.append((param, context[:120]))

    if not reflected:
        return [Finding("inject", "inject.no-reflection", "PASS",
                        "No reflected query parameters (%d vectors tested)" % len(PARAMS),
                        "Inert markers sent via %s; none were reflected into the HTML."
                        % ", ".join("?%s=" % p for p in PARAMS))]
    worst = "FAIL" if not csp_ok else "WARN"
    return [Finding(
        "inject", "inject.reflected", worst,
        "Query parameter reflected unescaped: %s" % ", ".join("?%s=" % p for p, _ in reflected),
        "Marker reflected in: %s%s" % (
            "; ".join("?%s= near: …%s…" % (p, c) for p, c in reflected),
            "" if csp_ok else " — and the page has no effective CSP, so reflected "
            "content is one step from script execution."),
        "Encode output for the reflected parameter(s); add a restrictive "
        "Content-Security-Policy as defense in depth.")]
