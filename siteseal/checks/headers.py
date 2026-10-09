"""Security-header grading.

Grades the main document's response headers. A header only PASSes when it is
present AND effective (e.g. HSTS with a real max-age, CSP without
'unsafe-inline'). Missing or toothless headers FAIL with a concrete fix line.
"""

import re

from ..fetch import FetchError, PoliteFetcher, RateLimited
from ..model import Finding

HSTS_MIN_AGE = 31536000  # 1 year


def _hsts(headers):
    v = headers.get("strict-transport-security")
    if not v:
        return Finding("headers", "headers.hsts-missing", "FAIL",
                       "HSTS header missing",
                       "No Strict-Transport-Security on the main document; first-visit "
                       "traffic can be downgraded to HTTP.",
                       "Serve Strict-Transport-Security: max-age=31536000; includeSubDomains.")
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age < HSTS_MIN_AGE:
        return Finding("headers", "headers.hsts-weak", "WARN",
                       "HSTS max-age too short (%d)" % age,
                       "Strict-Transport-Security: %s" % v,
                       "Raise max-age to at least 31536000.")
    return Finding("headers", "headers.hsts", "PASS",
                   "HSTS enabled (max-age=%d)" % age,
                   "Strict-Transport-Security: %s" % v)


def _csp(headers):
    v = headers.get("content-security-policy")
    if not v:
        return Finding("headers", "headers.csp-missing", "FAIL",
                       "Content-Security-Policy missing",
                       "No CSP on the main document; any injected script runs.",
                       "Ship a CSP, at minimum: default-src 'self'.")
    directives = [d.strip().split() for d in v.split(";") if d.strip()]
    has_src = any(d and d[0] in ("default-src", "script-src") for d in directives)
    unsafe = bool(re.search(r"'unsafe-inline'", v))
    if not has_src:
        return Finding("headers", "headers.csp-ineffective", "WARN",
                       "CSP present but has no default-src/script-src",
                       "Content-Security-Policy: %s" % v[:200],
                       "Add default-src 'self' (or a script-src) so the policy constrains scripts.")
    if unsafe:
        return Finding("headers", "headers.csp-unsafe-inline", "WARN",
                       "CSP allows 'unsafe-inline'",
                       "Content-Security-Policy: %s" % v[:200],
                       "Remove 'unsafe-inline'; use nonces or hashes for inline scripts.")
    return Finding("headers", "headers.csp", "PASS",
                   "Content-Security-Policy present and restrictive",
                   "Content-Security-Policy: %s" % v[:200])


def _simple(name, header, good_values, missing_fix, weak_fix=None):
    def check(headers):
        v = headers.get(header)
        if not v:
            return Finding("headers", "headers.%s-missing" % name, "FAIL",
                           "%s header missing" % header,
                           "No %s on the main document." % header, missing_fix)
        low = v.strip().lower()
        if any(g in low for g in good_values):
            return Finding("headers", "headers.%s" % name, "PASS",
                           "%s set (%s)" % (header, v[:80]), "%s: %s" % (header, v[:160]))
        return Finding("headers", "headers.%s-weak" % name, "WARN",
                       "%s set but weak (%s)" % (header, v[:80]),
                       "%s: %s" % (header, v[:160]),
                       weak_fix or missing_fix)
    return check


_xfo = _simple("xfo", "x-frame-options", ("deny", "sameorigin"),
              "Serve X-Frame-Options: DENY (or SAMEORIGIN).",
              "Use DENY or SAMEORIGIN; ALLOW-FROM is obsolete.")
_xcto = _simple("xcto", "x-content-type-options", ("nosniff",),
               "Serve X-Content-Type-Options: nosniff.")
_rp = _simple("rp", "referrer-policy",
              ("no-referrer", "strict-origin", "same-origin",
               "strict-origin-when-cross-origin", "origin-when-cross-origin"),
              "Serve Referrer-Policy: strict-origin-when-cross-origin (or stricter).")
def _permissions_policy(headers):
    v = headers.get("permissions-policy")
    if not v:
        return Finding("headers", "headers.pp-missing", "FAIL",
                       "Permissions-Policy header missing",
                       "No Permissions-Policy on the main document; powerful browser features "
                       "are available to any script that runs.",
                       "Serve Permissions-Policy, e.g.: camera=(), microphone=(), geolocation=().")
    return Finding("headers", "headers.pp", "PASS",
                   "Permissions-Policy present",
                   "Permissions-Policy: %s" % v[:200])


def run(fetcher: PoliteFetcher, base_url: str):
    try:
        resp = fetcher.get(base_url)
    except RateLimited:
        raise
    except FetchError as exc:
        return [Finding("headers", "headers.unreachable", "UNKNOWN",
                        "Could not fetch the site", str(exc))]
    if resp.status >= 400:
        return [Finding("headers", "headers.unreachable", "UNKNOWN",
                        "Site returned HTTP %d" % resp.status,
                        "Main document fetch returned %d; headers could not be graded." % resp.status)]
    h = resp.headers
    return [_hsts(h), _csp(h), _xfo(h), _xcto(h), _rp(h), _permissions_policy(h)]
