"""siteseal CLI: audit a deployed ChatGPT Site's security posture."""

import argparse
import datetime
import sys
import urllib.parse

from . import __version__
from .checks import auth, headers, inject, secrets, storage
from .fetch import FetchError, PoliteFetcher, RateLimited
from . import report as reporting
from . import score as scoring


def _normalize_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("empty URL")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
    except ValueError:
        raise ValueError("not a valid http(s) URL: %r" % raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("not a valid http(s) URL: %r" % raw)
    return raw


def audit(url, probe=True, delay=0.7, timeout=10, allow_private=False):
    """Run all checks. Returns (findings, error). error is None on success."""
    fetcher = PoliteFetcher(delay=delay, timeout=timeout, allow_private=allow_private)
    findings = []
    try:
        findings.extend(headers.run(fetcher, url))
        findings.extend(auth.run(fetcher, url))
        findings.extend(secrets.run(fetcher, url))
        findings.extend(storage.run(fetcher, url, probe=probe))
        findings.extend(inject.run(fetcher, url, probe=probe))
    except RateLimited as exc:
        return findings, "rate limited (HTTP 429) — audit stopped, not retried: %s" % exc
    except FetchError as exc:  # pragma: no cover - defensive; checks degrade to UNKNOWN
        return findings, "fetch error: %s" % exc
    return findings, None


def build_parser():
    p = argparse.ArgumentParser(
        prog="siteseal",
        description="Audit a deployed ChatGPT Site for security misconfigurations.")
    p.add_argument("--version", action="version", version="siteseal %s" % __version__)
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="audit a site URL")
    a.add_argument("url", help="site URL, e.g. mysite.chatgpt.site")
    a.add_argument("--json", action="store_true", help="machine-readable JSON output")
    a.add_argument("--html", metavar="PATH", help="write dark HTML report to PATH")
    a.add_argument("--no-probe", action="store_true",
                   help="passive mode: skip storage/injection probing (no extra requests)")
    a.add_argument("--timeout", type=int, default=10, help="per-request timeout seconds")
    a.add_argument("--delay", type=float, default=0.7,
                   help="minimum seconds between requests (politeness)")
    a.add_argument("--allow-local", action="store_true",
                   help="permit private/loopback targets (local testing only)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        url = _normalize_url(args.url)
    except ValueError as exc:
        print("siteseal: %s" % exc, file=sys.stderr)
        return 2

    findings, error = audit(url, probe=not args.no_probe, delay=args.delay,
                            timeout=args.timeout, allow_private=args.allow_local)
    counts = scoring.summarize(findings)
    code = scoring.exit_code(findings, error)
    if error:
        letter, gscore = "?", 0.0
    elif code == 2:
        # Nothing assessable (all UNKNOWN): report no grade rather than a
        # misleading "A".
        letter, gscore = None, 0.0
    else:
        letter, gscore = scoring.grade(findings)

    if args.json:
        print(reporting.render_json(url, findings, letter, gscore, counts, code, error))
    else:
        print(reporting.render_terminal(url, findings, letter, gscore, counts, error))

    if args.html:
        when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        doc = reporting.render_html(url, findings, letter, gscore, counts, when, __version__)
        try:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(doc)
        except OSError as exc:
            print("siteseal: cannot write %s: %s" % (args.html, exc), file=sys.stderr)
            return 2
    return code
