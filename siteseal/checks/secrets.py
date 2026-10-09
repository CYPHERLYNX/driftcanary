"""Secrets embedded in client-side JavaScript.

Fetches same-origin JS assets referenced by the main document and scans for
credential patterns. Findings are evidence, not proof: the tool NEVER tries to
validate a key against a third-party API (that would be someone else's
infrastructure). Keys are redacted in output (first 4 + last 2 chars only).
"""

import math
import re
import urllib.parse
from html.parser import HTMLParser

from ..fetch import FetchError, PoliteFetcher, RateLimited
from ..model import Finding

MAX_JS_ASSETS = 25

# (pattern-name, compiled regex, redaction-safe description)
PATTERNS = [
    # (?<![\w-]) guard: without it, minified CSS-in-JS like
    # "mask-image-linear-to-pos" false-positives on the sk- prefix.
    ("openai-key", re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
     "OpenAI-style secret key"),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "AWS access key ID"),
    ("aws-secret", re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{32,}['\"]"),
     "AWS secret access key"),
    ("stripe-key", re.compile(r"\b(?:sk_live|rk_live)_[A-Za-z0-9]{16,}\b"),
     "Stripe live secret key"),
    ("github-token", re.compile(r"\b(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{16,}\b"),
     "GitHub token"),
    ("slack-token", re.compile(r"\bxox[abpr]-[A-Za-z0-9\-]{8,}\b"),
     "Slack token"),
    ("generic-apikey", re.compile(r"(?i)(?:api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-./+=]{16,})['\"]"),
     "labeled API key assignment"),
]

# Strings that look secret-shaped but are almost certainly placeholders.
PLACEHOLDERS = re.compile(
    r"(?i)^(your[_-]?|test[_-]?|example[_-]?|demo[_-]?|xxx+|placeholder|changeme|"
    r"insert[_-]?|fake[_-]?|<.*>|\*+)$"
)

CONTEXT_WORDS = re.compile(r"(?i)(secret|token|password|passwd|credential|private[_-]?key)")

ENTROPY_THRESHOLD = 3.5  # bits/char; hex caps at 4.0, base62 keys sit ~5.9.
# Substring context matching is deliberate: JS identifiers are camelCase
# ("dbPassword", "authToken"), so word-boundary matching would miss the
# common case. False positives are contained by WARN severity + "verify".

# Heuristic hits are lower-confidence than pattern hits; run() reports them
# as WARN ("verify this is really a secret"), never FAIL.


def _entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class _AssetCollector(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.assets = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.assets.append(urllib.parse.urljoin(self.base_url, a["src"]))
        if tag == "link" and a.get("rel") == "modulepreload" and a.get("href"):
            self.assets.append(urllib.parse.urljoin(self.base_url, a["href"]))


def _same_origin(url, base):
    u, b = urllib.parse.urlparse(url), urllib.parse.urlparse(base)
    return (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)) == \
           (b.scheme, b.hostname, b.port or (443 if b.scheme == "https" else 80))


def _redact(secret):
    if len(secret) <= 8:
        return secret[:2] + "…" + secret[-1:]
    return secret[:4] + "…" + secret[-2:]


def _is_placeholder(value):
    v = value.strip().strip("'\"")
    return bool(PLACEHOLDERS.match(v)) or len(set(v.lower())) <= 3


def scan_text(js_text):
    """Scan JS text.

    Returns list of (pattern_name, description, match, line_no, severity).
    Pattern hits are FAIL-grade; the entropy heuristic is WARN-grade.
    """
    hits = []
    for name, rx, desc in PATTERNS:
        for m in rx.finditer(js_text):
            secret = m.group(0)
            # For the generic pattern, group(1) is the value; check it, keep full match.
            probe = m.group(1) if name == "generic-apikey" and m.lastindex else secret
            if _is_placeholder(probe):
                continue
            line_no = js_text.count("\n", 0, m.start()) + 1
            hits.append((name, desc, secret, line_no, "FAIL"))
    # High-entropy string heuristic: long quoted strings next to secret-ish words.
    for m in re.finditer(r"['\"]([A-Za-z0-9_\-./+=]{24,})['\"]", js_text):
        val = m.group(1)
        if _is_placeholder(val) or _entropy(val) < ENTROPY_THRESHOLD:
            continue
        window = js_text[max(0, m.start() - 120): m.end() + 40]
        if CONTEXT_WORDS.search(window):
            line_no = js_text.count("\n", 0, m.start()) + 1
            hits.append(("high-entropy", "high-entropy string near secret context",
                         val, line_no, "WARN"))
    return hits


def _dedupe(hits):
    seen, out = set(), []
    for h in hits:
        key = (h[0], h[2])
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def run(fetcher: PoliteFetcher, base_url: str):
    try:
        resp = fetcher.get(base_url)
    except RateLimited:
        raise
    except FetchError as exc:
        return [Finding("secrets", "secrets.unreachable", "UNKNOWN",
                        "Could not fetch the site", str(exc))]
    if resp.status >= 400:
        return [Finding("secrets", "secrets.unreachable", "UNKNOWN",
                        "Site returned HTTP %d" % resp.status, "")]

    collector = _AssetCollector(resp.url)
    try:
        collector.feed(resp.text)
    except Exception:
        pass
    assets = [u for u in dict.fromkeys(collector.assets)
              if _same_origin(u, resp.url)][:MAX_JS_ASSETS]

    findings = []
    scanned = 0
    for asset in assets:
        try:
            js = fetcher.get(asset)
        except FetchError:
            continue
        if js.status >= 400:
            continue
        scanned += 1
        text = js.text
        for name, desc, secret, line_no, sev in _dedupe(scan_text(text)):
            path = urllib.parse.urlparse(asset).path
            if sev == "WARN":
                findings.append(Finding(
                    "secrets", "secrets.possible-%s" % name, "WARN",
                    "Possible %s in client JS (verify)" % desc,
                    "File %s line %d: %s  (heuristic — could be a non-secret; "
                    "never validated against the provider)" % (path, line_no, _redact(secret)),
                    "Confirm whether this value is a live credential; if so, move it "
                    "server-side and rotate it."))
            else:
                findings.append(Finding(
                    "secrets", "secrets.embedded-%s" % name, "FAIL",
                    "%s embedded in client JS" % desc,
                    "File %s line %d: %s  (redacted; never validated against the provider)"
                    % (path, line_no, _redact(secret)),
                    "Move the secret server-side; the browser bundle must never contain it. "
                    "Rotate the exposed credential."))
    if not assets:
        return [Finding("secrets", "secrets.no-js", "UNKNOWN",
                        "No same-origin JS assets found to scan",
                        "The main document referenced no same-origin scripts; nothing to scan.")]
    if not findings:
        return [Finding("secrets", "secrets.clean", "PASS",
                        "No embedded secrets found in %d JS asset(s)" % scanned,
                        "%d same-origin JS file(s) scanned with %d patterns + entropy heuristic."
                        % (scanned, len(PATTERNS)))]
    return findings
