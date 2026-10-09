# siteseal

**Security-posture auditor for deployed ChatGPT Sites.**

ChatGPT Sites turns a prompt into a hosted web app — but builders ship blind. Sign-in-with-ChatGPT headers carry visitor emails to the site owner, API keys land in client JavaScript, storage endpoints sit unauthenticated, and nobody grades the security headers on a `*.chatgpt.site` deploy.

`siteseal` takes a Site URL and returns a graded security report: header grades, secret leaks, open storage endpoints, injection seams — each finding with evidence and a fix. Exit codes make it CI-gatable.

```bash
pip install siteseal
siteseal audit mysite.chatgpt.site
```

```
siteseal audit: https://mysite.chatgpt.site/

Site grade: GRADE F (12.5/100)
Findings: 8 fail, 2 warn, 1 pass, 0 unknown, 1 info

[FAIL] headers  Content-Security-Policy missing
         No CSP on the main document; any injected script runs.
         fix: Ship a CSP, at minimum: default-src 'self'.
[FAIL] secrets  OpenAI-style secret key embedded in client JS
         File /assets/index-CtVXNBql.js line 41: sk-p…34  (redacted; never validated against the provider)
         fix: Move the secret server-side; the browser bundle must never contain it. Rotate the exposed credential.
...
```

## What it checks

| Check | What it does |
|---|---|
| `headers` | Grades CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. A header only passes when present **and** effective. |
| `auth` | Detects a Sign-in-with-ChatGPT surface; reports the visitor-data exposure (email/name goes to the site owner) and flags auth endpoints answering without a token. Absence is informational, never a fail. |
| `secrets` | Fetches same-origin JS assets and scans for embedded credentials (OpenAI, AWS, Stripe, GitHub, Slack, labeled keys, high-entropy heuristic). Findings are redacted; keys are **never** validated against providers. |
| `storage` | Probes likely `/api/*` storage routes with read-only GETs. FAIL only on concrete evidence (sensitive fields returned unauthenticated); otherwise WARN ("verify this is meant to be public"). Never writes. |
| `inject` | Tests reflected query parameters with inert markers (never script payloads). FAIL when reflected with no effective CSP. |

Grades run A–F. Exit codes: `0` = A/B, `1` = actionable findings (C/D/F), `2` = error or nothing assessable. UNKNOWN findings (offline, blocked, absent surface) never move the grade.

## Usage

```bash
siteseal audit mysite.chatgpt.site                  # human-readable table
siteseal audit mysite.chatgpt.site --json             # machine-readable
siteseal audit mysite.chatgpt.site --html report.html # dark HTML report
siteseal audit mysite.chatgpt.site --no-probe         # passive mode: headers + JS scan only, no probing
```

## Polite by design

- One thread, ≥0.7s between requests (`--delay` to raise it), 10s timeouts.
- **Hard stop on HTTP 429** — the audit aborts, never retries.
- `--no-probe` skips all storage/injection probing.
- Private/loopback targets are refused unless `--allow-local` (local testing).
- Injection checks use inert alphanumeric markers, never payloads.

## Ethics — read this

Audit **your own Sites**, or Sites you have explicit permission to test. Probing someone else's deploy without permission may violate their terms and local law. Findings about third-party credentials are evidence, not proof — `siteseal` never phones home to validate a key, and neither should you without authorization. When in doubt, run `--no-probe`.

## Development

```bash
python -m unittest discover -s tests   # 64 tests, zero network in unit tests
```

Stdlib only — no dependencies, no supply chain. Python 3.10+.

## Limitations

- Header grading covers the main document; per-asset headers are not graded.
- The secret scan is pattern + heuristic — it can miss obfuscated keys and can flag strings that aren't secrets (those are WARN, not FAIL).
- An open JSON endpoint is reported as WARN unless it returns sensitive fields; only the site owner knows what's intentionally public.
- ChatGPT Sites is a young platform; endpoint shapes are versioned in code comments and missing surfaces degrade to UNKNOWN, never FAIL.

## License

MIT — see [LICENSE](LICENSE).
