# dontdial

**Your AI gave you a support number. Don't dial it yet.**

Attackers are poisoning AI search answers with fake support contacts at scale. In September 2026, researchers found ChatGPT, Gemini, and Google AI Overviews serving scammer phone numbers, emails, and login pages as official contacts for **374 major brands** — no prompt injection needed, just poisoned web content the AI retrieved. Every existing injection defense misses it, and most users never verify what the AI told them.

`dontdial` is a small CLI that checks the contacts inside an AI's answer — phone numbers, URLs, emails — against official sources, and tells you per contact whether it is **VERIFIED**, **SUSPICIOUS**, or **UNKNOWN**, with the evidence.

## How it works

1. **Extract** — phone numbers (via `phonenumbers`), URLs, and emails are pulled out of pasted text.
2. **Identify the brand** — from `--brand`, or by detecting brand mentions in the text, matched against a curated list of ~30 major brands (`dontdial/brands.json`).
3. **Cross-check** —
   - *URLs/emails*: the domain is compared against the brand's official domain. Exact or official subdomain = VERIFIED. Typosquats (`delta-support.com`), close misspellings (`dleta.com`), punycode/IDN tricks, and subdomain traps (`delta.com.evil.com`) = SUSPICIOUS, using edit distance plus structural heuristics. Anything else = UNKNOWN.
   - *Phones*: the brand's official contact pages are fetched and every listed number is extracted; if the AI's number appears there = VERIFIED. Premium-rate patterns (1-900, 1-976, +44 9…) = SUSPICIOUS. If the official site can't be reached, or the number isn't listed there, the verdict is UNKNOWN — the tool never guesses.
4. **Report** — human-readable table or `--json`, with CI-friendly exit codes.

The **only** network access is the explicit official-site fetch during phone verification. Everything else (extraction, domain analysis, verdicts) is fully offline and deterministic. No API keys, no LLM calls.

## Install

```bash
pip install dontdial
# or from source:
git clone https://github.com/CYPHERLYNX/dontdial && cd dontdial && pip install .
```

Requires Python 3.10+.

## Usage

Check an AI's answer (paste it quoted):

```bash
dontdial check --text "Call Delta support at 1-800-999-0000 or visit https://delta-support.com/login"
```

```
Checking against: Delta Air Lines (delta.com)

[??] PHONE  1-800-999-0000
       UNKNOWN: 1-800-999-0000 was not found on Delta Air Lines' official site; could not confirm it
[!!] URL    https://delta-support.com/login
       SUSPICIOUS: delta-support.com: embeds 'delta' but is not delta.com

0 verified, 1 suspicious, 1 unknown out of 2 contact(s).
Do not call, click, or email the suspicious ones. Find the real contact on the brand's official site yourself.
```

Force the brand context explicitly:

```bash
dontdial check --brand "Chase" --text "Reach Chase at 1-900-123-4567"
```

Show a brand's official contacts (ground truth to compare against manually):

```bash
dontdial check --brand "Delta"
```

Machine-readable output:

```bash
dontdial check --text "..." --json
```

List the curated brands:

```bash
dontdial brands
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Every contact verified (or the contact card was shown) |
| `1`  | At least one contact looks suspicious |
| `2`  | Only unknowns (nothing could be confirmed), nothing found, or an error |

`1` is the one that should stop you. `2` means "I couldn't prove it either way" — treat it with the same caution.

## Verdict semantics

- **VERIFIED** — the contact provably belongs to the brand: the domain *is* the official domain (or its subdomain), the email is on it, or the phone number is listed on the brand's official contact pages.
- **SUSPICIOUS** — structural evidence of deception: typosquat/lookalike domain, punycode, subdomain trick, or a premium-rate / scam-pattern phone number.
- **UNKNOWN** — could not confirm. The brand isn't in the curated list, the official site was unreachable, or the number simply wasn't listed there. UNKNOWN is not a clean bill of health.

## Limitations (read this)

- **Phone ground truth is heuristic.** There is no global database of official support numbers. `dontdial` compares against numbers it can scrape from a brand's public contact pages; a legitimate number that isn't published there (regional lines, new numbers, IVR-only lines) will come back UNKNOWN. It errs toward UNKNOWN rather than false accusations — but that also means a scammer number not yet seen anywhere will be UNKNOWN, not SUSPICIOUS, unless it matches a known scam pattern.
- **Curated brand list.** Only ~30 major brands ship in `brands.json` (airlines, banks, tech, retail). A brand outside the list can't be verified — contributions welcome.
- **URL checks are the strongest part** (deterministic domain analysis). **Phone checks depend on the official site being reachable and listing its numbers.**
- This tool checks *contacts*, not *content*. It won't catch a scammer using the real number in a social-engineering script, and it can't verify facts, prices, or policies in the AI's answer.
- Not legal advice, not a blocklist, not antivirus. When in doubt, navigate to the official site yourself and find the contact there.

## Development

```bash
python -m unittest discover -s tests   # 28 tests, no network (fetches are stubbed)
```

## License

MIT — see [LICENSE](LICENSE).
