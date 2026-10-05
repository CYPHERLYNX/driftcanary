"""dontdial CLI: verify contacts an AI gave you before you dial/click."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .brands import detect_brands, find_brand, load_brands
from .check import SUSPICIOUS, UNKNOWN, VERIFIED, Verdict, check_entity
from .extract import extract_all
from .fetch import fetch_official_numbers

EXIT_OK = 0          # every entity verified (or contact card shown)
EXIT_SUSPICIOUS = 1  # at least one entity looks malicious
EXIT_UNKNOWN = 2     # unknowns only, nothing found, or an error


def _verdict_to_dict(v: Verdict) -> dict:
    return {
        "kind": v.entity.kind,
        "raw": v.entity.raw,
        "verdict": v.verdict,
        "evidence": v.evidence,
        "brand": v.brand,
    }


def _print_human(verdicts: list[Verdict]) -> None:
    mark = {VERIFIED: "[OK] ", SUSPICIOUS: "[!!] ", UNKNOWN: "[??] "}
    for v in verdicts:
        print(f"{mark[v.verdict]}{v.entity.kind.upper():<6} {v.entity.raw}")
        print(f"       {v.verdict}: {v.evidence}")
    counts = {VERIFIED: 0, SUSPICIOUS: 0, UNKNOWN: 0}
    for v in verdicts:
        counts[v.verdict] += 1
    print()
    print(
        f"{counts[VERIFIED]} verified, {counts[SUSPICIOUS]} suspicious, "
        f"{counts[UNKNOWN]} unknown out of {len(verdicts)} contact(s)."
    )
    if counts[SUSPICIOUS]:
        print("Do not call, click, or email the suspicious ones. "
              "Find the real contact on the brand's official site yourself.")


def _exit_code(verdicts: list[Verdict]) -> int:
    if not verdicts:
        return EXIT_UNKNOWN
    if any(v.verdict == SUSPICIOUS for v in verdicts):
        return EXIT_SUSPICIOUS
    if any(v.verdict == UNKNOWN for v in verdicts):
        return EXIT_UNKNOWN
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    brands = load_brands()

    # --brand only: show the official contact card for manual comparison.
    if args.brand and not args.text:
        brand = find_brand(args.brand, brands)
        if brand is None:
            print(f"Unknown brand: {args.brand!r}. Try `dontdial brands`.", file=sys.stderr)
            return EXIT_UNKNOWN
        print(f"Official contacts for {brand.name} (from {brand.official_domain}):")
        numbers = fetch_official_numbers(brand.official_domain)
        if numbers is None:
            print("  Could not reach the official site right now.")
            return EXIT_UNKNOWN
        if not numbers:
            print("  No phone numbers found on the official contact pages.")
        for n in sorted(numbers):
            print(f"  phone: +{n}")
        print(f"  web: https://{brand.official_domain}")
        return EXIT_OK

    if not args.text:
        print("Nothing to check: pass --text \"...\" (optionally with --brand).", file=sys.stderr)
        return EXIT_UNKNOWN

    if args.brand:
        brand = find_brand(args.brand, brands)
        if brand is None:
            print(f"Unknown brand: {args.brand!r}. Try `dontdial brands`.", file=sys.stderr)
            return EXIT_UNKNOWN
        context_brands = [brand]
    else:
        context_brands = detect_brands(args.text, brands)

    entities = extract_all(args.text)
    if not entities:
        msg = "No phone numbers, URLs, or emails found in the text."
        if args.json:
            print(json.dumps({"entities": [], "note": msg}, indent=2))
        else:
            print(msg)
        return EXIT_UNKNOWN

    # Fetch official numbers only for brands in context, and only if there is
    # at least one phone number to verify (the fetch is the only network step).
    official_numbers: dict[str, set[str]] = {}
    if any(e.kind == "phone" for e in entities):
        for b in context_brands:
            fetched = fetch_official_numbers(b.official_domain)
            if fetched is not None:
                official_numbers[b.official_domain] = fetched

    verdicts = [check_entity(e, context_brands, official_numbers) for e in entities]

    if args.json:
        print(json.dumps(
            {
                "brands_in_context": [b.name for b in context_brands],
                "entities": [_verdict_to_dict(v) for v in verdicts],
            },
            indent=2,
        ))
    else:
        if context_brands:
            print(f"Checking against: {', '.join(b.name for b in context_brands)} "
                  f"({', '.join(b.official_domain for b in context_brands)})")
        else:
            print("No known brand detected in the text; checks are limited.")
        print()
        _print_human(verdicts)
    return _exit_code(verdicts)


def cmd_brands(_args: argparse.Namespace) -> int:
    for b in load_brands():
        print(f"{b.name:<28} {b.official_domain}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dontdial",
        description="Your AI gave you a support number. Don't dial it yet. "
                    "Verify contacts from AI answers against official sources.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="Check contacts in pasted AI output")
    c.add_argument("--text", help="The AI's answer to verify (quote it)")
    c.add_argument("--brand", help="Brand context, e.g. \"Delta\"")
    c.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    c.set_defaults(func=cmd_check)

    b = sub.add_parser("brands", help="List curated brands")
    b.set_defaults(func=cmd_brands)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_UNKNOWN


if __name__ == "__main__":
    sys.exit(main())
