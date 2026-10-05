"""dontdial tests. Network is never touched: official-site fetches are stubbed."""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from dontdial import brands as brands_mod
from dontdial.brands import detect_brands, find_brand, load_brands
from dontdial.check import (
    SUSPICIOUS,
    UNKNOWN,
    VERIFIED,
    check_email,
    check_entity,
    check_phone,
    check_url,
    levenshtein,
    registrable_domain,
)
from dontdial.cli import main
from dontdial.extract import Entity, extract_all


def _brand(name="Delta Air Lines"):
    return next(b for b in load_brands() if b.name == name)


def _url(raw):
    return Entity(kind="url", raw=raw)


def _email(raw):
    return Entity(kind="email", raw=raw)


def _phone(raw, normalized):
    return Entity(kind="phone", raw=raw, normalized=normalized)


class TestLevenshtein(unittest.TestCase):
    def test_known_distances(self):
        self.assertEqual(levenshtein("kitten", "sitting"), 3)
        self.assertEqual(levenshtein("delta", "delta"), 0)
        self.assertEqual(levenshtein("delta", "dleta"), 2)
        self.assertEqual(levenshtein("", "abc"), 3)


class TestRegistrableDomain(unittest.TestCase):
    def test_subdomain(self):
        self.assertEqual(registrable_domain("support.delta.com"), "delta.com")

    def test_multi_suffix(self):
        self.assertEqual(registrable_domain("shop.example.co.uk"), "example.co.uk")

    def test_bare(self):
        self.assertEqual(registrable_domain("delta.com"), "delta.com")


class TestExtraction(unittest.TestCase):
    def test_urls(self):
        ents = extract_all("Visit https://delta-support.com/login or www.evil.example/x now.")
        urls = [e.raw for e in ents if e.kind == "url"]
        self.assertIn("https://delta-support.com/login", urls)
        self.assertIn("www.evil.example/x", urls)

    def test_emails(self):
        ents = extract_all("Email support@delta-support.com for help.")
        emails = [e.raw for e in ents if e.kind == "email"]
        self.assertIn("support@delta-support.com", emails)

    def test_phones(self):
        ents = extract_all("Call Delta at 1-800-221-1212 or +1 (404) 209-1234.")
        phones = [e.raw for e in ents if e.kind == "phone"]
        self.assertEqual(len(phones), 2)
        norms = [e.normalized for e in ents if e.kind == "phone"]
        self.assertIn("18002211212", norms)
        self.assertIn("14042091234", norms)


class TestUrlVerdicts(unittest.TestCase):
    def test_exact_official_verified(self):
        v = check_url(_url("https://www.delta.com/us/en"), [_brand()])
        self.assertEqual(v.verdict, VERIFIED)

    def test_typosquat_suspicious(self):
        v = check_url(_url("https://delta-support.com/login"), [_brand()])
        self.assertEqual(v.verdict, SUSPICIOUS)
        self.assertIn("delta.com", v.evidence)

    def test_subdomain_trick_suspicious(self):
        v = check_url(_url("https://delta.com.evil.com/login"), [_brand()])
        self.assertEqual(v.verdict, SUSPICIOUS)

    def test_close_typo_suspicious(self):
        v = check_url(_url("https://dleta.com/"), [_brand()])
        self.assertEqual(v.verdict, SUSPICIOUS)

    def test_unrelated_unknown(self):
        v = check_url(_url("https://example.com/help"), [_brand()])
        self.assertEqual(v.verdict, UNKNOWN)

    def test_no_brand_unknown(self):
        v = check_url(_url("https://delta-support.com/"), [])
        self.assertEqual(v.verdict, UNKNOWN)


class TestEmailVerdicts(unittest.TestCase):
    def test_official_verified(self):
        v = check_email(_email("help@delta.com"), [_brand()])
        self.assertEqual(v.verdict, VERIFIED)

    def test_lookalike_suspicious(self):
        v = check_email(_email("support@delta-airlines-support.com"), [_brand()])
        self.assertEqual(v.verdict, SUSPICIOUS)


class TestPhoneVerdicts(unittest.TestCase):
    def test_listed_number_verified(self):
        v = check_phone(_phone("1-800-221-1212", "18002211212"), [_brand()],
                        {"delta.com": {"18002211212", "14042091234"}})
        self.assertEqual(v.verdict, VERIFIED)

    def test_unlisted_number_unknown(self):
        v = check_phone(_phone("1-800-999-0000", "18009990000"), [_brand()],
                        {"delta.com": {"18002211212"}})
        self.assertEqual(v.verdict, UNKNOWN)
        self.assertIn("not found", v.evidence)

    def test_fetch_failed_unknown(self):
        v = check_phone(_phone("1-800-999-0000", "18009990000"), [_brand()], {})
        self.assertEqual(v.verdict, UNKNOWN)
        self.assertIn("could not reach", v.evidence)

    def test_premium_rate_suspicious(self):
        v = check_phone(_phone("1-900-123-4567", "19001234567"), [_brand()],
                        {"delta.com": {"18002211212"}})
        self.assertEqual(v.verdict, SUSPICIOUS)

    def test_no_brand_context_unknown(self):
        v = check_phone(_phone("1-800-999-0000", "18009990000"), [], {})
        self.assertEqual(v.verdict, UNKNOWN)


class TestBrands(unittest.TestCase):
    def test_thirty_brands_with_fields(self):
        all_brands = load_brands()
        self.assertGreaterEqual(len(all_brands), 30)
        for b in all_brands:
            self.assertTrue(b.name)
            self.assertIn(".", b.official_domain)

    def test_find_brand(self):
        all_brands = load_brands()
        self.assertEqual(find_brand("Delta", all_brands).official_domain, "delta.com")
        self.assertEqual(find_brand("chase bank", all_brands).official_domain, "chase.com")
        self.assertIsNone(find_brand("Nonexistent Corp Xyz", all_brands))

    def test_detect_brands_in_text(self):
        all_brands = load_brands()
        found = detect_brands("I need the Chase support number and my Delta booking.", all_brands)
        names = {b.name for b in found}
        self.assertIn("Chase", names)
        self.assertIn("Delta Air Lines", names)


class TestCliEndToEnd(unittest.TestCase):
    # Synthetic AI answer mirroring the Sep-2026 research findings.
    SCAM_ANSWER = (
        "Here is Delta's official support info: call 1-800-999-0000 "
        "(available 24/7) or manage your booking at https://delta-support.com/login. "
        "You can also email help@delta-airlines-support.com."
    )

    def _run(self, argv, fetch_stub):
        with patch("dontdial.cli.fetch_official_numbers", fetch_stub):
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    code = main(argv)
                except SystemExit as e:
                    code = e.code
            return code, buf.getvalue()

    def test_scam_answer_exits_suspicious(self):
        def stub(domain, *a, **k):
            return {"18002211212"}  # real Delta number, not the scam one
        code, out = self._run(["check", "--text", self.SCAM_ANSWER], stub)
        self.assertEqual(code, 1)
        self.assertIn("SUSPICIOUS", out)

    def test_clean_answer_exits_zero(self):
        def stub(domain, *a, **k):
            return {"18002211212"}
        text = "Call Delta at 1-800-221-1212 or visit https://www.delta.com."
        code, out = self._run(["check", "--text", text], stub)
        self.assertEqual(code, 0)
        self.assertIn("VERIFIED", out)

    def test_unknown_only_exits_two(self):
        def stub(domain, *a, **k):
            return None  # site unreachable
        code, _ = self._run(["check", "--text", "Call 1-800-999-0000."], stub)
        self.assertEqual(code, 2)

    def test_json_output(self):
        def stub(domain, *a, **k):
            return {"18002211212"}
        code, out = self._run(
            ["check", "--text", "Visit https://www.delta.com.", "--json"], stub)
        data = json.loads(out)
        self.assertEqual(data["entities"][0]["verdict"], "VERIFIED")
        self.assertEqual(code, 0)

    def test_no_entities_exits_two(self):
        code, _ = self._run(["check", "--text", "Hello world, no contacts here."], lambda *a, **k: set())
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
