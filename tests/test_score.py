import unittest

from siteseal import score
from siteseal.model import Finding


def F(check, severity, fid="x"):
    return Finding(check, fid, severity, "t")


class TestScore(unittest.TestCase):
    def test_clean_is_a(self):
        out = [F("headers", "PASS"), F("secrets", "PASS")]
        letter, s = score.grade(out)
        self.assertEqual((letter, s), ("A", 100.0))

    def test_all_header_fails(self):
        out = [F("headers", "FAIL")]
        letter, s = score.grade(out)
        self.assertEqual(s, 70.0)
        self.assertEqual(letter, "C")

    def test_warn_costs_half(self):
        out = [F("headers", "WARN")]  # 30/2 = 15
        _, s = score.grade(out)
        self.assertEqual(s, 85.0)

    def test_unknown_never_moves_score(self):
        out = [F("headers", "UNKNOWN"), F("secrets", "INFO"), F("storage", "PASS")]
        letter, s = score.grade(out)
        self.assertEqual((letter, s), ("A", 100.0))

    def test_everything_failing_is_f(self):
        out = [F(c, "FAIL") for c in ("headers", "secrets", "storage", "inject", "auth")]
        letter, s = score.grade(out)
        self.assertEqual((letter, s), ("F", 0.0))

    def test_exit_codes(self):
        self.assertEqual(score.exit_code([F("headers", "PASS")]), 0)
        self.assertEqual(score.exit_code([F("headers", "FAIL")]), 1)  # C grade
        self.assertEqual(score.exit_code([F("headers", "UNKNOWN")]), 2)
        self.assertEqual(score.exit_code([], error="boom"), 2)
        self.assertEqual(score.exit_code([F("headers", "FAIL"), F("secrets", "FAIL")]), 1)

    def test_summarize(self):
        out = [F("headers", "FAIL"), F("secrets", "WARN"), F("auth", "INFO")]
        c = score.summarize(out)
        self.assertEqual((c["FAIL"], c["WARN"], c["INFO"]), (1, 1, 1))


if __name__ == "__main__":
    unittest.main()
