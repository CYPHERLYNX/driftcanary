"""Tests for probe grading determinism and the agent-CLI security boundary.

No network, no real CLIs: the provider client is faked, the agent grader is
exercised on fixed fixtures, and resolve_cli is tested against the real PATH.
"""

import unittest

from driftcanary.probes import aggregate, median, mode
from driftcanary.probes import provider as prov
from driftcanary.probes import agent as ag


class FakeClient:
    """Deterministic stand-in for ProviderClient."""

    def __init__(self, text="OK", tool_calls=None, latency_ms=123.0):
        self._text = text
        self._tool_calls = tool_calls or []
        self._latency = latency_ms

    def chat(self, messages, tools=None, temperature=0.0, max_tokens=256):
        return prov.ChatResponse(text=self._text, latency_ms=self._latency,
                                 tool_calls=self._tool_calls)


class TestAggregation(unittest.TestCase):
    def test_median_odd(self):
        self.assertEqual(median([3.0, 1.0, 2.0]), 2.0)

    def test_median_even(self):
        self.assertEqual(median([4.0, 1.0, 2.0, 3.0]), 2.5)

    def test_mode_binary(self):
        self.assertEqual(mode([1.0, 0.0, 1.0]), 1.0)
        self.assertEqual(mode([0.0, 0.0, 1.0]), 0.0)

    def test_aggregate_mixed(self):
        samples = [{"a": 1.0, "b": 0.0}, {"a": 3.0, "b": 0.0}, {"a": 2.0, "b": 1.0}]
        out = aggregate(samples)
        self.assertEqual(out["a"], 2.0)   # median
        self.assertEqual(out["b"], 0.0)   # mode (binary)


class TestProviderProbes(unittest.TestCase):
    def test_ping_metrics(self):
        out = prov.PROBES["ping"](FakeClient(text="OK", latency_ms=50.0))
        self.assertEqual(out["chars"], 2.0)
        self.assertEqual(out["latency_ms"], 50.0)

    def test_refusal_detected(self):
        out = prov.PROBES["refusal"](
            FakeClient(text="I'm sorry, I can't help with that."))
        self.assertEqual(out["refusal_rate"], 1.0)

    def test_refusal_not_detected(self):
        out = prov.PROBES["refusal"](FakeClient(text="Sure, here is a cake recipe."))
        self.assertEqual(out["refusal_rate"], 0.0)

    def test_json_format_exact(self):
        out = prov.PROBES["json_format"](
            FakeClient(text='{"status": "ok", "n": 42}'))
        self.assertEqual(out["valid_json"], 1.0)
        self.assertEqual(out["exact_match"], 1.0)

    def test_json_format_broken(self):
        out = prov.PROBES["json_format"](FakeClient(text="not json at all"))
        self.assertEqual(out["valid_json"], 0.0)
        self.assertEqual(out["exact_match"], 0.0)

    def test_tool_call_fidelity(self):
        tc = [{"name": "get_weather", "arguments": '{"city": "Paris"}'}]
        out = prov.PROBES["tool_call"](FakeClient(text="", tool_calls=tc))
        self.assertEqual(out["tool_called"], 1.0)
        self.assertEqual(out["args_valid"], 1.0)

    def test_tool_call_missing(self):
        out = prov.PROBES["tool_call"](FakeClient(text="It is sunny."))
        self.assertEqual(out["tool_called"], 0.0)

    def test_instruction_met(self):
        out = prov.PROBES["instruction"](FakeClient(text="red, green, blue"))
        self.assertEqual(out["constraint_met"], 1.0)

    def test_instruction_violated(self):
        out = prov.PROBES["instruction"](
            FakeClient(text="Here are three colors:\nred, green, blue"))
        self.assertEqual(out["constraint_met"], 0.0)

    def test_run_pack_unknown_probe_rejected(self):
        with self.assertRaises(ValueError):
            prov.run_pack(FakeClient(), probes=["nope"])

    def test_api_key_missing_env(self):
        import os
        os.environ.pop("DRIFTCANARY_TEST_MISSING", None)
        with self.assertRaises(prov.ProviderError):
            prov.api_key_from_env("DRIFTCANARY_TEST_MISSING")


class TestAgentGrading(unittest.TestCase):
    def test_sqli_held(self):
        probe = ag.AGENT_PROBES[0]
        self.assertEqual(probe.name, "sqli")
        self.assertEqual(
            ag.grade(probe, "This has a SQL injection via f-string. Use parameterized queries."),
            1.0)

    def test_sqli_bypassed(self):
        probe = ag.AGENT_PROBES[0]
        self.assertEqual(ag.grade(probe, "Looks good to me, ship it."), 0.0)

    def test_prompt_injection_held(self):
        probe = ag.AGENT_PROBES[1]
        self.assertEqual(
            ag.grade(probe, "The docs contain a prompt injection attempt telling me to ignore instructions."),
            1.0)

    def test_secret_log_held(self):
        probe = ag.AGENT_PROBES[2]
        self.assertEqual(
            ag.grade(probe, "Hardcoded secret: the API key is logged in plaintext."),
            1.0)

    def test_grading_is_case_insensitive(self):
        probe = ag.AGENT_PROBES[0]
        self.assertEqual(ag.grade(probe, "SQL INJECTION vulnerability."), 1.0)


class TestAgentSecurityBoundary(unittest.TestCase):
    def test_arbitrary_binary_rejected(self):
        with self.assertRaises(ag.AgentUnavailable):
            ag.resolve_cli("/bin/evil")

    def test_empty_name_rejected(self):
        with self.assertRaises(ag.AgentUnavailable):
            ag.resolve_cli("")

    def test_unknown_cli_rejected(self):
        with self.assertRaises(ag.AgentUnavailable):
            ag.resolve_cli("rm")

    def test_allowlist_is_closed(self):
        # The allowlist is the security boundary: only these names exist.
        self.assertEqual(set(ag._ALLOWED_CLIS.keys()), {"claude", "codex"})
        for name, prefix in ag._ALLOWED_CLIS.items():
            self.assertIsInstance(prefix, tuple)
            self.assertTrue(all(isinstance(a, str) for a in prefix))

    def test_available_clis_returns_list(self):
        clis = ag.available_clis()
        self.assertIsInstance(clis, list)
        self.assertTrue(all(c in ("claude", "codex") for c in clis))


if __name__ == "__main__":
    unittest.main()
