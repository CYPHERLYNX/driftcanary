"""driftcanary — a behavioral-drift canary for AI systems.

A zero-dependency (stdlib-only) CLI that runs a fixed battery of behavioral
probes against an LLM provider or coding-agent CLI on a schedule, baselines
results against the target's own history in local SQLite, and alerts on
statistically significant drift (two-sided CUSUM change-point detection).

Subcommands: init | probe | report | alert
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
