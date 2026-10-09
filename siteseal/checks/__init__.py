"""Check families. Each ``run_*`` takes a PoliteFetcher and a base URL and
returns a list of Finding. Networks errors inside a check degrade to UNKNOWN,
never raise (the fetcher raises; checks catch)."""

from . import auth, headers, inject, secrets, storage

__all__ = ["auth", "headers", "inject", "secrets", "storage"]
