"""Alert delivery: exit codes for cron/CI plus optional webhook POSTs.

Exit-code contract (documented, stable):
  0 -- no drift detected (still warming up counts as clean: warming up is
       not drift, and alerting on it would train users to ignore alerts)
  2 -- drift detected on at least one probe metric
  1 -- the alert evaluation itself failed (no history, DB error, ...)

Webhooks use urllib (stdlib). Two flavors:
  * generic webhook: POST JSON {"text": ...} to --webhook URL
  * ntfy.sh: POST the plain-text summary to https://ntfy.sh/<topic>

The message body never contains API keys or probe prompts -- only the drift
summary (target, probe, metric, direction, magnitude).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DRIFT = 2


def format_message(target: str, target_name: str,
                   drift_lines: List[str]) -> str:
    head = "driftcanary: DRIFT detected on %s/%s" % (target, target_name)
    return head + "\n" + "\n".join("- " + line for line in drift_lines)


def post_webhook(url: str, text: str, timeout_s: float = 15.0) -> None:
    """POST {"text": text} as JSON. Raises on network/HTTP failure."""
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status >= 400:
                raise RuntimeError("webhook returned HTTP %s" % resp.status)
    except urllib.error.URLError as exc:
        raise RuntimeError("webhook POST failed: %s" % exc) from exc


def post_ntfy(topic: str, text: str, base_url: str = "https://ntfy.sh",
              timeout_s: float = 15.0) -> None:
    """POST plain text to an ntfy topic. Raises on failure."""
    topic = topic.strip().strip("/")
    if not topic or "/" in topic or " " in topic:
        raise ValueError("invalid ntfy topic %r" % topic)
    url = base_url.rstrip("/") + "/" + topic
    req = urllib.request.Request(
        url, data=text.encode("utf-8"), method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status >= 400:
                raise RuntimeError("ntfy returned HTTP %s" % resp.status)
    except urllib.error.URLError as exc:
        raise RuntimeError("ntfy POST failed: %s" % exc) from exc
