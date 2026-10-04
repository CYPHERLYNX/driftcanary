"""driftcanary command-line interface.

Subcommands:
  init    create the data directory, database schema, and default config
  probe   run the probe pack against a provider or agent CLI, store results
  report  render the dark HTML trend report
  alert   evaluate CUSUM drift; exit 2 on drift, 0 when clean, 1 on error

Every failure prints a human-readable message with a remedy and exits 1.
Tracebacks never reach the user.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Dict, List, Optional

from . import __version__
from . import detect as detect_mod
from . import notify as notify_mod
from . import report as report_mod
from . import store as store_mod
from .probes import provider as provider_probes
from .probes import agent as agent_probes

DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".driftcanary")
CONFIG_NAME = "config.json"

DEFAULT_CONFIG = {
    "warmup_runs": detect_mod.DEFAULT_WARMUP_RUNS,
    "cusum_k": detect_mod.DEFAULT_K,
    "cusum_h": detect_mod.DEFAULT_H,
    "samples": 3,
    "provider_base_url": "https://api.openai.com/v1",
    "provider_api_key_env": "OPENAI_API_KEY",
    "agent_cli": "claude",
    "agent_timeout_s": 180.0,
}


# ---------------------------------------------------------------------------
# config file
# ---------------------------------------------------------------------------

def config_path(data_dir: str) -> str:
    return os.path.join(data_dir, CONFIG_NAME)


def load_config(data_dir: str) -> Dict:
    cfg = dict(DEFAULT_CONFIG)
    path = config_path(data_dir)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                user = json.load(fh)
            if isinstance(user, dict):
                for k, v in user.items():
                    if k in DEFAULT_CONFIG:
                        cfg[k] = v
        except (json.JSONDecodeError, OSError):
            pass  # corrupt config: fall back to defaults, never crash
    return cfg


def require_data_dir(data_dir: str) -> store_mod.Store:
    if not os.path.isdir(data_dir):
        raise _UserError(
            "data directory %s does not exist.\nRun: driftcanary init" % data_dir
        )
    return store_mod.Store(data_dir)


class _UserError(Exception):
    """An expected, human-explainable failure."""


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    data_dir = os.path.abspath(os.path.expanduser(args.dir))
    os.makedirs(data_dir, exist_ok=True)
    store_mod.Store(data_dir)  # creates schema
    cfg_path = config_path(data_dir)
    if not os.path.isfile(cfg_path):
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(DEFAULT_CONFIG, fh, indent=2)
            fh.write("\n")
    print("driftcanary initialized at %s" % data_dir)
    print()
    print("Next steps:")
    print("  1. Export your provider key (never stored in files):")
    print("       export OPENAI_API_KEY=sk-...")
    print("  2. Run your first probe:")
    print("       driftcanary probe --target provider --model gpt-4o-mini")
    print("     or, for agent prompt-decay monitoring:")
    print("       driftcanary probe --target agent --cli claude")
    print("  3. Schedule it (example cron, every 6 hours):")
    print("       0 */6 * * * driftcanary probe --target provider "
          "--model gpt-4o-mini && driftcanary alert")
    print()
    print("No alerts fire before %d baseline runs (warmup); "
          "see 'driftcanary report' any time." % DEFAULT_CONFIG["warmup_runs"])
    return 0


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------

def _run_provider_probe(args: argparse.Namespace, cfg: Dict,
                        store: store_mod.Store) -> int:
    model = args.model or cfg.get("provider_model")
    if not model:
        raise _UserError(
            "no model given.\nPass --model <id>, e.g. "
            "driftcanary probe --target provider --model gpt-4o-mini"
        )
    base_url = args.base_url or cfg["provider_base_url"]
    key_env = args.api_key_env or cfg["provider_api_key_env"]
    try:
        api_key = provider_probes.api_key_from_env(key_env)
    except provider_probes.ProviderError as exc:
        raise _UserError(str(exc) + "\nSet it with: export %s=..." % key_env) from exc

    samples = args.samples or int(cfg["samples"])
    probe_names = (args.probes.split(",") if args.probes
                   else sorted(provider_probes.PROBES.keys()))
    client = provider_probes.ProviderClient(
        base_url, model, api_key, timeout_s=float(cfg.get("provider_timeout_s", 60.0)))
    target_name = "%s@%s" % (model, base_url)
    run_id = store.start_run("provider", target_name)
    t0 = time.monotonic()
    try:
        print("Probing %s (%d probes x %d samples)..."
              % (target_name, len(probe_names), samples))
        pack = provider_probes.run_pack(client, samples=samples,
                                        probes=probe_names)
    except provider_probes.ProviderError as exc:
        store.finish_run(run_id, "error")
        raise _UserError(
            "probe run failed: %s\n"
            "This is a probe error, not drift — check the endpoint, model "
            "name, and key, then re-run." % exc) from exc
    for probe, metrics in pack.items():
        for metric, value in metrics.items():
            store.record(run_id, probe, metric, value, samples=samples)
    store.finish_run(run_id, "ok")
    n_runs = store.run_count("provider", target_name)
    print("Stored run #%d for %s (%d total runs, %.1fs)."
          % (run_id, target_name, n_runs, time.monotonic() - t0))
    warmup = int(cfg["warmup_runs"])
    if n_runs < warmup:
        print("Warming up: %d of %d baseline runs collected."
              % (n_runs, warmup))
    return 0


def _run_agent_probe(args: argparse.Namespace, cfg: Dict,
                     store: store_mod.Store) -> int:
    cli_name = (args.cli or cfg["agent_cli"] or "").strip().lower()
    try:
        agent_probes.resolve_cli(cli_name)
    except agent_probes.AgentUnavailable as exc:
        raise _UserError(
            "%s\nInstall claude or codex, or run provider mode instead:\n"
            "  driftcanary probe --target provider --model <id>" % exc) from exc
    timeout_s = float(args.timeout or cfg["agent_timeout_s"])
    target_name = cli_name
    run_id = store.start_run("agent", target_name)
    t0 = time.monotonic()
    failed = 0
    print("Probing agent CLI %r (%d probes)..."
          % (cli_name, len(agent_probes.AGENT_PROBES)))
    for probe in agent_probes.AGENT_PROBES:
        try:
            held, _ = agent_probes.run_one(
                agent_probes.resolve_cli(cli_name), cli_name, probe, timeout_s)
            store.record(run_id, probe.name, "held", held, samples=1)
            print("  %-16s %s" % (probe.name,
                                  "HELD (caught it)" if held else "BYPASSED (missed it)"))
        except agent_probes.AgentProbeError as exc:
            failed += 1
            print("  %-16s ERROR: %s" % (probe.name, exc))
    store.finish_run(run_id, "partial" if failed else "ok")
    n_runs = store.run_count("agent", target_name)
    print("Stored run #%d for agent %s (%d total runs, %.1fs)."
          % (run_id, cli_name, n_runs, time.monotonic() - t0))
    if failed:
        print("Note: %d probe(s) errored — recorded as a partial run, "
              "not as drift." % failed)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    data_dir = os.path.abspath(os.path.expanduser(args.dir))
    store = require_data_dir(data_dir)
    cfg = load_config(data_dir)
    if args.target == "provider":
        return _run_provider_probe(args, cfg, store)
    if args.target == "agent":
        return _run_agent_probe(args, cfg, store)
    raise _UserError("--target must be 'provider' or 'agent'")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def cmd_report(args: argparse.Namespace) -> int:
    data_dir = os.path.abspath(os.path.expanduser(args.dir))
    store = require_data_dir(data_dir)
    cfg = load_config(data_dir)
    cusum = detect_mod.CusumConfig(
        warmup_runs=int(args.warmup or cfg["warmup_runs"]),
        k=float(args.k or cfg["cusum_k"]),
        h=float(args.h or cfg["cusum_h"]),
    )
    data = store.as_dict()
    verdicts: Dict = {}
    statuses: Dict = {}
    for t in data["targets"]:
        key = (t["target"], t["target_name"])
        series_map = {}
        for skey, points in t["series"].items():
            probe, _, metric = skey.partition(".")
            series_map[skey] = (probe, metric, [v for _, v in points])
        tv = detect_mod.detect_all(series_map, cusum)
        verdicts[key] = tv
        statuses[key], _ = detect_mod.summarize(tv)
    out = args.out or os.path.join(data_dir, "report.html")
    html_text = report_mod.build_report(data, verdicts, statuses)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    print("Report written to %s" % out)
    return 0


# ---------------------------------------------------------------------------
# alert
# ---------------------------------------------------------------------------

def cmd_alert(args: argparse.Namespace) -> int:
    data_dir = os.path.abspath(os.path.expanduser(args.dir))
    store = require_data_dir(data_dir)
    cfg = load_config(data_dir)
    cusum = detect_mod.CusumConfig(
        warmup_runs=int(args.warmup or cfg["warmup_runs"]),
        k=float(args.k or cfg["cusum_k"]),
        h=float(args.h or cfg["cusum_h"]),
    )
    data = store.as_dict()
    if not data["targets"]:
        print("No probe history yet — nothing to evaluate. "
              "Run 'driftcanary probe' first.")
        return notify_mod.EXIT_OK
    any_drift = False
    for t in data["targets"]:
        key = (t["target"], t["target_name"])
        series_map = {}
        for skey, points in t["series"].items():
            probe, _, metric = skey.partition(".")
            series_map[skey] = (probe, metric, [v for _, v in points])
        tv = detect_mod.detect_all(series_map, cusum)
        status, drifted = detect_mod.summarize(tv)
        if status == "drift":
            any_drift = True
            lines = [
                "%s.%s drifted %s (change at run #%d, shift %+.2fsigma)"
                % (v.probe, v.metric, v.direction,
                   (v.change_index or 0) + 1, v.shift_sigma or 0.0)
                for v in drifted
            ]
            print("DRIFT on %s/%s:" % (t["target"], t["target_name"]))
            for line in lines:
                print("  - " + line)
            msg = notify_mod.format_message(t["target"], t["target_name"], lines)
            if args.webhook:
                try:
                    notify_mod.post_webhook(args.webhook, msg)
                    print("Webhook notified.")
                except RuntimeError as exc:
                    print("Warning: webhook failed: %s" % exc)
            if args.ntfy:
                try:
                    notify_mod.post_ntfy(args.ntfy, msg,
                                         base_url=args.ntfy_base)
                    print("ntfy notified.")
                except (RuntimeError, ValueError) as exc:
                    print("Warning: ntfy failed: %s" % exc)
        elif status == "warming_up":
            print("%s/%s: warming up (%d runs) — no verdict yet."
                  % (t["target"], t["target_name"], t["run_count"]))
        else:
            print("%s/%s: OK (%d runs, no drift)."
                  % (t["target"], t["target_name"], t["run_count"]))
    return notify_mod.EXIT_DRIFT if any_drift else notify_mod.EXIT_OK


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="driftcanary",
        description="Behavioral-drift canary for AI systems. "
                    "Probes a provider or agent on a schedule and alerts "
                    "when its behavior drifts from its own history.",
    )
    p.add_argument("--version", action="version",
                   version="driftcanary " + __version__)
    p.add_argument("--dir", default=DEFAULT_DIR,
                   help="data directory (default: %(default)s)")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="initialize the data directory")
    pi.set_defaults(func=cmd_init)

    pp = sub.add_parser("probe", help="run the probe pack and store results")
    pp.add_argument("--target", required=True, choices=["provider", "agent"])
    pp.add_argument("--model", help="provider model id (provider mode)")
    pp.add_argument("--base-url", help="OpenAI-compatible base URL")
    pp.add_argument("--api-key-env",
                    help="env var holding the API key (never stored)")
    pp.add_argument("--cli", choices=["claude", "codex"],
                    help="agent CLI to probe (agent mode)")
    pp.add_argument("--timeout", type=float,
                    help="per-probe timeout seconds (agent mode)")
    pp.add_argument("--samples", type=int,
                    help="samples per probe (provider mode)")
    pp.add_argument("--probes",
                    help="comma-separated probe subset (provider mode)")
    pp.set_defaults(func=cmd_probe)

    pr = sub.add_parser("report", help="render the HTML trend report")
    pr.add_argument("--out", help="output path (default: <dir>/report.html)")
    pr.add_argument("--warmup", type=int, help="override warmup runs")
    pr.add_argument("--k", type=float, help="override CUSUM k")
    pr.add_argument("--h", type=float, help="override CUSUM h")
    pr.set_defaults(func=cmd_report)

    pa = sub.add_parser("alert", help="evaluate drift; exit 2 on drift")
    pa.add_argument("--webhook", help="generic webhook URL (POSTs JSON)")
    pa.add_argument("--ntfy", help="ntfy.sh topic for push alerts")
    pa.add_argument("--ntfy-base", default="https://ntfy.sh",
                    help="self-hosted ntfy base URL")
    pa.add_argument("--warmup", type=int, help="override warmup runs")
    pa.add_argument("--k", type=float, help="override CUSUM k")
    pa.add_argument("--h", type=float, help="override CUSUM h")
    pa.set_defaults(func=cmd_alert)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except _UserError as exc:
        print("driftcanary: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ndriftcanary: interrupted.", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 1
    except Exception as exc:  # last resort: never a raw traceback
        print("driftcanary: unexpected error: %s" % exc, file=sys.stderr)
        print("If this repeats, run with a fresh data dir to isolate it.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
