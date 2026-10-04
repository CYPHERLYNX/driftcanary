# driftcanary

**The behavioral-drift canary for AI systems.** LLM providers silently change model behavior — and your own agent configs silently decay. driftcanary probes your model or coding-agent CLI on a schedule, baselines the results against *your own history*, and alerts when behavior drifts. Zero dependencies, one cron line, local SQLite.

## The pitch

**Problem:** Providers swap models, cap reasoning, or tune verbosity without telling you. Your agent harness decays after a config change ("it used to catch SQLi…"). Every existing scanner is a one-shot test — drift *between* runs is invisible.

**Solution:** An offline-first CLI that runs a fixed battery of behavioral probes on a schedule, stores results locally, applies CUSUM change-point detection against your own baseline, and alerts (exit code + webhook + dark HTML report) when something shifts.

**Why it's new:** Drift-monitoring platforms exist (proxies, Postgres, dashboards — see prior art below). Nobody ships it as a **zero-dependency artifact**: no pip install, no database server, no hosted service. And nobody probes *your coding agent's own harness* for prompt/config decay with a deterministic probe pack.

## Quickstart

```bash
# 1. Get it (stdlib only — Python 3.10+, nothing to install)
git clone https://github.com/CYPHERLYNX/driftcanary.git
cd driftcanary

# 2. Initialize
python -m driftcanary.cli init
# or, after `pip install -e .`: driftcanary init

# 3. Probe a provider (key via env only — never stored)
export OPENAI_API_KEY=sk-...
driftcanary probe --target provider --model gpt-4o-mini

# 4. Or probe your coding agent's harness for prompt decay
driftcanary probe --target agent --cli claude

# 5. Schedule it (every 6 hours) and alert on drift
# 0 */6 * * * driftcanary probe --target provider --model gpt-4o-mini && driftcanary alert
#    exit 2 = drift detected, 0 = clean, 1 = evaluation error

# 6. See the trend
driftcanary report   # writes ~/.driftcanary/report.html
```

## How it works

1. **Probe pack** — a fixed battery of deterministic behavioral probes:
   - *Provider mode* (any OpenAI-compatible endpoint): latency signature, refusal consistency, JSON format adherence, tool-call fidelity, verbosity stats, instruction-following. Each probe runs 3x; metrics aggregate by median/mode.
   - *Agent mode*: poison-pill code-review probes (SQLi, prompt-injection-in-docs, secret-in-log) executed through your real `claude -p` / `codex exec` CLI; graded HELD/BYPASSED. Catches "my agent got worse after Tuesday's config change."
2. **Baseline** — results land in local SQLite. Your own history *is* the baseline; no trusted-reference API key needed.
3. **Detection** — two-sided CUSUM over each probe metric. No verdicts before 20 baseline runs ("warming up" is a first-class status, not drift).
4. **Alert** — `driftcanary alert` exits 2 on drift and can POST to a webhook or ntfy.sh topic. `driftcanary report` renders the dark HTML trend report with drift markers.

## Honest scope

What this is and isn't, stated plainly:

- **It watches behavior, not quality.** A model can get worse in ways no fixed probe pack captures. driftcanary catches *changes* in the signatures it measures — latency, verbosity, refusal rate, format adherence, tool-call fidelity, agent catch-rate.
- **Warming up is not drift.** Nothing alerts before 20 baseline runs (configurable). A fresh install says WARMING UP, honestly.
- **Probe errors are not drift.** If the endpoint is unreachable, that's a probe error with a clear message — never a false drift alarm.
- **Statistics are measured, not claimed.** On synthetic step-change injection (4-sigma shift in a metric), CUSUM fires within a handful of post-change runs; gradual ramps take longer (documented tradeoff — see `tests/test_detect.py`). It does not "catch all drift."
- **Agent grading is heuristic.** Keyword-based HELD/BYPASSED grading is approximate; the pack measures *change over time*, not absolute competence.

## Probe cost

Default pack ≈ 3,400 tokens per provider run (6 probes x 3 samples, upper bound). At typical API pricing that's fractions of a cent per run — safe to cron every few hours. Agent-mode cost is whatever your CLI charges per prompt (3 short prompts per run).

## Configuration

`~/.driftcanary/config.json` (created by `init`):

```json
{
  "warmup_runs": 20,
  "cusum_k": 0.5,
  "cusum_h": 4.0,
  "samples": 3,
  "provider_base_url": "https://api.openai.com/v1",
  "provider_api_key_env": "OPENAI_API_KEY",
  "agent_cli": "claude",
  "agent_timeout_s": 180.0
}
```

CLI flags override config values. API keys are read from the environment only — never written to disk.

## Prior art

The drift-monitoring space is contested; here's where this fits:

| Project | What it is | How driftcanary differs |
|---|---|---|
| `iblamewisp/driftwatch` | Self-hosted LLM proxy detecting response-quality drift (Postgres + Redis + Celery) | Zero infrastructure: stdlib-only CLI, one cron line, SQLite |
| `sahelmain/drift_watch` | Continuous LLM eval platform (FastAPI + Postgres + React) | A CLI, not a platform; no servers to run |
| `GenesisClawbot/llm-drift` | Hosted service: scheduled prompts, drift alerts, web UI | Local-first, no hosted dependency, honest CUSUM stats |
| `arjinexe/llm-canary` | Scheduled behavioral test battery vs own baseline | Adds change-point statistics, warmup discipline, agent prompt-decay mode |
| `wartzar-bee/promptdrift` | Prompt-regression alarm for CI | Ours monitors production behavior longitudinally, not PR diffs |
| `graphsentinel/driftwatch` | K8s operator governing agent *tool-call* drift | We test the agent's *behavior* (does it still catch the SQLi?), not its tool calls |

Closest-existing-thing: DriftWatch-style platforms monitor LLM drift with proxies, Postgres, and dashboards; driftcanary is the version that runs as one cron line with zero dependencies — plus a probe pack that watches your coding agent itself for prompt decay.

## Security

- Agent CLIs execute via argv lists only — **never `shell=True`**. The binary is resolved with `shutil.which()` from a fixed allowlist (`claude`, `codex`); config can select *which* CLI, never *what* binary. Arbitrary paths are rejected.
- Every agent invocation has a hard timeout; timeouts are errors, not hangs.
- API keys come from the environment only. Probe fixtures use obviously-fake secrets (`sk-test-...`).
- Webhook URLs are only read from CLI flags, never stored.

## License

MIT — see [LICENSE](LICENSE).
