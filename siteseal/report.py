"""Reporters: terminal table, JSON, dark HTML.

The HTML report uses the OpenDesign `trading-terminal` dark tokens
(--bg #070b12, --surface #101826, --success #22c55e, --warn #f59e0b,
--danger #ef4444, mono data type) with the anti-ai-slop rules applied:
flat surfaces, no indigo accent, no emoji icons, no left-border card
accents, no invented metrics.
"""

import html as htmlmod
import json
import sys

from . import score as scoring

_SEV_COLOR = {
    "PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m",
    "UNKNOWN": "\033[90m", "INFO": "\033[36m",
}
_RESET = "\033[0m"
_GRADE_COLOR = {"A": "\033[32m", "B": "\033[32m", "C": "\033[33m",
                "D": "\033[31m", "F": "\033[31m"}

_SEV_CSS = {"PASS": "pass", "FAIL": "fail", "WARN": "warn",
            "UNKNOWN": "unk", "INFO": "info"}


def _colored(text, code):
    if sys.stdout.isatty():
        return code + text + _RESET
    return text


def _sanitize(text):
    """Strip control characters so hostile server output can't inject
    terminal escape sequences into the report."""
    return "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def render_terminal(url, findings, grade_letter, grade_score, counts, error=None):
    lines = []
    lines.append("siteseal audit: %s" % url)
    lines.append("")
    if error:
        lines.append(_colored("ERROR: %s" % _sanitize(error), _SEV_COLOR["FAIL"]))
        return "\n".join(lines)
    if grade_letter is None:
        # Nothing could be assessed (all UNKNOWN): never print a letter grade.
        lines.append(_colored("UNABLE TO ASSESS — no checkable surface", _SEV_COLOR["UNKNOWN"]))
        lines.append("Findings: %d unknown, %d info (nothing passed or failed)" % (
            counts["UNKNOWN"], counts["INFO"]))
        lines.append("")
    else:
        g = _colored("GRADE %s (%.1f/100)" % (grade_letter, grade_score),
                     _GRADE_COLOR[grade_letter])
        lines.append("Site grade: %s" % g)
        lines.append("Findings: %d fail, %d warn, %d pass, %d unknown, %d info" % (
            counts["FAIL"], counts["WARN"], counts["PASS"],
            counts["UNKNOWN"], counts["INFO"]))
        lines.append("")
    for f in findings:
        chip = _colored("[%s]" % f.severity, _SEV_COLOR[f.severity])
        lines.append("%s %-8s %s" % (chip, f.check, _sanitize(f.title)))
        if f.evidence:
            for eline in _sanitize(f.evidence).split("\n")[:4]:
                lines.append("         %s" % eline[:120])
        if f.fix:
            lines.append("         fix: %s" % _sanitize(f.fix)[:140])
    return "\n".join(lines)


def render_json(url, findings, grade_letter, grade_score, counts, code, error=None):
    doc = {
        "tool": "siteseal",
        "url": url,
        "grade": grade_letter,
        "score": grade_score,
        "exit_code": code,
        "counts": counts,
        "error": error,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>siteseal report — {url}</title>
<style>
:root {{
  --bg: #070b12; --surface: #101826; --surface-2: #162238;
  --fg: #f8fafc; --fg-2: #cbd5e1; --muted: #8492a6;
  --border: #263246; --accent: #38bdf8;
  --success: #22c55e; --warn: #f59e0b; --danger: #ef4444; --info: #38bdf8;
  --font-mono: "Roboto Mono", "SF Mono", ui-monospace, Menlo, Consolas, monospace;
  --font-body: Inter, system-ui, sans-serif;
}}
* {{ box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--fg); font-family: var(--font-body);
       margin: 0; padding: 32px 24px; }}
.wrap {{ max-width: 960px; margin: 0 auto; }}
.hdr {{ display: flex; align-items: baseline; gap: 16px; margin-bottom: 8px; }}
.brand {{ font-family: var(--font-mono); font-size: 13px; color: var(--muted);
          letter-spacing: 0.08em; text-transform: uppercase; }}
.target {{ font-family: var(--font-mono); font-size: 14px; color: var(--fg-2);
           word-break: break-all; }}
.gradebar {{ display: flex; align-items: center; gap: 20px; background: var(--surface);
             border: 1px solid var(--border); border-radius: 8px;
             padding: 20px 24px; margin: 16px 0 24px; }}
.grade {{ font-family: var(--font-mono); font-size: 56px; font-weight: 700;
          line-height: 1; }}
.grade.A, .grade.B {{ color: var(--success); }}
.grade.C {{ color: var(--warn); }}
.grade.D, .grade.F {{ color: var(--danger); }}
.gmeta {{ font-family: var(--font-mono); font-size: 12px; color: var(--muted); }}
.gmeta b {{ color: var(--fg); font-weight: 600; }}
.finding {{ background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; padding: 14px 16px; margin-bottom: 10px; }}
.fhead {{ display: flex; gap: 10px; align-items: baseline; }}
.chip {{ font-family: var(--font-mono); font-size: 11px; font-weight: 700;
         padding: 2px 8px; border-radius: 9999px; border: 1px solid; white-space: nowrap; }}
.chip.pass {{ color: var(--success); border-color: var(--success); }}
.chip.fail {{ color: var(--danger); border-color: var(--danger); }}
.chip.warn {{ color: var(--warn); border-color: var(--warn); }}
.chip.unk {{ color: var(--muted); border-color: var(--muted); }}
.chip.info {{ color: var(--info); border-color: var(--info); }}
.fcheck {{ font-family: var(--font-mono); font-size: 11px; color: var(--muted); }}
.ftitle {{ font-size: 15px; font-weight: 600; margin: 6px 0 4px; }}
.fev {{ font-family: var(--font-mono); font-size: 12px; color: var(--fg-2);
        background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
        padding: 10px 12px; white-space: pre-wrap; word-break: break-word; }}
.ffix {{ font-size: 13px; color: var(--fg-2); margin-top: 8px; }}
.ffix b {{ color: var(--accent); font-weight: 600; }}
.foot {{ margin-top: 28px; font-family: var(--font-mono); font-size: 11px;
         color: var(--muted); }}
</style></head>
<body><div class="wrap">
<div class="hdr"><span class="brand">siteseal</span>
<span class="target">{url}</span></div>
<div class="gradebar"><div class="grade {gclass}">{grade}</div>
<div class="gmeta"><b>{score}/100</b> &nbsp;·&nbsp; {fails} fail · {warns} warn ·
{passes} pass · {unks} unknown · {infos} info<br>audited {when}</div></div>
{sections}
<div class="foot">Generated by siteseal {ver} — deterministic, dependency-free
security-posture audit. UNKNOWN means the surface could not be assessed, not
that it is safe. Secrets shown redacted; none were validated against providers.</div>
</div></body></html>"""


def render_html(url, findings, grade_letter, grade_score, counts, when, version):
    import datetime
    grade_txt = grade_letter if grade_letter else "\u2014"
    gclass = grade_letter if grade_letter else ""
    sections = []
    for f in findings:
        ev = ("<div class=\"fev\">%s</div>" % htmlmod.escape(f.evidence)) if f.evidence else ""
        fix = ("<div class=\"ffix\"><b>Fix:</b> %s</div>" % htmlmod.escape(f.fix)) if f.fix else ""
        sections.append(
            "<div class=\"finding\"><div class=\"fhead\">"
            "<span class=\"chip %s\">%s</span>"
            "<span class=\"fcheck\">%s · %s</span></div>"
            "<div class=\"ftitle\">%s</div>%s%s</div>" % (
                _SEV_CSS[f.severity], f.severity,
                htmlmod.escape(f.check), htmlmod.escape(f.id),
                htmlmod.escape(f.title), ev, fix))
    return _HTML_TEMPLATE.format(
        url=htmlmod.escape(url), grade=grade_txt, gclass=gclass,
        score="%.1f" % grade_score, fails=counts["FAIL"], warns=counts["WARN"],
        passes=counts["PASS"], unks=counts["UNKNOWN"], infos=counts["INFO"],
        when=when or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        ver=htmlmod.escape(version),
        sections="\n".join(sections))
