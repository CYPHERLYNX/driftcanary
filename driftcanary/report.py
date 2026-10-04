"""Dark, self-contained HTML trend report.

Single file, inline CSS, hand-rolled inline SVG charts — no CDN, no JS
libraries, no network calls when viewed. The report is generated from
store.as_dict() plus CUSUM verdicts.

Design tokens (dark SOC-palette style):
  bg #0B0B0D, surface #141417, border #26262B,
  text #F5F5F7, secondary #A1A1AA,
  accent #0A84FF, ok #30D158, warming #FF9F0A, drift #FF453A, error #8E8E93
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from .detect import DriftVerdict

# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------

BG = "#0B0B0D"
SURFACE = "#141417"
SURFACE2 = "#1B1B1F"
BORDER = "#26262B"
TEXT = "#F5F5F7"
SECONDARY = "#A1A1AA"
ACCENT = "#0A84FF"
OK = "#30D158"
WARMING = "#FF9F0A"
DRIFT = "#FF453A"
ERROR = "#8E8E93"

STATUS_COLOR = {"ok": OK, "warming_up": WARMING, "drift": DRIFT, "error": ERROR}
STATUS_LABEL = {"ok": "OK", "warming_up": "WARMING UP",
                "drift": "DRIFT DETECTED", "error": "ERROR"}

CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { background: %(BG)s; color: %(TEXT)s; margin: 0;
       font-family: -apple-system, "Segoe UI", Inter, Roboto, sans-serif; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }
header.top { display: flex; align-items: baseline; justify-content: space-between;
             border-bottom: 1px solid %(BORDER)s; padding-bottom: 16px;
             margin-bottom: 24px; }
h1 { font-size: 22px; margin: 0; letter-spacing: -0.02em; }
h1 .mark { color: %(ACCENT)s; }
.sub { color: %(SECONDARY)s; font-size: 13px; }
h2 { font-size: 16px; margin: 32px 0 12px; letter-spacing: -0.01em; }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
         gap: 12px; }
.card { background: %(SURFACE)s; border: 1px solid %(BORDER)s; border-radius: 12px;
        padding: 16px; }
.card .tname { font-size: 15px; font-weight: 600; }
.card .tmeta { color: %(SECONDARY)s; font-size: 12px; margin-top: 4px; }
.badge { display: inline-block; font-size: 11px; font-weight: 700;
         letter-spacing: 0.06em; padding: 4px 10px; border-radius: 999px;
         margin-top: 10px; }
.panel { background: %(SURFACE)s; border: 1px solid %(BORDER)s; border-radius: 12px;
         padding: 20px; margin-bottom: 16px; }
.panel h3 { margin: 0 0 4px; font-size: 15px; }
.panel .pmeta { color: %(SECONDARY)s; font-size: 12px; margin-bottom: 12px; }
svg.chart { width: 100%%; height: auto; display: block;
            background: %(SURFACE2)s; border-radius: 8px; }
table.ev { width: 100%%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
table.ev th { text-align: left; color: %(SECONDARY)s; font-weight: 600;
              padding: 8px 10px; border-bottom: 1px solid %(BORDER)s; }
table.ev td { padding: 8px 10px; border-bottom: 1px solid %(BORDER)s; }
.alertbox { border: 1px solid %(DRIFT)s; background: rgba(255,69,58,0.08);
            border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; }
.alertbox h3 { color: %(DRIFT)s; margin: 0 0 8px; font-size: 15px; }
.empty { border: 1px dashed %(BORDER)s; border-radius: 12px; padding: 32px;
         text-align: center; color: %(SECONDARY)s; }
code { background: %(SURFACE2)s; padding: 2px 6px; border-radius: 6px;
       font-size: 12px; }
footer { color: %(SECONDARY)s; font-size: 12px; margin-top: 40px;
         border-top: 1px solid %(BORDER)s; padding-top: 16px; }
""" % {"BG": BG, "TEXT": TEXT, "BORDER": BORDER, "ACCENT": ACCENT,
       "SECONDARY": SECONDARY, "SURFACE": SURFACE, "SURFACE2": SURFACE2,
       "DRIFT": DRIFT}


# ---------------------------------------------------------------------------
# SVG charts (no JS)
# ---------------------------------------------------------------------------

def _svg_series(values: Sequence[float], width: int = 640, height: int = 140,
                change_index: Optional[int] = None,
                alarm_index: Optional[int] = None,
                baseline_mean: Optional[float] = None) -> str:
    """Line chart of a metric series with optional drift/change markers."""
    if not values:
        return ""
    vals = list(values)
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1.0
    lo -= span * 0.15
    hi += span * 0.15
    span = hi - lo
    n = len(vals)
    pad_l, pad_r, pad_t, pad_b = 8, 8, 10, 18
    iw, ih = width - pad_l - pad_r, height - pad_t - pad_b

    def x(i: int) -> float:
        return pad_l + (iw * i / max(1, n - 1)) if n > 1 else pad_l + iw / 2

    def y(v: float) -> float:
        return pad_t + ih * (1 - (v - lo) / span)

    pts = " ".join("%.1f,%.1f" % (x(i), y(v)) for i, v in enumerate(vals))
    parts = [
        '<svg class="chart" viewBox="0 0 %d %d" role="img">' % (width, height),
    ]
    if baseline_mean is not None:
        parts.append(
            '<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" '
            'stroke-dasharray="5,4" stroke-width="1" opacity="0.7"/>'
            % (pad_l, y(baseline_mean), width - pad_r, y(baseline_mean), SECONDARY)
        )
    parts.append(
        '<polyline points="%s" fill="none" stroke="%s" stroke-width="2"/>' % (pts, ACCENT)
    )
    for i, v in enumerate(vals):
        parts.append('<circle cx="%.1f" cy="%.1f" r="2.6" fill="%s"/>'
                     % (x(i), y(v), ACCENT))
    if change_index is not None and 0 <= change_index < n:
        parts.append(
            '<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="%s" '
            'stroke-width="2"/>'
            % (x(change_index), pad_t, x(change_index), height - pad_b, DRIFT)
        )
        parts.append(
            '<text x="%.1f" y="%d" fill="%s" font-size="10">change</text>'
            % (x(change_index) + 4, pad_t + 12, DRIFT)
        )
    # axis labels: min / max
    parts.append('<text x="%d" y="%d" fill="%s" font-size="10">%.3g</text>'
                 % (pad_l, height - 5, SECONDARY, lo))
    parts.append('<text x="%d" y="%d" fill="%s" font-size="10" text-anchor="end">%.3g</text>'
                 % (width - pad_r, height - 5, SECONDARY, hi))
    parts.append("</svg>")
    return "".join(parts)


def _sparkline(values: Sequence[float], width: int = 120,
               height: int = 28) -> str:
    if not values:
        return ""
    vals = list(values)
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1.0
    n = len(vals)

    def x(i: int) -> float:
        return (width * i / max(1, n - 1)) if n > 1 else width / 2

    def y(v: float) -> float:
        return 2 + (height - 4) * (1 - (v - lo) / span)

    pts = " ".join("%.1f,%.1f" % (x(i), y(v)) for i, v in enumerate(vals))
    return ('<svg width="%d" height="%d" viewBox="0 0 %d %d">'
            '<polyline points="%s" fill="none" stroke="%s" stroke-width="1.5"/>'
            "</svg>" % (width, height, width, height, pts, SECONDARY))


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def _esc(s: object) -> str:
    return html.escape(str(s), quote=True)


def build_report(data: Dict, verdicts: Dict[str, List[DriftVerdict]],
                 statuses: Dict[str, str],
                 generated_at: Optional[str] = None) -> str:
    """Assemble the full HTML report.

    data: store.as_dict() output. verdicts: {(target,target_name): [verdicts]}.
    statuses: {(target,target_name): 'ok'|'warming_up'|'drift'|'error'}.
    """
    now = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out: List[str] = []
    out.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
               "<meta name='viewport' content='width=device-width,initial-scale=1'>"
               "<title>driftcanary report</title><style>%s</style></head><body>"
               % CSS)
    out.append("<div class='wrap'>")
    out.append("<header class='top'><h1><span class='mark'>drift</span>canary"
               " report</h1>"
               "<div class='sub'>generated %s</div></header>" % _esc(now))

    targets = data.get("targets", [])
    if not targets:
        out.append("<div class='empty'>No probe history yet.<br>"
                   "Run <code>driftcanary probe</code> a few times, then "
                   "regenerate this report.</div>")
    else:
        # -- overview cards ------------------------------------------------
        out.append("<h2>Targets</h2><div class='cards'>")
        for t in targets:
            key = (t["target"], t["target_name"])
            status = statuses.get(key, "warming_up")
            color = STATUS_COLOR[status]
            label = STATUS_LABEL[status]
            # sparkline of the first series, if any
            spark = ""
            series = t.get("series", {})
            if series:
                first_key = sorted(series.keys())[0]
                spark = _sparkline([v for _, v in series[first_key][-30:]])
            out.append(
                "<div class='card'>"
                "<div class='tname'>%s</div>"
                "<div class='tmeta'>%s &middot; %d runs &middot; last %s</div>"
                "<div>%s</div>"
                "<span class='badge' style='color:%s;border:1px solid %s'>%s</span>"
                "</div>"
                % (_esc(t["target_name"]), _esc(t["target"]),
                   t["run_count"], _esc(t["last_run_at"] or "never"),
                   spark, color, color, label)
            )
        out.append("</div>")

        # -- per-target detail ---------------------------------------------
        for t in targets:
            key = (t["target"], t["target_name"])
            status = statuses.get(key, "warming_up")
            tverdicts = {v.probe + "." + v.metric: v
                         for v in verdicts.get(key, [])}
            out.append("<h2>%s <span class='sub'>%s</span></h2>"
                       % (_esc(t["target_name"]), _esc(t["target"])))
            if status == "warming_up":
                have = t["run_count"]
                need = max((v.warmup_runs for v in tverdicts.values()),
                           default=20)
                out.append(
                    "<div class='empty'>Warming up — %d of %d baseline runs "
                    "collected. No drift verdicts until the baseline is "
                    "established; keep the cron running.</div>" % (have, need)
                )
            drift_here = [v for v in tverdicts.values() if v.status == "drift"]
            if drift_here:
                out.append("<div class='alertbox'><h3>Drift detected</h3>"
                           "<table class='ev'><tr><th>Probe.metric</th>"
                           "<th>Direction</th><th>Change at run</th>"
                           "<th>Shift</th></tr>")
                for v in drift_here:
                    out.append(
                        "<tr><td><code>%s.%s</code></td><td>%s</td>"
                        "<td>#%d</td><td>%+.2f&sigma;</td></tr>"
                        % (_esc(v.probe), _esc(v.metric), _esc(v.direction or "?"),
                           (v.change_index or 0) + 1,
                           v.shift_sigma or 0.0)
                    )
                out.append("</table></div>")

            series = t.get("series", {})
            for skey in sorted(series):
                vals = [v for _, v in series[skey]]
                v = tverdicts.get(skey)
                probe, _, metric = skey.partition(".")
                meta = "%d observations" % len(vals)
                if v and v.baseline_mean is not None:
                    meta += (" &middot; baseline %.3g &plusmn; %.3g"
                             % (v.baseline_mean, v.baseline_std or 0.0))
                out.append(
                    "<div class='panel'><h3><code>%s</code> %s</h3>"
                    "<div class='pmeta'>%s</div>%s</div>"
                    % (_esc(probe), _esc(metric), meta,
                       _svg_series(
                           vals,
                           change_index=(v.change_index
                                         if v and v.status == "drift" else None),
                           alarm_index=(v.alarm_index
                                        if v and v.status == "drift" else None),
                           baseline_mean=(v.baseline_mean if v else None)))
                )

    out.append("<footer>driftcanary %s &middot; stdlib-only, local SQLite, "
               "CUSUM change-point detection. Warming up is not drift."
               "</footer>" % _esc(_version()))
    out.append("</div></body></html>")
    return "".join(out)


def _version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:
        return "0.1.0"
