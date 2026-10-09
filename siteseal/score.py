"""Site grading.

Weights per check family sum to 100. FAIL costs the full family weight, WARN
costs half. UNKNOWN and INFO never move the score — an unassessable surface
is reported, not punished.

Grades: A >= 90, B >= 75, C >= 60, D >= 40, F < 40.

Exit codes (CI-gatable):
  0 — grade A or B (no actionable findings)
  1 — grade C, D or F (actionable findings)
  2 — audit error, or nothing could be assessed (all UNKNOWN)
"""

WEIGHTS = {
    "headers": 30,
    "secrets": 30,
    "storage": 20,
    "inject": 15,
    "auth": 5,
}


def grade(findings):
    score = 100.0
    for f in findings:
        w = WEIGHTS.get(f.check, 0)
        if f.severity == "FAIL":
            score -= w
        elif f.severity == "WARN":
            score -= w / 2
    score = max(0.0, min(100.0, score))
    if score >= 90:
        letter = "A"
    elif score >= 75:
        letter = "B"
    elif score >= 60:
        letter = "C"
    elif score >= 40:
        letter = "D"
    else:
        letter = "F"
    return letter, round(score, 1)


def exit_code(findings, error=None):
    if error:
        return 2
    assessed = [f for f in findings if f.severity in ("PASS", "FAIL", "WARN")]
    if not assessed:
        return 2
    letter, _ = grade(findings)
    return 0 if letter in ("A", "B") else 1


def summarize(findings):
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "UNKNOWN": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
