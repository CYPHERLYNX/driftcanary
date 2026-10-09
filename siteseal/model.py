"""One finding from one check.

severity is one of: PASS, FAIL, WARN, UNKNOWN, INFO.
- PASS: the control is present and effective.
- FAIL: a concrete, evidenced problem.
- WARN: suspicious / needs a human look — never asserted as fact.
- UNKNOWN: the surface could not be assessed (offline, blocked, absent);
  UNKNOWN findings never move the grade.
- INFO: context, not a verdict.
"""

from dataclasses import dataclass


@dataclass
class Finding:
    check: str      # check family: headers, auth, secrets, storage, inject
    id: str         # stable id, e.g. "headers.csp-missing"
    severity: str
    title: str
    evidence: str = ""
    fix: str = ""

    def to_dict(self):
        return {
            "check": self.check,
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
            "fix": self.fix,
        }
