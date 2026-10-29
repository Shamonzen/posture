from pathlib import Path

from posture.models import Finding, Report, Severity
from posture.reports import FAILING


def load_report(path: Path) -> Report:
    return Report.model_validate_json(path.read_text(encoding="utf-8"))


def _failing(report: Report) -> dict[str, Finding]:
    return {f.fingerprint: f for f in report.findings if f.status in FAILING}


def diff(old: Report, new: Report) -> dict[str, list[Finding]]:
    """New, fixed and unchanged failing findings, matched by fingerprint."""
    before, after = _failing(old), _failing(new)
    return {
        "new": [f for fp, f in after.items() if fp not in before],
        "fixed": [f for fp, f in before.items() if fp not in after],
        "unchanged": [f for fp, f in after.items() if fp in before],
    }


def apply_baseline(findings: list[Finding], baseline: Report) -> list[Finding]:
    """Hide the failing findings someone already accepted; passes and new failures stay."""
    accepted = _failing(baseline)
    return [f for f in findings if not (f.status in FAILING and f.fingerprint in accepted)]


def gate(findings: list[Finding], fail_on: Severity) -> list[Finding]:
    """What fails the CI run: any fail or error at or above `fail_on` (errors fail closed)."""
    return [f for f in findings if f.status in FAILING and f.severity.rank >= fail_on.rank]
