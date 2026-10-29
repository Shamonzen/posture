"""SARIF 2.1.0 for GitHub code scanning: one rule per check, one result per failed finding."""

import json
from typing import Any

from posture import __version__
from posture.models import Check, Report, Severity, Status

# GitHub maps security-severity to critical (>= 9), high (>= 7), medium (>= 4) and low.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}
LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning"}
MAX_EVIDENCE_TEXT = 1000


def _rule(check: Check) -> dict[str, Any]:
    tags = ["security", *check.attack, *(f"cis:{k}:{v}" for k, v in (check.cis or {}).items())]
    return {
        "id": check.id,
        "name": check.id.replace("-", ""),
        "shortDescription": {"text": check.title},
        "fullDescription": {"text": check.rationale},
        "help": {"text": check.remediation.text},
        "defaultConfiguration": {"level": LEVEL.get(check.severity, "note")},
        "properties": {"security-severity": SECURITY_SEVERITY[check.severity], "tags": tags},
    }


def render_sarif(report: Report, checks: list[Check]) -> str:
    by_id = {c.id: c for c in checks}
    results = []
    # shortcut: `error` findings are not sent (code scanning has no "unknown" state); the CI
    # gate still fails on them. Add them as notifications if the Security tab should show them.
    for f in report.findings:
        if f.status != Status.FAIL:
            continue
        uri, line = by_id[f.check_id]._source
        evidence = json.dumps(f.evidence, ensure_ascii=False)[:MAX_EVIDENCE_TEXT]
        results.append(
            {
                "ruleId": f.check_id,
                "level": LEVEL.get(f.severity, "note"),
                # Findings are about hosts: the target is named here, the location is the check.
                "message": {"text": f"{f.target}: {f.title}. Evidence: {evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": line},
                        }
                    }
                ],
                "partialFingerprints": {"postureFingerprint/v1": f.fingerprint},
                "properties": {"target": f.target},
            }
        )
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "posture",
                        "version": __version__,
                        "informationUri": "https://github.com/Shamonzen/posture",
                        "rules": [
                            _rule(c) for c in checks if c.platform == report.snapshot.platform
                        ],
                    }
                },
                "automationDetails": {"id": f"posture/{report.snapshot.target}/"},
                "results": results,
            }
        ],
    }
    return json.dumps(log, indent=2, ensure_ascii=False)
