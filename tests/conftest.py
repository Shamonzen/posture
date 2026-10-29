from datetime import UTC, datetime
from typing import Any

from posture.models import Check, Snapshot


def make_check(check: Any, **overrides: Any) -> Check:
    data = {
        "id": "LNX-TEST-001",
        "title": "test check",
        "platform": "linux",
        "cis": None,
        "severity": "high",
        "attack": ["T1110.001"],
        "rationale": "because",
        "check": check,
        "remediation": {"text": "fix it"},
        "references": ["https://attack.mitre.org/techniques/T1110/001/"],
    }
    return Check.model_validate(data | overrides)


def make_snapshot(facts: dict[str, Any], platform: str = "linux") -> Snapshot:
    return Snapshot(
        tool_version="test",
        platform=platform,
        target="host1",
        collected_at=datetime(2026, 10, 29, tzinfo=UTC),
        facts=facts,
    )
