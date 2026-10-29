"""The contract every check signs: it fails on a weak recording and passes on a hardened one.

A check whose fact the parsers don't produce comes out as `error` here, so this also proves
every fact name used in checks/ exists.
"""

from pathlib import Path

import pytest

from posture.checks import load_checks
from posture.collectors import linux
from posture.collectors.transport import ReplayRunner
from posture.engine import evaluate
from posture.models import Status

ROOT = Path(__file__).parent.parent
RECORDINGS = Path(__file__).parent / "fixtures" / "recordings"
CHECKS = load_checks(ROOT / "checks")
WEAK = {
    name: linux.collect(ReplayRunner(RECORDINGS / name)) for name in ("ubuntu-weak", "rocky-weak")
}
HARDENED = {
    name: linux.collect(ReplayRunner(RECORDINGS / name))
    for name in ("ubuntu-hardened", "rocky-hardened")
}


@pytest.mark.parametrize("name", [*WEAK, *HARDENED])
def test_recording_collects_cleanly(name):
    snapshot = (WEAK | HARDENED)[name]
    assert snapshot.errors == []


def _statuses(check, snapshots):
    findings = {name: evaluate(check, snap) for name, snap in snapshots.items()}
    errors = {n: f.message for n, f in findings.items() if f.status == Status.ERROR}
    assert not errors, f"{check.id} could not be evaluated: {errors}"
    return {f.status for f in findings.values()}


@pytest.mark.parametrize("check", [c for c in CHECKS if c.platform == "linux"], ids=lambda c: c.id)
def test_fails_on_weak_and_passes_on_hardened(check):
    weak = _statuses(check, WEAK)
    hardened = _statuses(check, HARDENED)
    assert Status.FAIL in weak and weak <= {Status.FAIL, Status.SKIP}, f"weak: {weak}"
    assert Status.PASS in hardened and hardened <= {Status.PASS, Status.SKIP}, (
        f"hardened: {hardened}"
    )


def test_check_ids_are_unique_and_cover_linux():
    assert len({c.id for c in CHECKS}) == len(CHECKS) >= 20
