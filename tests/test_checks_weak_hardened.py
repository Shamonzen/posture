"""The contract every check signs: it fails on a weak recording and passes on a hardened one.

A check whose fact the parsers don't produce comes out as `error` here, so this also proves
every fact name used in checks/ exists.
"""

from pathlib import Path

import pytest

from posture.checks import load_checks
from posture.collectors import ad, azure, linux
from posture.collectors.transport import ReplayRunner
from posture.engine import evaluate
from posture.models import Status

ROOT = Path(__file__).parent.parent
RECORDINGS = Path(__file__).parent / "fixtures" / "recordings"
CHECKS = load_checks(ROOT / "checks")


def _collect(name):
    runner = ReplayRunner(RECORDINGS / name)
    if name.startswith("azure-"):
        return azure.collect(runner)
    return ad.collect(runner, runner) if name.startswith("dc-") else linux.collect(runner)


WEAK = {name: _collect(name) for name in ("ubuntu-weak", "rocky-weak", "dc-weak", "azure-weak")}
HARDENED = {
    name: _collect(name)
    for name in ("ubuntu-hardened", "rocky-hardened", "dc-hardened", "azure-hardened")
}
# Offenders the hardened lab keeps on purpose, reported honestly by the check: Vagrant logs on
# to the DC as `vagrant`, a builtin admin whose password must not expire under it.
LAB_KEEPS = {"AD-ACC-002": ["vagrant"]}


@pytest.mark.parametrize("name", [*WEAK, *HARDENED])
def test_recording_collects_cleanly(name):
    snapshot = (WEAK | HARDENED)[name]
    assert snapshot.errors == []


def _statuses(check, snapshots, platform):
    findings = {n: evaluate(check, s) for n, s in snapshots.items() if s.platform == platform}
    errors = {n: f.message for n, f in findings.items() if f.status == Status.ERROR}
    assert not errors, f"{check.id} could not be evaluated: {errors}"
    return findings


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.id)
def test_fails_on_weak_and_passes_on_hardened(check):
    weak = {f.status for f in _statuses(check, WEAK, check.platform).values()}
    hardened = {
        Status.PASS if f.evidence == LAB_KEEPS.get(check.id) else f.status
        for f in _statuses(check, HARDENED, check.platform).values()
    }
    assert Status.FAIL in weak and weak <= {Status.FAIL, Status.SKIP}, f"weak: {weak}"
    assert Status.PASS in hardened and hardened <= {Status.PASS, Status.SKIP}, (
        f"hardened: {hardened}"
    )


def test_check_ids_are_unique_and_cover_every_platform_recorded():
    assert len({c.id for c in CHECKS}) == len(CHECKS)
    assert {c.platform for c in CHECKS} == {"linux", "ad", "azure"}
    assert sum(c.platform == "ad" for c in CHECKS) >= 15
    assert sum(c.platform == "azure" for c in CHECKS) >= 12
