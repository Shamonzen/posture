"""Live audit of the Vagrant lab: `bash lab/lab.sh weak|hardened`, then `bash lab/lab.sh test`."""

import shlex
import subprocess  # nosec B404
from pathlib import Path

import pytest

from posture.checks import load_checks
from posture.cli import main
from posture.collectors import ad, linux
from posture.collectors.transport import ReplayRunner, SshRunner
from posture.engine import evaluate_all
from posture.models import Report, Status

pytestmark = pytest.mark.lab
ROOT = Path(__file__).parent.parent.parent
SSH_CONFIG = Path("lab/ssh-config")  # relative: its IdentityFile is relative to the repo root
# Hashes every /etc file the audit account can read, before and after the audit.
ETC_HASHES = "find /etc -xdev -type f -readable -print0 2>/dev/null | xargs -0 sha256sum"


def _ssh(vm: str, command: str) -> str:
    argv = ["ssh", "-F", str(SSH_CONFIG), "-o", "BatchMode=yes", "--", vm, command]
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=120).stdout  # noqa: S603, S607


@pytest.fixture(autouse=True)
def _from_repo_root(monkeypatch):
    monkeypatch.chdir(ROOT)


@pytest.mark.parametrize("vm", ["posture-ubuntu", "posture-rocky"])
def test_live_audit_is_read_only_and_matches_profile(vm):
    marker = _ssh(vm, shlex.join(["cat", "/etc/posture-lab"])).split()
    profile = next(line.split("=", 1)[1] for line in marker if line.startswith("profile="))

    before = _ssh(vm, ETC_HASHES)
    snapshot = linux.collect(SshRunner(vm, SSH_CONFIG))
    assert _ssh(vm, ETC_HASHES) == before, "the audit changed a file under /etc"

    assert snapshot.errors == []
    findings = evaluate_all(load_checks(ROOT / "checks"), snapshot)
    expected = {"weak": Status.FAIL, "hardened": Status.PASS}[profile]
    wrong = {f.check_id: f.status for f in findings if f.status not in (expected, Status.SKIP)}
    assert not wrong, f"{vm} ({profile}): {wrong}"


def _shape(snapshot):
    """What a profile decides, without the ages that move with every run."""
    facts = snapshot.facts
    users = sorted(
        (u["name"], u["enabled"], tuple(u["spns"]), u["no_preauth"]) for u in facts["users"]
    )
    computers = sorted(
        (c["name"], c["unconstrained_delegation"], c["laps"]) for c in facts["computers"]
    )
    return facts["domain"], users, computers, facts["privileged_groups"], facts["dc"]


def test_live_ldaps_and_winrm_audit_matches_a_recording():
    env = dict(
        line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines() if "=" in line
    )
    user, password = r"POSTURE\posture", env["POSTURE_AUDIT_PASSWORD"]
    runner = ad.LdapRunner("192.168.57.10", user, password, Path("lab/keys/posture-dc.pem"))
    live = ad.collect(runner, ad.WinrmRunner("192.168.57.10", user, password))
    runner.close()
    assert live.errors == [] and live.identity == r"POSTURE\posture"
    recordings = ROOT / "tests" / "fixtures" / "recordings"
    replays = [ReplayRunner(recordings / f"dc-{p}") for p in ("weak", "hardened")]
    recorded = [ad.collect(r, r) for r in replays]
    assert _shape(live) in [_shape(r) for r in recorded]


def test_live_inventory_audits_all_three_vms(tmp_path, monkeypatch):
    env = dict(
        line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines() if "=" in line
    )
    monkeypatch.setenv("POSTURE_LDAP_PASSWORD", env["POSTURE_AUDIT_PASSWORD"])
    out = tmp_path / "lab.json"
    assert main(["audit", "--inventory", "lab/inventory.yaml", "--json", str(out)]) == 0
    report = Report.model_validate_json(out.read_text(encoding="utf-8"))
    assert [s.target for s in report.snapshots][:2] == ["posture-ubuntu", "posture-rocky"]
    assert all(s.errors == [] for s in report.snapshots)
