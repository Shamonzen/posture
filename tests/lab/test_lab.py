"""Live audit of the Vagrant lab: `bash lab/lab.sh weak|hardened`, then `bash lab/lab.sh test`."""

import shlex
import subprocess  # nosec B404
from pathlib import Path

import pytest

from posture.checks import load_checks
from posture.collectors import linux
from posture.collectors.transport import SshRunner
from posture.engine import evaluate_all
from posture.models import Status

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
