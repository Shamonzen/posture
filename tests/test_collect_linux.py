import json
from pathlib import Path

from posture.cli import main
from posture.collectors import linux
from posture.collectors.transport import Command, ReplayRunner, Result

RECORDINGS = Path(__file__).parent / "fixtures" / "recordings"
UBUNTU_WEAK = RECORDINGS / "ubuntu-weak"


def test_replay_ubuntu_weak():
    snap = linux.collect(ReplayRunner(UBUNTU_WEAK))
    facts = snap.facts
    assert snap.errors == []
    assert (snap.target, snap.identity, facts["distro"]) == ("posture-ubuntu", "posture", "ubuntu")
    assert facts["ssh"]["permitrootlogin"] == "yes"
    users = {u["name"]: u for u in facts["users"]}
    assert users["guest"]["shadow_state"] == "empty"
    assert users["toor"]["uid"] == 0
    assert "shadow" not in facts
    assert facts["files"]["/etc/shadow"]["world_readable"]
    assert "/var/log/journal" not in facts["files"]
    assert facts["journald"] == {"storage": "volatile", "persistent": False}
    assert facts["audit"]["rules"] == []
    assert facts["ufw"]["active"] is False
    assert facts["units"]["ssh_service"]["active"] == "active"
    assert facts["updates"] == {
        "pending": 3,
        "pending_security": 2,
        "cache_mtime": 1789776000,
        "cache_age_days": 40.0,
        "automatic": False,
    }
    assert "firewalld" not in facts  # Rocky-only command, not run on Ubuntu


def test_record_then_replay_round_trip(tmp_path):
    first = linux.collect(ReplayRunner(UBUNTU_WEAK), record_dir=tmp_path)
    second = linux.collect(ReplayRunner(tmp_path))
    assert first.facts == second.facts
    assert json.loads((tmp_path / "_meta.json").read_text())["auditctl"]["exit_code"] == 1


class FakeRunner:
    def __init__(self, outputs: dict[str, Result]) -> None:
        self.outputs = outputs
        self.ran: list[str] = []

    def run(self, cmd: Command) -> Result:
        self.ran.append(cmd.name)
        return self.outputs.get(cmd.name, Result("", "boom", 2))


def test_hash_never_reaches_recording_or_facts(tmp_path):
    secret = "$6$salt$" + "B" * 86
    outputs = {
        "os_release": Result("ID=ubuntu\n"),
        "passwd": Result("alice:x:1000:1000::/home/alice:/bin/bash\n"),
        "shadow": Result(f"alice:{secret}:20300:0:99999:7:::\n"),
    }
    snap = linux.collect(FakeRunner(outputs), record_dir=tmp_path)
    assert snap.facts["users"][0]["shadow_state"] == "set"
    assert "$6$" not in snap.model_dump_json()
    assert all("$6$" not in f.read_text() for f in tmp_path.iterdir())


def test_failures_become_errors_and_distro_filters_commands():
    runner = FakeRunner({"os_release": Result('ID="rocky"\n')})
    snap = linux.collect(runner)
    assert "firewalld" in runner.ran and "ufw" not in runner.ran
    failed = {e.source for e in snap.errors}
    assert {"sshd", "passwd", "firewalld"} <= failed
    assert all("exit 2: boom" in e.message for e in snap.errors)


def test_parse_error_becomes_error():
    outputs = {"os_release": Result("ID=ubuntu\n"), "now": Result("not a number\n")}
    snap = linux.collect(FakeRunner(outputs))
    [now_error] = [e for e in snap.errors if e.source == "now"]
    assert now_error.message.startswith("parse error")


def test_cli_collect_replay(tmp_path, capsys):
    out = tmp_path / "snap.json"
    assert main(["collect", "linux", "--replay", str(UBUNTU_WEAK), "-o", str(out)]) == 0
    snap = json.loads(out.read_text())
    assert snap["platform"] == "linux"
    assert snap["facts"]["ssh"]["passwordauthentication"] == "yes"
