import json
from pathlib import Path

import pytest

from posture import __version__
from posture.cli import main

ROOT = Path(__file__).parent.parent
RECORDINGS = Path(__file__).parent / "fixtures" / "recordings"
CHECKS = ["--checks", str(ROOT / "checks")]


def test_help_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "MITRE ATT&CK" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def _audit(name, *extra):
    return main(["audit", "linux", "--replay", str(RECORDINGS / name), *CHECKS, *extra])


@pytest.mark.parametrize(
    ("name", "code"),
    [("ubuntu-weak", 1), ("rocky-weak", 1), ("ubuntu-hardened", 0), ("rocky-hardened", 0)],
)
def test_fail_on_high_gates_weak_and_passes_hardened(name, code):
    assert _audit(name, "--fail-on", "high") == code


def test_without_fail_on_findings_do_not_fail_the_run():
    assert _audit("ubuntu-weak") == 0


def test_collect_evaluate_and_outputs(tmp_path, capsys):
    snapshot = tmp_path / "snap.json"
    assert (
        main(["collect", "linux", "--replay", str(RECORDINGS / "ubuntu-weak"), "-o", str(snapshot)])
        == 0
    )
    out = {ext: tmp_path / f"r.{ext}" for ext in ("json", "html", "sarif")}
    args = ["evaluate", str(snapshot), *CHECKS] + [
        a for e, p in out.items() for a in (f"--{e}", str(p))
    ]
    assert main(args) == 0
    assert "LNX-SSH-001" in capsys.readouterr().out
    assert all(p.stat().st_size for p in out.values())
    assert b"\r\n" not in out["json"].read_bytes()


def test_baseline_accepting_everything_passes_the_gate(tmp_path):
    accepted = tmp_path / "accepted.json"
    assert _audit("ubuntu-weak", "--json", str(accepted)) == 0
    assert _audit("ubuntu-weak", "--baseline", str(accepted), "--fail-on", "low") == 0
    hardened = tmp_path / "hardened.json"
    assert _audit("ubuntu-hardened", "--json", str(hardened)) == 0
    assert _audit("ubuntu-weak", "--baseline", str(hardened), "--fail-on", "low") == 1


def test_diff_weak_to_hardened(tmp_path, capsys):
    weak, hardened = tmp_path / "weak.json", tmp_path / "hardened.json"
    _audit("ubuntu-weak", "--json", str(weak))
    _audit("ubuntu-hardened", "--json", str(hardened))
    capsys.readouterr()
    assert main(["diff", str(weak), str(hardened)]) == 0
    out = capsys.readouterr().out
    fixed = len(json.loads(weak.read_text())["findings"]) - 1  # all but the one skip
    assert f"new (0)\nfixed ({fixed})\n" in out and "unchanged (0)" in out


def test_usage_errors_exit_2(tmp_path):
    bad = tmp_path / "checks"
    bad.mkdir()
    (bad / "bad.yaml").write_text("- id: nope\n")
    assert _audit("ubuntu-weak") == 0
    assert (
        main(["audit", "linux", "--replay", str(RECORDINGS / "ubuntu-weak"), "--checks", str(bad)])
        == 2
    )
    assert main(["evaluate", str(tmp_path / "missing.json"), *CHECKS]) == 2
    with pytest.raises(SystemExit) as exc:
        main(["audit", "linux", "--replay", "x", "--fail-on", "urgent"])
    assert exc.value.code == 2


def test_nothing_collected_exits_2(tmp_path):
    (tmp_path / "rec").mkdir()  # an empty recording: every command is missing
    assert main(["audit", "linux", "--replay", str(tmp_path / "rec"), *CHECKS]) == 2
