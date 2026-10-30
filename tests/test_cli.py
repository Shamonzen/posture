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


INVENTORIES = Path(__file__).parent / "fixtures" / "inventories"


@pytest.mark.parametrize(("profile", "code"), [("weak", 1), ("hardened", 0)])
def test_inventory_audits_every_lab_target_into_one_report(tmp_path, profile, code):
    out = tmp_path / "report.json"
    inventory = str(INVENTORIES / f"lab-{profile}.yaml")
    assert (
        main(["audit", "--inventory", inventory, *CHECKS, "--fail-on", "high", "--json", str(out)])
        == code
    )
    report = json.loads(out.read_text())
    assert [s["platform"] for s in report["snapshots"]] == ["linux", "linux", "ad", "azure"]
    assert {f["target"] for f in report["findings"]} == {s["target"] for s in report["snapshots"]}


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ("targets: []", "no targets"),
        ("targets:\n  - platform: linux", "exactly one of"),
        ("targets:\n  - {platform: linux, local: true, ssh: h}", "exactly one of"),
        ("targets:\n  - {platform: linux, local: true, shell: id}", "Extra inputs"),
        ("targets: [{platform: linux, replay: R}, {platform: linux, replay: R}]", "two snapshots"),
    ],
)
def test_bad_inventory_exits_2(tmp_path, capsys, body, error):
    # An absolute replay path stays as it is; relative ones resolve against the inventory.
    (tmp_path / "inv.yaml").write_text(
        body.replace("R", json.dumps(str(RECORDINGS / "ubuntu-weak")))
    )
    assert main(["audit", "--inventory", str(tmp_path / "inv.yaml"), *CHECKS]) == 2
    assert error in capsys.readouterr().err


def test_inventory_and_platform_are_exclusive(tmp_path):
    assert main(["audit", "linux", "--inventory", str(INVENTORIES / "lab-weak.yaml")]) == 2
    with pytest.raises(SystemExit):
        main(["audit", "linux"])
