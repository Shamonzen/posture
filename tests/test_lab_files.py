"""The lab can only touch its own VMs: checked without starting anything."""

import os
import re
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).parent.parent / "lab"
VAGRANTFILE = (LAB / "Vagrantfile").read_text(encoding="utf-8")
VMS = {"posture-ubuntu": "192.168.57.11", "posture-rocky": "192.168.57.12"}


def test_every_shell_provisioner_runs_the_guard_first():
    shell = re.findall(
        r'provision "([\w-]+)", type: "shell"(.*?)\n\s*(?:node\.|end)', VAGRANTFILE, re.S
    )
    assert {name for name, _ in shell} == {"base", "weak", "hardened"}
    for name, body in shell:
        assert "inline: guarded(" in body, f"{name} must go through guarded()"
        assert "path:" not in body
    assert 'GUARD + "\\n" + File.read' in VAGRANTFILE


def test_only_host_only_network_on_the_lab_subnet():
    assert "public_network" not in VAGRANTFILE
    assert re.findall(r'LAB_NET = "([\d.]+)"', VAGRANTFILE) == ["192.168.57"]
    assert "192.168.56" not in VAGRANTFILE


def test_vm_names_hostnames_and_ssh_config_agree():
    assert set(re.findall(r'"(posture-[\w-]+)" =>', VAGRANTFILE)) == set(VMS)
    assert "node.vm.hostname = name" in VAGRANTFILE and "vb.name = name" in VAGRANTFILE
    ssh_config = (LAB / "ssh-config").read_text(encoding="utf-8")
    hosts = dict(re.findall(r"Host (posture-\w+)\s+HostName ([\d.]+)", ssh_config))
    assert hosts == VMS


def test_lab_driver_names_only_posture_vms():
    driver = (LAB / "lab.sh").read_text(encoding="utf-8")
    assert "VMS=(posture-ubuntu posture-rocky)" in driver
    for line in driver.splitlines():
        if re.search(r"\bvagrant (up|provision|snapshot|halt|destroy|status)\b", line):
            assert '"${VMS[@]}"' in line or '"$vm"' in line, line
    assert "global-status" not in driver


def _guard(tmp_path: Path, hostname: str, ip: str, marker: bool, base: bool = False) -> int:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "hostname").write_text(f"#!/bin/sh\necho {hostname}\n")
    (stubs / "ip").write_text(
        f"#!/bin/sh\necho '2: eth1    inet {ip}/24 brd x scope global eth1'\n"
    )
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    marker_file = tmp_path / "posture-lab"
    if marker:
        marker_file.write_text("vm=x\n")
    env = {
        "PATH": f"{stubs}:/usr/bin:/bin",
        "POSTURE_LAB_MARKER": str(marker_file),
        "POSTURE_LAB_BASE": "1" if base else "0",
    }
    return subprocess.run(["bash", str(LAB / "guard_lab.sh")], env=env, check=False).returncode  # noqa: S603, S607


linux_only = pytest.mark.skipif(sys.platform != "linux", reason="runs the guard with stub commands")


@linux_only
@pytest.mark.parametrize(
    ("hostname", "ip", "marker", "base", "allowed"),
    [
        ("posture-ubuntu", "192.168.57.11", True, False, True),
        ("posture-rocky", "192.168.57.12", True, False, True),
        ("posture-ubuntu", "192.168.57.11", False, True, True),  # base creates the marker
        ("posture-ubuntu", "192.168.57.11", False, False, False),
        ("ubuntu", "192.168.57.11", True, False, False),
        ("my-laptop", "192.168.57.11", True, False, False),
        ("posture-ubuntu", "192.168.56.11", True, False, False),
        ("posture-ubuntu", "10.0.2.15", True, False, False),
    ],
)
def test_guard_lab(tmp_path, hostname, ip, marker, base, allowed):
    assert (_guard(tmp_path, hostname, ip, marker, base) == 0) is allowed


def test_profiles_are_lf_only():
    # A CRLF checkout would break bash inside the VMs; .gitattributes keeps them LF.
    for script in [*LAB.rglob("*.sh"), LAB / "Vagrantfile", LAB / "ssh-config"]:
        assert b"\r\n" not in script.read_bytes(), script
    assert os.linesep  # (Windows checkouts included)
