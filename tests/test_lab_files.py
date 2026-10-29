"""The lab can only touch its own VMs: checked without starting anything."""

import os
import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).parent.parent / "lab"
VAGRANTFILE = (LAB / "Vagrantfile").read_text(encoding="utf-8")
VMS = {"posture-dc": "10", "posture-ubuntu": "11", "posture-rocky": "12"}  # host part of the IP
LINUX_VMS = ["posture-ubuntu", "posture-rocky"]


def test_every_shell_provisioner_runs_the_guard_first():
    shell = re.findall(
        r'provision "([\w-]+)", type: "shell"(.*?)\n\s*(?:node\.|end)', VAGRANTFILE, re.S
    )
    assert {name for name, _ in shell} == {"promote", "base", "weak", "hardened"}
    assert len(shell) == 7  # 4 on the DC, 3 on the Linux VMs
    for name, body in shell:
        assert "inline: guarded(" in body, f"{name} must go through guarded()"
        assert "path:" not in body
    assert 'GUARDS = { ".sh" => "guard_lab.sh", ".ps1" => "guard_lab.ps1" }' in VAGRANTFILE
    assert "parts = [GUARDS.fetch(File.extname(script))]" in VAGRANTFILE


def test_only_host_only_network_on_the_lab_subnet():
    assert "public_network" not in VAGRANTFILE
    assert re.findall(r'LAB_NET = "([\d.]+)"', VAGRANTFILE) == ["192.168.57"]
    assert "192.168.56" not in VAGRANTFILE
    # The Windows box forwards RDP on every host interface unless overridden.
    forwards = re.findall(r'"forwarded_port",(.*)', VAGRANTFILE)
    assert forwards and all('host_ip: "127.0.0.1"' in f for f in forwards)
    assert 'id: "tcp53389", guest: 3389' in VAGRANTFILE


def test_vm_names_hostnames_and_ssh_config_agree():
    assert set(re.findall(r'"(posture-[\w-]+)" =>', VAGRANTFILE)) == set(VMS)
    assert "node.vm.hostname = name" in VAGRANTFILE and "vb.name = name" in VAGRANTFILE
    ssh_config = (LAB / "ssh-config").read_text(encoding="utf-8")
    hosts = dict(re.findall(r"Host (posture-\w+)\s+HostName ([\d.]+)", ssh_config))
    assert hosts == {vm: f"192.168.57.{VMS[vm]}" for vm in LINUX_VMS}
    for vm, host in VMS.items():
        entry = rf'"{vm}" => {{(?:(?!=>).)*?ip: "#{{LAB_NET}}\.{host}"'
        assert re.search(entry, VAGRANTFILE, re.S), vm


def test_lab_driver_names_only_posture_vms():
    driver = (LAB / "lab.sh").read_text(encoding="utf-8")
    assert f"VMS=({' '.join(VMS)})" in driver
    assert f"LINUX_VMS=({' '.join(LINUX_VMS)})" in driver
    for line in driver.splitlines():
        if re.search(r"\bvagrant (up|provision|snapshot|halt|destroy|status)\b|VBoxManage", line):
            assert '"$vm"' in line, line
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


POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")
# Stands in for the cmdlet: a function shadows a cmdlet of the same name.
IP_STUB = "function Get-NetIPAddress {{ [pscustomobject]@{{ IPAddress = '{ip}' }} }}"


@pytest.mark.skipif(POWERSHELL is None, reason="needs PowerShell")
@pytest.mark.parametrize(
    ("hostname", "ip", "marker", "base", "allowed"),
    [
        ("posture-dc", "192.168.57.10", True, False, True),
        ("POSTURE-DC", "192.168.57.10", True, False, True),  # COMPUTERNAME is upper case
        ("posture-dc", "192.168.57.10", False, True, True),  # promote creates the marker
        ("posture-dc", "192.168.57.10", False, False, False),
        ("posture-dc-2", "192.168.57.10", True, False, False),
        ("dc01", "192.168.57.10", True, False, False),
        ("posture-dc", "192.168.56.10", True, False, False),
        ("posture-dc", "10.0.2.15", True, False, False),
    ],
)
def test_guard_lab_ps1(tmp_path, hostname, ip, marker, base, allowed):
    marker_file = tmp_path / "PostureLab"
    if marker:
        marker_file.write_text("vm=x\n")
    env = {
        **os.environ,
        "COMPUTERNAME": hostname,
        "POSTURE_LAB_MARKER": str(marker_file),
        "POSTURE_LAB_BASE": "1" if base else "0",
    }
    command = f"{IP_STUB.format(ip=ip)}; & '{LAB / 'guard_lab.ps1'}'; exit $LASTEXITCODE"
    argv = [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command]
    result = subprocess.run(argv, env=env, capture_output=True, check=False)  # noqa: S603
    assert (result.returncode == 0) is allowed, result.stderr


def test_profiles_are_lf_only():
    # A CRLF checkout would break bash inside the VMs; .gitattributes keeps them LF.
    for script in [
        *LAB.rglob("*.sh"),
        *LAB.rglob("*.ps1"),
        LAB / "Vagrantfile",
        LAB / "ssh-config",
    ]:
        assert b"\r\n" not in script.read_bytes(), script
    assert os.linesep  # (Windows checkouts included)
