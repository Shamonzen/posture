import pytest

from posture.collectors.transport import Result
from posture.parsers import linux as p


def test_os_release():
    facts = p.os_release(Result('NAME="Rocky Linux"\nVERSION_ID="9.4"\nID="rocky"\n'))
    assert facts["distro"] == "rocky"
    assert facts["os"]["version_id"] == "9.4"


def test_os_release_without_id():
    with pytest.raises(ValueError):
        p.os_release(Result('NAME="x"\n'))


def test_sshd_types():
    out = (
        "port 22\nport 2222\nmaxauthtries 4\npermitrootlogin no\n"
        "ciphers aes256-gcm@openssh.com,aes128-ctr\n"
    )
    ssh = p.sshd(Result(out))["ssh"]
    assert ssh["port"] == [22, 2222]
    assert ssh["maxauthtries"] == 4
    assert ssh["permitrootlogin"] == "no"
    assert ssh["ciphers"] == ["aes256-gcm@openssh.com", "aes128-ctr"]


def test_sshd_empty_is_error():
    with pytest.raises(ValueError):
        p.sshd(Result(""))


def test_passwd():
    out = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    root, daemon = p.passwd(Result(out))["users"]
    assert root["uid"] == 0 and root["login_shell"]
    assert not daemon["login_shell"]


def test_passwd_bad_line():
    with pytest.raises(ValueError):
        p.passwd(Result("root:x:0\n"))


HASH = "$6$rounds=5000$saltsalt$" + "A" * 86


def test_scrub_shadow_removes_hashes():
    raw = (
        f"alice:{HASH}:20300:0:99999:7:::\nbob:!{HASH}:20300::::::\n"
        "guest::20300::::::\nsvc:*:1::::::\n"
    )
    scrubbed = p.scrub_shadow(raw)
    assert "$6$" not in scrubbed
    assert scrubbed.splitlines() == [
        "alice:HASH-REMOVED:20300:0:99999:7:::",
        "bob:!:20300::::::",
        "guest::20300::::::",
        "svc:*:1::::::",
    ]


def test_shadow_states_even_unscrubbed():
    raw = f"alice:{HASH}:20300:0:90:7:::\nbob:!!:20300::::::\nguest::20300::::::\n"
    entries = p.shadow(Result(raw))["shadow"]
    assert entries == {
        "alice": {"shadow_state": "set", "max_days": 90},
        "bob": {"shadow_state": "locked", "max_days": None},
        "guest": {"shadow_state": "empty", "max_days": None},
    }
    assert "$6$" not in repr(entries)


def test_group():
    groups = p.group(Result("sudo:x:27:vagrant,alice\nwheel:x:10:\n"))["groups"]
    assert groups == {"sudo": ["vagrant", "alice"], "wheel": []}


def test_sudoers():
    out = (
        "/etc/sudoers:Defaults\tuse_pty, logfile=/var/log/sudo.log\n"
        "/etc/sudoers:# a comment\n"
        "/etc/sudoers:Defaults:posture !requiretty\n"
        "/etc/sudoers:Cmnd_Alias SHUTDOWN = /sbin/shutdown\n"
        "/etc/sudoers:%wheel\tALL=(ALL)\tALL\n"
        "/etc/sudoers.d/ops:ops ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx, \\\n"
        "/etc/sudoers.d/ops:    /usr/bin/journalctl\n"
        "/etc/sudoers.d/bad:alice ALL=(ALL:ALL) NOPASSWD:ALL\n"
    )
    facts = p.sudoers(Result(out))["sudoers"]
    assert facts["defaults"] == ["use_pty", "logfile=/var/log/sudo.log"]
    wheel, ops, alice = facts["rules"]
    assert (wheel["principal"], wheel["nopasswd"], wheel["all_commands"]) == ("%wheel", False, True)
    assert (ops["nopasswd"], ops["all_commands"]) == (True, False)
    assert "/usr/bin/journalctl" in ops["line"]
    assert (alice["file"], alice["nopasswd"], alice["all_commands"]) == (
        "/etc/sudoers.d/bad",
        True,
        True,
    )


def test_stat_files():
    files = p.stat_files(Result("640 root shadow /etc/shadow\n666 root root /etc/my file\n"))[
        "files"
    ]
    assert files["/etc/shadow"]["world_readable"] is False
    assert files["/etc/my file"]["world_writable"] is True


def test_special_files_ignores_temp_dirs():
    out = (
        "4755 /usr/bin/passwd\n2755 /usr/bin/chage\n777 /opt/run.sh\n"
        "666 /tmp/x\n6755 /usr/bin/both\n"
    )
    found = p.special_files(Result(out))["special_files"]
    assert found["setuid"] == ["/usr/bin/both", "/usr/bin/passwd"]
    assert found["setgid"] == ["/usr/bin/both", "/usr/bin/chage"]
    assert found["world_writable"] == ["/opt/run.sh"]


def test_units_block_count_must_match():
    with pytest.raises(ValueError, match="unit blocks"):
        p.units(Result("Id=ssh.service\nLoadState=loaded\n"))


def test_journald_last_storage_wins():
    out = "[Journal]\n#Storage=auto\nStorage=volatile\n\n# drop-in\n[Journal]\nStorage=persistent\n"
    assert p.journald(Result(out))["journald"]["storage"] == "persistent"


@pytest.mark.parametrize(
    ("result", "rules"),
    [
        (Result("No rules\n"), []),
        (Result("-w /etc/passwd -p wa -k identity\n"), ["-w /etc/passwd -p wa -k identity"]),
        (Result("", "sudo: /usr/sbin/auditctl: command not found\n", 1), []),
        (Result("", "auditctl: command not found", 127), []),
    ],
)
def test_auditctl(result, rules):
    assert p.auditctl(result)["audit"]["rules"] == rules


def test_auditctl_sudo_refused_is_error():
    with pytest.raises(ValueError, match="password is required"):
        p.auditctl(Result("", "sudo: a password is required\n", 1))


def test_ufw():
    out = (
        "Status: active\nLogging: on (low)\n"
        "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
    )
    assert p.ufw(Result(out))["ufw"] == {"active": True, "default_incoming": "deny"}
    assert p.ufw(Result("Status: inactive\n"))["ufw"] == {"active": False, "default_incoming": None}


def test_firewalld():
    out = (
        "public (active)\n  target: default\n  interfaces: eth0\n"
        "  services: cockpit dhcpv6-client ssh\n  ports: 8080/tcp\n"
    )
    zone = p.firewalld(Result(out))["firewalld"]
    assert zone == {
        "running": True,
        "zone": "public",
        "target": "default",
        "services": ["cockpit", "dhcpv6-client", "ssh"],
        "ports": ["8080/tcp"],
    }
    stopped = p.firewalld(Result("FirewallD is not running\n", exit_code=252))
    assert stopped["firewalld"] == {
        "running": False,
        "zone": None,
        "target": None,
        "services": [],
        "ports": [],
    }


def test_dnf_security():
    out = (
        "\n"
        "glibc.x86_64            2.34-168.el9_8.2           baseos\n"
        "kernel.x86_64           5.14.0-687.61.1.el9_8      baseos\n"
        "Obsoleting Packages\n"
        "grub2-tools.x86_64      1:2.06-104.el9_8           baseos\n"
        "    grub2-tools.x86_64  1:2.06-94.el9              @anaconda\n"
    )
    assert p.dnf_security(Result(out, exit_code=100))["updates"]["pending_security"] == 2
    assert p.dnf_security(Result(""))["updates"]["pending_security"] == 0


def test_apt_unattended():
    assert p.apt_unattended(Result('APT::Periodic::Unattended-Upgrade "1";\n'))["updates"][
        "automatic"
    ]
    assert not p.apt_unattended(Result(""))["updates"]["automatic"]
