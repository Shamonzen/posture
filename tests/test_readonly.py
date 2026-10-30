"""Posture never changes what it audits: every command it can run is checked here."""

import re
import shlex
import ssl
from pathlib import Path

import ldap3
import pytest

from posture.collectors import ad, linux, transport
from posture.collectors.transport import Command, SshRunner

SUDOERS = Path(__file__).parent.parent / "deploy" / "sudoers.posture"

# Per binary: which argument lists are read-only. A new command needs a reviewed entry here.
FIND_WRITES = {
    "-delete",
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-fprint",
    "-fprint0",
    "-fprintf",
    "-fls",
}
READ_ONLY = {
    "/usr/bin/cat": lambda a: all(x.startswith("/etc/") for x in a),
    "/usr/bin/uname": lambda a: a == ["-n"],
    "/usr/bin/id": lambda a: a == ["-un"],
    "/usr/bin/date": lambda a: a == ["+%s"],
    "/usr/sbin/sshd": lambda a: a == ["-T"],
    "/usr/bin/getent": lambda a: a in (["passwd"], ["shadow"], ["group"]),
    "/usr/bin/grep": lambda a: True,
    "/usr/bin/stat": lambda a: a[0] == "-c",
    "/usr/bin/find": lambda a: not FIND_WRITES & set(a),
    "/usr/bin/systemctl": lambda a: a[0] == "show",
    "/usr/bin/systemd-analyze": lambda a: a[0] == "cat-config",
    "/usr/sbin/auditctl": lambda a: a == ["-l"],
    "/usr/sbin/ufw": lambda a: a == ["status", "verbose"],
    "/usr/bin/apt-get": lambda a: a == ["-s", "upgrade"],
    "/usr/bin/apt-config": lambda a: a[0] == "dump",
    "/usr/bin/firewall-cmd": lambda a: a == ["--list-all"],
    "/usr/bin/dnf": lambda a: a == ["-C", "-q", "check-update", "--security"],
}


@pytest.mark.parametrize("cmd", linux.COMMANDS, ids=lambda c: c.name)
def test_command_is_read_only(cmd):
    binary, *args = cmd.argv
    assert binary in READ_ONLY, f"{binary} is not on the read-only allowlist"
    assert READ_ONLY[binary](args), f"{cmd.name}: {args} is not a read-only use of {binary}"


def test_every_command_has_a_parser():
    assert {c.name for c in linux.COMMANDS} == set(linux.PARSERS)


def _sudoers_commands() -> set[str]:
    text = re.sub(r"\\\n", " ", SUDOERS.read_text(encoding="utf-8"))
    [rule] = [line for line in text.splitlines() if line.startswith("posture ")]
    return {" ".join(c.split()) for c in rule.split("NOPASSWD:", 1)[1].split(",")}


def test_sudoers_matches_sudo_commands_exactly():
    expected = {" ".join(c.argv) for c in linux.COMMANDS if c.sudo}
    assert _sudoers_commands() == expected


def test_sudoers_has_no_wildcards_or_all():
    for command in _sudoers_commands():
        assert command != "ALL"
        assert not set("*?[]") & set(command), command


def test_ssh_runner_quotes_and_puts_host_after_double_dash(monkeypatch):
    monkeypatch.setattr(transport, "_run", lambda argv, timeout: argv)
    config = Path("lab/ssh-config")
    remote = Command("x", ("/usr/bin/find", "/", "-printf", "%m %p\\n"))
    sent = SshRunner("posture-ubuntu", config).run(remote)
    options = ["-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "-F", str(config)]
    assert sent[:-1] == ["ssh", *options, "--", "posture-ubuntu"]
    assert shlex.split(sent[-1]) == list(remote.argv)


def test_ssh_runner_adds_sudo_non_interactive(monkeypatch):
    monkeypatch.setattr(transport, "_run", lambda argv, timeout: argv)
    sent = SshRunner("posture-ubuntu").run(Command("t", ("/usr/sbin/sshd", "-T"), sudo=True))
    assert sent[-1] == "/usr/bin/sudo -n /usr/sbin/sshd -T"


@pytest.mark.parametrize("host", ["-oProxyCommand=calc", "", "-F/tmp/x"])
def test_ssh_runner_rejects_option_like_hosts(host):
    with pytest.raises(ValueError):
        SshRunner(host)


def test_ad_collector_only_reads():
    """Searches and "Who am I?" only: no LDAP write operation appears in the AD collector."""
    source = Path(ad.__file__).read_text(encoding="utf-8")
    assert not re.search(r"\.(add|modify|modify_dn|delete|password_modify)\(", source)
    assert {s.name for s in ad.SEARCHES} == set(ad.PARSERS)


def test_connection_is_ldaps_read_only_and_never_follows_referrals(monkeypatch):
    seen = {}

    class FakeConnection:
        def __init__(self, server, **kwargs):
            seen.update(kwargs, server=server)

        def open(self):
            pass

        def bind(self):
            return True

    monkeypatch.setattr(ldap3, "Connection", FakeConnection)
    ad.LdapRunner("dc.example.test", "EXAMPLE\\audit", "pw")
    server = seen["server"]
    assert (server.port, server.ssl) == (636, True)
    assert server.tls.validate == ssl.CERT_REQUIRED
    assert seen["read_only"] is True and seen["auto_referrals"] is False
    assert seen["authentication"] == ldap3.SIMPLE
