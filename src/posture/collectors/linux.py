# Only for TimeoutExpired: this module runs nothing itself.
import subprocess  # nosec B404
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from posture import __version__
from posture.collectors.transport import Command, NotRecorded, Result, write_recording
from posture.models import CollectError, Snapshot
from posture.parsers import linux as p

UBUNTU = frozenset({"ubuntu"})
ROCKY = frozenset({"rocky"})
STAT_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/var/log/journal",
)
FIND_SPECIAL = (
    "/usr/bin/find", "/", "-xdev", "-type", "f",
    "(", "-perm", "-4000", "-o", "-perm", "-2000", "-o", "-perm", "-0002", ")",
    "-printf", "%m %p\\n",
)  # fmt: skip

# The whole read-only surface on a Linux host. Full paths, so the target's PATH doesn't matter.
# Every `sudo=True` entry must match deploy/sudoers.posture exactly (tests/test_readonly.py).
COMMANDS = (
    Command("os_release", ("/usr/bin/cat", "/etc/os-release")),
    Command("hostname", ("/usr/bin/uname", "-n")),
    Command("identity", ("/usr/bin/id", "-un")),
    Command("now", ("/usr/bin/date", "+%s")),
    Command("sshd", ("/usr/sbin/sshd", "-T"), sudo=True),
    Command("passwd", ("/usr/bin/getent", "passwd")),
    Command("shadow", ("/usr/bin/getent", "shadow"), sudo=True),
    Command("group", ("/usr/bin/getent", "group")),
    Command("sudoers", ("/usr/bin/grep", "-rH", ".", "/etc/sudoers", "/etc/sudoers.d"), sudo=True),
    Command("stat", ("/usr/bin/stat", "-c", "%a %U %G %n", *STAT_PATHS), ok_codes=(0, 1)),
    # Not sudo: exact-argument sudoers can't express this safely. Unreadable dirs are skipped.
    Command("special_files", FIND_SPECIAL, ok_codes=(0, 1), timeout=300),
    Command(
        "units",
        (
            "/usr/bin/systemctl",
            "show",
            "--property=Id,LoadState,ActiveState,UnitFileState",
            *p.UNITS,
        ),
    ),
    Command("journald", ("/usr/bin/systemd-analyze", "cat-config", "systemd/journald.conf")),
    Command("auditctl", ("/usr/sbin/auditctl", "-l"), sudo=True, ok_codes=(0, 1, 127)),
    Command("ufw", ("/usr/sbin/ufw", "status", "verbose"), sudo=True, distros=UBUNTU),
    Command("apt_upgrade", ("/usr/bin/apt-get", "-s", "upgrade"), distros=UBUNTU),
    Command("apt_lists", ("/usr/bin/stat", "-c", "%Y", "/var/lib/apt/lists"), distros=UBUNTU),
    Command(
        "apt_unattended",
        ("/usr/bin/apt-config", "dump", "APT::Periodic::Unattended-Upgrade"),
        distros=UBUNTU,
    ),
    Command(
        "firewalld",
        ("/usr/bin/firewall-cmd", "--list-all"),
        sudo=True,
        ok_codes=(0, 252),
        distros=ROCKY,
    ),  # fmt: skip
    Command(
        "dnf_security",
        ("/usr/bin/dnf", "-C", "-q", "updateinfo", "list", "--security"),
        distros=ROCKY,
    ),  # fmt: skip
    Command("dnf_cache", ("/usr/bin/stat", "-c", "%Y", "/var/cache/dnf"), distros=ROCKY),
)

PARSERS: dict[str, Callable[[Result], dict[str, Any]]] = {
    "os_release": p.os_release,
    "hostname": p.hostname,
    "identity": p.identity,
    "now": p.now,
    "sshd": p.sshd,
    "passwd": p.passwd,
    "shadow": p.shadow,
    "group": p.group,
    "sudoers": p.sudoers,
    "stat": p.stat_files,
    "special_files": p.special_files,
    "units": p.units,
    "journald": p.journald,
    "auditctl": p.auditctl,
    "ufw": p.ufw,
    "apt_upgrade": p.apt_upgrade,
    "apt_lists": p.cache_mtime,
    "apt_unattended": p.apt_unattended,
    "firewalld": p.firewalld,
    "dnf_security": p.dnf_security,
    "dnf_cache": p.cache_mtime,
}
NO_SHADOW_ENTRY = {"shadow_state": "missing", "max_days": None}
# Applied the moment output arrives, before it is recorded or parsed.
SCRUB = {"shadow": p.scrub_shadow}


class Runner(Protocol):
    def run(self, cmd: Command) -> Result: ...


def _merge(facts: dict[str, Any], new: dict[str, Any]) -> None:
    for key, value in new.items():
        if isinstance(value, dict) and isinstance(facts.get(key), dict):
            facts[key].update(value)
        else:
            facts[key] = value


def _derive(facts: dict[str, Any]) -> None:
    shadow = facts.pop("shadow", None)
    if shadow is not None and "users" in facts:
        for user in facts["users"]:
            user.update(shadow.get(user["name"], NO_SHADOW_ENTRY))
    updates, units = facts.get("updates"), facts.get("units", {})
    if updates is not None:
        if "cache_mtime" in updates and "now" in facts:
            updates["cache_age_days"] = round((facts["now"] - updates["cache_mtime"]) / 86400, 1)
        if facts.get("distro") == "rocky" and units:
            # shortcut: an enabled dnf-automatic timer counts; apply_updates in automatic.conf
            # is not read. Upgrade if the hardened profile needs to tell them apart.
            timers = ("dnf-automatic_timer", "dnf-automatic-install_timer")
            updates["automatic"] = any(units[t]["enabled"] == "enabled" for t in timers)
    if "journald" in facts:
        storage = facts["journald"]["storage"]
        journal_dir = "/var/log/journal" in facts.get("files", {})
        persistent = storage == "persistent" or (storage == "auto" and journal_dir)
        facts["journald"]["persistent"] = persistent


def collect(runner: Runner, target: str | None = None, record_dir: Path | None = None) -> Snapshot:
    facts: dict[str, Any] = {}
    errors: list[CollectError] = []
    results: dict[str, Result] = {}
    for cmd in COMMANDS:
        if cmd.distros is not None and facts.get("distro") not in cmd.distros:
            continue
        try:
            result = runner.run(cmd)
        except (NotRecorded, subprocess.TimeoutExpired, OSError) as exc:
            errors.append(CollectError(source=cmd.name, message=str(exc)))
            continue
        if cmd.name in SCRUB:
            result = replace(result, stdout=SCRUB[cmd.name](result.stdout))
        results[cmd.name] = result
        if result.exit_code not in cmd.ok_codes:
            message = f"exit {result.exit_code}: {result.stderr.strip()[:500]}"
            errors.append(CollectError(source=cmd.name, message=message))
            continue
        try:
            _merge(facts, PARSERS[cmd.name](result))
        except ValueError as exc:
            errors.append(CollectError(source=cmd.name, message=f"parse error: {exc}"))
    if record_dir is not None:
        write_recording(record_dir, results)
    _derive(facts)
    return Snapshot(
        tool_version=__version__,
        platform="linux",
        target=target or facts.get("hostname") or "unknown",
        collected_at=datetime.now(UTC),
        identity=facts.get("identity"),
        facts=facts,
        errors=errors,
    )
