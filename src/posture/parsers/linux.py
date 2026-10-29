"""Turn the raw output of the Linux commands into facts. Every parser takes a Result."""

import re
from typing import Any

from posture.collectors.transport import Result

Facts = dict[str, Any]

# Order matters: `systemctl show` prints one block per unit, in this order.
UNITS = (
    "ssh.service",
    "sshd.service",
    "ufw.service",
    "firewalld.service",
    "auditd.service",
    "rsyslog.service",
    "systemd-journald.service",
    "unattended-upgrades.service",
    "apt-daily-upgrade.timer",
    "dnf-automatic.timer",
    "dnf-automatic-install.timer",
)
SSH_LIST_KEYS = {
    "ciphers",
    "macs",
    "kexalgorithms",
    "hostkeyalgorithms",
    "pubkeyacceptedalgorithms",
    "casignaturealgorithms",
}
SSH_REPEATED_KEYS = {"port", "listenaddress", "hostkey", "acceptenv"}
NO_LOGIN_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")
# World-writable files here are normal (sticky dirs, sockets); elsewhere they are a finding.
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")  # noqa: S108  # nosec B108
REMOVED = "HASH-REMOVED"


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def unit_key(unit: str) -> str:
    """`ufw.service` -> `ufw_service`: fact paths are dotted, so keys can't contain dots."""
    return unit.replace(".", "_")


def os_release(r: Result) -> Facts:
    values = {}
    for line in _lines(r.stdout):
        key, sep, value = line.partition("=")
        if sep and not key.startswith("#"):
            values[key.strip().lower()] = value.strip().strip("\"'")
    if "id" not in values:
        raise ValueError("no ID in /etc/os-release")
    os_info = {k: values.get(k) for k in ("id", "version_id", "pretty_name")}
    return {"os": os_info, "distro": values["id"]}


def hostname(r: Result) -> Facts:
    return {"hostname": r.stdout.strip()}


def identity(r: Result) -> Facts:
    return {"identity": r.stdout.strip()}


def now(r: Result) -> Facts:
    return {"now": int(r.stdout.strip())}


def sshd(r: Result) -> Facts:
    """`sshd -T`: the effective config, one lowercase `key value` per line."""
    config: Facts = {}
    for line in _lines(r.stdout):
        key, _, value = line.strip().partition(" ")
        key = key.lower()
        if key in SSH_LIST_KEYS:
            parsed: Any = value.split(",")
        else:
            parsed = int(value) if value.isdigit() else value
        if key in SSH_REPEATED_KEYS:
            config.setdefault(key, []).append(parsed)
        else:
            config[key] = parsed
    if not config:
        raise ValueError("sshd -T printed nothing")
    return {"ssh": config}


def passwd(r: Result) -> Facts:
    users = []
    for line in _lines(r.stdout):
        f = line.split(":")
        if len(f) != 7:
            raise ValueError(f"bad passwd line {line[:80]!r}")
        users.append(
            {
                "name": f[0],
                "uid": int(f[2]),
                "gid": int(f[3]),
                "home": f[5],
                "shell": f[6],
                "login_shell": not f[6].endswith(NO_LOGIN_SHELLS),
            }
        )
    return {"users": users}


def _password_state(field: str) -> str:
    if field == "":
        return ""
    return field[0] if field[0] in "!*" else REMOVED


def scrub_shadow(text: str) -> str:
    """Replace every password hash before anything is stored; keep only empty / locked / set."""
    out = []
    for line in text.splitlines():
        f = line.split(":")
        if len(f) > 1:
            f[1] = _password_state(f[1])
        out.append(":".join(f))
    return "\n".join(out) + "\n"


def shadow(r: Result) -> Facts:
    entries = {}
    for line in _lines(r.stdout):
        f = line.split(":")
        if len(f) != 9:
            raise ValueError(f"bad shadow line for {f[0][:32]!r}")
        state = _password_state(f[1])
        password = {"": "empty", "!": "locked", "*": "locked"}.get(state, "set")
        entries[f[0]] = {"shadow_state": password, "max_days": int(f[4]) if f[4] else None}
    return {"shadow": entries}


def group(r: Result) -> Facts:
    groups = {}
    for line in _lines(r.stdout):
        f = line.split(":")
        if len(f) != 4:
            raise ValueError(f"bad group line {line[:80]!r}")
        groups[f[0]] = f[3].split(",") if f[3] else []
    return {"groups": groups}


def _sudoers_lines(text: str) -> list[tuple[str, str]]:
    """`grep -rH .` output -> (file, logical line), with `\\` continuations joined."""
    out, pending = [], ""
    for raw in text.splitlines():
        path, sep, content = raw.partition(":")
        if not sep:
            continue
        content = f"{pending} {content.strip()}".strip()
        if content.endswith("\\"):
            pending = content[:-1].strip()
            continue
        pending = ""
        out.append((path, content))
    return out


def sudoers(r: Result) -> Facts:
    # shortcut: no aliases, scoped Defaults or per-command tags; upgrade if checks need them.
    defaults: list[str] = []
    rules = []
    for path, line in _sudoers_lines(r.stdout):
        if not line or line.startswith(("#", "@")):
            continue
        first, rest = (line.split(None, 1) + [""])[:2]
        if first == "Defaults":
            defaults += [token.strip() for token in rest.split(",") if token.strip()]
            continue
        if first.startswith("Defaults") or first.endswith("_Alias") or "=" not in rest:
            continue
        commands = re.sub(r"^\s*\([^)]*\)", "", rest.split("=", 1)[1])  # drop (runas)
        tags = re.findall(r"\b([A-Z_]+):", commands)
        commands = re.sub(r"\b[A-Z_]+:\s*", "", commands)
        rules.append(
            {
                "file": path,
                "principal": first,
                "nopasswd": "NOPASSWD" in tags,
                "all_commands": "ALL" in [c.strip() for c in commands.split(",")],
                "line": line,
            }
        )
    return {"sudoers": {"defaults": defaults, "rules": rules}}


def stat_files(r: Result) -> Facts:
    """`stat -c '%a %U %G %n'`; a missing file is simply absent."""
    files = {}
    for line in _lines(r.stdout):
        mode, owner, grp, path = line.split(None, 3)
        bits = int(mode, 8)
        files[path] = {
            "mode": mode,
            "owner": owner,
            "group": grp,
            "group_writable": bool(bits & 0o020),
            "world_readable": bool(bits & 0o004),
            "world_writable": bool(bits & 0o002),
        }
    return {"files": files}


def special_files(r: Result) -> Facts:
    """`find -printf '%m %p\\n'` over setuid, setgid and world-writable files."""
    found: dict[str, list[str]] = {"setuid": [], "setgid": [], "world_writable": []}
    for line in _lines(r.stdout):
        mode, path = line.split(" ", 1)
        bits = int(mode, 8)
        if bits & 0o4000:
            found["setuid"].append(path)
        if bits & 0o2000:
            found["setgid"].append(path)
        if bits & 0o002 and not path.startswith(TEMP_DIRS):
            found["world_writable"].append(path)
    return {"special_files": {k: sorted(v) for k, v in found.items()}}


def units(r: Result) -> Facts:
    blocks = [b for b in re.split(r"\n\s*\n", r.stdout.strip()) if b.strip()]
    if len(blocks) != len(UNITS):
        raise ValueError(f"expected {len(UNITS)} unit blocks, got {len(blocks)}")
    out = {}
    for unit, block in zip(UNITS, blocks, strict=True):
        props = dict(line.partition("=")[::2] for line in block.splitlines())
        out[unit_key(unit)] = {
            "load": props.get("LoadState", ""),
            "active": props.get("ActiveState", ""),
            "enabled": props.get("UnitFileState", ""),
        }
    return {"units": out}


def journald(r: Result) -> Facts:
    storage = "auto"
    for line in _lines(r.stdout):
        key, sep, value = line.strip().partition("=")
        if sep and key.strip() == "Storage":
            storage = value.strip().lower()
    return {"journald": {"storage": storage}}


def auditctl(r: Result) -> Facts:
    if r.exit_code == 127 or "command not found" in r.stderr:
        return {"audit": {"rules": []}}  # auditd not installed: no rules
    if r.exit_code != 0:
        raise ValueError(r.stderr.strip()[:200] or f"exit {r.exit_code}")
    rules = [line.strip() for line in _lines(r.stdout) if line.strip() != "No rules"]
    return {"audit": {"rules": rules}}


def ufw(r: Result) -> Facts:
    active, default_incoming = False, None
    for line in _lines(r.stdout):
        if line.startswith("Status:"):
            active = line.split(":", 1)[1].strip() == "active"
        elif line.startswith("Default:"):
            match = re.search(r"(\w+) \(incoming\)", line)
            default_incoming = match.group(1) if match else None
    return {"ufw": {"active": active, "default_incoming": default_incoming}}


def firewalld(r: Result) -> Facts:
    # Same keys whether running or not, so a stopped firewall fails checks instead of erroring.
    zone: Facts = {"running": False, "zone": None, "target": None, "services": [], "ports": []}
    if "not running" in (r.stdout + r.stderr).lower():
        return {"firewalld": zone}
    lines = _lines(r.stdout)
    if not lines:
        raise ValueError("firewall-cmd printed nothing")
    zone |= {"running": True, "zone": lines[0].split()[0]}
    for line in lines[1:]:
        key, sep, value = line.strip().partition(":")
        if sep and key in ("target", "services", "ports"):
            zone[key] = value.strip() if key == "target" else value.split()
    return {"firewalld": zone}


def apt_upgrade(r: Result) -> Facts:
    """`apt-get -s upgrade`: one `Inst` line per package it would upgrade."""
    inst = [line for line in _lines(r.stdout) if line.startswith("Inst ")]
    security = [line for line in inst if "-security" in line]
    return {"updates": {"pending": len(inst), "pending_security": len(security)}}


def dnf_security(r: Result) -> Facts:
    advisories = [line for line in _lines(r.stdout) if re.search(r"\s\S+/Sec\.\s", line)]
    return {"updates": {"pending_security": len(advisories)}}


def cache_mtime(r: Result) -> Facts:
    return {"updates": {"cache_mtime": int(r.stdout.strip())}}


def apt_unattended(r: Result) -> Facts:
    return {"updates": {"automatic": '"1"' in r.stdout}}
