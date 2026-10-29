import json
import os
import shlex
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path

# A hostile or broken host can't make us hold or parse unbounded output.
MAX_OUTPUT = 2_000_000
META_FILE = "_meta.json"


@dataclass(frozen=True)
class Result:
    stdout: str
    stderr: str = ""
    exit_code: int = 0


@dataclass(frozen=True)
class Command:
    """A fixed, read-only command. Nothing collected from a host is ever put into argv."""

    name: str
    argv: tuple[str, ...]
    sudo: bool = False
    ok_codes: tuple[int, ...] = (0,)
    distros: frozenset[str] | None = None  # None: run on every distro
    timeout: int = 60


class NotRecorded(Exception):
    """Replay asked for a command the recording doesn't have."""


def _run(argv: list[str], timeout: int) -> Result:
    try:
        proc = subprocess.run(  # noqa: S603  # nosec B603
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return Result("", f"{argv[0]}: command not found", 127)
    return Result(proc.stdout[:MAX_OUTPUT], proc.stderr[:MAX_OUTPUT], proc.returncode)


def _with_sudo(cmd: Command) -> list[str]:
    return ["/usr/bin/sudo", "-n", *cmd.argv] if cmd.sudo else list(cmd.argv)


class LocalRunner:
    """Runs on this host; only meaningful on Linux."""

    def run(self, cmd: Command) -> Result:
        argv = list(cmd.argv) if os.geteuid() == 0 else _with_sudo(cmd)
        return _run(argv, cmd.timeout)


class SshRunner:
    """Runs through the system ssh client, so ssh_config, host-key checking and the agent apply."""

    def __init__(self, host: str, ssh_config: Path | None = None) -> None:
        if not host or host.startswith("-"):
            raise ValueError(f"bad ssh host {host!r}")
        # LogLevel=ERROR: client warnings (e.g. OpenSSH 10's post-quantum notice) must not end
        # up in the target's stderr; errors such as a changed host key still fail.
        self.base = ["ssh", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR"]
        if ssh_config:
            self.base += ["-F", str(ssh_config)]
        self.host = host

    def run(self, cmd: Command) -> Result:
        # ssh hands the remote shell one string: every (fixed) argument is quoted.
        return _run([*self.base, "--", self.host, shlex.join(_with_sudo(cmd))], cmd.timeout)


class ReplayRunner:
    """Feeds back a recording: `<name>.txt` holds stdout, `_meta.json` any non-zero exit/stderr."""

    def __init__(self, directory: Path) -> None:
        if not directory.is_dir():
            raise ValueError(f"{directory}: not a directory")
        self.directory = directory
        meta = directory / META_FILE
        self.meta = json.loads(meta.read_text(encoding="utf-8")) if meta.is_file() else {}

    def run(self, cmd: Command) -> Result:
        path = self.directory / f"{cmd.name}.txt"
        if not path.is_file():
            raise NotRecorded(f"{cmd.name} is not in the recording {self.directory}")
        meta = self.meta.get(cmd.name, {})
        stdout = path.read_text(encoding="utf-8")[:MAX_OUTPUT]
        return Result(stdout, meta.get("stderr", ""), meta.get("exit_code", 0))


def write_recording(directory: Path, results: dict[str, Result]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    meta = {}
    for name, result in results.items():
        (directory / f"{name}.txt").write_text(result.stdout, encoding="utf-8", newline="")
        if result.exit_code or result.stderr:
            meta[name] = {"exit_code": result.exit_code, "stderr": result.stderr}
    if meta:
        text = json.dumps(meta, indent=2, sort_keys=True) + "\n"
        (directory / META_FILE).write_text(text, encoding="utf-8", newline="")
