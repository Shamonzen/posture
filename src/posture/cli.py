import argparse
import sys
from pathlib import Path

from posture import __version__
from posture.collectors import linux
from posture.collectors.transport import LocalRunner, ReplayRunner, SshRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="posture",
        description="Read-only security posture audit of Linux, Active Directory and Azure, "
        "mapped to CIS benchmarks and MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    collect = sub.add_parser("collect", help="read a system's settings into a snapshot (JSON)")
    collect.add_argument("platform", choices=["linux"])
    source = collect.add_mutually_exclusive_group(required=True)
    source.add_argument("--local", action="store_true", help="audit this host")
    source.add_argument("--ssh", metavar="HOST", help="audit HOST through the system ssh client")
    source.add_argument("--replay", type=Path, metavar="DIR", help="replay a recording")
    collect.add_argument("--ssh-config", type=Path, help="ssh config file (e.g. lab/.ssh-config)")
    collect.add_argument("--record", type=Path, metavar="DIR", help="also save the raw output")
    collect.add_argument("--target", help="name for the target (default: its hostname)")
    collect.add_argument("-o", "--output", type=Path, help="write the snapshot here, not stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "collect":
        if args.local:
            runner = LocalRunner()
        elif args.ssh:
            runner = SshRunner(args.ssh, args.ssh_config)
        else:
            runner = ReplayRunner(args.replay)
        snapshot = linux.collect(runner, target=args.target or args.ssh, record_dir=args.record)
        text = snapshot.model_dump_json(indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        for error in snapshot.errors:
            print(f"warning: {error.source}: {error.message}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
