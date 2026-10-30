import argparse
import getpass
import os
import sys
from pathlib import Path

from posture import __version__
from posture.baseline import apply_baseline, diff, gate, load_report
from posture.checks import CheckError, load_checks
from posture.collectors import ad, linux
from posture.collectors.transport import LocalRunner, ReplayRunner, SshRunner
from posture.engine import evaluate_all
from posture.models import Severity, Snapshot
from posture.reports import build_report, clean, summary
from posture.reports.html import render_html
from posture.reports.sarif import render_sarif

# 0: clean (or nothing at/above --fail-on) · 1: the gate failed · 2: usage, bad checks, or
# nothing could be collected at all.
EXIT_GATE, EXIT_USAGE = 1, 2


def _add_source(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("platform", choices=["linux", "ad"])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--local", action="store_true", help="audit this host (linux)")
    source.add_argument("--ssh", metavar="HOST", help="audit HOST through the system ssh client")
    source.add_argument("--ldap", metavar="DC", help="audit DC's domain over LDAPS (ad)")
    source.add_argument("--replay", type=Path, metavar="DIR", help="replay a recording")
    parser.add_argument("--ssh-config", type=Path, help="ssh config file (e.g. lab/ssh-config)")
    parser.add_argument(
        "--user",
        help=r"LDAP account (DOMAIN\user); password from $POSTURE_LDAP_PASSWORD or a prompt",
    )
    parser.add_argument("--ca-file", type=Path, help="CA (or pinned) certificate for LDAPS")
    parser.add_argument(
        "--winrm",
        action="store_true",
        help="with --ldap: also read the DC's registry settings over WinRM, same account",
    )
    parser.add_argument("--record", type=Path, metavar="DIR", help="also save the raw output")
    parser.add_argument("--target", help="name for the target (default: its hostname)")


def _add_outputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--checks", type=Path, default=Path("checks"), help="check directory")
    parser.add_argument("--json", type=Path, metavar="FILE", help="write the JSON report")
    parser.add_argument("--html", type=Path, metavar="FILE", help="write the HTML report")
    parser.add_argument("--sarif", type=Path, metavar="FILE", help="write SARIF 2.1.0")
    parser.add_argument(
        "--baseline", type=Path, metavar="FILE", help="JSON report of accepted findings to hide"
    )
    parser.add_argument(
        "--fail-on",
        type=Severity,
        choices=list(Severity),
        metavar="SEVERITY",
        help="exit 1 if a fail or error at or above this severity remains (low..critical)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="posture",
        description="Read-only security posture audit of Linux, Active Directory and Azure, "
        "mapped to CIS benchmarks and MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="read a system's settings into a snapshot (JSON)")
    _add_source(collect)
    collect.add_argument("-o", "--output", type=Path, help="write the snapshot here, not stdout")

    evaluate = sub.add_parser("evaluate", help="run the checks over a snapshot")
    evaluate.add_argument("snapshot", type=Path, help="snapshot JSON from `posture collect`")
    _add_outputs(evaluate)

    audit = sub.add_parser("audit", help="collect, then evaluate")
    _add_source(audit)
    _add_outputs(audit)

    compare = sub.add_parser("diff", help="new, fixed and unchanged findings between two reports")
    compare.add_argument("old", type=Path, help="earlier JSON report")
    compare.add_argument("new", type=Path, help="later JSON report")
    return parser


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8", newline="\n")


def _collect(args: argparse.Namespace) -> Snapshot:
    if (args.local or args.ssh) and args.platform != "linux":
        raise ValueError("--local and --ssh audit linux hosts")
    if args.ldap and args.platform != "ad":
        raise ValueError("--ldap audits ad")
    if args.winrm and not args.ldap:
        raise ValueError("--winrm goes with --ldap")
    host_runner = None
    if args.ldap:
        if not args.user:
            raise ValueError("--ldap needs --user")
        password = os.environ.get("POSTURE_LDAP_PASSWORD") or getpass.getpass()
        runner = ad.LdapRunner(args.ldap, args.user, password, args.ca_file)
        if args.winrm:
            host_runner = ad.WinrmRunner(args.ldap, args.user, password)
    elif args.local:
        runner = LocalRunner()
    elif args.ssh:
        runner = SshRunner(args.ssh, args.ssh_config)
    else:
        runner = host_runner = ReplayRunner(args.replay)
    if args.platform == "ad":
        snapshot = ad.collect(runner, host_runner, target=args.target, record_dir=args.record)
    else:
        snapshot = linux.collect(runner, target=args.target or args.ssh, record_dir=args.record)
    for error in snapshot.errors:
        print(clean(f"warning: {error.source}: {error.message}"), file=sys.stderr)
    return snapshot


def _evaluate(args: argparse.Namespace, snapshot: Snapshot) -> int:
    checks = load_checks(args.checks)
    findings = evaluate_all(checks, snapshot)
    if args.baseline:
        findings = apply_baseline(findings, load_report(args.baseline))
    report = build_report(snapshot, findings)
    if args.json:
        _write(args.json, report.model_dump_json(indent=2))
    if args.html:
        _write(args.html, render_html(report))
    if args.sarif:
        _write(args.sarif, render_sarif(report, checks))
    print(summary(report))
    if not snapshot.facts:
        print("error: nothing could be collected from the target", file=sys.stderr)
        return EXIT_USAGE
    if args.fail_on and (blocking := gate(findings, args.fail_on)):
        print(f"gate: {len(blocking)} finding(s) at or above {args.fail_on}", file=sys.stderr)
        return EXIT_GATE
    return 0


def _diff(args: argparse.Namespace) -> int:
    for name, findings in diff(load_report(args.old), load_report(args.new)).items():
        print(f"{name} ({len(findings)})")
        for f in findings:
            print(clean(f"  {f.status:<5}  {f.severity:<8}  {f.check_id:<14}  {f.target}"))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "collect":
            text = _collect(args).model_dump_json(indent=2)
            if args.output:
                _write(args.output, text)
            else:
                print(text)
        elif args.command == "evaluate":
            snapshot = Snapshot.model_validate_json(args.snapshot.read_text(encoding="utf-8"))
            return _evaluate(args, snapshot)
        elif args.command == "audit":
            return _evaluate(args, _collect(args))
        elif args.command == "diff":
            return _diff(args)
    except (CheckError, OSError, ValueError) as exc:
        # pydantic's ValidationError is a ValueError: a bad snapshot or report lands here too.
        print(clean(f"error: {exc}"), file=sys.stderr)
        return EXIT_USAGE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
