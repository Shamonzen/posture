import argparse

from posture import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="posture",
        description="Read-only security posture audit of Linux, Active Directory and Azure, "
        "mapped to CIS benchmarks and MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
