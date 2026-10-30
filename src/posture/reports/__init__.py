import re

from posture.models import Finding, Report, Severity, Snapshot, Status

# C0/C1 control characters except tab and newline: a hostile hostname or username can't
# move the cursor, recolor the terminal or hide text.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
FAILING = {Status.FAIL, Status.ERROR}
BY_SEVERITY = sorted(Severity, key=lambda s: s.rank, reverse=True)


def clean(text: str) -> str:
    return _CONTROL.sub("", text)


def build_report(snapshots: list[Snapshot], findings: list[Finding]) -> Report:
    metas = [s.model_copy(update={"facts": {}}) for s in snapshots]
    return Report(tool_version=snapshots[0].tool_version, snapshots=metas, findings=findings)


def summary(report: Report) -> str:
    """The terminal view: per target, what failed or could not be checked, most severe first."""
    lines = []
    for snap in report.snapshots:
        lines.append(
            clean(
                f"{snap.target} ({snap.platform}), collected {snap.collected_at:%Y-%m-%d %H:%M} UTC"
            )
        )
        lines += [clean(f"  collection error: {e.source}: {e.message}") for e in snap.errors]
        mine = [f for f in report.findings if f.target == snap.target]
        shown = sorted(
            (f for f in mine if f.status in FAILING), key=lambda f: (-f.severity.rank, f.check_id)
        )
        lines += [f"  {f.status:<5}  {f.severity:<8}  {f.check_id:<14}  {f.title}" for f in shown]
        counts = {s: sum(f.status == s for f in mine) for s in Status}
        lines.append("  " + ", ".join(f"{n} {s}" for s, n in counts.items()))
    return "\n".join(lines)
