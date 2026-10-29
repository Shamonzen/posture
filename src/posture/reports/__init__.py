import re

from posture.models import Finding, Report, Severity, Snapshot, Status

# C0/C1 control characters except tab and newline: a hostile hostname or username can't
# move the cursor, recolor the terminal or hide text.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
FAILING = {Status.FAIL, Status.ERROR}
BY_SEVERITY = sorted(Severity, key=lambda s: s.rank, reverse=True)


def clean(text: str) -> str:
    return _CONTROL.sub("", text)


def build_report(snapshot: Snapshot, findings: list[Finding]) -> Report:
    meta = snapshot.model_copy(update={"facts": {}})
    return Report(tool_version=snapshot.tool_version, snapshot=meta, findings=findings)


def summary(report: Report) -> str:
    """The terminal view: what failed or could not be checked, most severe first."""
    snap = report.snapshot
    lines = [
        clean(f"{snap.target} ({snap.platform}), collected {snap.collected_at:%Y-%m-%d %H:%M} UTC")
    ]
    lines += [clean(f"  collection error: {e.source}: {e.message}") for e in snap.errors]
    shown = sorted(
        (f for f in report.findings if f.status in FAILING),
        key=lambda f: (-f.severity.rank, f.check_id),
    )
    lines += [f"  {f.status:<5}  {f.severity:<8}  {f.check_id:<14}  {f.title}" for f in shown]
    counts = {s: sum(f.status == s for f in report.findings) for s in Status}
    lines.append("  " + ", ".join(f"{n} {s}" for s, n in counts.items()))
    return "\n".join(lines)
