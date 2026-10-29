import hashlib
import operator
import re
from collections.abc import Callable
from typing import Any

from posture.models import AllOf, AnyOf, Check, Compare, Finding, ForEach, Snapshot, Status

EVIDENCE_CAP = 50
_MISSING = object()


def _items(actual: Any) -> list[Any]:
    """List ops on a string would silently do substring tests: refuse anything but a list."""
    if not isinstance(actual, list):
        raise TypeError(f"expected a list, got {type(actual).__name__}")
    return actual


OPS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": operator.eq,
    "ne": operator.ne,
    "in": lambda actual, value: actual in value,
    "not_in": lambda actual, value: actual not in value,
    "lt": operator.lt,
    "le": operator.le,
    "gt": operator.gt,
    "ge": operator.ge,
    "regex": lambda actual, value: re.search(value, actual) is not None,
    "empty": lambda actual, _: len(actual) == 0,
    "not_empty": lambda actual, _: len(actual) > 0,
    "contains": lambda actual, value: value in _items(actual),
    "any_match": lambda actual, value: any(re.search(value, x) for x in _items(actual)),
    "none_match": lambda actual, value: not any(re.search(value, x) for x in _items(actual)),
    "subset": lambda actual, value: all(x in value for x in _items(actual)),
}
# On failure, these show only the items at fault (e.g. the weak ciphers), not the whole list.
OFFENDERS: dict[str, Callable[[Any, Any], list[Any]]] = {
    "none_match": lambda actual, value: [x for x in actual if re.search(value, x)],
    "subset": lambda actual, value: [x for x in actual if x not in value],
}


class FactError(Exception):
    """A fact is missing or has the wrong type, so the check can't be decided."""


def resolve(data: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(data, dict) or part not in data:
            return _MISSING
        data = data[part]
    return data


def _require(data: Any, path: str) -> Any:
    value = resolve(data, path)
    if value is _MISSING:
        raise FactError(f"fact {path!r} was not collected")
    return value


def _compare(cond: Compare, data: Any, evidence: list[Any]) -> bool:
    actual = resolve(data, cond.fact)
    if cond.op == "exists":
        return actual is not _MISSING
    if actual is _MISSING:
        raise FactError(f"fact {cond.fact!r} was not collected")
    try:
        ok = OPS[cond.op](actual, cond.value)
    except TypeError as exc:
        raise FactError(f"fact {cond.fact!r}: can't apply {cond.op} to {actual!r}") from exc
    if not ok and cond.op in OFFENDERS:
        actual = OFFENDERS[cond.op](actual, cond.value)
    evidence.append({"fact": cond.fact, "value": actual})
    return ok


def _holds(cond: Any, data: Any, evidence: list[Any]) -> bool:
    match cond:
        case Compare():
            return _compare(cond, data, evidence)
        case AllOf():
            # No short-circuit: every branch runs, so an uncollected fact is always an error.
            return all([_holds(c, data, evidence) for c in cond.all])
        case AnyOf():
            return any([_holds(c, data, evidence) for c in cond.any])
        case ForEach():
            items = _require(data, cond.for_each)
            if not isinstance(items, list):
                raise FactError(f"fact {cond.for_each!r} is not a list")
            offenders = [item for item in items if _holds(cond.where, item, [])]
            evidence.extend(_require(item, cond.key) for item in offenders)
            return not offenders
    raise TypeError(f"unknown condition {cond!r}")


def _applies(check: Check, facts: dict[str, Any]) -> bool:
    return all(_require(facts, path) in allowed for path, allowed in check.applies_to.items())


def evaluate(check: Check, snapshot: Snapshot) -> Finding:
    evidence: list[Any] = []
    message = None
    try:
        if _applies(check, snapshot.facts):
            ok = _holds(check.check, snapshot.facts, evidence)
            status = Status.PASS if ok else Status.FAIL
        else:
            status = Status.SKIP
    except FactError as exc:
        status, message, evidence = Status.ERROR, str(exc), []
    # The resource is who offends (for_each keys), never an observed value such as a package
    # count, so a baseline entry survives that number moving.
    resource = sorted(map(str, evidence)) if isinstance(check.check, ForEach) else []
    fingerprint = hashlib.sha256(
        "\0".join([check.id, snapshot.target, *resource]).encode()
    ).hexdigest()
    if len(evidence) > EVIDENCE_CAP:
        message = f"{len(evidence) - EVIDENCE_CAP} more not shown"
        evidence = evidence[:EVIDENCE_CAP]
    return Finding(
        check_id=check.id,
        title=check.title,
        platform=check.platform,
        target=snapshot.target,
        status=status,
        severity=check.severity,
        cis=check.cis,
        attack=check.attack,
        rationale=check.rationale,
        remediation=check.remediation,
        references=check.references,
        evidence=evidence,
        message=message,
        fingerprint=fingerprint,
    )


def evaluate_all(checks: list[Check], snapshot: Snapshot) -> list[Finding]:
    return [evaluate(check, snapshot) for check in checks if check.platform == snapshot.platform]
