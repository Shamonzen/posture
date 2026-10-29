from pathlib import Path

import yaml
from pydantic import TypeAdapter, ValidationError

from posture.models import Check

_CHECK_LIST = TypeAdapter(list[Check])


class CheckError(ValueError):
    """A check file is invalid; Posture refuses to start rather than skip it."""


def load_checks(directory: Path) -> list[Check]:
    """Load every `*.yaml` under `directory`; each file is a list of checks."""
    if not directory.is_dir():
        raise CheckError(f"{directory}: not a directory")
    checks: list[Check] = []
    seen: dict[str, Path] = {}
    for path in sorted(directory.rglob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise CheckError(f"{path}: {exc}") from exc
        if not isinstance(data, list):
            raise CheckError(f"{path}: expected a list of checks")
        try:
            file_checks = _CHECK_LIST.validate_python(data)
        except ValidationError as exc:
            raise CheckError(f"{path}: {exc}") from exc
        for check in file_checks:
            if check.id in seen:
                raise CheckError(
                    f"{path}: duplicate check id {check.id} (also in {seen[check.id]})"
                )
            seen[check.id] = path
        checks.extend(file_checks)
    return checks
