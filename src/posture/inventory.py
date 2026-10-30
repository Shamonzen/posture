"""An inventory: several targets audited in one run, each described like the CLI's own options."""

from pathlib import Path

import yaml
from pydantic import ValidationError, model_validator

from posture.models import Platform, Strict

SOURCES = ("local", "ssh", "ldap", "subscription", "replay")


class InventoryTarget(Strict):
    """The same fields as `posture audit PLATFORM ...`; paths relative to the inventory file."""

    platform: Platform
    target: str | None = None
    local: bool = False
    ssh: str | None = None
    ssh_config: Path | None = None
    ldap: str | None = None
    user: str | None = None
    ca_file: Path | None = None
    winrm: bool = False
    subscription: str | None = None
    replay: Path | None = None

    @model_validator(mode="after")
    def _one_source(self) -> "InventoryTarget":
        given = [s for s in SOURCES if getattr(self, s)]
        if len(given) != 1:
            raise ValueError(f"needs exactly one of {', '.join(SOURCES)} (got {given or 'none'})")
        return self


class Inventory(Strict):
    targets: list[InventoryTarget]


def load_inventory(path: Path) -> list[InventoryTarget]:
    try:
        inventory = Inventory.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, ValidationError) as exc:
        raise ValueError(f"{path}: {exc}") from exc
    if not inventory.targets:
        raise ValueError(f"{path}: no targets")
    base = path.parent
    return [
        t.model_copy(
            update={
                f: base / getattr(t, f)
                for f in ("ssh_config", "ca_file", "replay")
                if getattr(t, f)
            }
        )
        for t in inventory.targets
    ]
