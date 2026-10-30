import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Discriminator, Field, PrivateAttr, Tag, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Status(StrEnum):
    # A check status, not a password.
    PASS = "pass"  # noqa: S105  # nosec B105
    FAIL = "fail"
    ERROR = "error"  # the facts needed were not collected: never counted as a pass
    SKIP = "skip"  # applies_to did not match this target


Platform = Literal["linux", "ad", "azure"]
Op = Literal[
    "eq", "ne", "in", "not_in", "lt", "le", "gt", "ge", "regex", "exists", "empty", "not_empty",
    "contains", "any_match", "none_match", "subset",
]  # fmt: skip
NO_VALUE_OPS = {"exists", "empty", "not_empty"}
NUMBER_OPS = {"lt", "le", "gt", "ge"}
LIST_VALUE_OPS = {"in", "not_in", "subset"}
REGEX_OPS = {"regex", "any_match", "none_match"}


class Compare(Strict):
    fact: str
    op: Op
    value: Any = None

    @model_validator(mode="after")
    def _value_fits_op(self) -> "Compare":
        given = "value" in self.model_fields_set
        if self.op in NO_VALUE_OPS:
            if given:
                raise ValueError(f"op {self.op} takes no value")
            return self
        if not given:
            raise ValueError(f"op {self.op} needs a value")
        if self.op in LIST_VALUE_OPS and not isinstance(self.value, list):
            raise ValueError(f"op {self.op} needs a list value")
        if self.op in NUMBER_OPS and (
            isinstance(self.value, bool) or not isinstance(self.value, int | float)
        ):
            raise ValueError(f"op {self.op} needs a number value")
        if self.op in REGEX_OPS:
            if not isinstance(self.value, str):
                raise ValueError(f"op {self.op} needs a string value")
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError(f"bad regex {self.value!r}: {exc}") from exc
        return self


class AllOf(Strict):
    all: list["Condition"] = Field(min_length=1)


class AnyOf(Strict):
    any: list["Condition"] = Field(min_length=1)


class ForEach(Strict):
    """Every item of the list `for_each` that matches `where` is an offender, named by `key`."""

    for_each: str
    key: str
    where: "Condition"


def _condition_kind(value: Any) -> str:
    if isinstance(value, dict):
        return next((k for k in ("for_each", "all", "any") if k in value), "fact")
    return {AllOf: "all", AnyOf: "any", ForEach: "for_each"}.get(type(value), "fact")


# Picked by key, so a typo in a check reports one clear error instead of one per union member.
Condition = Annotated[
    Annotated[Compare, Tag("fact")]
    | Annotated[AllOf, Tag("all")]
    | Annotated[AnyOf, Tag("any")]
    | Annotated[ForEach, Tag("for_each")],
    Discriminator(_condition_kind),
]
for _model in (AllOf, AnyOf, ForEach):
    _model.model_rebuild()


# Benchmarks a check can cite, as `cis: {<key>: "<control id>"}`. Control IDs are taken from the
# benchmark itself or its ansible-lockdown implementation; the benchmark text is never copied.
BENCHMARKS = {
    "ubuntu-24.04": "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0",
    # Rocky Linux 9 is audited with RHEL 9 numbering (ansible-lockdown RHEL9-CIS supports Rocky).
    "rhel-9": "CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0",
    # Numbering as in ansible-lockdown Windows-2019-CIS; DC-only controls included.
    "windows-server-2019": "CIS Microsoft Windows Server 2019 Benchmark v4.0.0",
    # Azure and Entra ID numbering as mapped in Prowler's compliance files (cis_3.0_azure,
    # cis_4.0_m365); Entra items not in the Azure benchmark cite the Microsoft 365 one.
    "azure": "CIS Microsoft Azure Foundations Benchmark v3.0.0",
    "m365": "CIS Microsoft 365 Foundations Benchmark v4.0.0",
}
Benchmark = Literal["ubuntu-24.04", "rhel-9", "windows-server-2019", "azure", "m365"]
ControlId = Annotated[str, Field(pattern=r"^\d+(\.\d+)+$")]
Cis = dict[Benchmark, ControlId]


class Remediation(Strict):
    text: str
    script: str | None = None


AttackId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]


class Check(Strict):
    id: str = Field(pattern=r"^[A-Z]+(-[A-Z0-9]+)+$")
    title: str
    platform: Platform
    applies_to: dict[str, list[Any]] = {}
    cis: Annotated[Cis, Field(min_length=1)] | None  # required: null = "no CIS control"
    severity: Severity
    attack: list[AttackId] = Field(min_length=1)
    rationale: str
    check: Condition
    remediation: Remediation
    references: list[str] = []
    _source: tuple[str, int] = PrivateAttr(default=("checks", 1))  # (yaml file, line), for SARIF

    @model_validator(mode="after")
    def _source_given(self) -> "Check":
        if self.cis is None and not self.references:
            raise ValueError("a check without a CIS control needs references")
        return self


class CollectError(Strict):
    source: str
    message: str


class Snapshot(Strict):
    schema_version: Literal[1] = 1
    tool_version: str
    platform: Platform
    target: str
    collected_at: datetime
    identity: str | None = None
    facts: dict[str, Any]
    errors: list[CollectError] = []


class Finding(Strict):
    check_id: str
    title: str
    platform: Platform
    target: str
    status: Status
    severity: Severity
    cis: Cis | None
    attack: list[str]
    rationale: str
    remediation: Remediation
    references: list[str]
    evidence: list[Any] = []
    message: str | None = None
    fingerprint: str  # sha256(check_id, target, resource): stable across runs, for baselines


class Report(Strict):
    """The JSON report, which is also the baseline format."""

    schema_version: Literal[1] = 1
    tool_version: str
    snapshot: Snapshot  # facts dropped: the snapshot file is the evidence, not the report
    findings: list[Finding]
