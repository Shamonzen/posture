from conftest import make_check, make_snapshot

from posture.baseline import apply_baseline, diff, gate
from posture.engine import evaluate_all
from posture.models import Severity, Status
from posture.reports import build_report

ROOT_LOGIN = make_check({"fact": "ssh.permitrootlogin", "op": "eq", "value": "no"})
UID0 = make_check(
    {"for_each": "users", "key": "name", "where": {"fact": "uid", "op": "eq", "value": 0}},
    id="LNX-TEST-002",
    severity="critical",
)
PENDING = make_check(
    {"fact": "updates.pending", "op": "eq", "value": 0}, id="LNX-TEST-003", severity="low"
)


def _report(root_login="yes", uid0=("toor",), pending=3):
    users = [{"name": "root", "uid": 0}, *({"name": n, "uid": 0} for n in uid0)]
    facts = {
        "ssh": {"permitrootlogin": root_login},
        "users": users,
        "updates": {"pending": pending},
    }
    snapshot = make_snapshot(facts)
    return build_report([snapshot], evaluate_all([ROOT_LOGIN, UID0, PENDING], snapshot))


def _ids(findings):
    return sorted(f.check_id for f in findings)


def test_fingerprint_ignores_observed_values_but_not_offenders():
    a, b, c = _report(pending=3), _report(pending=9), _report(uid0=("toor", "admin2"))
    fps = [{f.check_id: f.fingerprint for f in r.findings} for r in (a, b, c)]
    assert fps[0] == fps[1]  # 3 -> 9 pending updates: still the same finding
    assert fps[0]["LNX-TEST-002"] != fps[2]["LNX-TEST-002"]  # a new UID 0 account is new


def test_diff_new_fixed_unchanged():
    old, new = _report(), _report(root_login="no", uid0=("toor", "admin2"), pending=9)
    result = diff(old, new)
    assert _ids(result["new"]) == ["LNX-TEST-002"]
    assert _ids(result["fixed"]) == ["LNX-TEST-001", "LNX-TEST-002"]
    assert _ids(result["unchanged"]) == ["LNX-TEST-003"]


def test_baseline_hides_only_accepted_failures():
    accepted = _report(uid0=())  # UID 0 check passes here, so it's not accepted
    kept = apply_baseline(_report(pending=9).findings, accepted)
    assert [(f.check_id, f.status) for f in kept] == [("LNX-TEST-002", Status.FAIL)]


def test_gate_counts_errors_and_respects_severity():
    findings = _report().findings
    assert _ids(gate(findings, Severity.HIGH)) == ["LNX-TEST-001", "LNX-TEST-002"]
    assert _ids(gate(findings, Severity.CRITICAL)) == ["LNX-TEST-002"]
    snapshot = make_snapshot({})  # nothing collected: every check is an error, and fails closed
    errors = evaluate_all([ROOT_LOGIN], snapshot)
    assert errors[0].status == Status.ERROR and gate(errors, Severity.HIGH) == errors
