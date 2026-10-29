import pytest
from conftest import make_check, make_snapshot

from posture.engine import EVIDENCE_CAP, evaluate, evaluate_all
from posture.models import Status


def run(check, facts, **overrides):
    return evaluate(make_check(check, **overrides), make_snapshot(facts))


@pytest.mark.parametrize(
    ("op", "value", "actual", "status"),
    [
        ("eq", "no", "no", Status.PASS),
        ("eq", "no", "yes", Status.FAIL),
        ("ne", "yes", "no", Status.PASS),
        ("ne", "yes", "yes", Status.FAIL),
        ("in", ["no", "prohibit-password"], "no", Status.PASS),
        ("in", ["no", "prohibit-password"], "yes", Status.FAIL),
        ("not_in", ["yes"], "no", Status.PASS),
        ("not_in", ["yes"], "yes", Status.FAIL),
        ("lt", 5, 4, Status.PASS),
        ("lt", 5, 5, Status.FAIL),
        ("le", 5, 5, Status.PASS),
        ("le", 5, 6, Status.FAIL),
        ("gt", 13, 14, Status.PASS),
        ("gt", 13, 13, Status.FAIL),
        ("ge", 14, 14, Status.PASS),
        ("ge", 14, 8, Status.FAIL),
        ("regex", r"^aes\d+-gcm", "aes256-gcm@openssh.com", Status.PASS),
        ("regex", r"^aes\d+-gcm", "3des-cbc", Status.FAIL),
        ("contains", "use_pty", ["env_reset", "use_pty"], Status.PASS),
        ("contains", "use_pty", ["env_reset"], Status.FAIL),
        ("any_match", "^logfile=", ["logfile=/var/log/sudo.log"], Status.PASS),
        ("any_match", "^logfile=", [], Status.FAIL),
        ("none_match", "-cbc$", ["aes128-ctr"], Status.PASS),
        ("none_match", "-cbc$", ["aes128-ctr", "aes128-cbc"], Status.FAIL),
        ("subset", ["/usr/bin/su", "/usr/bin/sudo"], ["/usr/bin/su"], Status.PASS),
        ("subset", ["/usr/bin/su"], ["/usr/bin/su", "/usr/bin/find"], Status.FAIL),
    ],
)
def test_operators(op, value, actual, status):
    assert run({"fact": "x", "op": op, "value": value}, {"x": actual}).status == status


@pytest.mark.parametrize("op", ["contains", "any_match", "none_match", "subset"])
def test_list_ops_refuse_strings(op):
    # "use_pty" in "nouse_ptyx" would be a substring test: a string is an error, not a list.
    value = ["x"] if op == "subset" else "x"
    assert run({"fact": "x", "op": op, "value": value}, {"x": "x"}).status == Status.ERROR


@pytest.mark.parametrize(
    ("op", "value", "actual", "offenders"),
    [
        (
            "none_match",
            "-cbc$",
            ["aes128-ctr", "aes128-cbc", "aes256-cbc"],
            ["aes128-cbc", "aes256-cbc"],
        ),
        ("subset", ["/usr/bin/su"], ["/usr/bin/su", "/usr/bin/find"], ["/usr/bin/find"]),
    ],
)
def test_failed_list_ops_show_only_offenders(op, value, actual, offenders):
    finding = run({"fact": "x", "op": op, "value": value}, {"x": actual})
    assert finding.evidence == [{"fact": "x", "value": offenders}]


@pytest.mark.parametrize(
    ("op", "facts", "status"),
    [
        ("exists", {"x": None}, Status.PASS),
        ("exists", {}, Status.FAIL),
        ("empty", {"x": []}, Status.PASS),
        ("empty", {"x": ["root"]}, Status.FAIL),
        ("not_empty", {"x": ["rule"]}, Status.PASS),
        ("not_empty", {"x": ""}, Status.FAIL),
    ],
)
def test_operators_without_value(op, facts, status):
    assert run({"fact": "x", "op": op}, facts).status == status


def test_dotted_path_and_evidence():
    finding = run(
        {"fact": "ssh.permitrootlogin", "op": "eq", "value": "no"},
        {"ssh": {"permitrootlogin": "yes"}},
    )
    assert finding.status == Status.FAIL
    assert finding.evidence == [{"fact": "ssh.permitrootlogin", "value": "yes"}]


def test_missing_fact_is_error_not_pass():
    finding = run({"fact": "ssh.permitrootlogin", "op": "ne", "value": "yes"}, {"ssh": {}})
    assert finding.status == Status.ERROR
    assert "ssh.permitrootlogin" in finding.message
    assert finding.evidence == []


@pytest.mark.parametrize(
    ("check", "actual"),
    [
        ({"fact": "x", "op": "lt", "value": 5}, "abc"),
        ({"fact": "x", "op": "regex", "value": "a"}, 5),
        ({"fact": "x", "op": "empty"}, None),
    ],
)
def test_wrong_type_is_error(check, actual):
    assert run(check, {"x": actual}).status == Status.ERROR


def test_all_and_any():
    facts = {"a": 1, "b": 2}
    both = {"all": [{"fact": "a", "op": "eq", "value": 1}, {"fact": "b", "op": "eq", "value": 3}]}
    either = {"any": [{"fact": "a", "op": "eq", "value": 1}, {"fact": "b", "op": "eq", "value": 3}]}
    assert run(both, facts).status == Status.FAIL
    assert run(either, facts).status == Status.PASS


def test_any_with_uncollected_branch_is_error():
    either = {
        "any": [{"fact": "a", "op": "eq", "value": 1}, {"fact": "gone", "op": "eq", "value": 1}]
    }
    assert run(either, {"a": 1}).status == Status.ERROR


KERBEROASTABLE = {
    "for_each": "ad.users",
    "key": "sam",
    "where": {
        "all": [{"fact": "enabled", "op": "eq", "value": True}, {"fact": "spns", "op": "not_empty"}]
    },
}


def test_for_each_lists_offenders():
    users = [
        {"sam": "svc_sql", "enabled": True, "spns": ["MSSQLSvc/db1"]},
        {"sam": "alice", "enabled": True, "spns": []},
        {"sam": "old_svc", "enabled": False, "spns": ["HTTP/web1"]},
    ]
    finding = run(KERBEROASTABLE, {"ad": {"users": users}}, platform="ad")
    assert finding.status == Status.FAIL
    assert finding.evidence == ["svc_sql"]


def test_for_each_no_offenders_passes():
    finding = run(KERBEROASTABLE, {"ad": {"users": []}}, platform="ad")
    assert finding.status == Status.PASS


def test_for_each_item_missing_field_is_error():
    users = [{"sam": "alice", "enabled": True}]
    assert run(KERBEROASTABLE, {"ad": {"users": users}}, platform="ad").status == Status.ERROR


def test_for_each_not_a_list_is_error():
    assert run(KERBEROASTABLE, {"ad": {"users": "x"}}, platform="ad").status == Status.ERROR


def test_evidence_is_capped():
    users = [{"sam": f"u{i}", "enabled": True, "spns": ["s"]} for i in range(EVIDENCE_CAP + 7)]
    finding = run(KERBEROASTABLE, {"ad": {"users": users}}, platform="ad")
    assert len(finding.evidence) == EVIDENCE_CAP
    assert finding.message == "7 more not shown"


def test_applies_to_skips():
    check = {"fact": "ufw.active", "op": "eq", "value": True}
    finding = run(check, {"distro": "rocky"}, applies_to={"distro": ["ubuntu"]})
    assert finding.status == Status.SKIP


def test_applies_to_unknown_is_error():
    check = {"fact": "ufw.active", "op": "eq", "value": True}
    assert run(check, {}, applies_to={"distro": ["ubuntu"]}).status == Status.ERROR


def test_evaluate_all_only_runs_the_snapshots_platform():
    linux = make_check({"fact": "x", "op": "exists"})
    azure = make_check({"fact": "x", "op": "exists"}, id="AZ-TEST-001", platform="azure")
    findings = evaluate_all([linux, azure], make_snapshot({"x": 1}))
    assert [f.check_id for f in findings] == ["LNX-TEST-001"]
