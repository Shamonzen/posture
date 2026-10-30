import ipaddress
import json
from pathlib import Path

import pytest

from posture.cli import main
from posture.collectors import ad
from posture.collectors.transport import ReplayRunner, Result
from posture.parsers import ad as p

RECORDINGS = Path(__file__).parent / "fixtures" / "recordings"
WEAK = ad.collect(ReplayRunner(RECORDINGS / "dc-weak"))
HARDENED = ad.collect(ReplayRunner(RECORDINGS / "dc-hardened"))


def _by_name(snapshot, key):
    return {item["name"]: item for item in snapshot.facts[key]}


def test_replay_dc_weak():
    assert WEAK.errors == []
    assert (WEAK.platform, WEAK.target, WEAK.identity) == (
        "ad",
        "posture-dc.posture.test",
        "POSTURE\\posture",
    )
    domain = WEAK.facts["domain"]
    assert (domain["min_password_length"], domain["lockout_threshold"]) == (7, 0)
    assert domain["reversible_encryption"] is True
    users = _by_name(WEAK, "users")
    assert users["svc-sql"]["spns"] == ["MSSQLSvc/sql01.posture.test:1433"]
    assert users["legacy.app"]["no_preauth"] and users["temp.user"]["password_not_required"]
    assert users["adm.ops"]["password_never_expires"] and users["adm.ops"]["privileged"]
    assert users["old.admin"]["admin_count"] and not users["old.admin"]["privileged"]
    assert users["old.contractor"]["last_logon_days"] is None  # never logged on
    assert not users["krbtgt"]["enabled"]
    computers = _by_name(WEAK, "computers")
    assert computers["ws01$"]["unconstrained_delegation"] and not computers["ws01$"]["dc"]
    assert computers["POSTURE-DC$"]["dc"]
    assert {c["laps"] for c in computers.values()} == {None}
    groups = _by_name(WEAK, "privileged_groups")
    assert groups["Domain Admins"]["members"] == [
        "Administrator",
        "adm.backup",
        "adm.helpdesk",
        "adm.ops",
    ]
    # Domain Admins is nested in BUILTIN\Administrators.
    assert set(groups["Domain Admins"]["members"]) <= set(groups["Administrators"]["members"])
    assert "groups" not in WEAK.facts and "now" in WEAK.facts


def test_replay_dc_hardened():
    assert HARDENED.errors == []
    domain = HARDENED.facts["domain"]
    assert (domain["min_password_length"], domain["lockout_threshold"]) == (14, 5)
    users = _by_name(HARDENED, "users")
    assert [u for u in users.values() if u["spns"] and u["name"] != "krbtgt"] == []
    assert users["svc-sql"]["enc_types"] == ["aes128", "aes256"]
    computers = _by_name(HARDENED, "computers")
    assert (computers["ws01$"]["laps"], computers["ws02$"]["laps"]) == ("windows", "windows")
    groups = _by_name(HARDENED, "privileged_groups")
    assert groups["Domain Admins"]["members"] == ["Administrator", "adm.ops"]


def test_record_then_replay_round_trip(tmp_path):
    first = ad.collect(ReplayRunner(RECORDINGS / "dc-weak"), record_dir=tmp_path)
    second = ad.collect(ReplayRunner(tmp_path))
    assert first.facts == second.facts


def test_privileged_groups_follow_nesting_and_survive_loops():
    domain_sid = "S-1-5-21-1-2-3"
    groups = [
        {"name": "Domain Admins", "dn": "CN=DA", "sid": f"{domain_sid}-512", "member": ["CN=A"]},
        {"name": "A", "dn": "CN=A", "sid": f"{domain_sid}-1101", "member": ["CN=B", "CN=u1"]},
        {"name": "B", "dn": "CN=B", "sid": f"{domain_sid}-1102", "member": ["CN=A", "CN=x"]},
        {"name": "Staff", "dn": "CN=S", "sid": f"{domain_sid}-1103", "member": ["CN=u2"]},
    ]
    accounts = [{"name": "u1", "dn": "cn=u1"}, {"name": "u2", "dn": "CN=u2"}]
    [da] = p.privileged_groups(groups, accounts)
    assert (da["name"], da["members"]) == ("Domain Admins", ["u1"])  # DNs compare case-blind


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (0, None),
        (0x1C, ["rc4", "aes128", "aes256"]),
        (0x3, ["des_cbc_crc", "des_cbc_md5"]),
    ],
)
def test_enc_types(value, expected):
    assert p.enc_types(value) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("0", None), ("9223372036854775807", None), ("116444736000000000", 0)],
)
def test_filetime_never_and_epoch(raw, expected):
    assert p._filetime({"attributes": {"t": [raw]}}, "t") == expected


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = outputs

    def run(self, search):
        return self.outputs.get(search.name, Result("[]", "insufficientAccessRights", 50))


def test_failures_and_bad_output_become_errors():
    snap = ad.collect(FakeRunner({"rootdse": Result("not json")}))
    errors = {e.source: e.message for e in snap.errors}
    assert errors["rootdse"].startswith("parse error")
    assert errors["users"] == "LDAP 50: insufficientAccessRights"
    assert snap.target == "unknown"


def test_certificate_must_name_the_ip():
    cert = {"subjectAltName": (("DNS", "dc.example.test"), ("IP Address", "192.0.2.10"))}
    assert ad._names_ip(cert, ipaddress.ip_address("192.0.2.10"))
    assert not ad._names_ip(cert, ipaddress.ip_address("192.0.2.11"))


def test_cli_collect_ad_replay(tmp_path):
    out = tmp_path / "snap.json"
    assert main(["collect", "ad", "--replay", str(RECORDINGS / "dc-weak"), "-o", str(out)]) == 0
    assert json.loads(out.read_text())["platform"] == "ad"


def test_cli_rejects_mismatched_source(capsys):
    assert main(["collect", "linux", "--ldap", "dc.example.test", "--user", "u"]) == 2
    assert "--ldap audits ad" in capsys.readouterr().err
