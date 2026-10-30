import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from posture.cli import main
from posture.collectors import azure
from posture.collectors.transport import ReplayRunner, Result
from posture.parsers import azure as p

RECORDINGS = Path(__file__).parent / "fixtures" / "recordings"
SUB = "00000000-0000-0000-0000-000000000001"
WEAK = azure.collect(ReplayRunner(RECORDINGS / "azure-weak"))
HARDENED = azure.collect(ReplayRunner(RECORDINGS / "azure-hardened"))


class FakeCredential:
    def __init__(self):
        self.scopes = []

    def get_token(self, scope):
        self.scopes.append(scope)
        return SimpleNamespace(token=f"token-for-{scope}")


def _runner(handler):
    return azure.AzureRunner(SUB, FakeCredential(), httpx.MockTransport(handler))


def _request(name):
    return next(r for r in azure.REQUESTS if r.name == name)


def test_replay_azure_weak():
    assert WEAK.errors == []
    assert (WEAK.platform, WEAK.target) == ("azure", "posture-lab-weak")
    assert WEAK.facts["identity"] == {
        "security_defaults": False,
        "admin_mfa_enforced": False,  # the only MFA policy is report-only
        "legacy_auth_blocked": False,
    }
    assert WEAK.facts["guests"] == {"invites_from": "everyone", "directory_access": "member"}
    legacy = {a["name"]: a for a in WEAK.facts["storage_accounts"]}["posturelabweaklegacy"]
    assert (legacy["public_blob_access"], legacy["min_tls_version"]) == (True, "TLS1_0")
    exposed = {(e["nsg"], e["port"]) for e in WEAK.facts["network"]["exposed_admin_ports"]}
    assert ("posture-lab-vm-nsg", 22) in exposed and ("posture-lab-vm-nsg", 5986) in exposed
    assert ("posture-lab-vm-nsg", 3306) not in exposed  # 443 and the listed ports only
    assert len(WEAK.facts["global_admins"]) == 5
    assert WEAK.facts["activity_log"]["exported"] is False


def test_replay_azure_hardened():
    assert HARDENED.errors == []
    assert HARDENED.facts["identity"]["admin_mfa_enforced"] is True
    assert HARDENED.facts["identity"]["legacy_auth_blocked"] is True
    assert HARDENED.facts["network"]["exposed_admin_ports"] == []  # SSH from one range only
    assert {d["tier"] for d in HARDENED.facts["defender_plans"]} == {"Standard"}


def test_record_then_replay_round_trip(tmp_path):
    first = azure.collect(ReplayRunner(RECORDINGS / "azure-weak"), record_dir=tmp_path)
    assert first.facts == azure.collect(ReplayRunner(tmp_path)).facts


def _policy(**overrides):
    policy = {
        "displayName": "p",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["all"],
        },
        "grantControls": {"builtInControls": ["mfa"]},
    }
    return policy | overrides


@pytest.mark.parametrize(
    ("defaults", "policies", "expected"),
    [
        (True, None, True),  # Security Defaults alone is enough, even if CA can't be read
        (False, [_policy()], True),
        (False, [_policy(state="enabledForReportingButNotEnforced")], False),
        (False, [], False),
        (False, None, "missing"),  # CA unreadable and no Security Defaults: unknown, not a pass
        (None, [], "missing"),
    ],
)
def test_security_defaults_or_conditional_access(defaults, policies, expected):
    facts = {}
    if defaults is not None:
        facts["identity"] = {"security_defaults": defaults}
    if policies is not None:
        facts.update(p.conditional_access(Result(json.dumps(policies))))
    p.derive(facts)
    assert facts.get("identity", {}).get("admin_mfa_enforced", "missing") == expected


@pytest.mark.parametrize(
    ("rule", "ports"),
    [
        ({"sourceAddressPrefix": "Internet", "destinationPortRange": "20-23"}, [22]),
        ({"sourceAddressPrefixes": ["10.0.0.0/8", "*"], "destinationPortRange": "3389"}, [3389]),
        ({"sourceAddressPrefix": "10.0.0.0/8", "destinationPortRange": "*"}, []),
        ({"sourceAddressPrefix": "*", "destinationPortRange": "22", "access": "Deny"}, []),
        ({"sourceAddressPrefix": "*", "destinationPortRange": "22", "direction": "Outbound"}, []),
    ],
)
def test_nsg_exposed_admin_ports(rule, ports):
    props = {"direction": "Inbound", "access": "Allow"} | rule
    nsg = {"name": "n", "properties": {"securityRules": [{"name": "r", "properties": props}]}}
    exposed = p.nsgs(Result(json.dumps([nsg])))["network"]["exposed_admin_ports"]
    assert [e["port"] for e in exposed] == ports


def test_graph_and_arm_paging_are_followed():
    pages = {
        "/v1.0/identity/conditionalAccess/policies": {
            "value": [1],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=x",
        },
        "/subscriptions/" + SUB + "/providers/Microsoft.Network/networkSecurityGroups": {
            "value": [3],
            "nextLink": f"https://management.azure.com/subscriptions/{SUB}/nsgs-page2",
        },
        f"/subscriptions/{SUB}/nsgs-page2": {"value": [4]},
    }
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.params.get("$skiptoken"):
            return httpx.Response(200, json={"value": [2]})
        return httpx.Response(200, json=pages[request.url.path])

    runner = _runner(handler)
    assert json.loads(runner.run(_request("conditional_access")).stdout) == [1, 2]
    assert json.loads(runner.run(_request("nsgs")).stdout) == [3, 4]
    tokens = {r.url.host: r.headers["Authorization"] for r in seen}
    assert tokens == {
        "graph.microsoft.com": "Bearer token-for-https://graph.microsoft.com/.default",
        "management.azure.com": "Bearer token-for-https://management.azure.com/.default",
    }


def test_paging_link_to_another_host_is_refused():
    hosts = []

    def handler(request):
        hosts.append(request.url.host)
        return httpx.Response(200, json={"value": [], "nextLink": "https://evil.example.test/x"})

    result = _runner(handler).run(_request("nsgs"))
    assert result.exit_code == 1 and "refused a paging link" in result.stderr
    assert hosts == ["management.azure.com"]  # the token never left for the other host


def test_throttling_is_retried_after_the_wait(monkeypatch):
    waits = []
    monkeypatch.setattr(azure.time, "sleep", waits.append)
    replies = iter(
        [
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(503, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
            httpx.Response(200, json={"isEnabled": True}),
        ]
    )
    result = _runner(lambda request: next(replies)).run(_request("security_defaults"))
    assert json.loads(result.stdout) == {"isEnabled": True}
    assert waits == [7.0, 2.0]  # an HTTP-date Retry-After falls back to backoff


def test_throttling_gives_up_after_the_retries(monkeypatch):
    monkeypatch.setattr(azure.time, "sleep", lambda s: None)
    result = _runner(lambda request: httpx.Response(429)).run(_request("security_defaults"))
    assert result.exit_code == 1 and result.stderr.startswith("HTTP 429")


def test_http_errors_become_collection_errors():
    body = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
    runner = _runner(lambda request: httpx.Response(403, json=body))
    snap = azure.collect(runner)
    errors = {e.source: e.message for e in snap.errors}
    assert errors["conditional_access"] == (
        "HTTP 403: Authorization_RequestDenied: Insufficient privileges"
    )
    assert len(errors) == len(azure.REQUESTS) and snap.target == "unknown"
    assert "admin_mfa_enforced" not in snap.facts.get("identity", {})


def test_oversized_response_is_an_error(monkeypatch):
    monkeypatch.setattr(azure, "MAX_OUTPUT", 100)
    runner = _runner(lambda request: httpx.Response(200, json={"value": ["x" * 200]}))
    snap = azure.collect(runner)
    assert any("response over 100 bytes" in e.message for e in snap.errors)


@pytest.mark.parametrize("sub", ["", "not-a-guid", "../../providers/x", f"{SUB}/../x"])
def test_subscription_must_be_a_guid(sub):
    with pytest.raises(ValueError, match="expected a GUID"):
        azure.AzureRunner(sub, FakeCredential())


def test_cli_collect_azure_replay(tmp_path):
    out = tmp_path / "snap.json"
    replay = str(RECORDINGS / "azure-weak")
    assert main(["collect", "azure", "--replay", replay, "-o", str(out)]) == 0
    assert json.loads(out.read_text())["platform"] == "azure"


def test_cli_rejects_subscription_for_other_platforms(capsys):
    assert main(["collect", "linux", "--subscription", SUB]) == 2
    assert "--subscription audits azure" in capsys.readouterr().err
