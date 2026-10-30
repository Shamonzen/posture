"""Turn the recorded ARM and Graph responses into facts. Every parser takes a Result whose stdout
is the JSON the Azure runner wrote: the merged `value` list of a collection (all pages), or the
single object for a singleton such as a policy."""

import json
from typing import Any

from posture.collectors.transport import Result

Facts = dict[str, Any]

GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10"
# authorizationPolicy.guestUserRoleId: what guests can read in the directory.
GUEST_ROLES = {
    "a0b1b346-4d3e-4e8b-98f8-753987be4970": "member",  # same access as members
    "10dae51f-b6af-4016-8d66-8c2a99b929b3": "limited",  # the default
    "2af84b1e-32c8-42b7-82bc-daa82404023b": "restricted",
}
# Inbound ports that give a shell, a desktop or a database to whoever reaches them.
ADMIN_PORTS = {22: "ssh", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5985: "winrm", 5986: "winrm"}
ANY_SOURCE = {"*", "any", "internet", "0.0.0.0/0", "::/0"}
LEGACY_CLIENTS = {"exchangeActiveSync", "other"}


def _object(r: Result) -> dict[str, Any]:
    data = json.loads(r.stdout)
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


def _list(r: Result) -> list[dict[str, Any]]:
    data = json.loads(r.stdout)
    if not isinstance(data, list):
        raise ValueError("expected a list")
    return data


def subscription(r: Result) -> Facts:
    s = _object(r)
    return {
        "subscription": {"id": s["subscriptionId"], "name": s["displayName"], "state": s["state"]}
    }


def storage_accounts(r: Result) -> Facts:
    accounts = []
    for a in _list(r):
        props = a["properties"]
        accounts.append(
            {
                "name": a["name"],
                # Absent on accounts older than the setting, which then allowed public access.
                "public_blob_access": props.get("allowBlobPublicAccess", True),
                "https_only": props.get("supportsHttpsTrafficOnly", False),
                "min_tls_version": props.get("minimumTlsVersion", "TLS1_0"),  # absent = TLS 1.0
            }
        )
    return {"storage_accounts": accounts}


def _covers(port_range: str, port: int) -> bool:
    if port_range == "*":
        return True
    low, _, high = port_range.partition("-")
    return int(low) <= port <= int(high or low)


def nsgs(r: Result) -> Facts:
    """Inbound Allow rules from anywhere to an admin port, one entry per (rule, port).

    shortcut: a higher-priority Deny for the same port is not subtracted, so such a rule is
    reported anyway; compare priorities if real NSGs show that pattern.
    """
    groups, exposed = _list(r), []
    for nsg in groups:
        for rule in nsg.get("properties", {}).get("securityRules", []):
            props = rule["properties"]
            if (props["direction"], props["access"]) != ("Inbound", "Allow"):
                continue
            sources = [props.get("sourceAddressPrefix"), *props.get("sourceAddressPrefixes", [])]
            if not any(s and s.lower() in ANY_SOURCE for s in sources):
                continue
            ranges = [props.get("destinationPortRange"), *props.get("destinationPortRanges", [])]
            for port, service in ADMIN_PORTS.items():
                if any(pr and _covers(pr, port) for pr in ranges):
                    exposed.append(
                        {"nsg": nsg["name"], "rule": rule["name"], "port": port, "service": service}
                    )
    return {"network": {"nsg_count": len(groups), "exposed_admin_ports": exposed}}


def diagnostic_settings(r: Result) -> Facts:
    exporting = [
        s["name"]
        for s in _list(r)
        if any(log.get("enabled") for log in s.get("properties", {}).get("logs", []))
    ]
    return {"activity_log": {"exported": bool(exporting), "settings": exporting}}


def defender_plans(r: Result) -> Facts:
    plans = [{"name": p["name"], "tier": p["properties"]["pricingTier"]} for p in _list(r)]
    return {"defender_plans": plans}


def security_defaults(r: Result) -> Facts:
    return {"identity": {"security_defaults": bool(_object(r)["isEnabled"])}}


def _policy(policy: dict[str, Any]) -> Facts:
    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    grant = policy.get("grantControls") or {}
    controls = set(grant.get("builtInControls") or [])
    return {
        "name": policy["displayName"],
        "enabled": policy["state"] == "enabled",  # report-only enforces nothing
        "all_users": "All" in (users.get("includeUsers") or []),
        "global_admins": GLOBAL_ADMIN_ROLE in (users.get("includeRoles") or []),
        "all_apps": "All"
        in ((conditions.get("applications") or {}).get("includeApplications") or []),
        "legacy_clients": set(conditions.get("clientAppTypes") or []) >= LEGACY_CLIENTS,
        "requires_mfa": "mfa" in controls or bool(grant.get("authenticationStrength")),
        "blocks": "block" in controls,
        "exclusions": sorted(
            (users.get("excludeUsers") or [])
            + (users.get("excludeGroups") or [])
            + (users.get("excludeRoles") or [])
        ),
    }


def conditional_access(r: Result) -> Facts:
    return {"conditional_access": [_policy(p) for p in _list(r)]}


def authorization_policy(r: Result) -> Facts:
    policy = _object(r)
    return {
        "guests": {
            "invites_from": policy["allowInvitesFrom"],
            "directory_access": GUEST_ROLES.get(policy["guestUserRoleId"], "unknown"),
        }
    }


def global_admins(r: Result) -> Facts:
    """shortcut: every active assignment counts as permanent, PIM activations included; read
    roleAssignmentSchedules (needs Entra ID P2) to tell them apart."""
    admins = []
    for assignment in _list(r):
        principal = assignment.get("principal") or {}
        kind = principal.get("@odata.type", "").removeprefix("#microsoft.graph.")
        name = principal.get("userPrincipalName") or principal.get("displayName")
        admins.append({"name": name or assignment["principalId"], "type": kind or "unknown"})
    return {"global_admins": sorted(admins, key=lambda a: a["name"].lower())}


def admin_mfa_registration(r: Result) -> Facts:
    admins = [
        {"name": u["userPrincipalName"], "mfa_registered": bool(u["isMfaRegistered"])}
        for u in _list(r)
    ]
    return {"admin_mfa_registration": sorted(admins, key=lambda a: a["name"].lower())}


def derive(facts: Facts) -> None:
    """Security Defaults or an enforced Conditional Access policy: either one counts. With one
    source missing and the other not enforcing, the fact is left out (an error, not a pass)."""
    identity = facts.setdefault("identity", {})
    defaults = identity.get("security_defaults")
    policies = facts.get("conditional_access")
    enforced = [p for p in policies or [] if p["enabled"] and p["all_apps"]]
    mfa = [
        p["name"] for p in enforced if p["requires_mfa"] and (p["all_users"] or p["global_admins"])
    ]
    legacy = [p["name"] for p in enforced if p["blocks"] and p["all_users"] and p["legacy_clients"]]
    for fact, names in (("admin_mfa_enforced", mfa), ("legacy_auth_blocked", legacy)):
        if defaults or names:
            identity[fact] = True
        elif defaults is not None and policies is not None:
            identity[fact] = False
    if not identity:
        facts.pop("identity")
