"""Turn the recorded LDAP searches into facts. Every LDAP parser takes a Result whose stdout is
the JSON the LDAP runner wrote: a list of {"dn", "attributes": {lowercase name: [string, ...]}}.
The registry parsers take the JSON object the WinRM script wrote: value name -> value or null."""

import json
from datetime import UTC, datetime
from typing import Any

from posture.collectors.transport import Result

Facts = dict[str, Any]

# userAccountControl bits (MS-ADTS 2.2.16) that checks care about.
UAC = {
    "disabled": 0x2,
    "password_not_required": 0x20,  # nosec B105: flag names, not passwords
    "reversible_password": 0x80,  # nosec B105
    "dc": 0x2000,
    "password_never_expires": 0x10000,  # nosec B105
    "unconstrained_delegation": 0x80000,
    "not_delegated": 0x100000,
    "des_only": 0x200000,
    "no_preauth": 0x400000,
    "protocol_transition": 0x1000000,
}
# msDS-SupportedEncryptionTypes bits (MS-KILE 2.2.7).
ENC_TYPES = {"des_cbc_crc": 0x1, "des_cbc_md5": 0x2, "rc4": 0x4, "aes128": 0x8, "aes256": 0x10}
# pwdProperties bits (MS-ADTS 3.1.1.4.5.27 / DOMAIN_PASSWORD_INFORMATION).
PWD_COMPLEX, PWD_STORE_CLEARTEXT = 0x1, 0x10
# FILETIME (100 ns since 1601) of the Unix epoch.
EPOCH_FILETIME = 116_444_736_000_000_000
# Groups whose members control the domain, by SID: domain RIDs, then BUILTIN (S-1-5-32-…).
PRIVILEGED_RIDS = {"512", "518", "519", "526", "527"}
PRIVILEGED_BUILTIN = {f"S-1-5-32-{rid}" for rid in (544, 548, 549, 550, 551)}


def _entries(r: Result) -> list[dict[str, Any]]:
    entries = json.loads(r.stdout)
    if not isinstance(entries, list):
        raise ValueError("expected a list of LDAP entries")
    return entries


def _one(entry: dict[str, Any], attr: str) -> str | None:
    values = entry["attributes"].get(attr) or []
    return values[0] if values else None


def _int(entry: dict[str, Any], attr: str) -> int | None:
    value = _one(entry, attr)
    return int(value) if value is not None else None


def _filetime(entry: dict[str, Any], attr: str) -> int | None:
    """FILETIME -> Unix seconds; 0 and the 'never' sentinel mean None."""
    value = _int(entry, attr)
    if not value or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    return (value - EPOCH_FILETIME) // 10_000_000


def _generalized_time(value: str | None) -> int | None:
    """`20261029120000.0Z` -> Unix seconds."""
    if value is None:
        return None
    return int(datetime.strptime(value[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC).timestamp())


def _flags(uac: int) -> dict[str, bool]:
    return {name: bool(uac & bit) for name, bit in UAC.items()}


def enc_types(value: int | None) -> list[str] | None:
    """None when unset (absent or 0): the KDC then picks its default (RC4 on older DCs)."""
    if not value:
        return None
    return [name for name, bit in ENC_TYPES.items() if value & bit]


def rootdse(r: Result) -> Facts:
    [entry] = _entries(r)
    now = _generalized_time(_one(entry, "currenttime"))
    if now is None:
        raise ValueError("no currentTime in rootDSE")
    return {
        "now": now,
        "hostname": _one(entry, "dnshostname"),
        "domain": {
            "dn": _one(entry, "defaultnamingcontext"),
            "functional_level": _int(entry, "domainfunctionality"),
        },
    }


def whoami(r: Result) -> Facts:
    # `u:POSTURE\posture` -> `POSTURE\posture`
    return {"identity": r.stdout.strip().removeprefix("u:") or None}


def domain(r: Result) -> Facts:
    [entry] = _entries(r)
    props = _int(entry, "pwdproperties") or 0
    lockout = _int(entry, "lockoutthreshold")
    # maxPwdAge is a negative interval in 100 ns; 0 (or the minimum int64) means never.
    max_age = _int(entry, "maxpwdage")
    max_age_days = round(-max_age / 864_000_000_000) if max_age and max_age > -(2**63) else None
    return {
        "domain": {
            "name": _one(entry, "name"),
            "min_password_length": _int(entry, "minpwdlength"),
            "password_complexity": bool(props & PWD_COMPLEX),
            "reversible_encryption": bool(props & PWD_STORE_CLEARTEXT),
            "max_password_age_days": max_age_days,
            "lockout_threshold": lockout,
            "machine_account_quota": _int(entry, "ms-ds-machineaccountquota"),
        }
    }


def _account(entry: dict[str, Any]) -> Facts:
    uac = _int(entry, "useraccountcontrol") or 0
    return {
        "name": _one(entry, "samaccountname"),
        "dn": entry["dn"],
        "enabled": not uac & UAC["disabled"],
        **_flags(uac),
        "last_logon": _filetime(entry, "lastlogontimestamp"),
        "password_last_set": _filetime(entry, "pwdlastset"),
        "created": _generalized_time(_one(entry, "whencreated")),
        "enc_types": enc_types(_int(entry, "msds-supportedencryptiontypes")),
        "allowed_to_delegate_to": entry["attributes"].get("msds-allowedtodelegateto", []),
    }


def users(r: Result) -> Facts:
    result = []
    for entry in _entries(r):
        user = _account(entry)
        user["spns"] = entry["attributes"].get("serviceprincipalname", [])
        user["admin_count"] = _int(entry, "admincount") == 1
        result.append(user)
    return {"users": result}


def computers(r: Result) -> Facts:
    result = []
    for entry in _entries(r):
        computer = _account(entry)
        computer["os"] = _one(entry, "operatingsystem")
        # Only the expiry attributes, never the passwords: either one means LAPS manages it.
        if _one(entry, "mslaps-passwordexpirationtime") is not None:
            computer["laps"] = "windows"
        elif _one(entry, "ms-mcs-admpwdexpirationtime") is not None:
            computer["laps"] = "legacy"
        else:
            computer["laps"] = None
        result.append(computer)
    return {"computers": result}


def groups(r: Result) -> Facts:
    return {
        "groups": [
            {
                "name": _one(entry, "samaccountname"),
                "dn": entry["dn"],
                "sid": _one(entry, "objectsid"),
                "member": entry["attributes"].get("member", []),
            }
            for entry in _entries(r)
        ]
    }


def _is_privileged(sid: str | None) -> bool:
    return sid is not None and (
        sid in PRIVILEGED_BUILTIN
        or (sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[1] in PRIVILEGED_RIDS)
    )


def privileged_groups(groups: list[Facts], accounts: list[Facts]) -> list[Facts]:
    """Each privileged group with its members expanded through nested groups.

    shortcut: membership through primaryGroupID and `member` values past AD's 1500-value
    range limit are not read; upgrade with range retrieval if a real domain needs it.
    """
    by_dn = {g["dn"].lower(): g for g in groups}
    names = {a["dn"].lower(): a["name"] for a in accounts}
    result = []
    for group in groups:
        if not _is_privileged(group["sid"]):
            continue
        members: set[str] = set()
        seen: set[str] = set()
        todo = [group["dn"].lower()]
        while todo:
            dn = todo.pop()
            if dn in seen:
                continue  # nesting loops are legal in AD
            seen.add(dn)
            for member in by_dn[dn]["member"]:
                key = member.lower()
                if key in by_dn:
                    todo.append(key)
                elif key in names:
                    members.add(names[key])
        result.append(
            {
                "name": group["name"],
                "sid": group["sid"],
                "members": sorted(members),
                "member_count": len(members),
            }
        )
    return result


def _registry(r: Result, name: str, default: int) -> int:
    values = json.loads(r.stdout)
    if not isinstance(values, dict) or name not in values:
        raise ValueError(f"expected a JSON object with {name}")
    value = values[name]
    return default if value is None else int(value)


# An absent value means the Windows Server 2019 default, which is what the DC then enforces.
def smb_server(r: Result) -> Facts:
    return {"dc": {"smb_signing_required": _registry(r, "RequireSecuritySignature", 0) == 1}}


def ldap_server(r: Result) -> Facts:
    # 0 none, 1 negotiate signing (the default), 2 require signing.
    return {"dc": {"ldap_server_integrity": _registry(r, "LDAPServerIntegrity", 1)}}


def lsa(r: Result) -> Facts:
    # 0-5; 5 = send NTLMv2 only, refuse LM and NTLM. The default is 3.
    return {"dc": {"lm_compatibility_level": _registry(r, "LmCompatibilityLevel", 3)}}
