"""Active Directory over LDAP: a fixed list of searches, nothing else. Optionally the DC's own
security settings over WinRM: a fixed list of registry values, read with `Get-Item` only.

LDAPS only, the certificate verified: a simple bind inside TLS meets "LDAP signing required"
(released ldap3 can't sign or seal an NTLM / Kerberos bind). The connection is `read_only`
(ldap3 refuses add / modify / delete client-side), referrals are never followed, and no
collected value is ever put into a search filter.
"""

import ipaddress
import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from posture import __version__
from posture.collectors.linux import _merge
from posture.collectors.transport import MAX_OUTPUT, NotRecorded, Result, write_recording
from posture.models import CollectError, Snapshot
from posture.parsers import ad as p

# A hostile or huge directory can't make us hold unbounded results.
MAX_ENTRIES = 50_000
PAGE_SIZE = 500
ACCOUNT_ATTRS = (
    "sAMAccountName",
    "userAccountControl",
    "lastLogonTimestamp",
    "pwdLastSet",
    "whenCreated",
    "msDS-SupportedEncryptionTypes",
    "msDS-AllowedToDelegateTo",
)


@dataclass(frozen=True)
class Search:
    """A fixed search. `filter=None` is the rootDSE (base ""), `base_only` the domain object."""

    name: str
    filter: str | None
    attributes: tuple[str, ...]
    base_only: bool = False


# The whole read-only surface on a domain. Filters are constants (tests/test_readonly.py).
SEARCHES = (
    Search(
        "rootdse",
        None,
        ("defaultNamingContext", "dnsHostName", "currentTime", "domainFunctionality"),
    ),
    Search("whoami", None, ()),  # the LDAP "Who am I?" extended operation, not a search
    Search(
        "domain",
        "(objectClass=domain)",
        (
            "name",
            "minPwdLength",
            "pwdProperties",
            "maxPwdAge",
            "lockoutThreshold",
            "ms-DS-MachineAccountQuota",
        ),
        base_only=True,
    ),
    Search(
        "users",
        "(&(objectCategory=person)(objectClass=user))",
        (*ACCOUNT_ATTRS, "servicePrincipalName", "adminCount"),
    ),
    # Expiry times only: the LAPS passwords themselves are never requested.
    Search(
        "computers",
        "(objectCategory=computer)",
        (
            *ACCOUNT_ATTRS,
            "operatingSystem",
            "msLAPS-PasswordExpirationTime",
            "ms-Mcs-AdmPwdExpirationTime",
        ),
    ),
    Search("groups", "(objectClass=group)", ("sAMAccountName", "objectSid", "member")),
)


@dataclass(frozen=True)
class RegistryRead:
    """Fixed values under one fixed HKLM key on the DC: key and names are constants."""

    name: str
    key: str
    values: tuple[str, ...]


# The whole read-only surface on the DC host (tests/test_readonly.py).
REGISTRY_READS = (
    RegistryRead(
        "smb_server",
        r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        ("RequireSecuritySignature",),
    ),
    RegistryRead(
        "ldap_server",
        r"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
        ("LDAPServerIntegrity",),
    ),
    RegistryRead("lsa", r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", ("LmCompatibilityLevel",)),
)


def registry_script(read: RegistryRead) -> str:
    """An unreadable key stops the script (an error, never a silent default); a missing value
    comes back as null, so the parser can apply the OS default."""
    names = ", ".join(f"'{v}'" for v in read.values)
    return (
        f"$k = Get-Item -LiteralPath '{read.key}' -ErrorAction Stop\n"
        f"$o = [ordered]@{{}}; foreach ($n in {names}) {{ $o[$n] = $k.GetValue($n) }}\n"
        "$o | ConvertTo-Json -Compress"
    )


PARSERS: dict[str, Callable[[Result], dict[str, Any]]] = {
    "rootdse": p.rootdse,
    "whoami": p.whoami,
    "domain": p.domain,
    "users": p.users,
    "computers": p.computers,
    "groups": p.groups,
    "smb_server": p.smb_server,
    "ldap_server": p.ldap_server,
    "lsa": p.lsa,
}


class Runner(Protocol):
    def run(self, search: Search) -> Result: ...


class HostRunner(Protocol):
    def run(self, read: RegistryRead) -> Result: ...


def _value(attr: str, raw: bytes) -> str:
    if attr == "objectsid":
        from ldap3.protocol.formatters.formatters import format_sid

        return format_sid(raw)
    return raw.decode("utf-8", errors="replace")


def _names_ip(cert: dict[str, Any], ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    sans = cert.get("subjectAltName", ())
    return any(kind == "IP Address" and ipaddress.ip_address(v.strip()) == ip for kind, v in sans)


class LdapRunner:
    """LDAPS to one DC. `ca_file`: the CA (or the pinned self-signed certificate) to trust;
    None means the system store. The certificate must name `host` (DNS name or IP address)."""

    def __init__(
        self, host: str, user: str, password: str, ca_file: Path | None = None, timeout: int = 60
    ) -> None:
        from ldap3 import NONE, SIMPLE, Connection, Server, Tls
        from ldap3.core.exceptions import LDAPException

        if not host or host.startswith("-"):
            raise ValueError(f"bad LDAP host {host!r}")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        tls = Tls(
            validate=ssl.CERT_REQUIRED,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ca_certs_file=str(ca_file) if ca_file else None,
            # ldap3's own name match ignores IP SANs: for an IP, the SAN is checked below.
            valid_names=["*"] if ip else None,
        )
        server = Server(host, port=636, use_ssl=True, tls=tls, get_info=NONE, connect_timeout=10)
        self.conn = Connection(
            server,
            user=user,
            password=password,
            authentication=SIMPLE,
            read_only=True,
            auto_referrals=False,
            receive_timeout=timeout,
            raise_exceptions=False,
        )
        try:
            self.conn.open()  # TLS handshake and chain verification, before any credential
            if ip and not _names_ip(self.conn.socket.getpeercert(), ip):
                raise ConnectionError(f"{host}: the certificate does not name this address")
            bound = self.conn.bind()
        except LDAPException as exc:
            raise ConnectionError(f"LDAPS to {host}: {exc}") from exc
        if not bound:
            raise ConnectionError(f"LDAP bind to {host} failed: {self.conn.result['description']}")
        self.base: str | None = None

    def run(self, search: Search) -> Result:
        if search.name == "whoami":
            return Result(self.conn.extend.standard.who_am_i() or "")
        base, scope = ("", "BASE") if search.filter is None else (self.base, "SUBTREE")
        if search.base_only:
            scope = "BASE"
        if base is None:
            raise ValueError("rootdse must run first: no domain to search")
        entries = []
        for entry in self.conn.extend.standard.paged_search(
            base,
            search.filter or "(objectClass=*)",
            search_scope=scope,
            attributes=list(search.attributes),
            paged_size=PAGE_SIZE,
            generator=True,
        ):
            if entry.get("type") != "searchResEntry":
                continue  # referrals are listed by the server, never followed
            if len(entries) == MAX_ENTRIES:
                return Result("[]", f"more than {MAX_ENTRIES} entries", 1)
            raw = entry["raw_attributes"]
            attrs = {k.lower(): [_value(k.lower(), v) for v in vals] for k, vals in raw.items()}
            entries.append({"dn": entry["dn"], "attributes": attrs})
        if self.conn.result["result"] != 0:
            return Result("[]", self.conn.result["description"], self.conn.result["result"])
        if search.name == "rootdse" and entries:
            self.base = entries[0]["attributes"].get("defaultnamingcontext", [None])[0]
        entries.sort(key=lambda e: e["dn"].lower())
        return Result(json.dumps(entries, indent=1, sort_keys=True) + "\n")

    def close(self) -> None:
        self.conn.unbind()


class WinrmRunner:
    """WinRM on 5985 with NTLM: the password never crosses the wire (NTLMv2 challenge/response)
    and every message is sealed (`encryption="always"`), so plain HTTP carries nothing readable.

    shortcut: on HTTP the DC is authenticated by NTLM only, with no certificate; move to HTTPS
    (5986) or Kerberos if a real domain needs the server pinned as LDAPS is.
    """

    def __init__(self, host: str, user: str, password: str, timeout: int = 60) -> None:
        from pypsrp.client import Client

        if not host or host.startswith("-"):
            raise ValueError(f"bad WinRM host {host!r}")
        self.host = host
        self.client = Client(
            host,
            username=user,
            password=password,
            ssl=False,
            auth="ntlm",
            encryption="always",
            connection_timeout=10,
            read_timeout=timeout,
        )

    def run(self, read: RegistryRead) -> Result:
        from pypsrp.exceptions import WinRMError
        from spnego.exceptions import SpnegoError

        try:
            output, streams, had_errors = self.client.execute_ps(registry_script(read))
        except (WinRMError, SpnegoError) as exc:
            raise ConnectionError(f"WinRM to {self.host}: {exc}") from exc
        if had_errors:
            return Result("", "\n".join(str(e) for e in streams.error)[:MAX_OUTPUT], 1)
        return Result(output[:MAX_OUTPUT].strip() + "\n")


def _days(now: int, then: int | None) -> float | None:
    return None if then is None else round((now - then) / 86400, 1)


def _derive(facts: dict[str, Any]) -> None:
    now = facts.get("now")
    accounts = facts.get("users", []) + facts.get("computers", [])
    if now is not None:
        for account in accounts:
            account["last_logon_days"] = _days(now, account.pop("last_logon"))
            account["password_age_days"] = _days(now, account.pop("password_last_set"))
            account["created_days"] = _days(now, account.pop("created"))
    groups = facts.pop("groups", None)
    if groups is not None:
        facts["privileged_groups"] = privileged = p.privileged_groups(groups, accounts)
        admins = {name for g in privileged for name in g["members"]}
        for user in facts.get("users", []):
            user["privileged"] = user["name"] in admins


def collect(
    runner: Runner,
    host_runner: HostRunner | None = None,
    target: str | None = None,
    record_dir: Path | None = None,
) -> Snapshot:
    """`host_runner` reads the DC's registry; without one, those facts are errors, not passes."""
    facts: dict[str, Any] = {}
    errors: list[CollectError] = []
    results: dict[str, Result] = {}
    jobs: list[tuple[Any, Search | RegistryRead]] = [(runner, s) for s in SEARCHES]
    jobs += [(host_runner, r) for r in REGISTRY_READS]
    for source, item in jobs:
        if source is None:
            message = "DC host settings not collected (they need WinRM: --winrm)"
            errors.append(CollectError(source=item.name, message=message))
            continue
        try:
            result = source.run(item)
        except (NotRecorded, OSError, ValueError) as exc:
            errors.append(CollectError(source=item.name, message=str(exc)))
            continue
        results[item.name] = result
        if result.exit_code:
            kind = "LDAP" if isinstance(item, Search) else "WinRM"
            message = f"{kind} {result.exit_code}: {result.stderr.strip()[:500]}"
            errors.append(CollectError(source=item.name, message=message))
            continue
        try:
            _merge(facts, PARSERS[item.name](result))
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(CollectError(source=item.name, message=f"parse error: {exc}"))
    if record_dir is not None:
        write_recording(record_dir, results)
    _derive(facts)
    return Snapshot(
        tool_version=__version__,
        platform="ad",
        target=target or facts.get("hostname") or "unknown",
        collected_at=datetime.now(UTC),
        identity=facts.get("identity"),
        facts=facts,
        errors=errors,
    )
