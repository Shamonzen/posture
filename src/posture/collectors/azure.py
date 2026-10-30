"""Azure and Entra ID over plain REST: a fixed list of GET requests to ARM and Microsoft Graph.

The HTTP client refuses every method but GET before anything is sent, never follows redirects,
and only follows paging links (`nextLink` / `@odata.nextLink`) that stay on the API they came
from, so the bearer token never reaches another host. The only input put into a URL is the
subscription id from the command line, and it must parse as a GUID.
"""

import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from posture import __version__
from posture.collectors.linux import _merge
from posture.collectors.transport import MAX_OUTPUT, NotRecorded, Result, write_recording
from posture.models import CollectError, Snapshot
from posture.parsers import azure as p

ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com/v1.0"
SCOPES = {
    ARM: "https://management.azure.com/.default",
    GRAPH: "https://graph.microsoft.com/.default",
}
# A hostile or huge tenant can't make us hold unbounded results.
MAX_ENTRIES = 50_000
# Throttling (429) and "busy" (503): retried this many times, waiting Retry-After (capped).
RETRIES, MAX_WAIT = 3, 30.0


@dataclass(frozen=True)
class Request:
    """A fixed GET. `{subscription}` is the only placeholder: the validated id, nothing else."""

    name: str
    base: str
    path: str


SUB = "/subscriptions/{subscription}"
# The whole read-only surface on a tenant and subscription (tests/test_readonly.py).
REQUESTS = (
    Request("subscription", ARM, f"{SUB}?api-version=2022-12-01"),
    Request(
        "storage_accounts",
        ARM,
        f"{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01",
    ),
    Request(
        "nsgs",
        ARM,
        f"{SUB}/providers/Microsoft.Network/networkSecurityGroups?api-version=2024-05-01",
    ),
    Request(
        "diagnostic_settings",
        ARM,
        f"{SUB}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview",
    ),
    Request(
        "defender_plans", ARM, f"{SUB}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
    ),
    Request("security_defaults", GRAPH, "/policies/identitySecurityDefaultsEnforcementPolicy"),
    Request("conditional_access", GRAPH, "/identity/conditionalAccess/policies"),
    Request("authorization_policy", GRAPH, "/policies/authorizationPolicy"),
    Request(
        "global_admins",
        GRAPH,
        "/roleManagement/directory/roleAssignments"
        f"?$filter=roleDefinitionId eq '{p.GLOBAL_ADMIN_ROLE}'&$expand=principal",
    ),
    Request(
        "admin_mfa_registration",
        GRAPH,
        "/reports/authenticationMethods/userRegistrationDetails?$filter=isAdmin eq true",
    ),
)

PARSERS: dict[str, Callable[[Result], dict[str, Any]]] = {
    "subscription": p.subscription,
    "storage_accounts": p.storage_accounts,
    "nsgs": p.nsgs,
    "diagnostic_settings": p.diagnostic_settings,
    "defender_plans": p.defender_plans,
    "security_defaults": p.security_defaults,
    "conditional_access": p.conditional_access,
    "authorization_policy": p.authorization_policy,
    "global_admins": p.global_admins,
    "admin_mfa_registration": p.admin_mfa_registration,
}


class Runner(Protocol):
    def run(self, request: Request) -> Result: ...


class ReadOnlyViolation(RuntimeError):
    """Something tried to send a method other than GET: a bug, never a collection error."""


def _get_only(request: Any) -> None:
    if request.method != "GET":
        raise ReadOnlyViolation(f"read-only client: {request.method} {request.url} refused")


def read_only_client(transport: Any = None) -> Any:
    """An httpx client that refuses any method but GET before it is sent (an event hook runs
    for every request, whatever helper built it). `transport`: tests pass a mock."""
    import httpx

    return httpx.Client(
        transport=transport,
        timeout=30,
        follow_redirects=False,
        event_hooks={"request": [_get_only]},
    )


def _retry_after(header: str | None, attempt: int) -> float:
    try:
        wait = float(header) if header else 2.0**attempt
    except ValueError:  # an HTTP date: not worth parsing for a short wait
        wait = 2.0**attempt
    return min(max(wait, 0.0), MAX_WAIT)


def _error(status: int, body: bytes) -> str:
    try:
        error = json.loads(body)["error"]
        detail = f"{error['code']}: {error['message']}"
    except (ValueError, KeyError, TypeError):
        detail = body.decode("utf-8", errors="replace")
    return f"HTTP {status}: {detail.strip()[:500]}"


class AzureRunner:
    """ARM and Graph with one credential: `azure-identity`'s default chain (environment
    variables, managed identity, `az login`...) unless tests pass their own."""

    def __init__(self, subscription: str, credential: Any = None, transport: Any = None) -> None:
        try:
            self.subscription = str(uuid.UUID(subscription))
        except ValueError:
            raise ValueError(f"bad subscription id {subscription!r}: expected a GUID") from None
        if credential is None:
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()
        self.credential = credential
        self.http = read_only_client(transport)
        self.tokens: dict[str, str] = {}

    def _token(self, base: str) -> str:
        from azure.core.exceptions import ClientAuthenticationError

        scope = SCOPES[base]
        if scope not in self.tokens:
            try:
                self.tokens[scope] = self.credential.get_token(scope).token
            except ClientAuthenticationError as exc:
                raise ConnectionError(f"no Azure token for {scope}: {exc}") from exc
        return self.tokens[scope]

    def _get(self, url: str, token: str) -> tuple[int, bytes]:
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        for attempt in range(RETRIES + 1):
            with self.http.stream("GET", url, headers=headers) as resp:
                body = bytearray()
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > MAX_OUTPUT:
                        raise ValueError(f"response over {MAX_OUTPUT} bytes")
                if resp.status_code not in (429, 503) or attempt == RETRIES:
                    return resp.status_code, bytes(body)
                wait = _retry_after(resp.headers.get("Retry-After"), attempt)
            time.sleep(wait)
        raise AssertionError("unreachable")  # pragma: no cover

    def run(self, request: Request) -> Result:
        import httpx

        token = self._token(request.base)
        url: str | None = request.base + request.path.format(subscription=self.subscription)
        items: list[Any] = []
        try:
            while url:
                if not url.startswith(request.base + "/"):
                    return Result("", f"refused a paging link off {request.base}: {url[:200]}", 1)
                status, body = self._get(url, token)
                if status != 200:
                    return Result("", _error(status, body), 1)
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise ValueError("expected a JSON object")
                if not isinstance(data.get("value"), list):  # a single object, not a collection
                    return Result(json.dumps(data, indent=1, sort_keys=True) + "\n")
                items += data["value"]
                if len(items) > MAX_ENTRIES:
                    return Result("", f"more than {MAX_ENTRIES} entries", 1)
                url = data.get("@odata.nextLink") or data.get("nextLink")
        except httpx.HTTPError as exc:
            raise ConnectionError(f"{request.base}: {exc}") from exc
        return Result(json.dumps(items, indent=1, sort_keys=True) + "\n")

    def close(self) -> None:
        self.http.close()


def collect(runner: Runner, target: str | None = None, record_dir: Path | None = None) -> Snapshot:
    facts: dict[str, Any] = {}
    errors: list[CollectError] = []
    results: dict[str, Result] = {}
    for request in REQUESTS:
        try:
            result = runner.run(request)
        except (NotRecorded, OSError, ValueError) as exc:
            errors.append(CollectError(source=request.name, message=str(exc)))
            continue
        results[request.name] = result
        if result.exit_code:
            errors.append(CollectError(source=request.name, message=result.stderr.strip()[:500]))
            continue
        try:
            _merge(facts, PARSERS[request.name](result))
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(CollectError(source=request.name, message=f"parse error: {exc}"))
    if record_dir is not None:
        write_recording(record_dir, results)
    p.derive(facts)
    return Snapshot(
        tool_version=__version__,
        platform="azure",
        target=target or facts.get("subscription", {}).get("name") or "unknown",
        collected_at=datetime.now(UTC),
        facts=facts,
        errors=errors,
    )
