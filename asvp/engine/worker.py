"""Worker interface (AR-3).

Security engines are wrapped, not built: the orchestrator only knows this
interface. The built-in `HttpProbeEngine` is the v1 custom-check library;
Newman/ZAP/Nuclei adapters implement the same interface (stubs included to
show the seam — see NewmanAdapter below).

AR-4 note: in the production deployment each worker runs as a K8s Job in an
isolated namespace with a NetworkPolicy egress allow-list. In this reference
implementation the equivalent guard is `assert_target_allowed`, which
refuses production CIDRs before any request is made.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal, Optional
from urllib.parse import urlparse

import httpx

from asvp.checks.generator import PlannedCheck
from asvp.config import get_config
from asvp.integrations.secrets import SecretsManager
from asvp.models.registry import ServiceRecord, TestIdentity

CheckStatus = Literal["pass", "fail", "error", "skipped"]

REDACTED_HEADERS = {"authorization", "cookie", "x-api-key", "proxy-authorization"}


def redact_headers(headers: dict) -> dict:
    return {
        k: ("[REDACTED]" if k.lower() in REDACTED_HEADERS else v)
        for k, v in headers.items()
    }


class TargetNotAllowedError(Exception):
    pass


def assert_target_allowed(base_url: str) -> None:
    """AR-4: zero route to production. Reject blocklisted CIDR prefixes."""
    host = urlparse(base_url).hostname or ""
    for prefix in get_config().production_cidr_blocklist:
        if host.startswith(prefix):
            raise TargetNotAllowedError(
                f"target {host} is within a production CIDR — scan refused"
            )


@dataclass
class ResolvedIdentity:
    name: str
    role: str
    token: str  # resolved at runtime, never persisted (AR-5)
    owned_objects: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class CheckResult:
    status: CheckStatus
    detail: str = ""
    parameter: str = ""
    evidence: dict = field(default_factory=dict)  # secrets redacted at capture
    reproduction: Optional[dict] = None  # sanitized template (FR-FND-8)


@dataclass
class ExecutionContext:
    base_url: str
    client: httpx.AsyncClient
    service: ServiceRecord
    identities: list[ResolvedIdentity] = field(default_factory=list)
    requests_made: int = 0

    def primary_identity(self) -> Optional[ResolvedIdentity]:
        return self.identities[0] if self.identities else None

    def identity_by_role(self, role: str) -> Optional[ResolvedIdentity]:
        for i in self.identities:
            if i.role == role:
                return i
        return None


def resolve_identities(
    service: ServiceRecord, secrets: SecretsManager
) -> list[ResolvedIdentity]:
    resolved = []
    for ident in service.test_identities:
        resolved.append(
            ResolvedIdentity(
                name=ident.name,
                role=ident.role,
                token=secrets.resolve(ident.credential_ref),
                owned_objects=ident.owned_objects,
            )
        )
    return resolved


class ScanWorker(ABC):
    """The swappable engine seam (AR-3)."""

    name: str = "abstract"

    @abstractmethod
    async def execute(self, check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
        ...


class NewmanAdapter(ScanWorker):
    """Seam for Newman collection replay (auth-context execution).

    Production implementation shells out to `newman run` inside the worker
    Job with credentials injected as environment; results map onto
    CheckResult. Not active in this environment (no Node runtime).

    ZAP, Nuclei and Burp are full *scan-level* engines (target in, findings
    out), so they implement the ExternalEngine interface in
    asvp.engine.adapters rather than the per-check ScanWorker interface."""

    name = "newman"

    async def execute(self, check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
        return CheckResult(
            status="skipped",
            detail="Newman adapter not available in this runtime",
        )
