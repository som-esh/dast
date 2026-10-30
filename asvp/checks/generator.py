"""Check generation (FR-CHK-1, FR-CHK-4, FR-EXE-3).

Selects applicable templates per endpoint from the library, honoring:
- destructiveness vs allowed classes for the target environment (safe-mode
  default — FR-EXE-3),
- the test-identity contract for authz checks: if unfulfilled, authz checks
  are skipped with a *visible* "coverage gap: authz untested" status, never
  silently omitted (FR-CHK-4),
- active suppressions (FR-CHK-5),
- changed-endpoint scoping (FR-EXE-6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from asvp.checks.suppression import SuppressionStore
from asvp.checks.template import CheckTemplate, TemplateLibrary
from asvp.models.canonical import CanonicalAPI, Endpoint
from asvp.models.registry import ServiceRecord


@dataclass
class PlannedCheck:
    template: CheckTemplate
    endpoint: Optional[Endpoint]  # None for service-level (once_per_service)
    parameter: str = ""

    @property
    def endpoint_id(self) -> str:
        return self.endpoint.endpoint_id if self.endpoint else "(service)"


@dataclass
class GenerationResult:
    checks: list[PlannedCheck] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)
    skipped_by_mode: list[str] = field(default_factory=list)


def _applies(template: CheckTemplate, endpoint: Endpoint) -> bool:
    a = template.applies
    if a.methods and endpoint.method.upper() not in [m.upper() for m in a.methods]:
        return False
    if a.state_changing_only and not endpoint.is_state_changing:
        return False
    if a.sensitive_only and not endpoint.sensitive:
        return False
    if a.requires_object_id_param and not endpoint.object_id_params():
        return False
    if a.requires_url_param and not endpoint.url_params():
        return False
    if a.requires_body and not endpoint.request_body_example:
        return False
    if a.deprecated_only and not endpoint.deprecated:
        return False
    return True


class CheckGenerator:
    def __init__(self, library: TemplateLibrary, suppressions: SuppressionStore):
        self._library = library
        self._suppressions = suppressions

    def generate(
        self,
        api: CanonicalAPI,
        service: ServiceRecord,
        environment: str,
        mode: str = "safe",
        scope_endpoints: Optional[list[str]] = None,
        only_check_id: Optional[str] = None,
    ) -> GenerationResult:
        result = GenerationResult()
        allowed_classes = (
            ["safe"]
            if mode == "safe"
            else service.allowed_destructiveness(environment)
        )
        identities_ok = service.identity_contract_fulfilled()

        endpoints = api.endpoints
        if scope_endpoints:
            scoped = [e for e in endpoints if e.endpoint_id in set(scope_endpoints)]
            # FR-EXE-6: fall back to full suite on spec-model ambiguity
            endpoints = scoped or api.endpoints

        for template in self._library.all():
            if only_check_id and template.id != only_check_id:
                continue

            if template.applies.requires_identities and not identities_ok:
                # FR-CHK-4: visible coverage gap, never silent omission
                result.coverage_gaps.append(
                    f"coverage gap: authz untested — {template.id} requires a "
                    f"fulfilled test-identity contract (>=2 identities with "
                    f"declared object ownership)"
                )
                continue

            if template.destructiveness not in allowed_classes:
                result.skipped_by_mode.append(
                    f"{template.id} ({template.destructiveness}) skipped: "
                    f"environment '{environment}' allows {allowed_classes}"
                )
                continue

            if template.applies.once_per_service:
                if self._suppressions.is_suppressed(service.name, template.id, "(service)"):
                    result.suppressed.append(f"{template.id} @ (service)")
                else:
                    result.checks.append(PlannedCheck(template=template, endpoint=None))
                continue

            for endpoint in endpoints:
                if not _applies(template, endpoint):
                    continue
                if self._suppressions.is_suppressed(
                    service.name, template.id, endpoint.endpoint_id
                ):
                    result.suppressed.append(f"{template.id} @ {endpoint.endpoint_id}")
                    continue
                result.checks.append(PlannedCheck(template=template, endpoint=endpoint))

        return result
