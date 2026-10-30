"""Service registry (FR-ING-7) and test-identity contract (FR-CHK-4)."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

CriticalityTier = Literal["tier1", "tier2", "tier3"]
DataClassification = Literal["public", "internal", "confidential", "pii", "pci"]
PolicyMode = Literal["report_only", "warn", "block"]


class TestIdentity(BaseModel):
    """One provisioned test identity with declared object ownership.

    `credential_ref` is a secrets-manager handle (AR-5) — never a raw secret.
    `owned_objects` maps an object-id parameter name to ids this identity owns,
    enabling cross-identity BOLA probes.
    """

    name: str
    role: str = "user"
    credential_ref: str
    owned_objects: dict[str, list[str]] = Field(default_factory=dict)


class ServiceRecord(BaseModel):
    name: str
    owner_team: str
    criticality_tier: CriticalityTier = "tier3"
    data_classification: DataClassification = "internal"
    target_environments: list[str] = Field(default_factory=lambda: ["dev"])
    environment_urls: dict[str, str] = Field(default_factory=dict)
    test_identities: list[TestIdentity] = Field(default_factory=list)
    policy_mode: PolicyMode = "report_only"
    # Environments whose owner opted in to mutating/aggressive checks (FR-EXE-3)
    destructive_opt_in: dict[str, list[str]] = Field(default_factory=dict)
    sla_overrides: dict[str, int] = Field(default_factory=dict)
    jira_project: Optional[str] = None
    slack_channel: Optional[str] = None
    # External scan engines to run for this service (zap | nuclei | burp).
    # These are aggressive-class, so they run only in full mode on opted-in
    # environments (FR-EXE-3).
    external_engines: list[str] = Field(default_factory=list)
    # Run the API crawler/spider to discover undocumented endpoints.
    crawl_enabled: bool = False

    def identity_contract_fulfilled(self) -> bool:
        """FR-CHK-4: >=2 identities with declared object ownership."""
        with_ownership = [i for i in self.test_identities if i.owned_objects]
        return len(with_ownership) >= 2

    def allowed_destructiveness(self, environment: str) -> list[str]:
        """FR-EXE-3: safe is always allowed; others by env-owner opt-in."""
        return ["safe"] + self.destructive_opt_in.get(environment, [])
