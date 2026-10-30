"""Scan request/status models (FR-EXE-1, FR-EXE-5)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

ScanMode = Literal["safe", "full"]
ScanProfile = Literal["pr", "qa", "preprod"]
ScanState = Literal["queued", "running", "complete", "failed"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanRequest(BaseModel):
    """FR-EXE-1: service, spec version, target environment, scope, mode."""

    service: str
    spec_version: str  # content hash or "latest"
    environment: str = "dev"
    profile: ScanProfile = "qa"
    mode: ScanMode = "safe"
    # Changed-endpoint scoping (FR-EXE-6); empty = full suite
    scope_endpoints: list[str] = Field(default_factory=list)
    # Ephemeral environment override (FR-EXE-7)
    target_url_override: Optional[str] = None
    commit_sha: Optional[str] = None
    webhook_url: Optional[str] = None
    requested_by: str = "system"
    # Fix-verification primitive (FR-EXE-8): restrict to one check+endpoint
    only_check_id: Optional[str] = None
    # Crawler + external engines. None = inherit from the service record.
    enable_crawler: Optional[bool] = None
    external_engines: Optional[list[str]] = None


class ScanStatus(BaseModel):
    scan_id: str = Field(default_factory=lambda: uuid4().hex[:12])
    request: ScanRequest
    state: ScanState = "queued"
    created_at: str = Field(default_factory=_now)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    checks_planned: int = 0
    checks_executed: int = 0
    checks_failed: int = 0
    coverage_gaps: list[str] = Field(default_factory=list)
    error: Optional[str] = None
    finding_ids: list[str] = Field(default_factory=list)
    gate_verdict: Optional[dict] = None
    # Crawler + external engine outputs
    discovered_endpoints: list[str] = Field(default_factory=list)
    engines_run: list[str] = Field(default_factory=list)
    engines_skipped: list[str] = Field(default_factory=list)
    external_findings_count: int = 0
