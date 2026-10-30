"""Finding schema and lifecycle state machine (FR-FND-1, FR-FND-2).

One normalized schema for all engine output. Fingerprint =
service + endpoint + check + parameter, used for cross-run dedupe.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]

FindingState = Literal[
    "new",
    "triaged",
    "confirmed",
    "false_positive",
    "risk_accepted",
    "in_remediation",
    "fix_verified",
    "closed",
    "reopened",
]

# FR-FND-2 lifecycle state machine. Reopen (regression / risk-acceptance
# expiry) re-enters at confirmed.
TRANSITIONS: dict[str, set[str]] = {
    "new": {"triaged"},
    "triaged": {"confirmed", "false_positive", "risk_accepted"},
    "confirmed": {"in_remediation", "false_positive", "risk_accepted"},
    "false_positive": {"closed"},
    "risk_accepted": {"closed", "reopened"},
    "in_remediation": {"fix_verified", "in_remediation"},
    "fix_verified": {"closed"},
    "closed": {"reopened"},
    "reopened": {"confirmed"},
}

# States requiring justification + approver (FR-FND-3)
APPROVAL_REQUIRED_STATES = {"false_positive", "risk_accepted"}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fingerprint(service: str, endpoint_id: str, check_id: str, parameter: str = "") -> str:
    raw = f"{service}|{endpoint_id}|{check_id}|{parameter}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


class StateTransition(BaseModel):
    from_state: str
    to_state: str
    actor: str
    timestamp: str = Field(default_factory=_now)
    justification: Optional[str] = None
    approver: Optional[str] = None


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: uuid4().hex[:12])
    fingerprint: str
    service: str
    owner_team: str = ""
    environment: str = "dev"
    endpoint_id: str
    check_id: str
    parameter: str = ""
    domain: str = "security"
    severity: Severity = "medium"
    cvss_vector: Optional[str] = None
    title: str
    description: str = ""
    remediation: str = ""
    compliance_mappings: list[str] = Field(default_factory=list)
    # Sanitized reproduction (FR-FND-8): placeholders, never live credentials
    reproduction: Optional[dict] = None
    evidence: dict = Field(default_factory=dict)  # secrets redacted at capture
    state: FindingState = "new"
    occurrences: int = 1
    first_seen: str = Field(default_factory=_now)
    last_seen: str = Field(default_factory=_now)
    confirmed_at: Optional[str] = None
    sla_due: Optional[str] = None
    risk_acceptance_expiry: Optional[str] = None
    is_regression: bool = False
    scan_id: Optional[str] = None
    jira_key: Optional[str] = None
    history: list[StateTransition] = Field(default_factory=list)

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)
