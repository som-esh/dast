"""Bidirectional Jira sync seam (FR-FND-7).

ASVP is the system of record for findings; Jira mirrors workflow state.
This adapter keeps the mapping table and state-mirroring logic; the HTTP
transport is injectable so production wiring is configuration, and the
default transport is a no-op recorder (suitable for dev and tests).
"""

from __future__ import annotations

from typing import Callable, Optional

from asvp.models.findings import Finding
from asvp.storage import Store

# ASVP state → Jira status
_STATE_TO_JIRA = {
    "confirmed": "To Do",
    "in_remediation": "In Progress",
    "fix_verified": "In Review",
    "closed": "Done",
    "false_positive": "Done",
    "risk_accepted": "On Hold",
    "reopened": "To Do",
}


class JiraSync:
    def __init__(
        self,
        store: Store,
        transport: Optional[Callable[[str, dict], Optional[str]]] = None,
    ):
        self._store = store
        # transport(action, payload) -> issue key | None
        self._transport = transport or self._record_only

    def _record_only(self, action: str, payload: dict) -> Optional[str]:
        self._store.append_event("jira.outbound", "jira", payload.get("finding_id", "-"),
                                 {"action": action, **payload})
        if action == "create":
            return f"SEC-{abs(hash(payload['finding_id'])) % 10000}"
        return None

    def on_finding_change(self, finding: Finding, event: str) -> Optional[str]:
        if event == "created" and finding.severity in ("critical", "high"):
            key = self._transport(
                "create",
                {
                    "finding_id": finding.finding_id,
                    "summary": f"[ASVP][{finding.severity.upper()}] {finding.title}",
                    "service": finding.service,
                    "endpoint": finding.endpoint_id,
                },
            )
            return key
        jira_status = _STATE_TO_JIRA.get(event)
        if jira_status and finding.jira_key:
            self._transport(
                "transition",
                {
                    "finding_id": finding.finding_id,
                    "issue": finding.jira_key,
                    "status": jira_status,
                },
            )
        return None

    def inbound_update(self, finding_service, issue_key: str, new_status: str) -> None:
        """Jira → ASVP mirroring: 'In Progress' marks in_remediation."""
        for finding in finding_service.all():
            if finding.jira_key == issue_key:
                if new_status == "In Progress" and finding.state == "confirmed":
                    finding_service.transition(
                        finding.finding_id, "in_remediation", actor=f"jira:{issue_key}"
                    )
                return
