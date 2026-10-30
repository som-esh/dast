"""Immutable audit log (FR-GOV-3, AR-8).

All privileged actions (policy mode change, risk acceptance, suppression,
bypass) and all finding-detail reads are journaled. Backed by the
append-only events table; there is no update/delete path.
"""

from __future__ import annotations

from typing import Any, Optional

from asvp.storage import Store

PRIVILEGED_ACTIONS = {
    "policy.mode_change",
    "finding.risk_accepted",
    "finding.false_positive",
    "suppression.created",
    "gate.bypass",
    "finding.read",
}


class AuditLog:
    def __init__(self, store: Store):
        self._store = store

    def record(
        self,
        action: str,
        actor: str,
        entity: str,
        entity_id: str,
        detail: Optional[dict[str, Any]] = None,
    ) -> int:
        return self._store.append_event(
            kind=f"audit.{action}",
            entity=entity,
            entity_id=entity_id,
            payload=detail or {},
            actor=actor,
        )

    def query(
        self,
        action: Optional[str] = None,
        entity_id: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        kind = f"audit.{action}" if action else None
        events = self._store.events(kind=kind, entity_id=entity_id, limit=limit)
        if action is None:
            events = [e for e in events if e["kind"].startswith("audit.")]
        return events
