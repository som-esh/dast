"""Per-service check suppression (FR-CHK-5).

Every suppression carries justification, approver, and a mandatory expiry.
Expired suppressions stop applying automatically.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from asvp.storage import Store


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Suppression(BaseModel):
    suppression_id: str = Field(default_factory=lambda: uuid4().hex[:10])
    service: str
    check_id: str
    endpoint_id: Optional[str] = None  # None = all endpoints of the service
    justification: str
    approver: str
    created_by: str
    expires_at: str  # ISO timestamp — mandatory
    created_at: str = Field(default_factory=lambda: _now().isoformat())

    def is_active(self) -> bool:
        return datetime.fromisoformat(self.expires_at) > _now()


class SuppressionStore:
    def __init__(self, store: Store):
        self._store = store

    def create(self, suppression: Suppression, actor: str) -> Suppression:
        if not suppression.justification.strip():
            raise ValueError("suppression requires a justification")
        if not suppression.approver.strip():
            raise ValueError("suppression requires an approver")
        datetime.fromisoformat(suppression.expires_at)  # mandatory + parseable
        self._store.put(
            "suppressions", suppression.suppression_id, suppression.model_dump(mode="json")
        )
        self._store.append_event(
            "audit.suppression.created",
            "suppressions",
            suppression.suppression_id,
            suppression.model_dump(mode="json"),
            actor=actor,
        )
        return suppression

    def active_for(self, service: str) -> list[Suppression]:
        out = []
        for doc in self._store.all("suppressions"):
            s = Suppression.model_validate(doc)
            if s.service == service and s.is_active():
                out.append(s)
        return out

    def is_suppressed(self, service: str, check_id: str, endpoint_id: str) -> bool:
        for s in self.active_for(service):
            if s.check_id == check_id and s.endpoint_id in (None, endpoint_id):
                return True
        return False
