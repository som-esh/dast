"""Service registry (FR-ING-7)."""

from __future__ import annotations

from typing import Optional

from asvp.models.registry import ServiceRecord
from asvp.storage import Store


class ServiceRegistry:
    def __init__(self, store: Store):
        self._store = store

    def register(self, record: ServiceRecord, actor: str = "system") -> ServiceRecord:
        self._store.put("services", record.name, record.model_dump(mode="json"))
        self._store.append_event(
            "service.registered", "services", record.name,
            {"tier": record.criticality_tier, "team": record.owner_team},
            actor=actor,
        )
        return record

    def get(self, name: str) -> Optional[ServiceRecord]:
        doc = self._store.get("services", name)
        return ServiceRecord.model_validate(doc) if doc else None

    def all(self) -> list[ServiceRecord]:
        return [ServiceRecord.model_validate(d) for d in self._store.all("services")]

    def set_policy_mode(self, name: str, mode: str, actor: str) -> ServiceRecord:
        """FR-GTE-2: mode transitions logged and role-restricted (role check
        happens at the API layer via rbac.authorize)."""
        record = self.get(name)
        if record is None:
            raise KeyError(f"service '{name}' not registered")
        old = record.policy_mode
        record.policy_mode = mode  # type: ignore[assignment]
        self._store.put("services", name, record.model_dump(mode="json"))
        self._store.append_event(
            "audit.policy.mode_change", "services", name,
            {"from": old, "to": mode}, actor=actor,
        )
        return record
