"""Baseline management (FR-FND-6).

Per service+environment baseline of accepted/known findings. The CI gate
evaluates only the diff against the baseline.
"""

from __future__ import annotations

from asvp.models.findings import Finding
from asvp.storage import Store


def _key(service: str, environment: str) -> str:
    return f"{service}:{environment}"


class BaselineStore:
    def __init__(self, store: Store):
        self._store = store

    def get(self, service: str, environment: str) -> set[str]:
        doc = self._store.get("baselines", _key(service, environment))
        return set(doc["fingerprints"]) if doc else set()

    def set(
        self, service: str, environment: str, fingerprints: set[str], actor: str
    ) -> None:
        self._store.put(
            "baselines",
            _key(service, environment),
            {"service": service, "environment": environment, "fingerprints": sorted(fingerprints)},
        )
        self._store.append_event(
            "baseline.updated", "baselines", _key(service, environment),
            {"count": len(fingerprints)}, actor=actor,
        )

    def add(self, service: str, environment: str, fingerprint: str, actor: str) -> None:
        current = self.get(service, environment)
        current.add(fingerprint)
        self.set(service, environment, current, actor)

    def diff(
        self, service: str, environment: str, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """Returns (new_vs_baseline, already_baselined)."""
        baseline = self.get(service, environment)
        new = [f for f in findings if f.fingerprint not in baseline]
        known = [f for f in findings if f.fingerprint in baseline]
        return new, known
