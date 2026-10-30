"""Immutable, versioned spec store (FR-ING-2, AR-8).

Every ingested source is secret-scanned (FR-ING-3), normalized to the
canonical model (AR-1), and stored immutably keyed by content hash. A
`latest` pointer per service is the only mutable element.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from asvp.ingestion.openapi import parse_openapi_spec
from asvp.ingestion.postman import CollectionValidationError, parse_postman_collection
from asvp.ingestion.secret_scan import SecretHit, scan_for_secrets
from asvp.models.canonical import CanonicalAPI
from asvp.storage import Store


class IngestionError(Exception):
    pass


@dataclass
class IngestResult:
    service: str
    version: str  # content hash
    canonical: CanonicalAPI
    secret_hits: list[SecretHit] = field(default_factory=list)
    is_new_version: bool = True


class SpecStore:
    def __init__(self, store: Store):
        self._store = store

    def ingest(
        self,
        document: dict,
        service: str,
        source_type: str = "postman",
        actor: str = "system",
    ) -> IngestResult:
        # FR-ING-3: secret scan before anything is persisted; raw secrets
        # are quarantined — only redacted document + hash fingerprints remain.
        cleaned, hits = scan_for_secrets(document, redact=True)

        try:
            if source_type == "postman":
                canonical = parse_postman_collection(cleaned, service)
            elif source_type == "openapi":
                canonical = parse_openapi_spec(cleaned, service)
            else:
                raise IngestionError(f"unsupported source type: {source_type}")
        except CollectionValidationError as exc:
            raise IngestionError(str(exc)) from exc

        version = canonical.content_hash()
        existing = self._store.get("specs", f"{service}:{version}")
        is_new = existing is None
        if is_new:
            self._store.put(
                "specs",
                f"{service}:{version}",
                {"service": service, "version": version, "model": canonical.model_dump(mode="json")},
            )
            self._store.append_event(
                "spec.ingested",
                "specs",
                f"{service}:{version}",
                {
                    "source_type": source_type,
                    "endpoints": len(canonical.endpoints),
                    "secret_hits": [
                        {"kind": h.kind, "location": h.location, "fingerprint": h.fingerprint}
                        for h in hits
                    ],
                },
                actor=actor,
            )
        self._store.put("spec_latest", service, {"service": service, "version": version})
        return IngestResult(
            service=service,
            version=version,
            canonical=canonical,
            secret_hits=hits,
            is_new_version=is_new,
        )

    def get(self, service: str, version: str = "latest") -> Optional[CanonicalAPI]:
        if version == "latest":
            pointer = self._store.get("spec_latest", service)
            if not pointer:
                return None
            version = pointer["version"]
        doc = self._store.get("specs", f"{service}:{version}")
        return CanonicalAPI.model_validate(doc["model"]) if doc else None

    def versions(self, service: str) -> list[str]:
        return [
            d["version"]
            for d in self._store.all("specs")
            if d["service"] == service
        ]

    def coverage(self, service: str, observed_endpoints: list[str]) -> dict:
        """FR-ING-6: reconcile canonical model vs gateway-observed inventory.

        `observed_endpoints` comes from read-only Istio access-log telemetry
        ("METHOD /path" strings). Returns coverage % and the deltas.
        """
        model = self.get(service)
        if model is None:
            return {"coverage_pct": 0.0, "untested": [], "undocumented": []}
        declared = {e.endpoint_id for e in model.endpoints}
        observed = set(observed_endpoints)
        covered = declared & observed if observed else declared
        untested = sorted(observed - declared)
        coverage_pct = round(100.0 * len(covered) / len(observed), 1) if observed else 100.0
        return {
            "coverage_pct": coverage_pct,
            "untested": untested,  # live at the gateway, absent from the model
            "undocumented": untested,
            "declared": sorted(declared),
        }
