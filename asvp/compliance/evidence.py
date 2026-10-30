"""Compliance evidence chain (§5.2, FR-RPT-3, NFR-5).

Every compliance-domain check execution is stored with: control ID,
timestamp, target service+version, redacted request/response excerpt, and
verdict — an audit-ready, immutable evidence chain (append-only journal).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from asvp.checks.generator import PlannedCheck
from asvp.engine.worker import CheckResult
from asvp.models.scan import ScanStatus
from asvp.storage import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceStore:
    def __init__(self, store: Store):
        self._store = store

    def capture(
        self,
        scan: ScanStatus,
        check: PlannedCheck,
        result: CheckResult,
        spec_version: str,
    ) -> list[str]:
        """Capture one evidence artifact per compliance control mapping."""
        if not check.template.compliance_mappings:
            return []
        ids = []
        for control in check.template.compliance_mappings:
            evidence_id = uuid4().hex[:12]
            artifact = {
                "evidence_id": evidence_id,
                "control_id": control,
                "timestamp": _now(),
                "service": scan.request.service,
                "spec_version": spec_version,
                "environment": scan.request.environment,
                "scan_id": scan.scan_id,
                "check_id": check.template.id,
                "endpoint": check.endpoint_id,
                "verdict": "pass" if result.status == "pass" else "fail"
                if result.status == "fail" else result.status,
                "evidence_excerpt": result.evidence,  # redacted at capture
                "detail": result.detail,
            }
            self._store.put("evidence", evidence_id, artifact)
            self._store.append_event(
                "evidence.captured", "evidence", evidence_id,
                {"control": control, "verdict": artifact["verdict"]},
            )
            ids.append(evidence_id)
        return ids

    def export(
        self,
        framework: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> dict:
        """FR-RPT-3: per-framework, time-bounded, machine-readable bundle.

        `framework` matches the control-id prefix (e.g. 'PCI-DSS-4.0',
        'GDPR', 'RBI')."""
        artifacts = []
        for a in self._store.all("evidence"):
            if framework and not a["control_id"].startswith(framework):
                continue
            if since and a["timestamp"] < since:
                continue
            if until and a["timestamp"] > until:
                continue
            artifacts.append(a)
        artifacts.sort(key=lambda a: (a["control_id"], a["timestamp"]))
        controls: dict[str, dict] = {}
        for a in artifacts:
            c = controls.setdefault(
                a["control_id"], {"control_id": a["control_id"], "pass": 0, "fail": 0}
            )
            if a["verdict"] == "pass":
                c["pass"] += 1
            elif a["verdict"] == "fail":
                c["fail"] += 1
        bundle = {
            "generated_at": _now(),
            "framework": framework or "all",
            "window": {"since": since, "until": until},
            "control_summary": sorted(controls.values(), key=lambda c: c["control_id"]),
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
        }
        # Immutability: the bundle itself is journaled with a content digest.
        import hashlib

        digest = hashlib.sha256(
            json.dumps(bundle, sort_keys=True).encode("utf-8")
        ).hexdigest()
        bundle["bundle_digest"] = digest
        self._store.append_event(
            "evidence.exported", "evidence", digest[:12],
            {"framework": framework, "artifacts": len(artifacts), "digest": digest},
        )
        return bundle
