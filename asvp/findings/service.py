"""Findings service (FR-FND-1..9).

Normalizes engine output to the finding schema, fingerprints for cross-run
dedupe, drives the lifecycle state machine, runs SLA clocks, performs
automated fix verification, and reopens regressions on the original finding.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Optional

from asvp.checks.generator import PlannedCheck
from asvp.config import get_config
from asvp.engine.worker import CheckResult
from asvp.models.findings import (
    APPROVAL_REQUIRED_STATES,
    Finding,
    StateTransition,
    TRANSITIONS,
    fingerprint,
)
from asvp.models.registry import ServiceRecord
from asvp.models.scan import ScanStatus
from asvp.storage import Store

ACTIVE_STATES = {"new", "triaged", "confirmed", "in_remediation", "reopened"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TransitionError(Exception):
    pass


class FindingsService:
    def __init__(self, store: Store, on_change: Optional[Callable[[Finding, str], None]] = None):
        self._store = store
        self._on_change = on_change  # integration hook (Jira/Slack mirroring)

    # ── persistence ─────────────────────────────────────────────────────

    def _save(self, finding: Finding) -> None:
        self._store.put("findings", finding.finding_id, finding.model_dump(mode="json"))

    def get(self, finding_id: str) -> Optional[Finding]:
        doc = self._store.get("findings", finding_id)
        return Finding.model_validate(doc) if doc else None

    def all(self, service: Optional[str] = None) -> list[Finding]:
        out = [Finding.model_validate(d) for d in self._store.all("findings")]
        if service:
            out = [f for f in out if f.service == service]
        return out

    def by_fingerprint(self, fp: str) -> Optional[Finding]:
        for f in self.all():
            if f.fingerprint == fp:
                return f
        return None

    # ── ingest engine output (FR-FND-1, regression guard §9.2) ──────────

    def ingest_results(
        self,
        scan: ScanStatus,
        results: list[tuple[PlannedCheck, CheckResult]],
        service: ServiceRecord,
    ) -> list[Finding]:
        touched: list[Finding] = []
        for check, result in results:
            if result.status != "fail":
                continue
            tpl = check.template
            touched.append(
                self._upsert_failure(
                    scan, service,
                    endpoint_id=check.endpoint_id,
                    check_id=tpl.id,
                    parameter=result.parameter,
                    domain=tpl.domain,
                    severity=tpl.default_severity,
                    title=tpl.name,
                    description=result.detail or tpl.description,
                    remediation=tpl.remediation,
                    compliance_mappings=list(tpl.compliance_mappings),
                    evidence=result.evidence,
                    reproduction=result.reproduction,
                )
            )
        scan.finding_ids = [f.finding_id for f in touched]
        return touched

    def ingest_external_findings(
        self,
        scan: ScanStatus,
        raw_findings: list,
        service: ServiceRecord,
    ) -> list[Finding]:
        """Normalize external-engine output (ZAP/Nuclei/Burp) to the finding
        schema (FR-FND-1), sharing dedupe + regression handling with the
        built-in engine. Extends (does not overwrite) scan.finding_ids."""
        touched: list[Finding] = []
        for rf in raw_findings:
            touched.append(
                self._upsert_failure(
                    scan, service,
                    endpoint_id=rf.endpoint_id,
                    check_id=rf.check_id,
                    parameter=rf.parameter,
                    domain=rf.domain,
                    severity=rf.severity,
                    title=f"[{rf.engine}] {rf.title}",
                    description=rf.description,
                    remediation=rf.remediation,
                    compliance_mappings=list(rf.compliance_mappings),
                    evidence=rf.evidence,
                    reproduction=None,
                )
            )
        scan.finding_ids = list(dict.fromkeys(scan.finding_ids + [f.finding_id for f in touched]))
        scan.external_findings_count = len(touched)
        return touched

    def _upsert_failure(
        self,
        scan: ScanStatus,
        service: ServiceRecord,
        *,
        endpoint_id: str,
        check_id: str,
        parameter: str,
        domain: str,
        severity: str,
        title: str,
        description: str,
        remediation: str,
        compliance_mappings: list,
        evidence: dict,
        reproduction=None,
    ) -> Finding:
        """Create, dedupe, or regression-reopen a finding for one failure."""
        fp = fingerprint(service.name, endpoint_id, check_id, parameter)
        existing = self.by_fingerprint(fp)
        if existing and existing.state in ACTIVE_STATES | {"risk_accepted"}:
            existing.occurrences += 1
            existing.last_seen = _now().isoformat()
            existing.scan_id = scan.scan_id
            existing.evidence = evidence
            self._save(existing)
            return existing
        if existing and existing.state in {"closed", "fix_verified", "false_positive"}:
            # Regression: reopen the original finding, never a new one.
            self._transition_internal(
                existing, "reopened", actor="asvp-regression-guard",
                justification=f"re-detected by scan {scan.scan_id}",
            )
            existing.is_regression = True
            existing.occurrences += 1
            existing.last_seen = _now().isoformat()
            existing.scan_id = scan.scan_id
            existing.evidence = evidence
            self._save(existing)
            self._store.append_event(
                "finding.regression", "findings", existing.finding_id,
                {"scan_id": scan.scan_id},
            )
            return existing

        new = Finding(
            fingerprint=fp,
            service=service.name,
            owner_team=service.owner_team,
            environment=scan.request.environment,
            endpoint_id=endpoint_id,
            check_id=check_id,
            parameter=parameter,
            domain=domain,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            compliance_mappings=compliance_mappings,
            reproduction=reproduction,
            evidence=evidence,
            scan_id=scan.scan_id,
        )
        self._save(new)
        self._store.append_event(
            "finding.created", "findings", new.finding_id,
            {"check": check_id, "severity": severity, "endpoint": endpoint_id},
        )
        if self._on_change:
            self._on_change(new, "created")
        return new

    def create_secret_finding(
        self, service: ServiceRecord, kind: str, location: str, scan_fp: str
    ) -> Finding:
        """FR-ING-3: a detected secret is an immediate Critical finding."""
        fp = fingerprint(service.name, "(spec)", "ING-SECRET-001", scan_fp)
        existing = self.by_fingerprint(fp)
        if existing and existing.state in ACTIVE_STATES:
            existing.occurrences += 1
            existing.last_seen = _now().isoformat()
            self._save(existing)
            return existing
        finding = Finding(
            fingerprint=fp,
            service=service.name,
            owner_team=service.owner_team,
            environment="(source)",
            endpoint_id="(spec)",
            check_id="ING-SECRET-001",
            parameter=scan_fp,
            domain="security",
            severity="critical",
            title=f"Secret committed in API specification ({kind})",
            description=(
                f"A credential of type '{kind}' was detected at {location} in the "
                "ingested specification. The raw value has been quarantined and is "
                "not stored; only its hash fingerprint is retained."
            ),
            remediation=(
                "Rotate the exposed credential immediately, purge it from the "
                "collection and its history, and replace it with a secrets-manager "
                "reference ('secret:' handle)."
            ),
            evidence={"kind": kind, "location": location, "value_fingerprint": scan_fp},
        )
        self._save(finding)
        self._store.append_event(
            "finding.created", "findings", finding.finding_id,
            {"check": "ING-SECRET-001", "severity": "critical"},
        )
        if self._on_change:
            self._on_change(finding, "created")
        return finding

    # ── lifecycle (FR-FND-2/3) ──────────────────────────────────────────

    def transition(
        self,
        finding_id: str,
        to_state: str,
        actor: str,
        justification: Optional[str] = None,
        approver: Optional[str] = None,
        risk_acceptance_days: Optional[int] = None,
        severity_override: Optional[str] = None,
        service: Optional[ServiceRecord] = None,
    ) -> Finding:
        finding = self.get(finding_id)
        if finding is None:
            raise KeyError(f"finding '{finding_id}' not found")
        if to_state in APPROVAL_REQUIRED_STATES:
            if not justification or not approver:
                raise TransitionError(
                    f"transition to '{to_state}' requires justification and approver"
                )
        if to_state == "risk_accepted":
            days = risk_acceptance_days or 90
            finding.risk_acceptance_expiry = (_now() + timedelta(days=days)).isoformat()
        if severity_override:
            if not justification:
                raise TransitionError("severity adjustment requires justification")
            finding.severity = severity_override  # type: ignore[assignment]
        self._transition_internal(finding, to_state, actor, justification, approver)
        if to_state == "confirmed":
            finding.confirmed_at = _now().isoformat()
            sla_days = None
            if service and finding.severity in service.sla_overrides:
                sla_days = service.sla_overrides[finding.severity]
            if sla_days is None:
                sla_days = get_config().sla.days_for(finding.severity)
            finding.sla_due = (_now() + timedelta(days=sla_days)).isoformat()
        self._save(finding)
        if self._on_change:
            self._on_change(finding, to_state)
        return finding

    def _transition_internal(
        self,
        finding: Finding,
        to_state: str,
        actor: str,
        justification: Optional[str] = None,
        approver: Optional[str] = None,
    ) -> None:
        allowed = TRANSITIONS.get(finding.state, set())
        if to_state not in allowed:
            raise TransitionError(
                f"illegal transition {finding.state} → {to_state} "
                f"(allowed: {sorted(allowed)})"
            )
        finding.history.append(
            StateTransition(
                from_state=finding.state,
                to_state=to_state,
                actor=actor,
                justification=justification,
                approver=approver,
            )
        )
        finding.state = to_state  # type: ignore[assignment]
        kind = (
            f"audit.finding.{to_state}"
            if to_state in APPROVAL_REQUIRED_STATES
            else f"finding.{to_state}"
        )
        self._store.append_event(
            kind, "findings", finding.finding_id,
            {"justification": justification, "approver": approver}, actor=actor,
        )

    # ── automated fix verification (FR-FND-4) ──────────────────────────

    async def verify_fix(
        self,
        finding_id: str,
        actor: str,
        rerun: Callable[[Finding], Awaitable[CheckResult]],
    ) -> Finding:
        """'Mark fixed' re-executes the originating check; only a passing
        re-run moves the finding to fix_verified. SLA clock never pauses on
        an unverified claim."""
        finding = self.get(finding_id)
        if finding is None:
            raise KeyError(f"finding '{finding_id}' not found")
        if finding.state != "in_remediation":
            raise TransitionError(
                f"fix verification requires state 'in_remediation', got '{finding.state}'"
            )
        result = await rerun(finding)
        if result.status == "pass":
            self._transition_internal(
                finding, "fix_verified", actor="asvp-fix-verification",
                justification=f"re-run of {finding.check_id} passed (marked fixed by {actor})",
            )
            self._save(finding)
            if self._on_change:
                self._on_change(finding, "fix_verified")
        else:
            self._store.append_event(
                "finding.fix_rejected", "findings", finding.finding_id,
                {"detail": result.detail, "marked_by": actor},
            )
            if self._on_change:
                self._on_change(finding, "fix_rejected")
        return self.get(finding_id)

    # ── clocks (FR-FND-3 expiry, FR-FND-5 SLA) ──────────────────────────

    def expire_risk_acceptances(self) -> list[Finding]:
        """Risk acceptance carries mandatory expiry and auto-reopens."""
        reopened = []
        for finding in self.all():
            if (
                finding.state == "risk_accepted"
                and finding.risk_acceptance_expiry
                and datetime.fromisoformat(finding.risk_acceptance_expiry) <= _now()
            ):
                self._transition_internal(
                    finding, "reopened", actor="asvp-risk-expiry",
                    justification="risk acceptance expired",
                )
                self._save(finding)
                reopened.append(finding)
        return reopened

    def sla_breaches(self) -> list[Finding]:
        breaches = []
        for finding in self.all():
            if (
                finding.state in ("confirmed", "in_remediation", "reopened")
                and finding.sla_due
                and datetime.fromisoformat(finding.sla_due) <= _now()
            ):
                breaches.append(finding)
        return breaches
