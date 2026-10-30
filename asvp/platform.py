"""ASVP composition root.

Wires the four planes together (PRD §6): sources → control plane →
execution plane → data & reporting. The API layer, CLI, and demo all sit
on top of this object.
"""

from __future__ import annotations

from typing import Callable, Optional

import httpx

from asvp.checks.generator import CheckGenerator, GenerationResult, PlannedCheck
from asvp.checks.suppression import SuppressionStore
from asvp.checks.template import TemplateLibrary
from asvp.compliance.evidence import EvidenceStore
from asvp.config import get_config
from asvp.engine.http_engine import HttpProbeEngine
from asvp.engine.adapters import RawFinding, build_default_registry
from asvp.engine.worker import CheckResult
from asvp.findings.baseline import BaselineStore
from asvp.findings.service import FindingsService
from asvp.governance.audit import AuditLog
from asvp.ingestion.store import IngestResult, SpecStore
from asvp.integrations.jira import JiraSync
from asvp.integrations.secrets import InMemorySecretsManager, SecretsManager
from asvp.integrations.slack import SlackNotifier
from asvp.models.findings import Finding
from asvp.models.scan import ScanRequest, ScanStatus
from asvp.orchestrator.orchestrator import Orchestrator
from asvp.policy.gate import (
    BuiltinPolicyEngine,
    BypassManager,
    GateInput,
    PolicyGate,
)
from asvp.registry import ServiceRegistry
from asvp.reporting.reports import Reporting
from asvp.storage import Store


class Platform:
    def __init__(
        self,
        db_path: Optional[str] = None,
        secrets: Optional[SecretsManager] = None,
        client_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
        target_rps: Optional[float] = None,
        external_engines: Optional[dict] = None,
    ):
        cfg = get_config()
        self.store = Store(db_path or cfg.db_path)
        self.audit = AuditLog(self.store)
        self.spec_store = SpecStore(self.store)
        self.registry = ServiceRegistry(self.store)
        self.templates = TemplateLibrary.load()
        self.suppressions = SuppressionStore(self.store)
        self.generator = CheckGenerator(self.templates, self.suppressions)
        self.secrets = secrets or InMemorySecretsManager()
        self.jira = JiraSync(self.store)
        self.slack = SlackNotifier(self.store)
        self.findings = FindingsService(self.store, on_change=self._on_finding_change)
        self.baselines = BaselineStore(self.store)
        self.evidence = EvidenceStore(self.store)
        self.gate = PolicyGate(BuiltinPolicyEngine(), self.store)
        self.bypasses = BypassManager(self.store, self.findings)
        self.reporting = Reporting(self.store, self.findings, self.registry)
        # External engine registry (AR-3). Defaults are built from configured
        # binary/jar paths; tests/demo inject adapters with canned runners.
        self.external_engines = (
            external_engines
            if external_engines is not None
            else build_default_registry(cfg)
        )
        self.orchestrator = Orchestrator(
            store=self.store,
            spec_store=self.spec_store,
            registry=self.registry,
            generator=self.generator,
            worker=HttpProbeEngine(),
            secrets=self.secrets,
            on_complete=self._on_scan_complete,
            client_factory=client_factory,
            target_rps=target_rps,
            external_engines=self.external_engines,
        )

    # ── ingestion entry point (FR-ING-1/2/3) ────────────────────────────

    def ingest_spec(
        self, document: dict, service: str, source_type: str = "postman",
        actor: str = "system",
    ) -> IngestResult:
        result = self.spec_store.ingest(document, service, source_type, actor)
        record = self.registry.get(service)
        if record:
            for hit in result.secret_hits:
                self.findings.create_secret_finding(
                    record, hit.kind, hit.location, hit.fingerprint
                )
        return result

    # ── scan completion pipeline ────────────────────────────────────────

    async def _on_scan_complete(
        self,
        scan: ScanStatus,
        results: list[tuple[PlannedCheck, CheckResult]],
        generation: GenerationResult,
        external_findings: list[RawFinding],
    ) -> None:
        service = self.registry.get(scan.request.service)

        # 1. Findings: normalize, dedupe, regression-guard (FR-FND-1/6, §9.2)
        #    from the built-in engine and the external engines (ZAP/Nuclei/Burp).
        touched = self.findings.ingest_results(scan, results, service)
        touched += self.findings.ingest_external_findings(scan, external_findings, service)

        # 2. Compliance evidence chain for every compliance-domain execution
        for check, result in results:
            if check.template.domain == "compliance":
                self.evidence.capture(scan, check, result, scan.request.spec_version)

        # 3. Baseline diff — the gate evaluates only the delta (FR-FND-6)
        new_findings, baselined = self.baselines.diff(
            scan.request.service, scan.request.environment, touched
        )

        # 4. Policy gate (FR-GTE-1/2)
        verdict = self.gate.evaluate(
            GateInput(
                service=service.name,
                tier=service.criticality_tier,
                environment=scan.request.environment,
                profile=scan.request.profile,
                policy_mode=service.policy_mode,
                new_findings=new_findings,
                baselined_count=len(baselined),
                coverage_gaps=scan.coverage_gaps,
            ),
            scan_id=scan.scan_id,
        )
        scan.gate_verdict = verdict.to_dict()
        scan.gate_verdict["new_findings"] = [f.finding_id for f in new_findings]

        # 5. Pre-prod profile produces the secure-to-ship record (FR-RPT-4)
        if scan.request.profile == "preprod":
            self.reporting.release_report(scan)

    def _on_finding_change(self, finding: Finding, event: str) -> None:
        key = self.jira.on_finding_change(finding, event)
        if key and not finding.jira_key:
            finding.jira_key = key
            self.findings._save(finding)

    # ── fix verification (FR-FND-4 + FR-EXE-8) ──────────────────────────

    async def verify_fix(self, finding_id: str, actor: str) -> Finding:
        finding = self.findings.get(finding_id)
        if finding is None:
            raise KeyError(f"finding '{finding_id}' not found")

        async def rerun(f: Finding) -> CheckResult:
            request = ScanRequest(
                service=f.service,
                spec_version="latest",
                environment=f.environment,
                profile="qa",
                mode="full",
                requested_by="fix-verification",
            )
            status = await self.orchestrator.rerun_single_check(
                request, f.check_id, f.endpoint_id
            )
            if status.state != "complete" or status.checks_executed == 0:
                return CheckResult(
                    status="error",
                    detail=f"verification scan {status.scan_id} did not execute the check "
                           f"({status.error or 'no applicable checks'})",
                )
            if status.checks_failed == 0:
                return CheckResult(status="pass", detail="originating check passed on re-run")
            return CheckResult(status="fail", detail="originating check still failing")

        return await self.findings.verify_fix(finding_id, actor, rerun)

    # ── maintenance clocks ──────────────────────────────────────────────

    def run_clocks(self) -> dict:
        """Risk-acceptance expiry (FR-FND-3) + SLA escalation (FR-FND-5)."""
        reopened = self.findings.expire_risk_acceptances()
        breaches = self.findings.sla_breaches()
        for f in breaches:
            service = self.registry.get(f.service)
            channel = (service.slack_channel if service else None) or "#security"
            self.slack.sla_escalation(channel, f.title, f.sla_due or "")
        return {
            "risk_acceptances_reopened": [f.finding_id for f in reopened],
            "sla_breaches": [f.finding_id for f in breaches],
        }

    async def close(self) -> None:
        await self.orchestrator.stop()
        self.store.close()
