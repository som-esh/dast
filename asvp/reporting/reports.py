"""Reporting and dashboards (FR-RPT-1/2/4, §11 metrics + counter-metrics)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from asvp.findings.service import ACTIVE_STATES, FindingsService
from asvp.models.scan import ScanStatus
from asvp.registry import ServiceRegistry
from asvp.storage import Store


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Reporting:
    def __init__(self, store: Store, findings: FindingsService, registry: ServiceRegistry):
        self._store = store
        self._findings = findings
        self._registry = registry

    # ── FR-RPT-1: team dashboard ────────────────────────────────────────

    def team_dashboard(self, team: str) -> dict:
        findings = [f for f in self._findings.all() if f.owner_team == team]
        open_findings = [f for f in findings if f.state in ACTIVE_STATES]
        by_severity = Counter(f.severity for f in open_findings)
        sla_breached = [
            f.finding_id
            for f in open_findings
            if f.sla_due and datetime.fromisoformat(f.sla_due) <= _now()
        ]
        gate_events = [
            e for e in self._store.events(kind="gate.evaluated", limit=500)
        ]
        team_services = {s.name for s in self._registry.all() if s.owner_team == team}
        team_gate = [e for e in gate_events if e["payload"].get("service") in team_services]
        passed = sum(1 for e in team_gate if e["payload"].get("verdict") == "pass")
        return {
            "team": team,
            "open_findings": len(open_findings),
            "by_severity": dict(by_severity),
            "sla_breached": sla_breached,
            "gate_evaluations": len(team_gate),
            "gate_pass_rate": round(passed / len(team_gate), 2) if team_gate else None,
            "regressions": sum(1 for f in findings if f.is_regression),
        }

    # ── FR-RPT-2: executive dashboard ───────────────────────────────────

    def executive_dashboard(self) -> dict:
        services = self._registry.all()
        findings = self._findings.all()
        open_findings = [f for f in findings if f.state in ACTIVE_STATES]

        # MTTR by severity (confirmed → fix_verified)
        mttr: dict[str, Optional[float]] = {}
        for sev in ("critical", "high", "medium", "low"):
            durations = []
            for f in findings:
                if f.severity != sev or not f.confirmed_at:
                    continue
                verified = next(
                    (h.timestamp for h in f.history if h.to_state == "fix_verified"), None
                )
                if verified:
                    delta = datetime.fromisoformat(verified) - datetime.fromisoformat(
                        f.confirmed_at
                    )
                    durations.append(delta.total_seconds() / 86400)
            mttr[sev] = round(sum(durations) / len(durations), 2) if durations else None

        fp_closed = sum(1 for f in findings if f.state == "false_positive")
        triaged = sum(
            1 for f in findings if f.state not in ("new",)
        )
        bypasses = [e for e in self._store.events(limit=2000) if e["kind"] == "audit.gate.bypass"]

        # Counter-metrics (§11): a green-but-routed-around platform has failed.
        suppressions = list(self._store.all("suppressions"))
        return {
            "services_onboarded": len(services),
            "services_blocking_mode": sum(1 for s in services if s.policy_mode == "block"),
            "tier1_identity_contract_fulfilled": sum(
                1 for s in services
                if s.criticality_tier == "tier1" and s.identity_contract_fulfilled()
            ),
            "open_findings_by_severity": dict(
                Counter(f.severity for f in open_findings)
            ),
            "findings_by_engine": dict(
                Counter(
                    f.check_id.split(":")[0] if ":" in f.check_id else "builtin"
                    for f in findings
                )
            ),
            "mttr_days": mttr,
            "false_positive_rate": round(fp_closed / triaged, 3) if triaged else None,
            "regressions": sum(1 for f in findings if f.is_regression),
            "gate_bypasses": len(bypasses),
            "counter_metrics": {
                "active_suppressions": len(suppressions),
                "fp_closed": fp_closed,
            },
        }

    # ── FR-RPT-4: per-release report ────────────────────────────────────

    def release_report(self, scan: ScanStatus) -> dict:
        findings = [
            self._findings.get(fid) for fid in scan.finding_ids
        ]
        findings = [f for f in findings if f]
        accepted = [
            f for f in self._findings.all(scan.request.service)
            if f.state == "risk_accepted"
        ]
        report = {
            "report_type": "secure-to-ship record (FR-RPT-4)",
            "service": scan.request.service,
            "environment": scan.request.environment,
            "profile": scan.request.profile,
            "commit_sha": scan.request.commit_sha,
            "spec_version": scan.request.spec_version,
            "scan_id": scan.scan_id,
            "executed_at": scan.finished_at,
            "scope": scan.request.scope_endpoints or "full suite",
            "checks_executed": scan.checks_executed,
            "checks_failed": scan.checks_failed,
            "coverage_gaps": scan.coverage_gaps,
            "gate_verdict": scan.gate_verdict,
            "findings": [
                {
                    "id": f.finding_id,
                    "severity": f.severity,
                    "title": f.title,
                    "endpoint": f.endpoint_id,
                    "state": f.state,
                }
                for f in findings
            ],
            "accepted_risks": [
                {
                    "id": f.finding_id,
                    "title": f.title,
                    "expires": f.risk_acceptance_expiry,
                }
                for f in accepted
            ],
        }
        self._store.put("release_reports", scan.scan_id, report)
        self._store.append_event(
            "report.release_generated", "release_reports", scan.scan_id,
            {"service": scan.request.service, "verdict": (scan.gate_verdict or {}).get("verdict")},
        )
        return report

    # ── PR comment payload (FR-DX-2): top-3, never a wall ───────────────

    def pr_comment(self, scan: ScanStatus) -> str:
        findings = [self._findings.get(fid) for fid in scan.finding_ids]
        findings = [f for f in findings if f]
        findings.sort(key=lambda f: -f.severity_rank())
        verdict = (scan.gate_verdict or {}).get("verdict", "n/a")
        icon = {"pass": "✅", "warn": "⚠️", "block": "🛑"}.get(verdict, "ℹ️")
        lines = [
            f"{icon} **ASVP scan `{scan.scan_id}` — verdict: {verdict.upper()}**",
            f"Checks: {scan.checks_executed} executed, {scan.checks_failed} failed."
            + (f" Coverage gaps: {len(scan.coverage_gaps)}." if scan.coverage_gaps else ""),
        ]
        for f in findings[:3]:
            lines.append(
                f"- **{f.severity.upper()}** {f.title} on `{f.endpoint_id}` — "
                f"{f.remediation.strip().splitlines()[0]} "
                f"([details](https://asvp.internal/findings/{f.finding_id}))"
            )
        if len(findings) > 3:
            lines.append(
                f"…and {len(findings) - 3} more — see the "
                f"[full report](https://asvp.internal/scans/{scan.scan_id})."
            )
        return "\n".join(lines)
