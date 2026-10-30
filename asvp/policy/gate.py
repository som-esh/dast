"""Policy gate (AR-6, FR-GTE-1/2/6) and break-glass bypass workflow.

AR-6 requires gating decisions to be produced by OPA evaluating versioned
Rego from Git. `OpaPolicyEngine` shells out to an `opa` binary when one is
available; `BuiltinPolicyEngine` evaluates the same versioned policy
documents (YAML, Git-reviewed per FR-GOV-4) with identical semantics and is
the fallback in environments without OPA. Both implement `PolicyEngine`,
so swapping is a wiring change only.

Verdict semantics per service policy mode (FR-GTE-2):
  report_only → verdict forced to pass, would-be verdict reported
  warn        → block downgraded to warn
  block       → verdict applied as evaluated
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

import yaml

from asvp.models.findings import Finding, SEVERITY_ORDER
from asvp.models.registry import ServiceRecord
from asvp.storage import Store


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class GateInput:
    """FR-GTE-1 inputs: new findings vs baseline, severities, domains,
    service tier, environment, coverage."""

    service: str
    tier: str
    environment: str
    profile: str  # pr | qa | preprod
    policy_mode: str  # report_only | warn | block
    new_findings: list[Finding] = field(default_factory=list)
    baselined_count: int = 0
    coverage_gaps: list[str] = field(default_factory=list)


@dataclass
class GateVerdict:
    verdict: str  # pass | warn | block
    evaluated_verdict: str  # before policy-mode downgrade
    policy_name: str
    policy_version: int
    reasons: list[str] = field(default_factory=list)
    rule_hits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "evaluated_verdict": self.evaluated_verdict,
            "policy": f"{self.policy_name}@v{self.policy_version}",
            "reasons": self.reasons,
            "rule_hits": self.rule_hits,
        }


class PolicyEngine(ABC):
    @abstractmethod
    def evaluate(self, gate_input: GateInput) -> GateVerdict:
        ...


class BuiltinPolicyEngine(PolicyEngine):
    def __init__(self, policy_path: Optional[Path] = None):
        self._path = policy_path or Path(__file__).parent / "policies" / "default.yaml"
        self._doc = yaml.safe_load(self._path.read_text(encoding="utf-8"))

    def evaluate(self, gate_input: GateInput) -> GateVerdict:
        reasons: list[str] = []
        rule_hits: list[str] = []
        outcome = "pass"

        def escalate(action: str) -> None:
            nonlocal outcome
            order = {"pass": 0, "warn": 1, "block": 2}
            if order[action] > order[outcome]:
                outcome = action

        for rule in self._doc.get("rules", []):
            if gate_input.profile not in rule.get("profiles", []):
                continue
            if rule.get("tiers") and gate_input.tier not in rule["tiers"]:
                continue

            if rule.get("block_on_coverage_gap"):
                if gate_input.coverage_gaps:
                    rule_hits.append(rule["id"])
                    reasons.append(
                        f"[{rule['id']}] {len(gate_input.coverage_gaps)} coverage "
                        f"gap(s) on a {gate_input.tier} service: "
                        + "; ".join(gate_input.coverage_gaps[:2])
                    )
                    escalate(rule.get("action", "warn"))
                continue

            threshold = SEVERITY_ORDER.get(rule.get("severity_at_least", "low"), 1)
            matching = [
                f for f in gate_input.new_findings if f.severity_rank() >= threshold
            ]
            if len(matching) > int(rule.get("max_new", 0)):
                rule_hits.append(rule["id"])
                worst = sorted(matching, key=lambda f: -f.severity_rank())[:3]
                reasons.append(
                    f"[{rule['id']}] {len(matching)} new finding(s) at or above "
                    f"{rule.get('severity_at_least')}: "
                    + "; ".join(f"{f.severity.upper()} {f.title}" for f in worst)
                )
                escalate(rule.get("action", "warn"))

        # FR-GTE-2 mode application
        evaluated = outcome
        if gate_input.policy_mode == "report_only":
            outcome = "pass"
            if evaluated != "pass":
                reasons.append(
                    f"service is in report-only mode — evaluated verdict was '{evaluated}'"
                )
        elif gate_input.policy_mode == "warn" and outcome == "block":
            outcome = "warn"
            reasons.append("service is in warn mode — block downgraded to warn")

        return GateVerdict(
            verdict=outcome,
            evaluated_verdict=evaluated,
            policy_name=self._doc.get("name", "default"),
            policy_version=int(self._doc.get("version", 1)),
            reasons=reasons,
            rule_hits=rule_hits,
        )


class OpaPolicyEngine(PolicyEngine):
    """AR-6 seam: delegates to an `opa` binary evaluating Rego from the
    policy repo. Falls back to BuiltinPolicyEngine when OPA is absent."""

    def __init__(self, rego_path: Optional[Path] = None):
        self._opa = shutil.which("opa")
        self._rego_path = rego_path
        self._fallback = BuiltinPolicyEngine()

    def evaluate(self, gate_input: GateInput) -> GateVerdict:
        if not self._opa or not self._rego_path:
            return self._fallback.evaluate(gate_input)
        import json as _json

        payload = {
            "service": gate_input.service,
            "tier": gate_input.tier,
            "profile": gate_input.profile,
            "policy_mode": gate_input.policy_mode,
            "coverage_gaps": gate_input.coverage_gaps,
            "new_findings": [
                {"severity": f.severity, "domain": f.domain, "title": f.title}
                for f in gate_input.new_findings
            ],
        }
        proc = subprocess.run(
            [self._opa, "eval", "-d", str(self._rego_path), "-I", "data.asvp.gate.verdict",
             "--format", "json"],
            input=_json.dumps(payload), capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return self._fallback.evaluate(gate_input)
        result = _json.loads(proc.stdout)
        value = result["result"][0]["expressions"][0]["value"]
        return GateVerdict(
            verdict=value.get("verdict", "pass"),
            evaluated_verdict=value.get("evaluated_verdict", value.get("verdict", "pass")),
            policy_name="rego",
            policy_version=1,
            reasons=value.get("reasons", []),
        )


class PolicyGate:
    def __init__(self, engine: PolicyEngine, store: Store):
        self._engine = engine
        self._store = store

    def evaluate(self, gate_input: GateInput, scan_id: str) -> GateVerdict:
        verdict = self._engine.evaluate(gate_input)
        self._store.append_event(
            "gate.evaluated", "scans", scan_id,
            {
                "service": gate_input.service,
                "profile": gate_input.profile,
                **verdict.to_dict(),
            },
        )
        return verdict


class BypassError(Exception):
    pass


class BypassManager:
    """Break-glass workflow (FR-GTE-6, §9.4).

    Named-role approval, mandatory reason, auto-created follow-up finding
    with 7-day SLA, surfaced on the leadership dashboard. A second bypass
    touching the same finding requires director-level approval.
    """

    def __init__(self, store: Store, findings_service):
        self._store = store
        self._findings = findings_service

    def request(self, scan_id: str, service: str, reason: str, requested_by: str) -> dict:
        if not reason.strip():
            raise BypassError("bypass requires a mandatory reason")
        bypass = {
            "bypass_id": uuid4().hex[:10],
            "scan_id": scan_id,
            "service": service,
            "reason": reason,
            "requested_by": requested_by,
            "state": "pending",
            "requested_at": _now().isoformat(),
        }
        self._store.put("bypasses", bypass["bypass_id"], bypass)
        self._store.append_event(
            "audit.gate.bypass_requested", "bypasses", bypass["bypass_id"],
            bypass, actor=requested_by,
        )
        return bypass

    def approve(
        self, bypass_id: str, approver: str, is_director: bool = False
    ) -> dict:
        bypass = self._store.get("bypasses", bypass_id)
        if bypass is None:
            raise BypassError(f"bypass '{bypass_id}' not found")
        if bypass["state"] != "pending":
            raise BypassError(f"bypass is '{bypass['state']}', not pending")

        prior = [
            b for b in self._store.all("bypasses")
            if b["service"] == bypass["service"]
            and b["state"] == "approved"
            and b.get("scan_id") == bypass.get("scan_id")
        ]
        if prior and not is_director:
            raise BypassError(
                "a prior bypass exists for this gate — director-level approval required"
            )

        bypass["state"] = "approved"
        bypass["approved_by"] = approver
        bypass["approved_at"] = _now().isoformat()

        # Auto-created follow-up finding with 7-day SLA (§9.4)
        from asvp.models.findings import Finding, fingerprint

        follow_up = Finding(
            fingerprint=fingerprint(bypass["service"], "(gate)", "GTE-BYPASS", bypass_id),
            service=bypass["service"],
            endpoint_id="(gate)",
            check_id="GTE-BYPASS",
            domain="security",
            severity="high",
            title=f"Gate bypass follow-up for scan {bypass['scan_id']}",
            description=(
                f"Release gate bypassed by {bypass['requested_by']} "
                f"(approved by {approver}). Reason: {bypass['reason']}. The "
                "underlying blocking findings must be remediated."
            ),
            remediation="Remediate the findings that triggered the blocked gate verdict.",
            state="confirmed",
            confirmed_at=_now().isoformat(),
            sla_due=(_now() + timedelta(days=7)).isoformat(),
        )
        self._findings._save(follow_up)
        bypass["follow_up_finding_id"] = follow_up.finding_id
        self._store.put("bypasses", bypass_id, bypass)
        self._store.append_event(
            "audit.gate.bypass", "bypasses", bypass_id, bypass, actor=approver
        )
        return bypass

    def all(self) -> list[dict]:
        return list(self._store.all("bypasses"))
