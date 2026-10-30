"""End-to-end scan, findings dedupe, lifecycle, SLA, fix verification, gate."""

from __future__ import annotations

import asyncio
import unittest

from asvp.findings.service import TransitionError
from asvp.models.scan import ScanRequest
from tests.conftest import DEMO_COLLECTION, make_platform, tier1_service


def run(coro):
    return asyncio.run(coro)


class ScanTestBase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.platform = make_platform()
        await self.platform.orchestrator.start(runner_count=4)
        self.platform.registry.register(tier1_service())
        self.platform.ingest_spec(DEMO_COLLECTION, "payments-api")

    async def asyncTearDown(self):
        await self.platform.close()

    async def _scan(self, profile="preprod", mode="full", environment="staging", scope=None):
        req = ScanRequest(
            service="payments-api", spec_version="latest", environment=environment,
            profile=profile, mode=mode, scope_endpoints=scope or [], commit_sha="abc1234",
        )
        status = await self.platform.orchestrator.submit(req)
        return await self.platform.orchestrator.wait(status.scan_id, timeout=60)


class TestScan(ScanTestBase):
    async def test_scan_detects_known_vulnerabilities(self):
        status = await self._scan()
        self.assertEqual(status.state, "complete")
        self.assertGreater(status.checks_failed, 0)
        findings = self.platform.findings.all("payments-api")
        titles = {f.title for f in findings}
        self.assertIn("Cross-identity object access (BOLA)", titles)
        self.assertIn("Excessive data exposure in responses", titles)
        self.assertTrue(any(f.severity == "critical" for f in findings))

    async def test_gate_blocks_tier1_with_criticals(self):
        status = await self._scan()
        self.assertEqual(status.gate_verdict["verdict"], "block")

    async def test_report_only_forces_pass(self):
        self.platform.registry.register(tier1_service(policy_mode="report_only"))
        status = await self._scan()
        self.assertEqual(status.gate_verdict["verdict"], "pass")
        self.assertEqual(status.gate_verdict["evaluated_verdict"], "block")

    async def test_dedupe_increments_occurrences(self):
        await self._scan()
        first = len(self.platform.findings.all("payments-api"))
        await self._scan()
        second = len(self.platform.findings.all("payments-api"))
        self.assertEqual(first, second)  # no duplicate findings on re-scan
        bola = next(f for f in self.platform.findings.all("payments-api")
                    if f.check_id == "SEC-BOLA-001")
        self.assertGreaterEqual(bola.occurrences, 2)

    async def test_changed_endpoint_scoping(self):
        status = await self._scan(scope=["GET /accounts"])
        endpoints = {f.endpoint_id for f in
                     [self.platform.findings.get(i) for i in status.finding_ids]}
        # service-level (once_per_service) checks may also appear; the scoped
        # endpoint must be present and unrelated per-endpoint ones absent.
        self.assertIn("GET /accounts", endpoints)
        self.assertNotIn("POST /transfers", endpoints)

    async def test_production_cidr_target_refused(self):
        svc = tier1_service()
        svc.environment_urls["prod"] = "http://10.100.5.5"
        svc.target_environments.append("prod")
        self.platform.registry.register(svc)
        status = await self._scan(environment="prod")
        self.assertEqual(status.state, "failed")
        self.assertIn("production", status.error.lower())


class TestLifecycle(ScanTestBase):
    async def _a_critical(self):
        await self._scan()
        return next(f for f in self.platform.findings.all("payments-api")
                    if f.severity == "critical")

    async def test_confirm_starts_sla_clock(self):
        f = await self._a_critical()
        self.platform.findings.transition(f.finding_id, "triaged", actor="sec")
        updated = self.platform.findings.transition(
            f.finding_id, "confirmed", actor="sec",
            service=self.platform.registry.get("payments-api"),
        )
        self.assertIsNotNone(updated.sla_due)
        self.assertIsNotNone(updated.confirmed_at)

    async def test_false_positive_requires_approver(self):
        f = await self._a_critical()
        self.platform.findings.transition(f.finding_id, "triaged", actor="sec")
        with self.assertRaises(TransitionError):
            self.platform.findings.transition(f.finding_id, "false_positive", actor="sec")

    async def test_illegal_transition_rejected(self):
        f = await self._a_critical()
        with self.assertRaises(TransitionError):
            self.platform.findings.transition(f.finding_id, "closed", actor="sec")

    async def test_risk_acceptance_expiry_reopens(self):
        f = await self._a_critical()
        self.platform.findings.transition(f.finding_id, "triaged", actor="sec")
        self.platform.findings.transition(
            f.finding_id, "risk_accepted", actor="sec",
            justification="compensating control", approver="rahul.security",
            risk_acceptance_days=-1,  # already expired
        )
        reopened = self.platform.findings.expire_risk_acceptances()
        self.assertIn(f.finding_id, [r.finding_id for r in reopened])
        self.assertEqual(self.platform.findings.get(f.finding_id).state, "reopened")

    async def test_fix_verification_against_unfixed_app_stays_in_remediation(self):
        f = await self._a_critical()
        self.platform.findings.transition(f.finding_id, "triaged", actor="sec")
        self.platform.findings.transition(
            f.finding_id, "confirmed", actor="sec",
            service=self.platform.registry.get("payments-api"))
        self.platform.findings.transition(f.finding_id, "in_remediation", actor="dev")
        result = await self.platform.verify_fix(f.finding_id, actor="dev")
        # App is still vulnerable, so re-run fails and it must NOT be verified.
        self.assertEqual(result.state, "in_remediation")

    async def test_regression_reopens_original(self):
        # Drive a finding to closed, then re-scan to trigger regression.
        f = await self._a_critical()
        for to in ("triaged", "false_positive"):
            kwargs = {"actor": "sec"}
            if to == "false_positive":
                kwargs.update(justification="benign", approver="rahul.security")
            self.platform.findings.transition(f.finding_id, to, **kwargs)
        self.platform.findings.transition(f.finding_id, "closed", actor="sec")
        await self._scan()
        reborn = self.platform.findings.get(f.finding_id)
        self.assertTrue(reborn.is_regression)
        self.assertEqual(reborn.state, "reopened")


if __name__ == "__main__":
    unittest.main()
