"""Gate policy, break-glass, RBAC, baseline, compliance evidence, audit."""

from __future__ import annotations

import unittest

from asvp.findings.baseline import BaselineStore
from asvp.governance.rbac import AuthorizationError, Role, User, authorize, can_view_finding
from asvp.models.findings import Finding, fingerprint
from asvp.policy.gate import BuiltinPolicyEngine, BypassError, GateInput
from tests.conftest import make_platform, tier1_service


def _finding(severity, title="x", team="payments-team"):
    return Finding(
        fingerprint=fingerprint("s", "e", "c", severity),
        service="s", owner_team=team, endpoint_id="e", check_id="c",
        severity=severity, title=title,
    )


class TestGatePolicy(unittest.TestCase):
    def setUp(self):
        self.engine = BuiltinPolicyEngine()

    def _gi(self, **kw):
        base = dict(service="s", tier="tier1", environment="staging", profile="preprod",
                    policy_mode="block", new_findings=[], baselined_count=0, coverage_gaps=[])
        base.update(kw)
        return GateInput(**base)

    def test_new_critical_blocks(self):
        v = self.engine.evaluate(self._gi(new_findings=[_finding("critical")]))
        self.assertEqual(v.verdict, "block")

    def test_clean_scan_passes(self):
        v = self.engine.evaluate(self._gi())
        self.assertEqual(v.verdict, "pass")

    def test_warn_mode_downgrades_block(self):
        v = self.engine.evaluate(self._gi(policy_mode="warn", new_findings=[_finding("critical")]))
        self.assertEqual(v.verdict, "warn")
        self.assertEqual(v.evaluated_verdict, "block")

    def test_coverage_gap_blocks_tier1_preprod(self):
        v = self.engine.evaluate(self._gi(coverage_gaps=["authz untested"]))
        self.assertEqual(v.verdict, "block")
        self.assertIn("tier1-authz-coverage", v.rule_hits)

    def test_high_warns_at_pr_blocks_at_preprod(self):
        pr = self.engine.evaluate(self._gi(profile="pr", new_findings=[_finding("high")]))
        pp = self.engine.evaluate(self._gi(profile="preprod", new_findings=[_finding("high")]))
        self.assertEqual(pr.verdict, "warn")
        self.assertEqual(pp.verdict, "block")


class TestBaseline(unittest.TestCase):
    def test_diff_excludes_baselined(self):
        platform = make_platform()
        store = BaselineStore(platform.store)
        f1, f2 = _finding("high", "a"), _finding("critical", "b")
        f2.fingerprint = fingerprint("s", "e2", "c2", "")
        store.set("s", "staging", {f1.fingerprint}, actor="sec")
        new, known = store.diff("s", "staging", [f1, f2])
        self.assertEqual([f.fingerprint for f in new], [f2.fingerprint])
        self.assertEqual([f.fingerprint for f in known], [f1.fingerprint])


class TestBreakGlass(unittest.TestCase):
    def setUp(self):
        self.platform = make_platform()
        self.platform.registry.register(tier1_service())

    def test_bypass_requires_reason(self):
        with self.assertRaises(BypassError):
            self.platform.bypasses.request("scan1", "payments-api", "", "anita.lead")

    def test_approval_creates_followup_finding(self):
        b = self.platform.bypasses.request("scan1", "payments-api", "hotfix", "anita.lead")
        approved = self.platform.bypasses.approve(b["bypass_id"], approver="rahul.security")
        self.assertEqual(approved["state"], "approved")
        follow = self.platform.findings.get(approved["follow_up_finding_id"])
        self.assertIsNotNone(follow)
        self.assertEqual(follow.severity, "high")
        self.assertIsNotNone(follow.sla_due)

    def test_second_bypass_needs_director(self):
        b1 = self.platform.bypasses.request("scan1", "payments-api", "r1", "anita.lead")
        self.platform.bypasses.approve(b1["bypass_id"], approver="rahul.security")
        b2 = self.platform.bypasses.request("scan1", "payments-api", "r2", "anita.lead")
        with self.assertRaises(BypassError):
            self.platform.bypasses.approve(b2["bypass_id"], approver="rahul.security")
        # director override succeeds
        ok = self.platform.bypasses.approve(b2["bypass_id"], approver="dir", is_director=True)
        self.assertEqual(ok["state"], "approved")


class TestRBAC(unittest.TestCase):
    def test_developer_cannot_approve_risk(self):
        with self.assertRaises(AuthorizationError):
            authorize(User("d", Role.DEVELOPER), "finding.approve_risk")

    def test_security_engineer_can_approve_risk(self):
        authorize(User("s", Role.SECURITY_ENGINEER), "finding.approve_risk")  # no raise

    def test_finding_visibility_scoped_to_team(self):
        dev = User("d", Role.DEVELOPER, teams=["payments-team"])
        self.assertTrue(can_view_finding(dev, "payments-team"))
        self.assertFalse(can_view_finding(dev, "other-team"))
        # auditor and security see everything
        self.assertTrue(can_view_finding(User("a", Role.AUDITOR), "other-team"))


class TestComplianceEvidence(unittest.IsolatedAsyncioTestCase):
    async def test_evidence_bundle_is_per_framework_and_immutable(self):
        from asvp.models.scan import ScanRequest
        from tests.conftest import DEMO_COLLECTION

        platform = make_platform()
        await platform.orchestrator.start(runner_count=4)
        platform.registry.register(tier1_service())
        platform.ingest_spec(DEMO_COLLECTION, "payments-api")
        req = ScanRequest(service="payments-api", spec_version="latest",
                          environment="staging", profile="preprod", mode="full")
        status = await platform.orchestrator.submit(req)
        await platform.orchestrator.wait(status.scan_id, timeout=60)

        bundle = platform.evidence.export(framework="PCI-DSS-4.0")
        self.assertGreater(bundle["artifact_count"], 0)
        self.assertTrue(all(a["control_id"].startswith("PCI-DSS-4.0")
                            for a in bundle["artifacts"]))
        self.assertIn("bundle_digest", bundle)
        # GDPR bundle is disjoint
        gdpr = platform.evidence.export(framework="GDPR")
        self.assertNotEqual(bundle["bundle_digest"], gdpr["bundle_digest"])
        await platform.close()


class TestAudit(unittest.TestCase):
    def test_privileged_action_is_audited(self):
        platform = make_platform()
        platform.registry.register(tier1_service(policy_mode="report_only"))
        platform.registry.set_policy_mode("payments-api", "block", actor="rahul.security")
        events = platform.audit.query(action="policy.mode_change")
        self.assertTrue(events)
        self.assertEqual(events[0]["actor"], "rahul.security")


if __name__ == "__main__":
    unittest.main()
