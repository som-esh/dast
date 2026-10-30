"""Check generation, safe-mode default, authz coverage gap (FR-CHK-1/4, FR-EXE-3)."""

from __future__ import annotations

import unittest

from asvp.ingestion.postman import parse_postman_collection
from tests.conftest import DEMO_COLLECTION, make_platform, tier1_service


class TestGeneration(unittest.TestCase):
    def setUp(self):
        self.platform = make_platform()
        self.api = parse_postman_collection(DEMO_COLLECTION, "payments-api")

    def test_safe_mode_excludes_mutating_and_aggressive(self):
        service = tier1_service()
        result = self.platform.generator.generate(
            self.api, service, environment="staging", mode="safe"
        )
        classes = {c.template.destructiveness for c in result.checks}
        self.assertEqual(classes, {"safe"})
        self.assertTrue(result.skipped_by_mode)

    def test_full_mode_includes_opted_in_classes(self):
        service = tier1_service()  # staging opted into mutating+aggressive
        result = self.platform.generator.generate(
            self.api, service, environment="staging", mode="full"
        )
        classes = {c.template.destructiveness for c in result.checks}
        self.assertIn("mutating", classes)
        self.assertIn("aggressive", classes)

    def test_authz_coverage_gap_is_visible_not_silent(self):
        service = tier1_service(with_identities=False)
        result = self.platform.generator.generate(
            self.api, service, environment="staging", mode="full"
        )
        # No BOLA/BFLA checks planned...
        ids = {c.template.id for c in result.checks}
        self.assertNotIn("SEC-BOLA-001", ids)
        # ...but the gap is reported explicitly.
        self.assertTrue(any("authz untested" in g for g in result.coverage_gaps))

    def test_authz_generated_when_contract_fulfilled(self):
        service = tier1_service(with_identities=True)
        result = self.platform.generator.generate(
            self.api, service, environment="staging", mode="full"
        )
        ids = {c.template.id for c in result.checks}
        self.assertIn("SEC-BOLA-001", ids)
        self.assertEqual(result.coverage_gaps, [])

    def test_suppression_excludes_check(self):
        from asvp.checks.suppression import Suppression

        service = tier1_service()
        self.platform.suppressions.create(
            Suppression(
                service="payments-api", check_id="SEC-RATE-001",
                justification="known gateway gap, ticket SEC-1", approver="rahul.security",
                created_by="anita.lead", expires_at="2999-01-01T00:00:00+00:00",
            ),
            actor="rahul.security",
        )
        result = self.platform.generator.generate(
            self.api, service, environment="staging", mode="full"
        )
        ids = {c.template.id for c in result.checks}
        self.assertNotIn("SEC-RATE-001", ids)
        self.assertTrue(result.suppressed)


if __name__ == "__main__":
    unittest.main()
