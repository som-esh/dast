"""API-layer RBAC and the request→poll scan flow (AR-2, FR-GOV-2, NFR-8)."""

from __future__ import annotations

import unittest

from starlette.testclient import TestClient

from asvp.api.app import create_app
from tests.conftest import DEMO_COLLECTION, make_platform, tier1_service

AUTH = {
    "admin": {"Authorization": "Bearer admin-token"},
    "sec": {"Authorization": "Bearer sec-token"},
    "lead": {"Authorization": "Bearer lead-token"},
    "dev": {"Authorization": "Bearer dev-token"},
    "auditor": {"Authorization": "Bearer audit-token"},
}


def _await_scan(client, scan_id):
    for _ in range(200):
        status = client.get(f"/api/v1/scans/{scan_id}", headers=AUTH["dev"]).json()
        if status["state"] in ("complete", "failed"):
            return status
    return status


class TestApi(unittest.TestCase):
    # TestClient as a context manager runs the app lifespan, which starts the
    # orchestrator runners on the client's event loop (AR-2 async execution).
    def test_unauthenticated_rejected(self):
        with TestClient(create_app(make_platform())) as client:
            self.assertEqual(client.get("/api/v1/services").status_code, 401)

    def test_register_ingest_scan_flow(self):
        with TestClient(create_app(make_platform())) as client:
            r = client.post("/api/v1/services",
                            json=tier1_service().model_dump(mode="json"), headers=AUTH["lead"])
            self.assertEqual(r.status_code, 200)
            r = client.post("/api/v1/specs/ingest",
                            json={"service": "payments-api", "document": DEMO_COLLECTION},
                            headers=AUTH["dev"])
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["endpoints"], 4)

            r = client.post("/api/v1/scans",
                            json={"service": "payments-api", "spec_version": "latest",
                                  "environment": "staging", "profile": "preprod", "mode": "full"},
                            headers=AUTH["dev"])
            self.assertEqual(r.status_code, 202)
            status = _await_scan(client, r.json()["scan_id"])
            self.assertEqual(status["state"], "complete")
            self.assertGreater(status["checks_failed"], 0)

            comment = client.get(f"/api/v1/scans/{status['scan_id']}/pr-comment",
                                 headers=AUTH["dev"]).json()
            self.assertIn("verdict", comment["markdown"].lower())

    def test_developer_cannot_change_policy_mode(self):
        with TestClient(create_app(make_platform())) as client:
            client.post("/api/v1/services",
                        json=tier1_service().model_dump(mode="json"), headers=AUTH["lead"])
            r = client.post("/api/v1/services/payments-api/policy-mode",
                            json={"mode": "block"}, headers=AUTH["dev"])
            self.assertEqual(r.status_code, 403)

    def test_finding_visibility_and_audited_reads(self):
        with TestClient(create_app(make_platform())) as client:
            client.post("/api/v1/services",
                        json=tier1_service().model_dump(mode="json"), headers=AUTH["lead"])
            client.post("/api/v1/specs/ingest",
                        json={"service": "payments-api", "document": DEMO_COLLECTION},
                        headers=AUTH["dev"])
            r = client.post("/api/v1/scans",
                            json={"service": "payments-api", "spec_version": "latest",
                                  "environment": "staging", "profile": "preprod", "mode": "full"},
                            headers=AUTH["dev"])
            _await_scan(client, r.json()["scan_id"])
            # auditor sees findings across teams
            aud = client.get("/api/v1/findings", headers=AUTH["auditor"]).json()
            self.assertTrue(aud)
            fid = aud[0]["finding_id"]
            detail = client.get(f"/api/v1/findings/{fid}", headers=AUTH["auditor"])
            self.assertEqual(detail.status_code, 200)
            # FR-GOV-3: the detail read is audit-logged
            audit = client.get("/api/v1/audit?action=finding.read", headers=AUTH["sec"]).json()
            self.assertTrue(audit)


if __name__ == "__main__":
    unittest.main()
