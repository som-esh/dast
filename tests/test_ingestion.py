"""Ingestion, normalization, secret scanning (FR-ING-*, AR-1)."""

from __future__ import annotations

import unittest

from asvp.ingestion.postman import CollectionValidationError, parse_postman_collection
from asvp.ingestion.openapi import parse_openapi_spec
from asvp.ingestion.secret_scan import scan_for_secrets
from tests.conftest import DEMO_COLLECTION, make_platform, tier1_service


class TestPostmanIngestion(unittest.TestCase):
    def test_normalizes_paths_and_params(self):
        api = parse_postman_collection(DEMO_COLLECTION, "payments-api")
        ids = {e.endpoint_id for e in api.endpoints}
        self.assertIn("GET /accounts/{account_id}", ids)
        ep = api.endpoint("GET /accounts/{account_id}")
        self.assertTrue(ep.object_id_params())
        self.assertTrue(ep.auth_required)

    def test_content_hash_is_stable(self):
        a = parse_postman_collection(DEMO_COLLECTION, "x")
        b = parse_postman_collection(DEMO_COLLECTION, "x")
        self.assertEqual(a.content_hash(), b.content_hash())

    def test_empty_collection_rejected(self):
        with self.assertRaises(CollectionValidationError):
            parse_postman_collection({"info": {"name": "z"}, "item": []}, "z")


class TestOpenApiIngestion(unittest.TestCase):
    def test_openapi_parses_to_same_model(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "svc"},
            "security": [{"bearer": []}],
            "paths": {
                "/users/{user_id}": {
                    "get": {"operationId": "getUser",
                            "parameters": [{"name": "user_id", "in": "path", "required": True}]}
                }
            },
        }
        api = parse_openapi_spec(spec, "svc")
        ep = api.endpoint("GET /users/{user_id}")
        self.assertIsNotNone(ep)
        self.assertTrue(ep.auth_required)
        self.assertTrue(ep.object_id_params())


class TestSecretScan(unittest.TestCase):
    def test_detects_and_quarantines_secret(self):
        doc = {"item": [{"auth": "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"}]}
        cleaned, hits = scan_for_secrets(doc, redact=True)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].kind, "github_token")
        # raw value must not survive into the cleaned document
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz", str(cleaned))

    def test_placeholders_are_not_secrets(self):
        doc = {"key": "{{api_key}}", "other": "<YOUR_TOKEN>"}
        _, hits = scan_for_secrets(doc)
        self.assertEqual(hits, [])

    def test_ingested_secret_creates_critical_finding(self):
        platform = make_platform()
        platform.registry.register(tier1_service())
        collection = dict(DEMO_COLLECTION)
        collection = {
            **DEMO_COLLECTION,
            "variable": [{"key": "token", "value": "AKIAIOSFODNN7EXAMPLE"}],
        }
        platform.ingest_spec(collection, "payments-api")
        secret_findings = [
            f for f in platform.findings.all("payments-api")
            if f.check_id == "ING-SECRET-001"
        ]
        self.assertTrue(secret_findings)
        self.assertEqual(secret_findings[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
