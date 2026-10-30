"""Shared fixtures. Uses unittest-style helpers so the suite runs under the
stdlib runner (no pytest dependency required in this environment)."""

from __future__ import annotations

import httpx

from asvp.demo.vulnerable_app import build_vulnerable_app
from asvp.integrations.secrets import InMemorySecretsManager
from asvp.models.registry import ServiceRecord, TestIdentity
from asvp.platform import Platform


def vulnerable_client_factory() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=build_vulnerable_app())
    return httpx.AsyncClient(transport=transport, timeout=10.0)


def make_platform(client_factory_override=None) -> Platform:
    secrets = InMemorySecretsManager(
        {"secret:payments/alice": "tok-alice", "secret:payments/bob": "tok-bob"}
    )
    return Platform(
        db_path=":memory:",
        secrets=secrets,
        client_factory=client_factory_override or vulnerable_client_factory,
        target_rps=1000.0,
    )


def tier1_service(policy_mode: str = "block", with_identities: bool = True) -> ServiceRecord:
    identities = []
    if with_identities:
        identities = [
            TestIdentity(name="alice", role="user", credential_ref="secret:payments/alice",
                         owned_objects={"account_id": ["1001"]}),
            TestIdentity(name="bob", role="user", credential_ref="secret:payments/bob",
                         owned_objects={"account_id": ["2002"]}),
        ]
    return ServiceRecord(
        name="payments-api",
        owner_team="payments-team",
        criticality_tier="tier1",
        data_classification="pci",
        target_environments=["staging"],
        environment_urls={"staging": "http://payments.staging.svc"},
        policy_mode=policy_mode,
        destructive_opt_in={"staging": ["mutating", "aggressive"]},
        test_identities=identities,
    )


DEMO_COLLECTION = {
    "info": {"name": "payments-api"},
    "variable": [{"key": "baseUrl", "value": "https://payments.dev.svc"}],
    "item": [
        {"name": "List accounts",
         "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/accounts", "path": ["accounts"]}}},
        {"name": "Get account",
         "request": {"method": "GET", "auth": {"type": "bearer"},
                     "url": {"raw": "{{baseUrl}}/accounts/:account_id", "path": ["accounts", ":account_id"]}}},
        {"name": "Create transfer",
         "request": {"method": "POST", "auth": {"type": "bearer"},
                     "url": {"raw": "{{baseUrl}}/transfers", "path": ["transfers"]},
                     "body": {"mode": "raw", "raw": "{\"amount\": 100}"}}},
        {"name": "Admin config",
         "request": {"method": "GET", "auth": {"type": "bearer"},
                     "url": {"raw": "{{baseUrl}}/admin/config", "path": ["admin", "config"]}}},
    ],
}
