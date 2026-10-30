"""End-to-end demo (PRD §9.1 walkthrough).

Onboards a vulnerable demo service, ingests a Postman collection, runs a
pre-prod scan against the in-process vulnerable app, and prints the gate
verdict, findings, the secure-to-ship report, and a compliance evidence
bundle. Hermetic: the target is mounted via httpx ASGITransport.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys

import httpx
from rich.console import Console
from rich.table import Table

from asvp.demo.vulnerable_app import build_vulnerable_app
from asvp.integrations.secrets import InMemorySecretsManager
from asvp.models.registry import ServiceRecord, TestIdentity
from asvp.models.scan import ScanRequest
from asvp.platform import Platform

console = Console()

DEMO_COLLECTION = {
    "info": {"name": "payments-api"},
    "variable": [{"key": "baseUrl", "value": "https://payments.dev.svc"}],
    "item": [
        {
            "name": "List accounts",
            "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/accounts", "path": ["accounts"]}},
        },
        {
            "name": "Get account",
            "request": {
                "method": "GET",
                "auth": {"type": "bearer"},
                "url": {"raw": "{{baseUrl}}/accounts/:account_id", "path": ["accounts", ":account_id"]},
            },
        },
        {
            "name": "Create transfer",
            "request": {
                "method": "POST",
                "auth": {"type": "bearer"},
                "url": {"raw": "{{baseUrl}}/transfers", "path": ["transfers"]},
                "body": {"mode": "raw", "raw": "{\"amount\": 100, \"to_account\": \"2002\"}"},
            },
        },
        {
            "name": "Admin config",
            "request": {
                "method": "GET",
                "auth": {"type": "bearer"},
                "url": {"raw": "{{baseUrl}}/admin/config", "path": ["admin", "config"]},
            },
        },
    ],
}


def _client_factory() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=build_vulnerable_app())
    return httpx.AsyncClient(transport=transport, timeout=10.0)


# Canned ZAP / Nuclei output so the demo exercises the real adapter parse +
# ingest path without the tools installed. Drop in real binaries by setting
# ASVP_ZAP_PATH / ASVP_NUCLEI_PATH / ASVP_BURP_JAR and the same code runs them.
_ZAP_REPORT = (
    '{"site":[{"@name":"http://payments.staging.svc","alerts":['
    '{"pluginid":"40012","alert":"Cross Site Scripting (Reflected)",'
    '"riskdesc":"High (Medium)","desc":"<p>Reflected XSS</p>","solution":"Encode output",'
    '"instances":[{"uri":"http://payments.staging.svc/accounts","method":"GET","param":"q"}]}]}]}'
)
_NUCLEI_JSONL = (
    '{"template-id":"exposed-env-file","info":{"name":"Exposed .env file",'
    '"severity":"high","description":"Environment file exposed","remediation":"Block access"},'
    '"matched-at":"http://payments.staging.svc/.env","type":"http"}'
)


def _demo_engines():
    import os
    import tempfile

    from asvp.engine.adapters import NucleiAdapter, ZapAdapter

    tmp = tempfile.mkdtemp(prefix="asvp-demo-engines-")
    zap_bin = os.path.join(tmp, "zap")
    nuclei_bin = os.path.join(tmp, "nuclei")
    for b in (zap_bin, nuclei_bin):
        open(b, "w").close()

    async def zap_runner(cmd, cwd=None, timeout=None):
        return (0, _ZAP_REPORT, "")

    async def nuclei_runner(cmd, cwd=None, timeout=None):
        return (0, _NUCLEI_JSONL, "")

    return {
        "zap": ZapAdapter(path=zap_bin, runner=zap_runner),
        "nuclei": NucleiAdapter(path=nuclei_bin, runner=nuclei_runner),
    }


async def _run() -> None:
    secrets = InMemorySecretsManager(
        {"secret:payments/alice": "tok-alice", "secret:payments/bob": "tok-bob"}
    )
    platform = Platform(
        db_path=":memory:", secrets=secrets, client_factory=_client_factory,
        target_rps=1000.0, external_engines=_demo_engines(),
    )
    await platform.orchestrator.start(runner_count=4)

    console.rule("[bold]1. Onboard service (FR-ING-7, FR-CHK-4)")
    platform.registry.register(
        ServiceRecord(
            name="payments-api",
            owner_team="payments-team",
            criticality_tier="tier1",
            data_classification="pci",
            target_environments=["staging"],
            environment_urls={"staging": "http://payments.staging.svc"},
            policy_mode="block",
            slack_channel="#payments-sec",
            test_identities=[
                TestIdentity(name="alice", role="user", credential_ref="secret:payments/alice",
                             owned_objects={"account_id": ["1001"]}),
                TestIdentity(name="bob", role="user", credential_ref="secret:payments/bob",
                             owned_objects={"account_id": ["2002"]}),
            ],
        )
    )
    console.print("Registered [cyan]payments-api[/] (Tier-1, blocking mode, "
                  "test-identity contract fulfilled).")

    console.rule("[bold]2. Ingest Postman collection (FR-ING-1/2/3)")
    result = platform.ingest_spec(DEMO_COLLECTION, "payments-api")
    console.print(f"Canonical model: [green]{len(result.canonical.endpoints)}[/] endpoints, "
                  f"version [dim]{result.version[:12]}[/], "
                  f"secrets quarantined: {len(result.secret_hits)}.")

    console.rule("[bold]3. Pre-prod scan (FR-EXE-*, full + runtime + crawler + engines)")
    platform.registry.register(
        platform.registry.get("payments-api").model_copy(
            update={
                "destructive_opt_in": {"staging": ["mutating", "aggressive"]},
                "external_engines": ["zap", "nuclei", "burp"],  # burp jar absent → skipped
                "crawl_enabled": True,
            }
        )
    )
    request = ScanRequest(
        service="payments-api", spec_version="latest", environment="staging",
        profile="preprod", mode="full", commit_sha="abc1234",
    )
    status = await platform.orchestrator.submit(request)
    status = await platform.orchestrator.wait(status.scan_id, timeout=60)
    console.print(f"Scan [cyan]{status.scan_id}[/]: {status.checks_executed} checks executed, "
                  f"[red]{status.checks_failed}[/] failed, "
                  f"{len(status.coverage_gaps)} coverage gaps.")
    console.print(f"External engines run: [green]{status.engines_run or 'none'}[/]; "
                  f"skipped: [dim]{status.engines_skipped or 'none'}[/]; "
                  f"external findings: [red]{status.external_findings_count}[/]; "
                  f"crawler discovered: {len(status.discovered_endpoints)} endpoint(s).")

    console.rule("[bold]4. Gate verdict (AR-6, FR-GTE-1/2)")
    verdict = status.gate_verdict or {}
    color = {"pass": "green", "warn": "yellow", "block": "red"}.get(verdict.get("verdict"), "white")
    console.print(f"Verdict: [{color} bold]{verdict.get('verdict', 'n/a').upper()}[/] "
                  f"(policy {verdict.get('policy')})")
    for reason in verdict.get("reasons", []):
        console.print(f"  - {reason}")

    console.rule("[bold]5. Findings (FR-FND-1)")
    table = Table(show_lines=False)
    for col in ("Severity", "Domain", "Endpoint", "Title", "State"):
        table.add_column(col)
    for f in sorted(platform.findings.all("payments-api"), key=lambda x: -x.severity_rank()):
        sev_color = {"critical": "red", "high": "orange3", "medium": "yellow"}.get(f.severity, "white")
        table.add_row(f"[{sev_color}]{f.severity}[/]", f.domain, f.endpoint_id, f.title, f.state)
    console.print(table)

    console.rule("[bold]6. Vulnerability lifecycle (FR-FND-2/3/4)")
    crit = next((f for f in platform.findings.all("payments-api")
                 if f.severity == "critical"), None)
    if crit:
        platform.findings.transition(crit.finding_id, "triaged", actor="rahul.security")
        platform.findings.transition(crit.finding_id, "confirmed", actor="rahul.security",
                                     service=platform.registry.get("payments-api"))
        console.print(f"Confirmed [red]{crit.title}[/] — SLA due {crit.finding_id} → "
                      f"{platform.findings.get(crit.finding_id).sla_due}")
        platform.findings.transition(crit.finding_id, "in_remediation", actor="dev.kumar")
        verified = await platform.verify_fix(crit.finding_id, actor="dev.kumar")
        console.print(f"Fix verification re-ran the check → finding state now "
                      f"[bold]{verified.state}[/] (unfixed app, so re-run still fails as expected).")

    console.rule("[bold]7. Secure-to-ship report (FR-RPT-4)")
    report = platform.store.get("release_reports", status.scan_id)
    if report:
        console.print(f"Release record for commit [cyan]{report['commit_sha']}[/]: "
                      f"{report['checks_failed']} failed checks, gate "
                      f"[bold]{(report['gate_verdict'] or {}).get('verdict')}[/].")

    console.rule("[bold]8. Compliance evidence bundle (FR-RPT-3)")
    bundle = platform.evidence.export(framework="PCI-DSS-4.0")
    console.print(f"PCI-DSS bundle: {bundle['artifact_count']} artifacts across "
                  f"{len(bundle['control_summary'])} controls, "
                  f"digest [dim]{bundle['bundle_digest'][:16]}[/].")

    console.rule("[bold]9. Executive dashboard (FR-RPT-2)")
    exec_dash = platform.reporting.executive_dashboard()
    console.print_json(data=exec_dash)

    await platform.close()
    console.rule("[bold green]Demo complete")


def run_demo() -> None:
    # Windows consoles often default to cp1252; the report uses box-drawing
    # and arrow glyphs. Reconfigure to UTF-8 where supported.
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(encoding="utf-8")
    asyncio.run(_run())
