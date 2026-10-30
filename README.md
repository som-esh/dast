# ASVP — Enterprise API Security Validation Platform

A working reference implementation of the [PRD](PRD.md): an internal platform
that automatically assesses internal microservice APIs for **security
weaknesses, compliance posture, configuration quality, and pre-production
runtime behavior**, gates CI/CD through policy-as-code, and manages the full
vulnerability lifecycle from detection to verified remediation.

> Single success criterion (PRD §1): new microservices reach production with
> zero unmitigated Critical/High API security findings, without adding more
> than 10 minutes (p95) to any pipeline.

This implementation is in Python and runs end-to-end and hermetically — the
demo and tests exercise a deliberately-vulnerable in-process target service
through the real engine, orchestrator, findings, gate, and reporting paths.
Engine adapters (Newman/ZAP/Nuclei) and infrastructure bindings (Vault, OPA
binary, EKS Jobs, Istio logs) are present as documented seams.

## Quick start

```bash
python -m pip install -e .

python -m asvp.cli demo          # full §9.1 walkthrough against a vuln target
python -m asvp.cli templates     # list the check template library
python -m asvp.cli serve         # run the control-plane REST API on :8080
python -m unittest discover -s tests   # 42 tests
```

## The four planes (PRD §6)

```
Sources            Control plane              Execution plane          Data & reporting
─────────          ───────────────            ────────────────         ─────────────────
Postman    ──►  ingestion/  (canonical    ──► engine/ (ScanWorker  ──► findings/  (dedupe,
OpenAPI         model, secret scan,            seam + 23 built-in       lifecycle, SLA, fix
CI triggers     versioned spec store)          executors)               verify, regression)
                checks/ (template lib,         orchestrator/ (queue,    compliance/ (evidence)
                generator, suppression)        per-env concurrency,     reporting/ (dashboards,
                policy/ (OPA + builtin)        rps throttle, prod-CIDR   release report, PR comment)
                registry, governance/          guard)                   integrations/ (Jira, Slack)
```

`asvp/platform.py` is the composition root that wires them together;
`asvp/api/app.py` is the REST surface; `asvp/cli.py` is the CLI.

## What the demo shows

`python -m asvp.cli demo` runs the PR-of-record walkthrough:

1. Onboard a Tier-1 service with a fulfilled test-identity contract (FR-ING-7, FR-CHK-4)
2. Ingest a Postman collection → canonical model, secret-scanned, versioned (FR-ING-1/2/3)
3. Run a pre-prod scan (full suite + runtime checks, env opted-in) (FR-EXE-*)
4. OPA-style gate verdict against versioned policy (AR-6, FR-GTE-1/2)
5. Normalized, deduped findings across all four domains (FR-FND-1)
6. Drive a finding through the lifecycle with automated fix verification (FR-FND-2/3/4)
7. Emit the secure-to-ship release report (FR-RPT-4)
8. Export an immutable PCI-DSS compliance evidence bundle (FR-RPT-3)
9. Executive dashboard with counter-metrics (FR-RPT-2, §11)

## Assessment domains & check library (PRD §5)

24 check templates across the four domains live in
[`asvp/checks/templates/`](asvp/checks/templates) as Git-reviewed YAML
(FR-CHK-2/3). Each carries a domain, default severity, destructiveness class,
compliance mappings, and remediation text. The built-in executors that run
them are in [`asvp/engine/executors.py`](asvp/engine/executors.py).

| Domain | Examples | Templates |
|---|---|---|
| Security (OWASP API Top 10) | BOLA, BFLA, broken/forged auth, mass assignment, excessive data exposure, rate limit, SSRF, injection, verbose errors, deprecated versions, debug endpoints | `security.yaml` |
| Compliance | PCI-DSS TLS & access control, GDPR PII exposure, RBI data-residency — each emits an evidence artifact | `compliance.yaml` |
| Configuration quality | security headers, cache-control, CORS strictness, error hygiene, request-size limits | `configuration.yaml` |
| Pre-prod runtime | race conditions, idempotency-key enforcement, bounded-burst degradation | `runtime.yaml` |

## Architectural requirements (PRD §6) — where they live

| AR | Requirement | Implementation |
|---|---|---|
| AR-1 | One canonical API model; no raw source downstream | `models/canonical.py`, ingestion normalizes Postman & OpenAPI to it |
| AR-2 | Async, queue-based scans; CI via request + poll/webhook | `orchestrator/orchestrator.py`, `api` 202 + status poll, action |
| AR-3 | Engines wrapped behind a swappable worker interface | `engine/worker.py` `ScanWorker` (per-check) + `engine/adapters/` `ExternalEngine` (ZAP, Nuclei, Burp jar) |
| AR-4 | Worker isolation; zero route to production | `assert_target_allowed` prod-CIDR guard; hermetic ASGI target |
| AR-5 | Credentials injected at runtime, never persisted | `integrations/secrets.py`; tokens resolved into worker memory only |
| AR-6 | Gating by OPA over versioned Rego from Git | `policy/gate.py` (OPA seam + builtin), `policy/rego/gate.rego`, `policy/policies/default.yaml` |
| AR-7 | Per-environment concurrency caps | `orchestrator` per-env semaphores + `Throttle` rps spacing |
| AR-8 | Everything immutable & reproducible (event-sourced) | `storage/db.py` append-only `events` journal + projections |

## Functional-requirement traceability

| Area | Requirements | Where |
|---|---|---|
| Ingestion & inventory | FR-ING-1..7 | `ingestion/`, `registry.py` |
| Check generation & mgmt | FR-CHK-1..5 | `checks/` |
| Orchestration & execution | FR-EXE-1..8 | `orchestrator/`, `engine/` |
| Findings & vuln mgmt | FR-FND-1..9 | `findings/` |
| Policy gates & CI/CD | FR-GTE-1..7 | `policy/`, `integrations/github-action/` |
| Reporting & dashboards | FR-RPT-1..5 | `reporting/`, `compliance/` |
| Governance, RBAC, audit | FR-GOV-1..5 | `governance/`, enforced in `api/app.py` |
| Developer experience | FR-DX-1..6 | `cli.py` (`repro`), `reporting.pr_comment`, portal payloads |

Non-goals (PRD §3.2) are respected: no SAST, no SCA/container scanning, no
production runtime protection, no production traffic analysis. "Runtime
weakness" means behavior observed by exercising the API in non-production
only, enforced by the boundary guard.

## REST API

`python -m asvp.cli serve` then authenticate with a dev bearer token
(`admin-token`, `sec-token`, `lead-token`, `dev-token`, `audit-token` — these
stand in for OIDC SSO, FR-GOV-1). Key endpoints:

```
POST /api/v1/services                       register a service (FR-ING-7)
POST /api/v1/specs/ingest                   ingest a collection/spec
POST /api/v1/scans                           request a scan (202 + poll)  (AR-2)
GET  /api/v1/scans/{id}                       scan status
GET  /api/v1/scans/{id}/pr-comment            top-3 PR summary (FR-DX-2)
GET  /api/v1/findings[/{id}]                  findings (team-scoped, NFR-8)
POST /api/v1/findings/{id}/transition         lifecycle (FR-FND-2/3)
POST /api/v1/findings/{id}/verify-fix         automated fix verification (FR-FND-4)
POST /api/v1/suppressions                     suppression w/ expiry (FR-CHK-5)
POST /api/v1/bypasses[/{id}/approve]          break-glass (FR-GTE-6)
GET  /api/v1/reports/{team|executive}         dashboards (FR-RPT-1/2)
GET  /api/v1/evidence/export                  compliance bundle (FR-RPT-3)
GET  /api/v1/audit                            immutable audit log (FR-GOV-3)
```

## External scan engines (ZAP, Nuclei, Burp) and the API crawler

ZAP, Nuclei and Burp are integrated as **scan-level external engines** behind
the `ExternalEngine` interface in [`asvp/engine/adapters/`](asvp/engine/adapters).
Each takes a target URL and produces findings that are normalized into the one
finding schema (FR-FND-1), deduped, regression-guarded, baseline-diffed, and
fed to the gate exactly like built-in findings.

They are **operator-provided tools, not pip dependencies** — drop them in via
environment variables:

```bash
export ASVP_ZAP_PATH=/opt/zap/zap.sh
export ASVP_NUCLEI_PATH=/usr/local/bin/nuclei
export ASVP_BURP_JAR=/opt/burp/burpsuite_pro.jar   # the jar you add
export ASVP_JAVA_PATH=/usr/bin/java                 # JRE for the Burp jar
```

- **ZAP** — `zap.sh -cmd -quickurl <target> -quickout report.json`, JSON report parsed.
- **Nuclei** — `nuclei -u <target> -jsonl`, JSONL parsed (CVE/CWE mapped to compliance tags).
- **Burp** — `java -jar burpsuite_pro.jar --headless --target=… --report-format=xml`, Burp XML issue export parsed (via `defusedxml`).

When a path is unset the engine reports unavailable and is **skipped** —
scans never fail because a tool is missing (`scan.engines_skipped` records why).
External engines are aggressive-class, so they run only in **full mode on
opted-in environments** (FR-EXE-3). Each adapter's report parser is pure and
unit-tested against captured tool output, so normalization is verified without
the tool installed; an injectable subprocess runner makes the full run path
testable too.

The **API crawler/spider** ([`asvp/engine/crawler.py`](asvp/engine/crawler.py))
discovers endpoints reachable from the target: it fetches well-known
OpenAPI/Swagger docs, BFS-spiders HTML/JSON references on-host (GET-only,
bounded by depth/URL caps), and probes common API/management paths.
Discovered-but-undocumented endpoints are merged into the scan scope and
reported (`scan.discovered_endpoints`) — an improper-inventory cue (OWASP API9)
and an input to coverage % (FR-ING-6). Enable per service (`crawl_enabled`) or
per scan (`enable_crawler`). The demo exercises both: it injects canned ZAP and
Nuclei output and runs the crawler against the in-process target.

Configure per service in the registry:

```json
{ "name": "payments-api", "external_engines": ["zap", "nuclei", "burp"], "crawl_enabled": true }
```

## Notes on fidelity

This is a faithful, runnable model of the PRD's logic, not the production
deployment. The control-plane logic (normalization, generation, gating,
lifecycle, SLA, evidence, RBAC, audit) is real and tested. The substrate
bindings the PRD assumes — EKS Jobs, KEDA autoscaling, Vault, the OPA binary,
Istio access logs, real Jira/Slack/SIEM transports — are represented by
interfaces with in-process implementations, so swapping in the real backends
is a wiring change rather than a redesign.
