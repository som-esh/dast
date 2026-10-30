# Product Requirements Document — Enterprise API Security Validation Platform (ASVP)

> The authoritative PRD this repository implements. See [README.md](README.md)
> for the requirement → code traceability matrix. Document status: Draft v0.9.
> Last updated 2026-06-12.

## 1. Executive summary

Internal engineering teams ship microservice APIs faster than the security
team can review them. ASVP automatically assesses API implementations for
security weaknesses, compliance posture, configuration quality, and
pre-production runtime behavior across dev/test/pre-prod. It ingests API
definitions (Postman at v1, OpenAPI at v1.1), generates and executes
validation checks against live non-production environments, gates CI/CD via
policy-as-code, and manages the vulnerability lifecycle from detection to
verified remediation.

**Single success criterion:** new microservices reach production with zero
unmitigated Critical/High API security findings, without adding more than 10
minutes (p95) to any pipeline.

## 2. Assessment domains (§5)

1. **Security** — OWASP API Security Top 10 aligned: BOLA, broken auth,
   broken object-property authz (mass assignment / excessive exposure),
   unrestricted resource consumption, BFLA, SSRF, injection, security
   misconfiguration, improper inventory, unsafe upstream consumption.
2. **Compliance** — PCI-DSS v4.0, GDPR, RBI controls producing evidence
   artifacts (control id, timestamp, target+version, redacted excerpt, verdict).
3. **Configuration quality** — security headers, TLS posture, CORS,
   error-response hygiene, limit declarations, gateway/Istio policy presence.
4. **Pre-production runtime weakness** — resource-exhaustion behavior, token
   revocation, race conditions, idempotency-key enforcement, fault-injection
   leakage. Boundary: only behavior observable by exercising the API in
   non-production.

## 3. Architectural requirements (§6, binding)

- **AR-1** one canonical API model; no raw source consumed downstream.
- **AR-2** async, queue-based scans; CI via request + webhook/poll.
- **AR-3** engines wrapped behind a swappable worker interface.
- **AR-4** workers isolated; egress allow-list; zero route to production.
- **AR-5** credentials injected at runtime from the secrets manager; never persisted.
- **AR-6** gating produced exclusively by OPA over versioned Rego in Git.
- **AR-7** per-target-environment concurrency caps enforced by the orchestrator.
- **AR-8** every spec/scan/finding/transition immutable and reproducible.

## 4. Functional requirements

The full MoSCoW table (FR-ING-*, FR-CHK-*, FR-EXE-*, FR-FND-*, FR-GTE-*,
FR-RPT-*, FR-GOV-*, FR-DX-*) is implemented and traced in the README. Non-goals
(§3.2): not SAST, not SCA/container scanning, not production runtime
protection, not production traffic analysis, internal services only.

## 5. Lifecycle & gate semantics

- Finding FSM: new → triaged → (confirmed | false_positive | risk_accepted)
  → in_remediation → fix_verified → closed, with regression reopen.
- SLA clocks start at confirmation: Critical 7d / High 30d / Medium 90d /
  Low 180d, overridable per tier.
- Gate verdict (pass | warn | block) from OPA over baseline-diffed findings,
  applied per service policy mode (report_only → warn → block).
- Break-glass: named-role approval, mandatory reason, auto follow-up finding
  with 7-day SLA, second bypass needs director approval.

This Markdown is an abridged restatement for repo self-containment; the
canonical narrative PRD lives in the planning system.
