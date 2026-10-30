"""ASVP REST API (control-plane surface).

Authentication: OIDC SSO via the corporate IdP (FR-GOV-1). In this
reference implementation the IdP handshake is replaced by a static
bearer-token → identity map (ASVP_DEV_TOKENS); the authorization layer
(RBAC, team scoping, audit) is fully enforced (FR-GOV-2/3, NFR-8).

CI integration is request + poll/webhook, never blocking (AR-2).
"""

from __future__ import annotations

import contextlib
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from asvp.governance.rbac import AuthorizationError, Role, User, authorize, can_view_finding
from asvp.models.registry import ServiceRecord
from asvp.models.scan import ScanRequest
from asvp.checks.suppression import Suppression
from asvp.platform import Platform

# Dev-mode identity map (replace with OIDC middleware in production).
DEV_TOKENS: dict[str, User] = {
    "admin-token": User("priya.admin", Role.PLATFORM_ADMIN),
    "sec-token": User("rahul.security", Role.SECURITY_ENGINEER),
    "lead-token": User("anita.lead", Role.TEAM_LEAD, teams=["payments-team"]),
    "dev-token": User("dev.kumar", Role.DEVELOPER, teams=["payments-team"]),
    "audit-token": User("alex.auditor", Role.AUDITOR),
}


# Request bodies must live at module scope: with `from __future__ import
# annotations` FastAPI resolves handler annotations against the module
# globals, so locally-scoped models would be misread as query params.
class IngestBody(BaseModel):
    service: str
    source_type: str = "postman"
    document: dict


class TransitionBody(BaseModel):
    to_state: str
    justification: Optional[str] = None
    approver: Optional[str] = None
    risk_acceptance_days: Optional[int] = None
    severity_override: Optional[str] = None


class BypassRequestBody(BaseModel):
    scan_id: str
    service: str
    reason: str


def create_app(platform: Optional[Platform] = None) -> FastAPI:
    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        await app.state.platform.orchestrator.start()
        yield
        await app.state.platform.close()

    app = FastAPI(title="ASVP — API Security Validation Platform", lifespan=lifespan)
    app.state.platform = platform or Platform()

    def p() -> Platform:
        return app.state.platform

    def current_user(authorization: str = Header(default="")) -> User:
        token = authorization.removeprefix("Bearer ").strip()
        user = DEV_TOKENS.get(token)
        if user is None:
            raise HTTPException(401, "invalid or missing bearer token")
        return user

    def require(user: User, action: str) -> None:
        try:
            authorize(user, action)
        except AuthorizationError as exc:
            raise HTTPException(403, str(exc))

    # ── services / registry ─────────────────────────────────────────────

    @app.post("/api/v1/services")
    def register_service(record: ServiceRecord, user: User = Depends(current_user)):
        require(user, "service.register")
        p().registry.register(record, actor=user.username)
        return {"registered": record.name}

    @app.get("/api/v1/services")
    def list_services(user: User = Depends(current_user)):
        return [s.model_dump() for s in p().registry.all()]

    @app.post("/api/v1/services/{name}/policy-mode")
    def set_policy_mode(name: str, body: dict, user: User = Depends(current_user)):
        require(user, "policy.mode_change")
        mode = body.get("mode")
        if mode not in ("report_only", "warn", "block"):
            raise HTTPException(422, "mode must be report_only|warn|block")
        record = p().registry.set_policy_mode(name, mode, actor=user.username)
        return {"service": name, "policy_mode": record.policy_mode}

    # ── ingestion ───────────────────────────────────────────────────────

    @app.post("/api/v1/specs/ingest")
    def ingest(body: IngestBody, user: User = Depends(current_user)):
        require(user, "scan.request")
        from asvp.ingestion.store import IngestionError

        try:
            result = p().ingest_spec(
                body.document, body.service, body.source_type, actor=user.username
            )
        except IngestionError as exc:
            raise HTTPException(422, str(exc))
        return {
            "service": result.service,
            "version": result.version,
            "endpoints": len(result.canonical.endpoints),
            "secrets_quarantined": len(result.secret_hits),
            "is_new_version": result.is_new_version,
        }

    @app.get("/api/v1/specs/{service}/coverage")
    def coverage(service: str, observed: str = "", user: User = Depends(current_user)):
        eps = [e.strip() for e in observed.split(",") if e.strip()]
        return p().spec_store.coverage(service, eps)

    # ── scans (AR-2: async; request + poll/webhook) ─────────────────────

    @app.post("/api/v1/scans", status_code=202)
    async def request_scan(request: ScanRequest, user: User = Depends(current_user)):
        require(user, "scan.request")
        request.requested_by = user.username
        try:
            status = await p().orchestrator.submit(request)
        except KeyError as exc:
            raise HTTPException(404, str(exc))
        return {"scan_id": status.scan_id, "state": status.state}

    @app.get("/api/v1/scans/{scan_id}")
    def scan_status(scan_id: str, user: User = Depends(current_user)):
        status = p().orchestrator.get_status(scan_id)
        if status is None:
            raise HTTPException(404, "scan not found")
        return status.model_dump()

    @app.get("/api/v1/scans/{scan_id}/pr-comment")
    def scan_pr_comment(scan_id: str, user: User = Depends(current_user)):
        status = p().orchestrator.get_status(scan_id)
        if status is None:
            raise HTTPException(404, "scan not found")
        return {"markdown": p().reporting.pr_comment(status)}

    # ── findings ────────────────────────────────────────────────────────

    @app.get("/api/v1/findings")
    def list_findings(service: Optional[str] = None, user: User = Depends(current_user)):
        items = p().findings.all(service)
        items = [f for f in items if can_view_finding(user, f.owner_team)]
        return [
            {
                "finding_id": f.finding_id,
                "severity": f.severity,
                "state": f.state,
                "title": f.title,
                "service": f.service,
                "endpoint": f.endpoint_id,
                "sla_due": f.sla_due,
            }
            for f in items
        ]

    @app.get("/api/v1/findings/{finding_id}")
    def get_finding(finding_id: str, user: User = Depends(current_user)):
        f = p().findings.get(finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        if not can_view_finding(user, f.owner_team):
            raise HTTPException(403, "finding belongs to another team")
        # FR-GOV-3: finding-detail reads are audit-logged
        p().audit.record("finding.read", user.username, "findings", finding_id)
        return f.model_dump()

    @app.post("/api/v1/findings/{finding_id}/transition")
    def transition(finding_id: str, body: TransitionBody, user: User = Depends(current_user)):
        if body.to_state in ("false_positive", "risk_accepted"):
            require(user, "finding.approve_fp" if body.to_state == "false_positive"
                    else "finding.approve_risk")
        else:
            require(user, "finding.triage")
        from asvp.findings.service import TransitionError

        f = p().findings.get(finding_id)
        service = p().registry.get(f.service) if f else None
        try:
            f = p().findings.transition(
                finding_id,
                body.to_state,
                actor=user.username,
                justification=body.justification,
                approver=body.approver or (
                    user.username if body.to_state in ("false_positive", "risk_accepted") else None
                ),
                risk_acceptance_days=body.risk_acceptance_days,
                severity_override=body.severity_override,
                service=service,
            )
        except (TransitionError, KeyError) as exc:
            raise HTTPException(422, str(exc))
        return {"finding_id": f.finding_id, "state": f.state, "sla_due": f.sla_due}

    @app.post("/api/v1/findings/{finding_id}/verify-fix")
    async def verify_fix(finding_id: str, user: User = Depends(current_user)):
        require(user, "finding.mark_fixed")
        from asvp.findings.service import TransitionError

        try:
            f = await p().verify_fix(finding_id, actor=user.username)
        except (TransitionError, KeyError) as exc:
            raise HTTPException(422, str(exc))
        return {"finding_id": f.finding_id, "state": f.state}

    # ── suppressions (FR-CHK-5) ─────────────────────────────────────────

    @app.post("/api/v1/suppressions")
    def create_suppression(s: Suppression, user: User = Depends(current_user)):
        require(user, "suppression.create")
        try:
            created = p().suppressions.create(s, actor=user.username)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return created.model_dump()

    # ── baselines (FR-FND-6) ────────────────────────────────────────────

    @app.post("/api/v1/baselines/{service}/{environment}")
    def set_baseline(service: str, environment: str, body: dict,
                     user: User = Depends(current_user)):
        require(user, "finding.triage")
        p().baselines.set(service, environment, set(body.get("fingerprints", [])),
                          actor=user.username)
        return {"service": service, "environment": environment,
                "count": len(body.get("fingerprints", []))}

    # ── break-glass (FR-GTE-6) ──────────────────────────────────────────

    @app.post("/api/v1/bypasses")
    def request_bypass(body: BypassRequestBody, user: User = Depends(current_user)):
        require(user, "gate.bypass_request")
        from asvp.policy.gate import BypassError

        try:
            return p().bypasses.request(body.scan_id, body.service, body.reason,
                                        requested_by=user.username)
        except BypassError as exc:
            raise HTTPException(422, str(exc))

    @app.post("/api/v1/bypasses/{bypass_id}/approve")
    def approve_bypass(bypass_id: str, body: dict | None = None,
                       user: User = Depends(current_user)):
        require(user, "gate.bypass_approve")
        from asvp.policy.gate import BypassError

        try:
            result = p().bypasses.approve(
                bypass_id, approver=user.username,
                is_director=bool((body or {}).get("is_director")),
            )
        except BypassError as exc:
            raise HTTPException(422, str(exc))
        service = p().registry.get(result["service"])
        channel = (service.slack_channel if service else None) or "#security"
        p().slack.bypass_alert(channel, result["service"], user.username, result["reason"])
        return result

    # ── reporting & evidence ────────────────────────────────────────────

    @app.get("/api/v1/reports/team/{team}")
    def team_report(team: str, user: User = Depends(current_user)):
        require(user, "report.read")
        return p().reporting.team_dashboard(team)

    @app.get("/api/v1/reports/executive")
    def exec_report(user: User = Depends(current_user)):
        require(user, "report.read")
        return p().reporting.executive_dashboard()

    @app.get("/api/v1/reports/release/{scan_id}")
    def release_report(scan_id: str, user: User = Depends(current_user)):
        require(user, "report.read")
        report = p().store.get("release_reports", scan_id)
        if report is None:
            raise HTTPException(404, "no release report for this scan")
        return report

    @app.get("/api/v1/evidence/export")
    def evidence_export(framework: Optional[str] = None, since: Optional[str] = None,
                        until: Optional[str] = None, user: User = Depends(current_user)):
        require(user, "evidence.export")
        return p().evidence.export(framework, since, until)

    # ── audit & ops ─────────────────────────────────────────────────────

    @app.get("/api/v1/audit")
    def audit_log(action: Optional[str] = None, entity_id: Optional[str] = None,
                  user: User = Depends(current_user)):
        require(user, "audit.read")
        return p().audit.query(action, entity_id)

    @app.post("/api/v1/ops/run-clocks")
    def run_clocks(user: User = Depends(current_user)):
        require(user, "admin.config")
        return p().run_clocks()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app
