"""Built-in custom-check executors (the v1 internal check library, AR-3).

Each executor probes a live non-production target and returns a CheckResult.
Evidence is captured with secrets redacted; reproductions are sanitized
request templates with credential placeholders (FR-FND-8).
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Awaitable, Callable, Optional

import httpx

from asvp.checks.generator import PlannedCheck
from asvp.engine.worker import (
    CheckResult,
    ExecutionContext,
    ResolvedIdentity,
    redact_headers,
)

# ── helpers ─────────────────────────────────────────────────────────────


def _fill_path(check: PlannedCheck, identity: Optional[ResolvedIdentity]) -> str:
    ep = check.endpoint
    path = ep.path
    for p in ep.parameters:
        if p.location != "path":
            continue
        value = None
        if identity and p.name in identity.owned_objects and identity.owned_objects[p.name]:
            value = identity.owned_objects[p.name][0]
        if value is None and p.example:
            value = p.example
        if value is None:
            value = "1"
        path = path.replace("{%s}" % p.name, str(value))
    return path


def _build(
    check: PlannedCheck,
    ctx: ExecutionContext,
    identity: Optional[ResolvedIdentity],
    *,
    body: object = "__default__",
    headers: Optional[dict] = None,
    path: Optional[str] = None,
) -> dict:
    ep = check.endpoint
    url = ctx.base_url.rstrip("/") + (path or _fill_path(check, identity))
    h = dict(headers or {})
    if identity is not None:
        h["Authorization"] = f"Bearer {identity.token}"
    req: dict = {"method": ep.method if ep else "GET", "url": url, "headers": h}
    if body == "__default__":
        body = ep.request_body_example if ep else None
    if body is not None and req["method"] in ("POST", "PUT", "PATCH", "DELETE"):
        req["json"] = body
    return req


async def _send(ctx: ExecutionContext, req: dict) -> httpx.Response:
    throttle = getattr(ctx, "throttle", None)
    if throttle is not None:
        await throttle.acquire()
    ctx.requests_made += 1
    return await ctx.client.request(
        req["method"], req["url"], headers=req.get("headers"), json=req.get("json")
    )


def _repro(req: dict) -> dict:
    """Sanitized reproduction template — placeholders, never live creds."""
    headers = {
        k: ("Bearer {{TEST_IDENTITY_TOKEN}}" if k.lower() == "authorization" else v)
        for k, v in req.get("headers", {}).items()
    }
    out = {"method": req["method"], "url": req["url"], "headers": headers}
    if "json" in req:
        out["json"] = req["json"]
    return out


def _evidence(resp: httpx.Response, note: str = "") -> dict:
    body = resp.text[:600]
    return {
        "status_code": resp.status_code,
        "response_headers": redact_headers(dict(resp.headers)),
        "response_excerpt": body,
        "note": note,
    }


_PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "pan_card_number": re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
    "phone": re.compile(r"\b(?:\+91[- ]?)?[6-9]\d{9}\b"),
    "aadhaar_like": re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
}

_SENSITIVE_KEYS = (
    "password",
    "password_hash",
    "secret",
    "api_key",
    "token",
    "ssn",
    "is_admin",
    "internal",
    "salt",
)

_ERROR_SIGNATURES = (
    "traceback",
    "stack trace",
    "stacktrace",
    "at java.",
    'file "',
    "sqlite3",
    "psycopg2",
    "syntax error",
    "ora-",
    "mysql",
    "exception",
)

_PRIVILEGED_HINTS = ("admin", "internal", "manage", "config")


def _collect_keys(node: object, found: set[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            found.add(str(k).lower())
            _collect_keys(v, found)
    elif isinstance(node, list):
        for v in node:
            _collect_keys(v, found)


# ── authentication ──────────────────────────────────────────────────────


async def auth_missing_token(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    if check.endpoint.auth_required is False:
        return CheckResult(status="skipped", detail="endpoint declared public in spec")
    req = _build(check, ctx, identity=None)
    resp = await _send(ctx, req)
    if 200 <= resp.status_code < 300:
        return CheckResult(
            status="fail",
            detail=f"{check.endpoint_id} returned {resp.status_code} with no credentials",
            evidence=_evidence(resp, "request sent with no Authorization header"),
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail=f"unauthenticated request rejected ({resp.status_code})")


async def auth_forged_token(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    if check.endpoint.auth_required is False:
        return CheckResult(status="skipped", detail="endpoint declared public in spec")
    forged = ResolvedIdentity(
        name="forged", role="attacker", token="eyJhbGciOiJub25lIn0.eyJzdWIiOiJmb3JnZWQifQ.invalid"
    )
    req = _build(check, ctx, identity=forged)
    resp = await _send(ctx, req)
    if 200 <= resp.status_code < 300:
        return CheckResult(
            status="fail",
            detail=f"{check.endpoint_id} accepted a forged bearer token ({resp.status_code})",
            evidence=_evidence(resp, "forged unsigned JWT accepted"),
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail=f"forged token rejected ({resp.status_code})")


# ── authorization (require fulfilled identity contract) ─────────────────


async def bola_cross_identity(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    id_params = check.endpoint.object_id_params()
    if not id_params:
        return CheckResult(status="skipped", detail="no object-id parameter")
    param = id_params[0]
    owner = next(
        (i for i in ctx.identities if i.owned_objects.get(param.name)), None
    )
    attacker = next(
        (i for i in ctx.identities if owner and i.name != owner.name), None
    )
    if not owner or not attacker:
        return CheckResult(
            status="skipped",
            detail=f"no identity pair with declared ownership of '{param.name}'",
        )
    victim_object = owner.owned_objects[param.name][0]
    path = check.endpoint.path.replace("{%s}" % param.name, str(victim_object))
    for p in check.endpoint.parameters:  # fill any remaining path params
        if p.location == "path" and p.name != param.name:
            path = path.replace("{%s}" % p.name, str(p.example or "1"))
    req = _build(check, ctx, identity=attacker, path=path)
    resp = await _send(ctx, req)
    if 200 <= resp.status_code < 300:
        return CheckResult(
            status="fail",
            parameter=param.name,
            detail=(
                f"identity '{attacker.name}' accessed object {param.name}="
                f"{victim_object} owned by '{owner.name}' ({resp.status_code})"
            ),
            evidence=_evidence(resp, "cross-identity object access succeeded"),
            reproduction=_repro(req),
        )
    return CheckResult(
        status="pass",
        parameter=param.name,
        detail=f"cross-identity access denied ({resp.status_code})",
    )


async def bfla_role_matrix(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    haystack = (check.endpoint.path + " " + " ".join(check.endpoint.tags)).lower()
    if not any(h in haystack for h in _PRIVILEGED_HINTS):
        return CheckResult(status="skipped", detail="endpoint not privileged")
    low_priv = next((i for i in ctx.identities if i.role not in ("admin", "superuser")), None)
    if low_priv is None:
        return CheckResult(status="skipped", detail="no non-privileged test identity")
    req = _build(check, ctx, identity=low_priv)
    resp = await _send(ctx, req)
    if 200 <= resp.status_code < 300:
        return CheckResult(
            status="fail",
            detail=(
                f"non-privileged identity '{low_priv.name}' (role={low_priv.role}) "
                f"reached privileged endpoint ({resp.status_code})"
            ),
            evidence=_evidence(resp, "function-level authorization bypass"),
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail=f"privileged endpoint denied ({resp.status_code})")


# ── object property / data exposure ─────────────────────────────────────


async def mass_assignment(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    identity = ctx.primary_identity()
    injected = {"is_admin": True, "role": "admin", "balance_override": 999999}
    body = dict(check.endpoint.request_body_example or {})
    body.update(injected)
    req = _build(check, ctx, identity=identity, body=body)
    resp = await _send(ctx, req)
    if 200 <= resp.status_code < 300:
        try:
            echoed = resp.json()
        except ValueError:
            echoed = {}
        hit = [
            k for k, v in injected.items()
            if isinstance(echoed, dict) and echoed.get(k) == v
        ]
        if hit:
            return CheckResult(
                status="fail",
                parameter=",".join(hit),
                detail=f"privileged properties bound from request body: {hit}",
                evidence=_evidence(resp, f"injected {hit} persisted/echoed"),
                reproduction=_repro(req),
            )
    return CheckResult(status="pass", detail="injected privileged properties not honored")


async def excessive_data_exposure(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    req = _build(check, ctx, identity=ctx.primary_identity())
    resp = await _send(ctx, req)
    if resp.status_code >= 400:
        return CheckResult(status="skipped", detail=f"endpoint returned {resp.status_code}")
    keys: set[str] = set()
    try:
        _collect_keys(resp.json(), keys)
    except ValueError:
        return CheckResult(status="pass", detail="non-JSON response")
    leaked = sorted(k for k in keys if any(s in k for s in _SENSITIVE_KEYS))
    if leaked:
        return CheckResult(
            status="fail",
            parameter=",".join(leaked[:5]),
            detail=f"response exposes sensitive properties: {leaked}",
            evidence=_evidence(resp, f"sensitive keys present: {leaked}"),
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail="no sensitive property names in response")


# ── resource consumption ─────────────────────────────────────────────────


async def rate_limit_probe(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    burst = int(check.template.params.get("burst", 15))
    req = _build(check, ctx, identity=ctx.primary_identity())
    statuses = []
    for _ in range(burst):
        resp = await _send(ctx, req)
        statuses.append(resp.status_code)
        if resp.status_code == 429:
            return CheckResult(
                status="pass",
                detail=f"throttled after {len(statuses)} requests (429)",
            )
    return CheckResult(
        status="fail",
        detail=f"no 429 across burst of {burst} requests",
        evidence={"statuses": statuses, "note": "no rate limiting observed"},
        reproduction=_repro(req),
    )


async def payload_size_limit(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    oversize_kb = int(check.template.params.get("oversize_kb", 256))
    body = dict(check.endpoint.request_body_example or {})
    body["_asvp_padding"] = "A" * (oversize_kb * 1024)
    req = _build(check, ctx, identity=ctx.primary_identity(), body=body)
    resp = await _send(ctx, req)
    if 200 <= resp.status_code < 300:
        return CheckResult(
            status="fail",
            detail=f"{oversize_kb}KB body accepted ({resp.status_code}) — no size limit",
            evidence=_evidence(resp, f"oversized body of {oversize_kb}KB accepted"),
        )
    return CheckResult(status="pass", detail=f"oversized body rejected ({resp.status_code})")


# ── SSRF / injection ─────────────────────────────────────────────────────


async def ssrf_probe(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    url_params = check.endpoint.url_params()
    if not url_params:
        return CheckResult(status="skipped", detail="no URL-accepting parameter")
    target = url_params[0]
    payload = "http://169.254.169.254/latest/meta-data/"
    identity = ctx.primary_identity()
    if target.location == "query":
        req = _build(check, ctx, identity=identity)
        req["url"] += ("&" if "?" in req["url"] else "?") + f"{target.name}={payload}"
    else:
        body = dict(check.endpoint.request_body_example or {})
        body[target.name] = payload
        req = _build(check, ctx, identity=identity, body=body)
    resp = await _send(ctx, req)
    indicators = ("meta-data", "instance-id", "ami-", "169.254")
    if 200 <= resp.status_code < 300 and any(i in resp.text.lower() for i in indicators):
        return CheckResult(
            status="fail",
            parameter=target.name,
            detail=f"server fetched internal address via '{target.name}'",
            evidence=_evidence(resp, "internal metadata content in response"),
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", parameter=target.name, detail="no SSRF indicators")


_INJECTION_PAYLOADS = ["'", "1' OR '1'='1", '{"$ne": null}', "1; SELECT 1"]


async def injection_probe(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    identity = ctx.primary_identity()
    query_params = [p for p in check.endpoint.parameters if p.location == "query"]
    if not query_params and not check.endpoint.request_body_example:
        return CheckResult(status="skipped", detail="no injectable input vector")
    for payload in _INJECTION_PAYLOADS:
        if query_params:
            req = _build(check, ctx, identity=identity)
            sep = "&" if "?" in req["url"] else "?"
            req["url"] += f"{sep}{query_params[0].name}={payload}"
            param_name = query_params[0].name
        else:
            body = dict(check.endpoint.request_body_example or {})
            first_key = next(iter(body), None)
            if first_key is None:
                return CheckResult(status="skipped", detail="empty body example")
            body[first_key] = payload
            req = _build(check, ctx, identity=identity, body=body)
            param_name = first_key
        resp = await _send(ctx, req)
        text = resp.text.lower()
        if any(sig in text for sig in _ERROR_SIGNATURES):
            return CheckResult(
                status="fail",
                parameter=param_name,
                detail=f"database/interpreter error triggered via '{param_name}'",
                evidence=_evidence(resp, f"payload {payload!r} produced an engine error"),
                reproduction=_repro(req),
            )
    return CheckResult(status="pass", detail="no injection error signatures")


# ── misconfiguration / hygiene ───────────────────────────────────────────


async def verbose_errors(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    identity = ctx.primary_identity()
    if check.endpoint.is_state_changing:
        req = _build(check, ctx, identity=identity, body={"_asvp_malformed": {"deeply": None}})
    else:
        req = _build(check, ctx, identity=identity)
        sep = "&" if "?" in req["url"] else "?"
        req["url"] += f"{sep}_asvp_probe='"
    resp = await _send(ctx, req)
    text = resp.text.lower()
    hits = [sig for sig in _ERROR_SIGNATURES if sig in text]
    if hits:
        return CheckResult(
            status="fail",
            detail=f"verbose error disclosure: {hits}",
            evidence=_evidence(resp, f"error signatures: {hits}"),
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail="no verbose error content")


async def deprecated_version_live(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    req = _build(check, ctx, identity=ctx.primary_identity())
    resp = await _send(ctx, req)
    if resp.status_code in (404, 410):
        return CheckResult(status="pass", detail=f"deprecated endpoint retired ({resp.status_code})")
    return CheckResult(
        status="fail",
        detail=f"deprecated endpoint still responding ({resp.status_code})",
        evidence=_evidence(resp, "deprecated version live"),
        reproduction=_repro(req),
    )


_DEBUG_PATHS = ("/debug", "/actuator", "/actuator/env", "/env", "/__debug__", "/debug/vars")


async def debug_endpoint_probe(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    open_paths = []
    last_resp = None
    for path in _DEBUG_PATHS:
        req = {"method": "GET", "url": ctx.base_url.rstrip("/") + path, "headers": {}}
        resp = await _send(ctx, req)
        if resp.status_code == 200:
            open_paths.append(path)
            last_resp = resp
    if open_paths:
        return CheckResult(
            status="fail",
            detail=f"debug/management endpoints exposed: {open_paths}",
            evidence=_evidence(last_resp, f"open paths: {open_paths}"),
        )
    return CheckResult(status="pass", detail="no well-known debug endpoints exposed")


async def security_headers(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    req = {"method": "GET", "url": ctx.base_url.rstrip("/") + "/", "headers": {}}
    resp = await _send(ctx, req)
    missing = []
    if "strict-transport-security" not in resp.headers:
        missing.append("Strict-Transport-Security")
    if resp.headers.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options")
    if missing:
        return CheckResult(
            status="fail",
            detail=f"missing security headers: {missing}",
            evidence=_evidence(resp, f"missing: {missing}"),
        )
    return CheckResult(status="pass", detail="required security headers present")


async def cache_control_sensitive(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    req = _build(check, ctx, identity=ctx.primary_identity())
    resp = await _send(ctx, req)
    cc = resp.headers.get("cache-control", "")
    if "no-store" not in cc.lower():
        return CheckResult(
            status="fail",
            detail=f"sensitive endpoint lacks Cache-Control: no-store (got {cc!r})",
            evidence=_evidence(resp, f"cache-control: {cc!r}"),
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail="no-store enforced")


async def cors_strictness(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    origin = "https://evil.example.com"
    req = {
        "method": "OPTIONS",
        "url": ctx.base_url.rstrip("/") + "/",
        "headers": {"Origin": origin, "Access-Control-Request-Method": "GET"},
    }
    resp = await _send(ctx, req)
    acao = resp.headers.get("access-control-allow-origin", "")
    creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    if acao == "*" or acao == origin:
        sev_note = " with credentials allowed" if creds else ""
        return CheckResult(
            status="fail",
            detail=f"permissive CORS: Access-Control-Allow-Origin={acao!r}{sev_note}",
            evidence=_evidence(resp, f"ACAO={acao!r} credentials={creds}"),
        )
    return CheckResult(status="pass", detail=f"CORS restricted (ACAO={acao!r})")


_INTERNAL_LEAK = re.compile(
    r"\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9-]+\.(?:internal|local|svc|cluster\.local))\b"
)


async def error_schema_hygiene(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    req = {"method": "GET", "url": ctx.base_url.rstrip("/") + "/asvp-nonexistent-probe", "headers": {}}
    resp = await _send(ctx, req)
    problems = []
    try:
        resp.json()
    except ValueError:
        problems.append("error response is not structured JSON")
    leaks = _INTERNAL_LEAK.findall(resp.text)
    leaks = [l for l in leaks if not l.startswith("127.")]
    if leaks:
        problems.append(f"internal hostnames/IPs leaked: {leaks[:3]}")
    if problems:
        return CheckResult(
            status="fail",
            detail="; ".join(problems),
            evidence=_evidence(resp, "; ".join(problems)),
        )
    return CheckResult(status="pass", detail="error responses are hygienic")


# ── compliance ───────────────────────────────────────────────────────────


async def tls_enforcement(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    if ctx.base_url.lower().startswith("https://"):
        return CheckResult(status="pass", detail="target served over TLS")
    return CheckResult(
        status="fail",
        detail=f"target {ctx.base_url} is served over plaintext HTTP",
        evidence={"target": ctx.base_url, "note": "PCI-DSS Req 4: encrypt in transit"},
    )


async def pii_exposure(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    req = _build(check, ctx, identity=ctx.primary_identity())
    resp = await _send(ctx, req)
    if resp.status_code >= 400:
        return CheckResult(status="skipped", detail=f"endpoint returned {resp.status_code}")
    matched = sorted(
        kind for kind, pat in _PII_PATTERNS.items() if pat.search(resp.text)
    )
    if matched:
        return CheckResult(
            status="fail",
            parameter=",".join(matched),
            detail=f"PII classes detected in response: {matched}",
            evidence={
                "status_code": resp.status_code,
                "matched_classes": matched,
                "note": "values masked — classification dictionary match only",
            },
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail="no PII dictionary matches")


async def residency_header(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    allowed = check.template.params.get("allowed_regions", [])
    req = {"method": "GET", "url": ctx.base_url.rstrip("/") + "/", "headers": {}}
    resp = await _send(ctx, req)
    region = resp.headers.get("x-data-region")
    if region is None:
        return CheckResult(
            status="fail",
            detail="X-Data-Region header absent — residency posture unverifiable",
            evidence=_evidence(resp, "no residency header"),
        )
    if allowed and region not in allowed:
        return CheckResult(
            status="fail",
            detail=f"X-Data-Region={region!r} outside approved set {allowed}",
            evidence=_evidence(resp, f"region {region!r}"),
        )
    return CheckResult(status="pass", detail=f"region {region!r} within approved set")


# ── runtime weaknesses ───────────────────────────────────────────────────


async def race_condition_probe(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    parallelism = int(check.template.params.get("parallelism", 4))
    identity = ctx.primary_identity()
    req = _build(check, ctx, identity=identity)

    async def fire() -> int:
        resp = await _send(ctx, req)
        return resp.status_code

    statuses = await asyncio.gather(*(fire() for _ in range(parallelism)))
    accepted = sum(1 for s in statuses if 200 <= s < 300)
    if accepted >= 2:
        return CheckResult(
            status="fail",
            detail=(
                f"{accepted}/{parallelism} parallel duplicate submissions accepted "
                f"— double-spend class race"
            ),
            evidence={"statuses": statuses, "note": "no concurrency control observed"},
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail=f"duplicates rejected ({statuses})")


async def idempotency_probe(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    identity = ctx.primary_identity()
    key = "asvp-idem-probe-001"
    req = _build(check, ctx, identity=identity, headers={"Idempotency-Key": key})
    r1 = await _send(ctx, req)
    r2 = await _send(ctx, req)
    if not (200 <= r1.status_code < 300):
        return CheckResult(status="skipped", detail=f"first request failed ({r1.status_code})")
    if r2.status_code == 409:
        return CheckResult(status="pass", detail="duplicate key rejected (409)")
    try:
        id1 = (r1.json() or {}).get("id")
        id2 = (r2.json() or {}).get("id")
    except ValueError:
        id1 = id2 = None
    if 200 <= r2.status_code < 300 and id1 is not None and id1 != id2:
        return CheckResult(
            status="fail",
            detail=f"same Idempotency-Key created two resources (ids {id1!r}, {id2!r})",
            evidence={"first_id": id1, "second_id": id2, "statuses": [r1.status_code, r2.status_code]},
            reproduction=_repro(req),
        )
    return CheckResult(status="pass", detail="idempotency honored")


async def bounded_burst_probe(check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
    burst = int(check.template.params.get("burst", 20))
    req = {"method": "GET", "url": ctx.base_url.rstrip("/") + "/", "headers": {}}
    statuses = []
    for _ in range(burst):
        resp = await _send(ctx, req)
        statuses.append(resp.status_code)
    errors = [s for s in statuses if s >= 500]
    if errors:
        return CheckResult(
            status="fail",
            detail=f"{len(errors)}/{burst} requests degraded to 5xx under bounded burst",
            evidence={"statuses": statuses},
        )
    return CheckResult(status="pass", detail=f"graceful behavior across {burst}-request burst")


# ── registry ─────────────────────────────────────────────────────────────

Executor = Callable[[PlannedCheck, ExecutionContext], Awaitable[CheckResult]]

EXECUTORS: dict[str, Executor] = {
    "auth_missing_token": auth_missing_token,
    "auth_forged_token": auth_forged_token,
    "bola_cross_identity": bola_cross_identity,
    "bfla_role_matrix": bfla_role_matrix,
    "mass_assignment": mass_assignment,
    "excessive_data_exposure": excessive_data_exposure,
    "rate_limit_probe": rate_limit_probe,
    "payload_size_limit": payload_size_limit,
    "ssrf_probe": ssrf_probe,
    "injection_probe": injection_probe,
    "verbose_errors": verbose_errors,
    "deprecated_version_live": deprecated_version_live,
    "debug_endpoint_probe": debug_endpoint_probe,
    "security_headers": security_headers,
    "cache_control_sensitive": cache_control_sensitive,
    "cors_strictness": cors_strictness,
    "error_schema_hygiene": error_schema_hygiene,
    "tls_enforcement": tls_enforcement,
    "pii_exposure": pii_exposure,
    "residency_header": residency_header,
    "race_condition_probe": race_condition_probe,
    "idempotency_probe": idempotency_probe,
    "bounded_burst_probe": bounded_burst_probe,
}
