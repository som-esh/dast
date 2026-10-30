"""OpenAPI 3.x spec → canonical API model (FR-ING-5, v1.1 source)."""

from __future__ import annotations

from typing import Any

from asvp.models.canonical import CanonicalAPI, Endpoint, Parameter

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_SENSITIVE_PATH_HINTS = ("user", "account", "card", "payment", "transaction", "transfer", "kyc")


def _body_example(operation: dict) -> dict | None:
    content = (operation.get("requestBody") or {}).get("content") or {}
    media = content.get("application/json") or next(iter(content.values()), None)
    if not media:
        return None
    if "example" in media and isinstance(media["example"], dict):
        return media["example"]
    schema = media.get("schema") or {}
    props = schema.get("properties") or {}
    return {k: v.get("example", "") for k, v in props.items()} or None


def parse_openapi_spec(spec: dict, service: str) -> CanonicalAPI:
    endpoints: list[Endpoint] = []
    global_security = bool(spec.get("security"))
    for path, path_item in (spec.get("paths") or {}).items():
        shared_params = path_item.get("parameters", [])
        for method in _METHODS:
            op = path_item.get(method)
            if not op:
                continue
            params: list[Parameter] = []
            for p in list(shared_params) + list(op.get("parameters", [])):
                loc = p.get("in", "query")
                if loc not in ("path", "query", "header"):
                    continue
                params.append(
                    Parameter(
                        name=p.get("name", ""),
                        location=loc,  # type: ignore[arg-type]
                        required=bool(p.get("required")),
                        example=str(p["example"]) if "example" in p else None,
                    )
                )
            body = _body_example(op)
            if body:
                for key in body:
                    params.append(Parameter(name=str(key), location="body"))
            has_security = "security" in op
            auth_required = bool(op["security"]) if has_security else global_security
            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    name=op.get("operationId", op.get("summary", "")),
                    auth_required=auth_required,
                    parameters=params,
                    request_body_example=body,
                    tags=op.get("tags", []),
                    sensitive=any(h in path.lower() for h in _SENSITIVE_PATH_HINTS),
                    deprecated=bool(op.get("deprecated")) or "/v0/" in path,
                )
            )
    return CanonicalAPI(
        service=service,
        title=(spec.get("info") or {}).get("title", service),
        source_type="openapi",
        source_name=(spec.get("info") or {}).get("title", ""),
        endpoints=endpoints,
    )
