"""Postman collection → canonical API model (FR-ING-1/2/4, AR-1)."""

from __future__ import annotations

import re
from typing import Any, Optional

from asvp.models.canonical import CanonicalAPI, Endpoint, Parameter


class CollectionValidationError(Exception):
    """FR-ING-4: actionable rejection (e.g. unresolvable auth variables)."""


_VAR = re.compile(r"\{\{([^}]+)\}\}")
_SENSITIVE_PATH_HINTS = ("user", "account", "card", "payment", "transaction", "transfer", "kyc")


def _normalize_path(raw_path: list[str] | str) -> tuple[str, list[Parameter]]:
    """Normalize Postman path segments: ':id' and '{{var}}' become {name}."""
    segments = raw_path if isinstance(raw_path, list) else [s for s in str(raw_path).split("/") if s]
    out: list[str] = []
    params: list[Parameter] = []
    for seg in segments:
        if not seg:
            continue
        if seg.startswith(":"):
            name = seg[1:]
            out.append("{%s}" % name)
            params.append(Parameter(name=name, location="path", required=True))
        elif _VAR.fullmatch(seg):
            name = _VAR.fullmatch(seg).group(1).strip()
            if name.lower() in ("baseurl", "base_url", "host", "url"):
                continue  # host variable, not a path param
            out.append("{%s}" % name)
            params.append(Parameter(name=name, location="path", required=True))
        else:
            out.append(seg)
    return "/" + "/".join(out), params


def _parse_body(body: Optional[dict]) -> Optional[dict]:
    if not body:
        return None
    if body.get("mode") == "raw":
        import json

        try:
            parsed = json.loads(body.get("raw", ""))
            return parsed if isinstance(parsed, dict) else None
        except (ValueError, TypeError):
            return None
    if body.get("mode") == "urlencoded":
        return {p.get("key"): p.get("value") for p in body.get("urlencoded", [])}
    return None


def _has_auth(request: dict, inherited: bool) -> bool:
    auth = request.get("auth")
    if auth:
        return auth.get("type", "noauth") != "noauth"
    for h in request.get("header", []):
        if str(h.get("key", "")).lower() == "authorization":
            return True
    return inherited


def _walk_items(
    items: list[dict],
    endpoints: list[Endpoint],
    folder: str,
    inherited_auth: bool,
) -> None:
    for item in items:
        if "item" in item:  # folder
            child_auth = inherited_auth or bool(
                item.get("auth") and item["auth"].get("type", "noauth") != "noauth"
            )
            _walk_items(item["item"], endpoints, item.get("name", folder), child_auth)
            continue
        request = item.get("request")
        if not isinstance(request, dict):
            continue
        url = request.get("url")
        if isinstance(url, str):
            url = {"raw": url, "path": [s for s in url.split("://")[-1].split("/")[1:] if s]}
        if not url:
            continue
        path, path_params = _normalize_path(url.get("path", []))
        params = list(path_params)
        for q in url.get("query", []) or []:
            params.append(
                Parameter(
                    name=str(q.get("key", "")),
                    location="query",
                    example=str(q.get("value")) if q.get("value") is not None else None,
                )
            )
        body = _parse_body(request.get("body"))
        if body:
            for key in body:
                params.append(Parameter(name=str(key), location="body"))
        method = str(request.get("method", "GET")).upper()
        sensitive = any(h in path.lower() for h in _SENSITIVE_PATH_HINTS)
        endpoints.append(
            Endpoint(
                method=method,
                path=path,
                name=item.get("name", ""),
                auth_required=_has_auth(request, inherited_auth),
                parameters=params,
                request_body_example=body,
                tags=[folder] if folder else [],
                sensitive=sensitive,
                deprecated="deprecated" in (item.get("name", "") + path).lower()
                or "/v0/" in path,
            )
        )


def _validate_variables(collection: dict, endpoints: list[Endpoint]) -> None:
    """FR-ING-4: reject collections whose auth variables cannot resolve."""
    declared = {v.get("key") for v in collection.get("variable", [])}
    declared |= {"baseUrl", "base_url", "host", "url"}  # resolved by the platform

    auth_var_refs: set[str] = set()

    def _collect(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "bearer" or "auth" in str(node.get("key", "")).lower():
                for m in _VAR.finditer(str(node)):
                    auth_var_refs.add(m.group(1).strip())
            for v in node.values():
                _collect(v)
        elif isinstance(node, list):
            for v in node:
                _collect(v)
        elif isinstance(node, str) and "authorization" in node.lower():
            for m in _VAR.finditer(node):
                auth_var_refs.add(m.group(1).strip())

    _collect(collection.get("item", []))
    unresolved = {v for v in auth_var_refs if v not in declared}
    # Variables resolved at scan time from the secrets manager are declared
    # by convention with a `secret:` prefix or listed in collection variables.
    unresolved = {v for v in unresolved if not v.startswith("secret:")}
    if unresolved:
        raise CollectionValidationError(
            "Unresolvable auth variables: "
            + ", ".join(sorted(unresolved))
            + ". Declare them as collection variables (placeholder values) or "
            "reference secrets-manager handles with the 'secret:' prefix."
        )


def parse_postman_collection(collection: dict, service: str) -> CanonicalAPI:
    info = collection.get("info", {})
    endpoints: list[Endpoint] = []
    collection_auth = bool(
        collection.get("auth") and collection["auth"].get("type", "noauth") != "noauth"
    )
    _walk_items(collection.get("item", []), endpoints, "", collection_auth)
    if not endpoints:
        raise CollectionValidationError(
            "Collection contains no requests — nothing to assess."
        )
    _validate_variables(collection, endpoints)
    variables = {
        str(v.get("key")): str(v.get("value", ""))
        for v in collection.get("variable", [])
    }
    return CanonicalAPI(
        service=service,
        title=info.get("name", service),
        source_type="postman",
        source_name=info.get("name", ""),
        endpoints=endpoints,
        variables=variables,
    )
