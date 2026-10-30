"""Canonical API model (AR-1).

Every source (Postman v1, OpenAPI v1.1) normalizes to this model. No
downstream service may consume raw source documents directly.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Optional

from pydantic import BaseModel, Field

ParamLocation = Literal["path", "query", "header", "body"]


class Parameter(BaseModel):
    name: str
    location: ParamLocation
    example: Optional[str] = None
    required: bool = False

    def looks_like_object_id(self) -> bool:
        """Heuristic used by authz (BOLA) check generation."""
        n = self.name.lower()
        return self.location == "path" and (
            n in ("id", "uuid")
            or n.endswith("id")
            or n.endswith("_id")
            or n.endswith("uuid")
        )

    def looks_like_url(self) -> bool:
        """Heuristic used by SSRF check generation."""
        n = self.name.lower()
        return any(t in n for t in ("url", "uri", "callback", "webhook", "redirect"))


class Endpoint(BaseModel):
    method: str
    path: str  # normalized template, e.g. /api/v1/users/{user_id}
    name: str = ""
    auth_required: Optional[bool] = None  # None = undeclared in source
    parameters: list[Parameter] = Field(default_factory=list)
    request_body_example: Optional[dict] = None
    tags: list[str] = Field(default_factory=list)
    sensitive: bool = False  # carries PII / payment data per data classification
    deprecated: bool = False
    discovered: bool = False  # found by the crawler, not declared in any source

    @property
    def endpoint_id(self) -> str:
        return f"{self.method.upper()} {self.path}"

    @property
    def is_state_changing(self) -> bool:
        return self.method.upper() in ("POST", "PUT", "PATCH", "DELETE")

    def object_id_params(self) -> list[Parameter]:
        return [p for p in self.parameters if p.looks_like_object_id()]

    def url_params(self) -> list[Parameter]:
        return [p for p in self.parameters if p.looks_like_url()]


class CanonicalAPI(BaseModel):
    service: str
    title: str = ""
    source_type: Literal["postman", "openapi"] = "postman"
    source_name: str = ""
    endpoints: list[Endpoint] = Field(default_factory=list)
    variables: dict[str, str] = Field(default_factory=dict)  # secrets already redacted

    def content_hash(self) -> str:
        """Stable hash for immutable versioned storage (FR-ING-2)."""
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def endpoint(self, endpoint_id: str) -> Optional[Endpoint]:
        for ep in self.endpoints:
            if ep.endpoint_id == endpoint_id:
                return ep
        return None
