"""Check template schema and library (FR-CHK-2, FR-CHK-3).

Templates live as YAML in Git (asvp/checks/templates/). Every template
carries: domain, default severity, compliance mappings, destructiveness
class, and remediation guidance. `validate_template` is what template-repo
CI runs on PRs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError

Domain = Literal["security", "compliance", "configuration", "runtime"]
Destructiveness = Literal["safe", "mutating", "aggressive"]


class AppliesTo(BaseModel):
    """Endpoint selector — which endpoints a template generates checks for."""

    methods: Optional[list[str]] = None
    state_changing_only: bool = False
    sensitive_only: bool = False
    requires_object_id_param: bool = False
    requires_url_param: bool = False
    requires_body: bool = False
    requires_identities: bool = False  # authz checks (FR-CHK-4)
    deprecated_only: bool = False
    once_per_service: bool = False  # service-level, not per-endpoint


class CheckTemplate(BaseModel):
    id: str
    name: str
    domain: Domain
    default_severity: Literal["critical", "high", "medium", "low", "info"]
    destructiveness: Destructiveness
    executor: str  # registered executor name in the engine
    description: str = ""
    remediation: str = ""
    compliance_mappings: list[str] = Field(default_factory=list)
    applies: AppliesTo = Field(default_factory=AppliesTo)
    params: dict = Field(default_factory=dict)
    version: int = 1


class TemplateValidationError(Exception):
    pass


def validate_template(raw: dict) -> CheckTemplate:
    """Schema validation for template-repo CI (FR-CHK-2)."""
    try:
        tpl = CheckTemplate.model_validate(raw)
    except ValidationError as exc:
        raise TemplateValidationError(str(exc)) from exc
    if tpl.domain == "compliance" and not tpl.compliance_mappings:
        raise TemplateValidationError(
            f"{tpl.id}: compliance-domain templates must declare compliance_mappings"
        )
    if not tpl.remediation:
        raise TemplateValidationError(f"{tpl.id}: remediation guidance is mandatory")
    return tpl


class TemplateLibrary:
    def __init__(self, templates: list[CheckTemplate]):
        self._templates = {t.id: t for t in templates}

    @classmethod
    def load(cls, directory: Optional[Path] = None) -> "TemplateLibrary":
        directory = directory or Path(__file__).parent / "templates"
        templates: list[CheckTemplate] = []
        for f in sorted(directory.glob("*.yaml")):
            docs = yaml.safe_load(f.read_text(encoding="utf-8")) or []
            for raw in docs:
                templates.append(validate_template(raw))
        return cls(templates)

    def get(self, template_id: str) -> Optional[CheckTemplate]:
        return self._templates.get(template_id)

    def all(self) -> list[CheckTemplate]:
        return list(self._templates.values())

    def by_domain(self, domain: str) -> list[CheckTemplate]:
        return [t for t in self._templates.values() if t.domain == domain]
