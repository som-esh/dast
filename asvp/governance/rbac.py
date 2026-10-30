"""RBAC and multi-tenant visibility (FR-GOV-1/2, NFR-8).

Authentication is delegated to the corporate IdP via OIDC; the API layer
maps a validated identity to a `User`. This module is the authorization
boundary — enforced at the API layer, not UI filtering.

In this reference implementation the OIDC handshake is stubbed with a
bearer-token → user mapping (see asvp.api.app); role logic is real.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Role(str, Enum):
    PLATFORM_ADMIN = "platform_admin"
    SECURITY_ENGINEER = "security_engineer"
    TEAM_LEAD = "team_lead"
    DEVELOPER = "developer"
    AUDITOR = "auditor"  # read-only


@dataclass
class User:
    username: str
    role: Role
    teams: list[str] = field(default_factory=list)


# action → roles allowed (FR-GOV-2, FR-GTE-2, FR-FND-3, FR-GTE-6)
_PERMISSIONS: dict[str, set[Role]] = {
    "scan.request": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER, Role.TEAM_LEAD, Role.DEVELOPER},
    "service.register": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER, Role.TEAM_LEAD},
    "finding.triage": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER, Role.TEAM_LEAD, Role.DEVELOPER},
    "finding.approve_fp": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER},
    "finding.approve_risk": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER},
    "finding.mark_fixed": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER, Role.TEAM_LEAD, Role.DEVELOPER},
    "suppression.create": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER},
    "policy.mode_change": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER},
    "gate.bypass_request": {Role.TEAM_LEAD, Role.PLATFORM_ADMIN},
    "gate.bypass_approve": {Role.SECURITY_ENGINEER, Role.PLATFORM_ADMIN},
    "report.read": set(Role),  # all roles
    "evidence.export": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER, Role.AUDITOR},
    "audit.read": {Role.PLATFORM_ADMIN, Role.SECURITY_ENGINEER, Role.AUDITOR},
    "admin.config": {Role.PLATFORM_ADMIN},
}


class AuthorizationError(Exception):
    pass


def authorize(user: User, action: str) -> None:
    allowed = _PERMISSIONS.get(action)
    if allowed is None or user.role not in allowed:
        raise AuthorizationError(
            f"role '{user.role.value}' is not permitted to perform '{action}'"
        )


def can_view_finding(user: User, finding_owner_team: str) -> bool:
    """NFR-8 / FR-GOV-2: finding visibility scoped to owning team +
    security + auditor + platform admin."""
    if user.role in (Role.SECURITY_ENGINEER, Role.AUDITOR, Role.PLATFORM_ADMIN):
        return True
    return finding_owner_team in user.teams
