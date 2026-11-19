"""Role -> permission matrix, enforced server-side by api.deps.require().

Roles (per organization): org_admin, analyst, engineer, viewer.  Platform role: super_admin.
A super_admin manages the platform (organizations, global rules/config) but, like everyone else,
only ever sees the security data of their OWN organization.
"""
from __future__ import annotations

ROLES = ("super_admin", "org_admin", "analyst", "engineer", "viewer")
ORG_ASSIGNABLE_ROLES = ("org_admin", "analyst", "engineer", "viewer")

_VIEWER = {"events:read", "alerts:read", "incidents:read", "assets:read", "response:read",
           "reports:read", "mitre:read", "dashboard:read"}
_ANALYST = _VIEWER | {"alerts:write", "incidents:write", "ai:use", "response:propose", "hunt:run", "rules:read"}
_ENGINEER = _VIEWER | {"rules:read", "rules:override", "rules:org_write", "assets:write", "keys:manage", "response:propose",
                       "response:approve", "hunt:run"}
_ORG_ADMIN = _ANALYST | _ENGINEER | {"users:manage", "org:manage", "audit:read", "settings:read", "ai:configure"}
_SUPER = _ORG_ADMIN | {"rules:write", "platform:manage"}

PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset(_VIEWER), "analyst": frozenset(_ANALYST), "engineer": frozenset(_ENGINEER),
    "org_admin": frozenset(_ORG_ADMIN), "super_admin": frozenset(_SUPER),
    "admin": frozenset(_SUPER),  # legacy alias, rewritten to super_admin by migration 0002
}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, frozenset())
