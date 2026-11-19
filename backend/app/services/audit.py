"""Append-only audit trail helper. Callers commit the session."""
from __future__ import annotations

from sqlalchemy.orm import Session

import uuid

from sqlalchemy import or_

from app.domain.tenancy import DEFAULT_ORG_ID, UNSCOPED_ORG_ID
from app.models import AuditLog, User

_SECRET_KEYS = {"password", "token", "secret", "api_key", "key", "authorization"}


def _clean(details: dict | None) -> dict:
    out = {}
    for k, v in (details or {}).items():
        out[k] = "[REDACTED]" if k.lower() in _SECRET_KEYS else v
    return out


def record(db: Session, *, actor: User | None, action: str, target_type: str = "", target_id: str = "",
           outcome: str = "success", request_id: str = "", client_ip: str = "",
           details: dict | None = None, actor_email: str | None = None,
           org_id: uuid.UUID | str | None = None) -> AuditLog:
    """org_id defaults to the actor's organization; events with no tenant are stored as 'unscoped' (platform)."""
    scope = org_id or (actor.org_id if actor else None) or UNSCOPED_ORG_ID
    entry = AuditLog(org_id=uuid.UUID(str(scope)), actor_id=actor.id if actor else None,
                     actor_email=actor.email if actor else (actor_email or "system"),
                     action=action, target_type=target_type, target_id=str(target_id), outcome=outcome,
                     request_id=request_id, client_ip=client_ip, details=_clean(details))
    db.add(entry)
    return entry


def org_clause(org_id):
    """Audit rows of one organization. Legacy rows (org_id NULL) belong to the default organization."""
    if str(org_id) == DEFAULT_ORG_ID:
        return or_(AuditLog.org_id == org_id, AuditLog.org_id.is_(None))
    return AuditLog.org_id == org_id
