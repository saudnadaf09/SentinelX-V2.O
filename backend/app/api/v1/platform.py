from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import request_id, require
from app.api.serializers import audit_out
from app.core.errors import Conflict, NotFound
from app.db.session import get_db
from app.domain.tenancy import DEFAULT_ORG_ID, UNSCOPED_ORG_ID
from app.models import Alert, Asset, AuditLog, Organization, User
from app.schemas.api import PlatformOrgPatchIn
from app.services import audit, org_service

router = APIRouter(prefix="/platform", tags=["platform"])


@router.get("/orgs")
def orgs(user: User = Depends(require("platform:manage")), db: Session = Depends(get_db)):
    """Organization management view. Aggregate counts only: a platform admin does not browse tenant security data."""
    items = []
    for o in db.scalars(select(Organization).order_by(Organization.created_at)):
        d = org_service.org_out(db, o)
        d["alert_count"] = db.scalar(select(func.count()).select_from(Alert).where(Alert.org_id == o.id))
        items.append(d)
    return {"items": items}


@router.patch("/orgs/{org_id}")
def set_active(org_id: uuid.UUID, body: PlatformOrgPatchIn, request: Request, user: User = Depends(require("platform:manage")),
               db: Session = Depends(get_db)):
    o = db.get(Organization, org_id)
    if o is None:
        raise NotFound("organization not found")
    if str(o.id) == DEFAULT_ORG_ID and not body.is_active:
        raise Conflict("the platform default workspace cannot be suspended")
    if o.is_active != body.is_active:
        o.is_active = body.is_active
        audit.record(db, actor=user, action="platform.org_suspended" if not body.is_active else "platform.org_reactivated",
                     target_type="organization", target_id=str(o.id), request_id=request_id(request), org_id=o.id)
    db.commit()
    return org_service.org_out(db, o)


@router.get("/audit")
def platform_audit(user: User = Depends(require("platform:manage")), db: Session = Depends(get_db),
                   page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200)):
    """Platform-level activity: registrations/failed logins without a tenant, and organization management actions."""
    stmt = select(AuditLog).where(or_(AuditLog.org_id == uuid.UUID(UNSCOPED_ORG_ID), AuditLog.action.like("platform.%"),
                                      AuditLog.action == "user.registered", AuditLog.action == "org.deleted"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(AuditLog.id.desc()).offset((page - 1) * size).limit(size))
    return {"total": total, "page": page, "size": size, "items": [audit_out(r) for r in rows]}
