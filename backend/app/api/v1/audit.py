from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.api.serializers import audit_out
from app.db.session import get_db
from app.models import AuditLog, User
from app.services import audit as audit_svc
from app.services.report_service import to_csv

router = APIRouter(prefix="/audit-logs", tags=["audit"])


def _stmt(user, action, actor, target_type, start, end):
    stmt = select(AuditLog).where(audit_svc.org_clause(user.org_id))  # tenant boundary
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if actor:
        stmt = stmt.where(func.lower(AuditLog.actor_email).like(f"%{actor.lower()}%"))
    if target_type:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if start:
        stmt = stmt.where(AuditLog.timestamp >= start)
    if end:
        stmt = stmt.where(AuditLog.timestamp < end)
    return stmt


@router.get("")
def list_logs(user: User = Depends(require("audit:read")), db: Session = Depends(get_db), action: str | None = Query(None, max_length=64),
              actor: str | None = Query(None, max_length=100), target_type: str | None = Query(None, max_length=32),
              start: datetime | None = None, end: datetime | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200)):
    stmt = _stmt(user, action, actor, target_type, start, end)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(AuditLog.id.desc()).offset((page - 1) * size).limit(size))
    return {"total": total, "page": page, "size": size, "items": [audit_out(r) for r in rows]}


@router.get("/export.csv")
def export_csv(user: User = Depends(require("audit:read")), db: Session = Depends(get_db), action: str | None = Query(None, max_length=64),
               actor: str | None = Query(None, max_length=100), target_type: str | None = Query(None, max_length=32),
               start: datetime | None = None, end: datetime | None = None):
    rows = db.scalars(_stmt(user, action, actor, target_type, start, end).order_by(AuditLog.id.desc()).limit(10000))
    body = to_csv(["timestamp", "actor", "action", "target_type", "target_id", "outcome", "request_id", "client_ip", "details"],
                  [[r.timestamp.isoformat(), r.actor_email, r.action, r.target_type, r.target_id, r.outcome, r.request_id,
                    r.client_ip, r.details] for r in rows])
    return Response(body, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit-logs.csv"})
