from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, request_id, require, scoped_get
from app.api.serializers import alert_out, incident_out
from app.core.errors import Conflict, NotFound
from app.db.session import get_db
from app.models import Alert, User
from app.schemas.api import AlertPatchIn
from app.services import audit, incident_service

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(user: User = Depends(require("alerts:read")), db: Session = Depends(get_db),
                severity: str | None = None, status: str | None = None, q: str | None = Query(None, max_length=100),
                host: str | None = Query(None, max_length=255), rule_key: str | None = Query(None, max_length=64),
                technique: str | None = Query(None, max_length=16), incident_id: uuid.UUID | None = None,
                assignee_id: uuid.UUID | None = None, data_class: str | None = Query(None, max_length=12),
                page: int = Query(1, ge=1), size: int = Query(25, ge=1, le=100)):
    stmt = select(Alert).where(Alert.org_id == user.org_id)  # tenant boundary: first predicate of every query
    for col, val in ((Alert.severity, severity), (Alert.status, status), (Alert.host_name, host), (Alert.rule_key, rule_key),
                     (Alert.incident_id, incident_id), (Alert.assignee_id, assignee_id), (Alert.data_class, data_class)):
        if val:
            stmt = stmt.where(col == val)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Alert.title).like(like), func.lower(Alert.host_name).like(like),
                              func.lower(Alert.user_name).like(like), Alert.source_ip.like(like)))
    rows = list(db.scalars(stmt.order_by(Alert.last_seen.desc())))
    if technique:
        rows = [a for a in rows if any(m.get("technique_id") == technique for m in a.mitre)]
    return {"total": len(rows), "page": page, "size": size, "items": [alert_out(a) for a in rows[(page - 1) * size: page * size]]}


@router.get("/{alert_id}")
def get_alert(alert_id: uuid.UUID, user: User = Depends(require("alerts:read")), db: Session = Depends(get_db)):
    return alert_out(scoped_get(db, Alert, alert_id, user), detail=True)


@router.patch("/{alert_id}")
def patch_alert(alert_id: uuid.UUID, body: AlertPatchIn, request: Request, user: User = Depends(require("alerts:write")),
                db: Session = Depends(get_db)):
    a = scoped_get(db, Alert, alert_id, user)
    changes = {}
    if body.status and body.status != a.status:
        changes["status"] = [a.status, body.status]
        a.status = body.status
    if body.severity and body.severity != a.severity:
        changes["severity"] = [a.severity, body.severity]
        a.severity = body.severity
    if body.unassign:
        changes["assignee"] = None
        a.assignee_id = None
    elif body.assignee_id and body.assignee_id != a.assignee_id:
        assignee = db.get(User, body.assignee_id)
        if assignee is None or assignee.org_id != user.org_id:
            raise NotFound("assignee not found")
        changes["assignee"] = str(body.assignee_id)
        a.assignee_id = body.assignee_id
    if changes:
        audit.record(db, actor=user, action="alert.updated", target_type="alert", target_id=str(a.id),
                     request_id=request_id(request), client_ip=client_ip(request), details=changes)
        db.commit()
    return alert_out(a, detail=True)


@router.post("/{alert_id}/incident", status_code=201)
def create_incident_from_alert(alert_id: uuid.UUID, request: Request, user: User = Depends(require("incidents:write")),
                               db: Session = Depends(get_db)):
    a = scoped_get(db, Alert, alert_id, user)
    if a.incident_id:
        raise Conflict("alert is already linked to an incident")
    inc = incident_service.create_incident(db, user, a.title, a.severity, a.explanation or "", [a.id], request_id(request))
    db.commit()
    return incident_out(inc, 1)
