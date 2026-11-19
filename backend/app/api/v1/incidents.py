from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import request_id, require, scoped_get
from app.api.serializers import alert_out, incident_out
from app.core.errors import Conflict, NotFound
from app.db.session import get_db
from app.models import Alert, Incident, IncidentNote, User
from app.schemas.api import IncidentCreateIn, IncidentPatchIn, LinkAlertIn, NoteIn
from app.services import audit, incident_service

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents(user: User = Depends(require("incidents:read")), db: Session = Depends(get_db),
                   status: str | None = None, severity: str | None = None, page: int = Query(1, ge=1), size: int = Query(25, ge=1, le=100)):
    stmt = select(Incident).where(Incident.org_id == user.org_id)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = list(db.scalars(stmt.order_by(Incident.updated_at.desc()).offset((page - 1) * size).limit(size)))
    counts = dict(db.execute(select(Alert.incident_id, func.count()).where(Alert.org_id == user.org_id,
                  Alert.incident_id.in_([r.id for r in rows])).group_by(Alert.incident_id)).all()) if rows else {}
    return {"total": total, "page": page, "size": size, "items": [incident_out(r, counts.get(r.id, 0)) for r in rows]}


@router.post("", status_code=201)
def create(body: IncidentCreateIn, request: Request, user: User = Depends(require("incidents:write")), db: Session = Depends(get_db)):
    inc = incident_service.create_incident(db, user, body.title, body.severity, body.summary, body.alert_ids, request_id(request))
    db.commit()
    return incident_out(inc, len(body.alert_ids))


@router.get("/{incident_id}")
def detail(incident_id: uuid.UUID, user: User = Depends(require("incidents:read")), db: Session = Depends(get_db)):
    inc = scoped_get(db, Incident, incident_id, user)
    alerts = list(db.scalars(select(Alert).where(Alert.incident_id == inc.id, Alert.org_id == user.org_id).order_by(Alert.first_seen)))
    notes = list(db.scalars(select(IncidentNote).where(IncidentNote.incident_id == inc.id).order_by(IncidentNote.created_at)))
    authors = {u.id: u.email for u in db.scalars(select(User).where(User.id.in_([n.author_id for n in notes if n.author_id])))} if notes else {}
    return {**incident_out(inc, len(alerts)), "alerts": [alert_out(a) for a in alerts],
            "notes": [{"id": n.id, "note": n.note, "author": authors.get(n.author_id, "unknown"), "created_at": n.created_at} for n in notes]}


@router.patch("/{incident_id}")
def patch(incident_id: uuid.UUID, body: IncidentPatchIn, request: Request, user: User = Depends(require("incidents:write")),
          db: Session = Depends(get_db)):
    inc = scoped_get(db, Incident, incident_id, user)
    incident_service.update_incident(db, user, inc, status=body.status, severity=body.severity, assignee_id=body.assignee_id,
                                     set_assignee=bool(body.unassign or body.assignee_id), title=body.title, summary=body.summary,
                                     request_id=request_id(request))
    db.commit()
    return incident_out(inc)


@router.get("/{incident_id}/timeline")
def get_timeline(incident_id: uuid.UUID, user: User = Depends(require("incidents:read")), db: Session = Depends(get_db)):
    return {"items": incident_service.timeline(db, scoped_get(db, Incident, incident_id, user))}


@router.post("/{incident_id}/notes", status_code=201)
def add_note(incident_id: uuid.UUID, body: NoteIn, request: Request, user: User = Depends(require("incidents:write")),
             db: Session = Depends(get_db)):
    n = incident_service.add_note(db, user, scoped_get(db, Incident, incident_id, user), body.note, request_id(request))
    db.commit()
    return {"id": n.id, "note": n.note, "author": user.email, "created_at": n.created_at}


@router.post("/{incident_id}/alerts", status_code=201)
def link_alert(incident_id: uuid.UUID, body: LinkAlertIn, request: Request, user: User = Depends(require("incidents:write")),
               db: Session = Depends(get_db)):
    inc = scoped_get(db, Incident, incident_id, user)
    a = scoped_get(db, Alert, body.alert_id, user)
    if a.incident_id and a.incident_id != inc.id:
        raise Conflict("alert already belongs to another incident")
    a.incident_id = inc.id
    audit.record(db, actor=user, action="incident.alert_linked", target_type="incident", target_id=str(inc.id),
                 request_id=request_id(request), details={"alert": str(a.id)})
    db.commit()
    return {"ok": True}
