"""Incident lifecycle, notes and timeline."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import Conflict, NotFound
from app.db.base import utcnow
from app.domain.correlation import SEVERITY_RANK
from app.models import Alert, AuditLog, Incident, IncidentNote, ResponseAction, User
from app.services import audit

INCIDENT_STATUSES = ("open", "investigating", "contained", "closed")
SEVERITIES = tuple(SEVERITY_RANK)
_TRANSITIONS = {"open": {"investigating", "contained", "closed"},
                "investigating": {"open", "contained", "closed"},
                "contained": {"investigating", "closed"},
                "closed": {"open"}}


def create_incident(db: Session, user: User, title: str, severity: str, summary: str,
                    alert_ids: list[uuid.UUID], request_id: str = "") -> Incident:
    alerts = [a for a in (db.get(Alert, i) for i in alert_ids) if a and a.org_id == user.org_id]  # same tenant only
    if len(alerts) != len(set(alert_ids)):
        raise NotFound("one or more alerts not found")
    inc = Incident(org_id=user.org_id, title=title.strip(), severity=severity, summary=summary, created_by=user.id)
    db.add(inc)
    db.flush()
    for a in alerts:
        a.incident_id = inc.id
        if SEVERITY_RANK[a.severity] > SEVERITY_RANK[inc.severity]:
            inc.severity = a.severity
    audit.record(db, actor=user, action="incident.created", target_type="incident", target_id=str(inc.id),
                 request_id=request_id, details={"alerts": [str(a.id) for a in alerts]})
    return inc


def update_incident(db: Session, user: User, inc: Incident, *, status: str | None, severity: str | None,
                    assignee_id: uuid.UUID | None, set_assignee: bool, title: str | None, summary: str | None,
                    request_id: str = "") -> Incident:
    changes: dict = {}
    if status and status != inc.status:
        if status not in _TRANSITIONS[inc.status]:
            raise Conflict(f"cannot move incident from '{inc.status}' to '{status}'")
        changes["status"] = [inc.status, status]
        inc.status = status
        inc.closed_at = utcnow() if status == "closed" else None
    if severity and severity != inc.severity:
        changes["severity"] = [inc.severity, severity]
        inc.severity = severity
    if set_assignee and assignee_id != inc.assignee_id:
        assignee = db.get(User, assignee_id) if assignee_id else None
        if assignee_id and (assignee is None or assignee.org_id != inc.org_id):
            raise NotFound("assignee not found")
        changes["assignee_id"] = [str(inc.assignee_id) if inc.assignee_id else None,
                                  str(assignee_id) if assignee_id else None]
        inc.assignee_id = assignee_id
    if title and title != inc.title:
        changes["title"] = True
        inc.title = title.strip()
    if summary is not None and summary != inc.summary:
        changes["summary"] = True
        inc.summary = summary
    if changes:
        audit.record(db, actor=user, action="incident.updated", target_type="incident", target_id=str(inc.id),
                     request_id=request_id, details=changes)
    return inc


def add_note(db: Session, user: User, inc: Incident, text: str, request_id: str = "") -> IncidentNote:
    note = IncidentNote(incident_id=inc.id, author_id=user.id, note=text.strip())
    db.add(note)
    inc.updated_at = utcnow()
    db.flush()
    audit.record(db, actor=user, action="incident.note_added", target_type="incident", target_id=str(inc.id),
                 request_id=request_id, details={"note_id": str(note.id)})
    return note


def timeline(db: Session, inc: Incident) -> list[dict]:
    items: list[dict] = []
    for a in db.scalars(select(Alert).where(Alert.incident_id == inc.id)):
        items.append({"time": a.first_seen, "kind": "alert", "title": a.title, "severity": a.severity,
                      "detail": a.correlation_reason or a.explanation, "ref": str(a.id)})
    for n in db.scalars(select(IncidentNote).where(IncidentNote.incident_id == inc.id)):
        author = db.get(User, n.author_id) if n.author_id else None
        items.append({"time": n.created_at, "kind": "note", "title": f"Note by {author.email if author else 'unknown'}",
                      "severity": None, "detail": n.note, "ref": str(n.id)})
    for r in db.scalars(select(ResponseAction).where(ResponseAction.incident_id == inc.id)):
        items.append({"time": r.created_at, "kind": "response", "title": f"Response: {r.action_type} ({r.status})",
                      "severity": None, "detail": r.rationale, "ref": str(r.id)})
    for e in db.scalars(select(AuditLog).where(AuditLog.org_id == inc.org_id, AuditLog.target_type == "incident",
                                               AuditLog.target_id == str(inc.id),
                                               AuditLog.action.in_(["incident.updated", "incident.auto_created",
                                                                    "incident.created"]))):
        items.append({"time": e.timestamp, "kind": "status", "title": e.action.replace("incident.", "Incident "),
                      "severity": None, "detail": f"{e.actor_email}: {e.details}" if e.details else e.actor_email,
                      "ref": str(e.id)})
    items.sort(key=lambda i: i["time"])
    return items
