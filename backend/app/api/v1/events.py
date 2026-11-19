from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.container import get_store
from app.core.errors import AppError, NotFound
from app.db.session import get_db
from app.domain.query import EventQuery, Filter, QueryError
from app.domain.tenancy import doc_org
from app.models import SavedQuery, User
from app.schemas.api import HuntIn, SavedQueryIn

router = APIRouter(tags=["events"])


def _run(q: EventQuery) -> dict:
    try:
        total, hits = get_store().search(q.validate())
    except QueryError as exc:
        raise AppError(str(exc)) from exc
    return {"total": total, "page": q.page, "size": q.size, "items": hits}


def _filters(host, user_name, source_ip, action, dataset, category, data_class):
    pairs = [("host.name", host), ("user.name", user_name), ("source.ip", source_ip), ("event.action", action),
             ("event.dataset", dataset), ("event.category", category), ("event.data_class", data_class)]
    return [Filter(f, "eq", v) for f, v in pairs if v]


@router.get("/events")
def list_events(user: User = Depends(require("events:read")), start: datetime | None = None, end: datetime | None = None,
                q: str | None = Query(None, max_length=200), host: str | None = Query(None, max_length=255),
                user_name: str | None = Query(None, max_length=255), source_ip: str | None = Query(None, max_length=64),
                action: str | None = Query(None, max_length=64), dataset: str | None = Query(None, max_length=64),
                category: str | None = Query(None, max_length=64), data_class: str | None = Query(None, max_length=12),
                page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=100)):
    end = end or datetime.now(timezone.utc) + timedelta(minutes=1)
    start = start or end - timedelta(hours=24)
    return _run(EventQuery(start=start, end=end, filters=_filters(host, user_name, source_ip, action, dataset, category, data_class),
                           text=q, page=page, size=size, org_id=str(user.org_id)))


@router.get("/events/export.jsonl")
def export_events(user: User = Depends(require("events:read")), hours: int = Query(24, ge=1, le=720),
                  host: str | None = Query(None, max_length=255)):
    """Bounded export (max 5,000 newest events) of YOUR organization's events."""
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    out, page = [], 1
    while len(out) < 5000:
        res = _run(EventQuery(start=end - timedelta(hours=hours), end=end, filters=_filters(host, None, None, None, None, None, None),
                              page=page, size=100, org_id=str(user.org_id)))
        out += res["items"]
        if len(res["items"]) < 100:
            break
        page += 1
    body = "\n".join(json.dumps(e, default=str) for e in out[:5000])
    return Response(body, media_type="application/x-ndjson", headers={"Content-Disposition": 'attachment; filename="events.jsonl"'})


@router.get("/events/{event_id}")
def get_event(event_id: str, user: User = Depends(require("events:read"))):
    doc = get_store().get(event_id)
    if not doc or doc_org(doc) != str(user.org_id):  # another tenant's event is indistinguishable from a missing one
        raise NotFound("event not found (it may have been removed by retention)")
    return doc


@router.post("/hunt/search")
def hunt(body: HuntIn, user: User = Depends(require("hunt:run"))):
    return _run(EventQuery(start=body.start, end=body.end, text=body.text, page=body.page, size=body.size, org_id=str(user.org_id),
                           filters=[Filter(f.field, f.op, f.value) for f in body.filters]))


@router.get("/hunt/saved")
def saved(user: User = Depends(require("hunt:run")), db: Session = Depends(get_db)):
    rows = db.scalars(select(SavedQuery).where(SavedQuery.owner_id == user.id).order_by(SavedQuery.created_at.desc()))
    return {"items": [{"id": r.id, "name": r.name, "definition": r.definition, "created_at": r.created_at} for r in rows]}


@router.post("/hunt/saved", status_code=201)
def save_query(body: SavedQueryIn, user: User = Depends(require("hunt:run")), db: Session = Depends(get_db)):
    row = SavedQuery(owner_id=user.id, name=body.name, definition=body.definition)
    db.add(row)
    db.commit()
    return {"id": row.id, "name": row.name, "definition": row.definition, "created_at": row.created_at}


@router.delete("/hunt/saved/{query_id}", status_code=204)
def delete_saved(query_id: str, user: User = Depends(require("hunt:run")), db: Session = Depends(get_db)):
    import uuid
    try:
        row = db.get(SavedQuery, uuid.UUID(query_id))
    except ValueError:
        raise NotFound("saved query not found") from None
    if not row or row.owner_id != user.id:
        raise NotFound("saved query not found")
    db.delete(row)
    db.commit()
