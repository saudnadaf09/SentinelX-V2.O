from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import request_id, require, scoped_get
from app.api.serializers import investigation_out
from app.core.config import get_settings
from app.core.container import get_store
from app.core.errors import RateLimited
from app.core.ratelimit import limiter
from app.db.session import get_db
from app.models import AiSetting, Alert, Investigation, User
from app.schemas.api import AiSettingsIn, AiTestIn
from app.services import ai_service

router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/providers")
def providers(user: User = Depends(require("alerts:read"))):
    return {"items": ai_service.catalog(), "note": "Model names are suggestions; you can enter any model your account can use."}


@router.get("/status")
def status(user: User = Depends(require("alerts:read")), db: Session = Depends(get_db)):
    return ai_service.status(db, get_settings(), user.org_id)


@router.get("/settings")
def get_settings_(user: User = Depends(require("ai:configure")), db: Session = Depends(get_db)):
    row = db.get(AiSetting, user.org_id)
    base = ai_service.status(db, get_settings(), user.org_id)
    if row is None:
        return {"organization": None, "effective": base}
    return {"organization": {"provider": row.provider, "model": row.model, "enabled": row.enabled, "key_set": bool(row.api_key_enc),
                             "key_hint": row.key_hint, "last_test_at": row.last_test_at, "last_test_ok": row.last_test_ok,
                             "last_test_message": row.last_test_message, "updated_at": row.updated_at},
            "effective": base}  # the API key itself is never returned


@router.put("/settings")
def put_settings(body: AiSettingsIn, request: Request, user: User = Depends(require("ai:configure")), db: Session = Depends(get_db)):
    ai_service.save_settings(db, get_settings(), user, provider=body.provider, model=body.model, api_key=body.api_key,
                             enabled=body.enabled, request_id=request_id(request))
    db.commit()
    return get_settings_(user, db)


@router.delete("/settings", status_code=204)
def delete_settings(request: Request, user: User = Depends(require("ai:configure")), db: Session = Depends(get_db)):
    ai_service.clear_settings(db, user, request_id(request))
    db.commit()


@router.post("/settings/test")
def test(body: AiTestIn, request: Request, user: User = Depends(require("ai:configure")), db: Session = Depends(get_db)):
    if not limiter.allow(f"ai-test:{user.id}", 10):
        raise RateLimited("too many connection tests; wait a minute")
    cand = body.model_dump() if body.api_key and body.provider and body.model else None
    result = ai_service.test_settings(db, get_settings(), user, candidate=cand, request_id=request_id(request))
    db.commit()
    return result


@router.post("/investigate/{alert_id}", status_code=201)
def investigate(alert_id: uuid.UUID, request: Request, user: User = Depends(require("ai:use")), db: Session = Depends(get_db)):
    if not limiter.allow(f"ai:{user.id}", 20):
        raise RateLimited("too many investigation requests; try again in a minute")
    alert = scoped_get(db, Alert, alert_id, user)
    inv = ai_service.investigate(db, get_settings(), get_store(), user, alert, request_id(request))
    db.commit()
    return investigation_out(inv)


@router.post("/rule-summary/{alert_id}", status_code=201)
def rule_summary(alert_id: uuid.UUID, request: Request, user: User = Depends(require("alerts:read")), db: Session = Depends(get_db)):
    alert = scoped_get(db, Alert, alert_id, user)
    inv = ai_service.rule_summary(db, get_store(), user, alert, request_id(request))
    db.commit()
    return investigation_out(inv)


@router.get("/investigations")
def history(user: User = Depends(require("alerts:read")), db: Session = Depends(get_db), alert_id: uuid.UUID | None = None,
            size: int = Query(25, ge=1, le=100)):
    stmt = (select(Investigation, Alert.title).join(Alert, Alert.id == Investigation.alert_id)
            .where(Alert.org_id == user.org_id).order_by(Investigation.created_at.desc()).limit(size))
    if alert_id:
        stmt = stmt.where(Investigation.alert_id == alert_id)
    return {"items": [{**investigation_out(i), "alert_title": t} for i, t in db.execute(stmt).all()]}
