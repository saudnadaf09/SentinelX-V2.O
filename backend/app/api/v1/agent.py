"""Endpoints used by the endpoint agent (authenticated with the endpoint's API key)."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_collector, request_id
from app.core import security
from app.core.config import get_settings
from app.db.base import utcnow
from app.db.session import get_db
from app.models import ApiKey
from app.schemas.api import HeartbeatIn
from app.services import audit

router = APIRouter(prefix="/agent", tags=["agent"])
ROTATE_AFTER_DAYS = 60


@router.post("/heartbeat")
def heartbeat(body: HeartbeatIn, request: Request, collector=Depends(get_collector), db: Session = Depends(get_db)):
    key, asset = collector
    now = utcnow()
    if asset.enrolled_at is None:
        asset.enrolled_at = now
        audit.record(db, actor=None, action="endpoint.enrolled", target_type="asset", target_id=str(asset.id),
                     org_id=asset.org_id, request_id=request_id(request), details={"agent_version": body.agent_version})
    asset.last_heartbeat_at = now
    asset.agent_version, asset.os_version, asset.ip_address = body.agent_version, body.os_version, body.ip_address
    asset.collection_status = {"sources": body.sources, "spooled_events": body.spooled_events, "last_error": body.last_error,
                               "reported_at": now.isoformat()}
    key.last_used_at = now
    db.commit()
    age = (now - key.created_at).days
    return {"endpoint_id": str(asset.id), "organization_id": str(asset.org_id), "server_time": now.isoformat(),
            "key_rotation_due": age >= ROTATE_AFTER_DAYS,
            "config": {"interval_seconds": 30, "max_batch": 500}}


@router.post("/rotate-key")
def rotate_key(request: Request, collector=Depends(get_collector), db: Session = Depends(get_db)):
    key, asset = collector
    full, prefix, digest = security.generate_api_key()
    ttl = get_settings().collector_key_ttl_days
    db.add(ApiKey(asset_id=asset.id, name=f"{key.name} (rotated)", prefix=prefix, key_hash=digest,
                  expires_at=utcnow() + timedelta(days=ttl)))
    key.revoked_at = utcnow()  # the old credential stops working immediately
    audit.record(db, actor=None, action="apikey.rotated", target_type="asset", target_id=str(asset.id), org_id=asset.org_id,
                 request_id=request_id(request), details={"old_prefix": key.prefix, "new_prefix": prefix})
    db.commit()
    return {"api_key": full, "expires_in_days": ttl}


@router.post("/deregister")
def deregister(request: Request, collector=Depends(get_collector), db: Session = Depends(get_db)):
    _, asset = collector
    now = utcnow()
    asset.deregistered_at = now
    for k in db.scalars(select(ApiKey).where(ApiKey.asset_id == asset.id, ApiKey.revoked_at.is_(None))):
        k.revoked_at = now
    audit.record(db, actor=None, action="endpoint.deregistered", target_type="asset", target_id=str(asset.id),
                 org_id=asset.org_id, request_id=request_id(request), details={"by": "agent"})
    db.commit()
    return {"deregistered": True}
