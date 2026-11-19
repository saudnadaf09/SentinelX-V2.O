from __future__ import annotations

import ipaddress
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import client_ip, request_id, require, scoped_get
from app.api.serializers import asset_out, key_out
from app.core import security
from app.core.config import get_settings
from app.core.errors import AppError, Conflict, NotFound
from app.db.base import utcnow
from app.db.session import get_db
from app.models import ApiKey, Asset, User
from app.schemas.api import AssetPatchIn, AssetRegisterIn, KeyCreateIn
from app.services import audit

router = APIRouter(tags=["assets"])


def _ip(v: str | None) -> str | None:
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        raise AppError("source_ip is not a valid IP address") from None


@router.get("/assets")
def list_assets(user: User = Depends(require("assets:read")), db: Session = Depends(get_db), include_deregistered: bool = False):
    stmt = select(Asset).where(Asset.org_id == user.org_id).order_by(Asset.hostname)
    if not include_deregistered:
        stmt = stmt.where(Asset.deregistered_at.is_(None))
    return {"items": [asset_out(a) for a in db.scalars(stmt)]}


@router.post("/assets/register", status_code=201)
def register(body: AssetRegisterIn, request: Request, user: User = Depends(require("assets:write")), db: Session = Depends(get_db)):
    if not body.authorized:
        raise Conflict("you must confirm you are authorized to monitor this system")
    src = _ip(body.source_ip)
    if src and db.scalar(select(Asset.id).where(Asset.source_ip == src, Asset.deregistered_at.is_(None))):
        raise Conflict("another endpoint already uses this syslog source IP")  # source IP maps a datagram to exactly one tenant
    a = Asset(org_id=user.org_id, hostname=body.hostname, platform=body.platform, owner=body.owner, tags=body.tags,
              is_lab_authorized=True, created_by=user.id, data_class=body.data_class, source_ip=src)
    db.add(a)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise Conflict("an endpoint with this hostname already exists in your workspace") from None
    audit.record(db, actor=user, action="asset.registered", target_type="asset", target_id=str(a.id), request_id=request_id(request),
                 client_ip=client_ip(request), details={"hostname": a.hostname, "platform": a.platform, "data_class": a.data_class})
    db.commit()
    return asset_out(a)


@router.patch("/assets/{asset_id}")
def patch_asset(asset_id: uuid.UUID, body: AssetPatchIn, request: Request, user: User = Depends(require("assets:write")),
                db: Session = Depends(get_db)):
    a = scoped_get(db, Asset, asset_id, user)
    if body.owner is not None:
        a.owner = body.owner
    if body.tags is not None:
        a.tags = body.tags
    if body.data_class is not None:
        a.data_class = body.data_class
    if body.source_ip is not None:
        src = _ip(body.source_ip)
        if src and db.scalar(select(Asset.id).where(Asset.source_ip == src, Asset.id != a.id, Asset.deregistered_at.is_(None))):
            raise Conflict("another endpoint already uses this syslog source IP")
        a.source_ip = src
    audit.record(db, actor=user, action="asset.updated", target_type="asset", target_id=str(a.id), request_id=request_id(request))
    db.commit()
    return asset_out(a)


@router.delete("/assets/{asset_id}")
def deregister(asset_id: uuid.UUID, request: Request, user: User = Depends(require("assets:write")), db: Session = Depends(get_db)):
    """Deregister: revoke every credential and stop accepting telemetry. Existing events are retained."""
    a = scoped_get(db, Asset, asset_id, user)
    now = utcnow()
    a.deregistered_at = now
    revoked = 0
    for k in db.scalars(select(ApiKey).where(ApiKey.asset_id == a.id, ApiKey.revoked_at.is_(None))):
        k.revoked_at = now
        revoked += 1
    audit.record(db, actor=user, action="endpoint.deregistered", target_type="asset", target_id=str(a.id),
                 request_id=request_id(request), details={"by": "admin", "keys_revoked": revoked})
    db.commit()
    return asset_out(a)


@router.get("/assets/{asset_id}/keys")
def list_keys(asset_id: uuid.UUID, user: User = Depends(require("keys:manage")), db: Session = Depends(get_db)):
    scoped_get(db, Asset, asset_id, user)
    return {"items": [key_out(k) for k in db.scalars(select(ApiKey).where(ApiKey.asset_id == asset_id).order_by(ApiKey.created_at.desc()))]}


@router.post("/assets/{asset_id}/keys", status_code=201)
def create_key(asset_id: uuid.UUID, body: KeyCreateIn, request: Request, user: User = Depends(require("keys:manage")),
               db: Session = Depends(get_db)):
    a = scoped_get(db, Asset, asset_id, user)
    if a.deregistered_at:
        raise Conflict("endpoint is deregistered")
    full, prefix, digest = security.generate_api_key()
    ttl = body.ttl_days or get_settings().collector_key_ttl_days
    k = ApiKey(asset_id=a.id, name=body.name, prefix=prefix, key_hash=digest, created_by=user.id, expires_at=utcnow() + timedelta(days=ttl))
    db.add(k)
    db.flush()
    audit.record(db, actor=user, action="apikey.created", target_type="api_key", target_id=str(k.id), request_id=request_id(request),
                 client_ip=client_ip(request), details={"asset": str(a.id), "prefix": prefix, "ttl_days": ttl})
    db.commit()
    return {**key_out(k), "api_key": full, "notice": "Copy this key now. It is shown only once."}


@router.post("/assets/keys/{key_id}/revoke")
def revoke_key(key_id: uuid.UUID, request: Request, user: User = Depends(require("keys:manage")), db: Session = Depends(get_db)):
    k = db.get(ApiKey, key_id)
    asset = db.get(Asset, k.asset_id) if k else None
    if k is None or asset is None or asset.org_id != user.org_id:  # a key of another tenant is simply "not found"
        raise NotFound("key not found")
    if k.revoked_at is None:
        k.revoked_at = utcnow()
        audit.record(db, actor=user, action="apikey.revoked", target_type="api_key", target_id=str(k.id),
                     request_id=request_id(request), client_ip=client_ip(request))
        db.commit()
    return key_out(k)
