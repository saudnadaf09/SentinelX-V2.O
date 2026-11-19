"""Shared FastAPI dependencies: auth, RBAC, collector keys, request metadata."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import jwt
from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import get_settings
from app.core.errors import Forbidden, RateLimited, Unauthorized
from app.core.permissions import has_permission
from app.core.ratelimit import limiter
from app.db.session import get_db
from app.models import ApiKey, Asset, Organization, User

bearer = HTTPBearer(auto_error=False)


def request_id(request: Request) -> str:
    return request.scope.get("state", {}).get("request_id", "")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def get_current_user(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer),
                     db: Session = Depends(get_db)) -> User:
    if creds is None:
        raise Unauthorized("authentication required")
    try:
        payload = security.decode_token(creds.credentials, "access")
        user = db.get(User, uuid.UUID(payload["sub"]))
    except (jwt.PyJWTError, ValueError, KeyError):
        raise Unauthorized("invalid or expired token") from None
    if user is None or not user.is_active:
        raise Unauthorized("invalid or expired token")
    if user.org_id is None:
        raise Forbidden("account is not attached to an organization")
    org = db.get(Organization, user.org_id)
    if org is None or (not org.is_active and user.role != "super_admin"):
        raise Forbidden("organization is suspended or does not exist")
    return user


def require(permission: str):
    """Deny-by-default permission check, enforced on the server for every protected route."""
    def dep(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user.role, permission):
            raise Forbidden("insufficient permissions")
        return user
    return dep


def get_collector(request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key"),
                  db: Session = Depends(get_db)) -> tuple[ApiKey, Asset]:
    if not x_api_key:
        raise Unauthorized("missing X-API-Key")
    prefix = security.parse_api_key_prefix(x_api_key)
    key = db.scalar(select(ApiKey).where(ApiKey.prefix == prefix)) if prefix else None
    now = datetime.now(timezone.utc)
    if (key is None or not security.verify_api_key(x_api_key, key.key_hash) or key.revoked_at is not None
            or (key.expires_at is not None and key.expires_at <= now) or "ingest" not in key.scopes):
        raise Unauthorized("invalid, expired or revoked API key")
    if not limiter.allow(f"ingest:{key.id}", get_settings().ingest_rate_per_minute):
        raise RateLimited("ingestion rate limit exceeded")
    asset = db.get(Asset, key.asset_id)
    if asset is None or asset.deregistered_at is not None:
        raise Unauthorized("invalid API key")
    org = db.get(Organization, asset.org_id) if asset.org_id else None
    if org is None or not org.is_active:
        raise Unauthorized("organization is suspended")
    return key, asset


def scoped_get(db: Session, model, object_id, user: User):
    """Fetch an object ONLY if it belongs to the caller's organization (404 otherwise - no existence leak).
    The organization always comes from the authenticated user's DB record, never from the request."""
    from app.core.errors import NotFound
    obj = db.get(model, object_id)
    if obj is None or getattr(obj, "org_id", None) != user.org_id:
        raise NotFound(f"{model.__name__.lower()} not found")
    return obj
