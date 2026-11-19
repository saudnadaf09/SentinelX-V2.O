from __future__ import annotations

import uuid
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user, request_id
from app.api.serializers import user_out
from app.core import security
from app.core.config import get_settings
from app.core.errors import AppError, Conflict, RateLimited, Unauthorized
from app.core.ratelimit import limiter
from app.db.base import utcnow
from app.db.session import get_db
from app.domain import accounts
from app.models import Organization, RefreshToken, User
from app.schemas.api import (AcceptInviteIn, ForgotIn, LoginIn, PasswordChangeIn, ProfileIn, RefreshIn, RegisterIn,
                             ResetIn, TokenIn)
from app.services import account_service, audit

router = APIRouter(prefix="/auth", tags=["auth"])


def _fields(exc: accounts.ValidationFailed):
    raise AppError("validation failed: " + "; ".join(f"{k}: {v}" for k, v in exc.errors.items()))


def _ua(request: Request) -> str:
    return request.headers.get("user-agent", "")


@router.get("/config")
def public_config():
    s = get_settings()
    return {"registration_enabled": s.allow_registration, "email_verification_required": s.require_email_verification,
            "mail_mode": s.mail_mode,
            "mail_notice": "Email delivery is in console mode: no real email is sent; links appear in the server window/outbox."
            if s.mail_mode != "smtp" else None}


@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    try:
        user, mailres = account_service.register(db, body.model_dump(), client_ip(request), request_id(request))
        db.commit()
    except accounts.ValidationFailed as exc:
        db.rollback()
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": {"code": "validation_error", "message": "Please correct the highlighted fields",
                                       "request_id": request_id(request),
                                       "details": [{"field": k, "message": v} for k, v in exc.errors.items()]}}, status_code=400)
    except IntegrityError:
        db.rollback()
        raise Conflict("email or username already in use") from None
    org = db.get(Organization, user.org_id)
    return {"user": user_out(user, org), "verification": {"mode": mailres["mode"], "delivered": mailres["delivered"],
            "message": "A verification email was sent." if mailres["delivered"] else
            "Verification email NOT sent (console mail mode). See the server window or backend/data/outbox for the link."}}


@router.post("/verify-email")
def verify_email(body: TokenIn, request: Request, db: Session = Depends(get_db)):
    if not limiter.allow(f"verify:{client_ip(request)}", 20, 3600):
        raise RateLimited("too many attempts")
    user = account_service.verify_email(db, body.token)
    db.commit()
    return {"verified": True, "email": user.email}


@router.post("/resend-verification")
def resend_verification(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.email_verified:
        return {"already_verified": True}
    if not limiter.allow(f"resend:{user.id}", 3, 3600):
        raise RateLimited("too many requests; try again later")
    res = account_service.send_verification(db, user)
    db.commit()
    return {"sent": res["delivered"], "mode": res["mode"]}


@router.post("/forgot-password")
def forgot(body: ForgotIn, request: Request, db: Session = Depends(get_db)):
    account_service.forgot_password(db, body.email, client_ip(request), request_id(request))
    db.commit()
    return {"message": "If an account exists for that email, a reset link has been sent."}


@router.post("/reset-password")
def reset(body: ResetIn, request: Request, db: Session = Depends(get_db)):
    try:
        account_service.reset_password(db, body.token, body.new_password, client_ip(request), request_id(request))
    except accounts.ValidationFailed as exc:
        db.rollback()
        _fields(exc)
    db.commit()
    return {"ok": True}


@router.post("/accept-invite", status_code=201)
def accept_invite(body: AcceptInviteIn, request: Request, db: Session = Depends(get_db)):
    try:
        user = account_service.accept_invite(db, body.token, body.model_dump(exclude={"token"}), client_ip(request), request_id(request))
        db.commit()
    except accounts.ValidationFailed as exc:
        db.rollback()
        _fields(exc)
    return {"user": user_out(user, db.get(Organization, user.org_id))}


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    user, tokens = account_service.login(db, body.email, body.password, client_ip(request), _ua(request), request_id(request))
    db.commit()
    return {**tokens, "user": user_out(user, db.get(Organization, user.org_id))}


@router.post("/refresh")
def refresh(body: RefreshIn, request: Request, db: Session = Depends(get_db)):
    try:
        payload = security.decode_token(body.refresh_token, "refresh")
        row = db.get(RefreshToken, payload["jti"])
        user = db.get(User, uuid.UUID(payload["sub"]))
    except (jwt.PyJWTError, ValueError, KeyError):
        raise Unauthorized("invalid refresh token") from None
    if row is None or row.revoked_at is not None or row.expires_at <= datetime.now(timezone.utc) or user is None or not user.is_active:
        raise Unauthorized("invalid refresh token")
    row.revoked_at = utcnow()  # rotation: each refresh token works once
    tokens = account_service.issue_session(db, user, client_ip(request), _ua(request))
    db.commit()
    return {**tokens, "user": user_out(user, db.get(Organization, user.org_id))}


@router.post("/logout")
def logout(body: RefreshIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        payload = security.decode_token(body.refresh_token, "refresh")
        row = db.get(RefreshToken, payload["jti"])
        if row and row.user_id == user.id and row.revoked_at is None:
            row.revoked_at = utcnow()
    except jwt.PyJWTError:
        pass
    audit.record(db, actor=user, action="auth.logout", request_id=request_id(request), client_ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return user_out(user, db.get(Organization, user.org_id))


@router.patch("/profile")
def update_profile(body: ProfileIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.full_name = " ".join(body.full_name.split())
    audit.record(db, actor=user, action="user.profile_updated", target_type="user", target_id=str(user.id), request_id=request_id(request))
    db.commit()
    return user_out(user, db.get(Organization, user.org_id))


@router.post("/change-password")
def change_password(body: PasswordChangeIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not security.verify_password(body.current_password, user.password_hash):
        raise Unauthorized("current password is incorrect")
    problems = accounts.password_problems(body.new_password, email=user.email, username=user.username or "")
    if problems:
        raise AppError("new password " + "; ".join(problems))
    user.password_hash = security.hash_password(body.new_password)
    account_service.revoke_all_sessions(db, user)
    audit.record(db, actor=user, action="auth.password_changed", target_type="user", target_id=str(user.id),
                 request_id=request_id(request), client_ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.get("/sessions")
def sessions(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"items": account_service.list_sessions(db, user)}


@router.post("/sessions/revoke-all")
def revoke_all(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    n = account_service.revoke_all_sessions(db, user)
    audit.record(db, actor=user, action="auth.sessions_revoked", request_id=request_id(request), details={"count": n})
    db.commit()
    return {"revoked": n}
