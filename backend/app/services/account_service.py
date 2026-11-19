"""Registration, login, email verification, password reset, invitations and sessions."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import get_settings
from app.core.errors import AppError, Conflict, Forbidden, NotFound, RateLimited, Unauthorized
from app.core.ratelimit import limiter
from app.db.base import utcnow
from app.domain import accounts, secrets_util as su
from app.domain.mailer import send_mail
from app.models import AuthToken, Organization, RefreshToken, User
from app.services import audit

log = logging.getLogger("sentinelx.accounts")


# ------------------------------------------------------------------------------------ tokens
def issue_token(db: Session, purpose: str, ttl: timedelta, *, user_id=None, org_id=None, meta: dict | None = None) -> str:
    raw = su.new_token()
    db.add(AuthToken(purpose=purpose, token_hash=su.hash_token(get_settings().secret_key, raw), user_id=user_id,
                     org_id=org_id, meta=meta or {}, expires_at=utcnow() + ttl))
    db.flush()
    return raw


def consume_token(db: Session, raw: str, purpose: str) -> AuthToken:
    """Single use. Same error for unknown, used and expired tokens (no oracle)."""
    row = db.scalar(select(AuthToken).where(AuthToken.token_hash == su.hash_token(get_settings().secret_key, raw),
                                            AuthToken.purpose == purpose))
    if row is None or row.used_at is not None or row.expires_at <= utcnow():
        raise AppError("this link is invalid or has expired")
    row.used_at = utcnow()
    return row


def mail(to: str, subject: str, body: str) -> dict:
    s = get_settings()
    return send_mail(mode=s.mail_mode, to=to, subject=subject, body=body, sender=s.mail_from, 
                     outbox_dir=s.outbox_dir,
                     smtp_host=s.smtp_host, smtp_port=s.smtp_port, smtp_user=s.smtp_user,
                     smtp_password=s.smtp_password, smtp_starttls=s.smtp_starttls)


def _link(path: str, token: str) -> str:
    return f"{get_settings().frontend_base_url.rstrip('/')}{path}?token={token}"


def send_verification(db: Session, user: User) -> dict:
    tok = issue_token(db, "verify_email", timedelta(hours=get_settings().verify_token_hours), user_id=user.id, org_id=user.org_id)
    return mail(user.email, "Verify your SentinelX email",
                f"Hello {user.full_name},\n\nConfirm your email address:\n{_link('/verify-email', tok)}\n\nIf you did not register, ignore this message.")


# ------------------------------------------------------------------------------- registration
def register(db: Session, payload: dict, ip: str, request_id: str) -> tuple[User, dict]:
    s = get_settings()
    if not s.allow_registration:
        raise Forbidden("registration is disabled on this server")
    if not limiter.allow(f"register:{ip}", 5, 3600):
        raise RateLimited("too many registrations from this address; try again later")
    c = accounts.validate_registration(payload)  # raises ValidationFailed (mapped to field errors by the API)
    if db.scalar(select(User.id).where(User.email == c["email"])):
        raise Conflict("an account with this email already exists")
    if db.scalar(select(User.id).where(User.username == c["username"].lower())):
        raise Conflict("this username is already taken")
    is_org = c["account_type"] == "organization"
    name = c["organization_name"] if is_org else f"{c['full_name']}'s workspace"
    org = Organization(name=name, slug=f"{accounts.slugify(name)}-{uuid.uuid4().hex[:6]}",
                       kind="organization" if is_org else "individual",
                       contact_email=c["organization_email"] if is_org else c["email"], details=c["organization_details"] or "")
    db.add(org)
    db.flush()
    # public registration can only ever create an owner of the NEW workspace - never a platform administrator
    user = User(email=c["email"], username=c["username"].lower(), full_name=c["full_name"], role="org_admin",
                org_id=org.id, password_hash=security.hash_password(c["password"]), email_verified=False)
    db.add(user)
    db.flush()
    audit.record(db, actor=user, action="user.registered", target_type="user", target_id=str(user.id), request_id=request_id,
                 client_ip=ip, details={"account_type": c["account_type"], "org": str(org.id)})
    return user, send_verification(db, user)


def verify_email(db: Session, raw: str) -> User:
    tok = consume_token(db, raw, "verify_email")
    user = db.get(User, tok.user_id)
    if user is None:
        raise AppError("this link is invalid or has expired")
    user.email_verified = True
    audit.record(db, actor=user, action="user.email_verified", target_type="user", target_id=str(user.id))
    return user


def forgot_password(db: Session, email: str, ip: str, request_id: str) -> None:
    """Always behaves identically whether or not the account exists."""
    email = accounts.normalize_email(email)
    if not limiter.allow(f"forgot-ip:{ip}", 5, 3600) or not limiter.allow(f"forgot:{email}", 3, 3600):
        return
    user = db.scalar(select(User).where(User.email == email, User.is_active.is_(True)))
    if user is None:
        return
    tok = issue_token(db, "reset_password", timedelta(minutes=get_settings().reset_token_minutes), user_id=user.id, org_id=user.org_id)
    mail(user.email, "Reset your SentinelX password",
         f"A password reset was requested for your account.\n\nReset link (valid {get_settings().reset_token_minutes} minutes):\n"
         f"{_link('/reset-password', tok)}\n\nIf this was not you, ignore this message.")
    audit.record(db, actor=user, action="auth.password_reset_requested", target_type="user", target_id=str(user.id),
                 request_id=request_id, client_ip=ip)


def reset_password(db: Session, raw: str, new_password: str, ip: str, request_id: str) -> None:
    if not limiter.allow(f"reset:{ip}", 20, 3600):
        raise RateLimited("too many attempts")
    tok = consume_token(db, raw, "reset_password")
    user = db.get(User, tok.user_id)
    if user is None or not user.is_active:
        raise AppError("this link is invalid or has expired")
    problems = accounts.password_problems(new_password, email=user.email, username=user.username or "")
    if problems:
        tok.used_at = None  # let the user retry with the same link
        raise accounts.ValidationFailed({"new_password": "; ".join(problems)})
    user.password_hash = security.hash_password(new_password)
    revoke_all_sessions(db, user)
    audit.record(db, actor=user, action="auth.password_reset", target_type="user", target_id=str(user.id),
                 request_id=request_id, client_ip=ip)


def accept_invite(db: Session, raw: str, data: dict, ip: str, request_id: str) -> User:
    tok = consume_token(db, raw, "invite")
    org = db.get(Organization, tok.org_id)
    if org is None or not org.is_active:
        raise AppError("this invitation is no longer valid")
    c = accounts.validate_registration({**data, "email": tok.meta["email"], "account_type": "individual"})
    if db.scalar(select(User.id).where(User.email == c["email"])):
        raise Conflict("an account with this email already exists")
    if db.scalar(select(User.id).where(User.username == c["username"].lower())):
        raise Conflict("this username is already taken")
    role = tok.meta.get("role", "viewer")
    user = User(email=c["email"], username=c["username"].lower(), full_name=c["full_name"], role=role, org_id=org.id,
                password_hash=security.hash_password(c["password"]), email_verified=True)  # the invite proves mailbox access
    db.add(user)
    db.flush()
    audit.record(db, actor=user, action="org.invite_accepted", target_type="user", target_id=str(user.id), org_id=org.id,
                 request_id=request_id, client_ip=ip, details={"role": role})
    return user


# ------------------------------------------------------------------------------------- login
def login(db: Session, identifier: str, password: str, ip: str, ua: str, request_id: str) -> tuple[User, dict]:
    s = get_settings()
    ident = identifier.strip().lower()
    if not limiter.allow(f"login:{ip}", s.login_rate_per_minute) or not limiter.allow(f"login-id:{ident}", 10, 900):
        raise RateLimited("too many login attempts; try again later")
    user = db.scalar(select(User).where(or_(User.email == ident, User.username == ident)))
    ok = security.verify_password(password, user.password_hash if user else None)
    if not ok or user is None or not user.is_active:
        audit.record(db, actor=None, actor_email=ident[:320], action="auth.login", outcome="failure", request_id=request_id,
                     client_ip=ip, org_id=user.org_id if user else None)
        db.commit()
        raise Unauthorized("invalid credentials")
    if s.require_email_verification and not user.email_verified:
        audit.record(db, actor=user, action="auth.login", outcome="denied", request_id=request_id, client_ip=ip,
                     details={"reason": "email_not_verified"})
        db.commit()
        raise Forbidden("email not verified: check your inbox for the verification link")
    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(password)
    user.last_login_at = utcnow()
    tokens = issue_session(db, user, ip, ua)
    audit.record(db, actor=user, action="auth.login", request_id=request_id, client_ip=ip)
    return user, tokens


def issue_session(db: Session, user: User, ip: str = "", ua: str = "") -> dict:
    access = security.create_access_token(user.id)
    refresh, jti, exp = security.create_refresh_token(user.id)
    db.add(RefreshToken(jti=jti, user_id=user.id, expires_at=exp, ip=ip[:64] or None, user_agent=ua[:200] or None))
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer",
            "expires_in": get_settings().access_token_minutes * 60}


def revoke_all_sessions(db: Session, user: User) -> int:
    n = 0
    for t in db.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))):
        t.revoked_at = utcnow()
        n += 1
    return n


def list_sessions(db: Session, user: User) -> list[dict]:
    now = datetime.now(timezone.utc)
    rows = db.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None),
                                                 RefreshToken.expires_at > now).order_by(RefreshToken.created_at.desc()))
    return [{"id": r.jti[:12], "created_at": r.created_at, "expires_at": r.expires_at, "ip": r.ip, "user_agent": r.user_agent}
            for r in rows]
