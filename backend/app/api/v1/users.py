from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import client_ip, request_id, require
from app.api.serializers import user_out
from app.core import security
from app.core.errors import AppError, Conflict
from app.db.session import get_db
from app.domain import accounts
from app.models import User
from app.schemas.api import UserCreateIn, UserUpdateIn
from app.services import audit, org_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get("")
def list_users(admin: User = Depends(require("users:manage")), db: Session = Depends(get_db)):
    return {"items": [user_out(u) for u in org_service.members(db, admin.org_id)]}


@router.get("/directory")
def directory(user: User = Depends(require("alerts:read")), db: Session = Depends(get_db)):
    """Minimal list for assignment dropdowns - members of the caller's own organization only."""
    return {"items": [{"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role}
                      for u in db.scalars(select(User).where(User.org_id == user.org_id, User.is_active.is_(True)).order_by(User.email))]}


@router.post("", status_code=201)
def create_user(body: UserCreateIn, request: Request, admin: User = Depends(require("users:manage")), db: Session = Depends(get_db)):
    """Direct creation with an initial password (prefer invitations). The new user always joins the CALLER's organization."""
    email = accounts.normalize_email(body.email)
    problems = accounts.password_problems(body.password, email=email)
    if not accounts.valid_email(email) or problems:
        raise AppError("invalid email or weak password: " + "; ".join(problems))
    u = User(email=email, full_name=body.full_name, role=body.role, org_id=admin.org_id, email_verified=False,
             password_hash=security.hash_password(body.password))
    db.add(u)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise Conflict("a user with this email already exists") from None
    audit.record(db, actor=admin, action="user.created", target_type="user", target_id=str(u.id), request_id=request_id(request),
                 client_ip=client_ip(request), details={"role": u.role, "email": email})
    db.commit()
    return user_out(u)


@router.patch("/{user_id}")
def update_user(user_id: uuid.UUID, body: UserUpdateIn, request: Request, admin: User = Depends(require("users:manage")),
                db: Session = Depends(get_db)):
    u = org_service.update_member(db, admin, user_id, role=body.role, is_active=body.is_active, request_id=request_id(request))
    if body.full_name is not None:
        u.full_name = body.full_name
    if body.password:
        problems = accounts.password_problems(body.password, email=u.email)
        if problems:
            raise AppError("weak password: " + "; ".join(problems))
        u.password_hash = security.hash_password(body.password)
        audit.record(db, actor=admin, action="user.password_reset_by_admin", target_type="user", target_id=str(u.id),
                     request_id=request_id(request))
    db.commit()
    return user_out(u)
