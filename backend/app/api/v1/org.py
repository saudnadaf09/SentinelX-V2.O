from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user, request_id, require
from app.api.serializers import user_out
from app.core.container import get_store
from app.core.errors import NotFound
from app.core.permissions import PERMISSIONS, ORG_ASSIGNABLE_ROLES
from app.db.session import get_db
from app.models import Organization, User
from app.schemas.api import InviteIn, MemberPatchIn, OrgDeleteIn, OrgPatchIn
from app.services import org_service

router = APIRouter(prefix="/org", tags=["organization"])


def _my_org(db: Session, user: User) -> Organization:
    return db.get(Organization, user.org_id)  # always the caller's own organization


@router.get("")
def get_org(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return org_service.org_out(db, _my_org(db, user))


@router.patch("")
def patch_org(body: OrgPatchIn, request: Request, user: User = Depends(require("org:manage")), db: Session = Depends(get_db)):
    org = org_service.update_org(db, user, name=body.name, contact_email=body.contact_email, details=body.details,
                                 retention_days=body.retention_days, request_id=request_id(request))
    db.commit()
    return org_service.org_out(db, org)


@router.get("/roles")
def roles(user: User = Depends(get_current_user)):
    """Role reference for the Role Management view (read-only; roles are fixed by the platform)."""
    return {"assignable": list(ORG_ASSIGNABLE_ROLES), "permissions": {r: sorted(PERMISSIONS[r]) for r in (*ORG_ASSIGNABLE_ROLES, "super_admin")}}


@router.get("/members")
def list_members(user: User = Depends(require("users:manage")), db: Session = Depends(get_db)):
    return {"items": [user_out(u) for u in org_service.members(db, user.org_id)]}


@router.patch("/members/{member_id}")
def patch_member(member_id: uuid.UUID, body: MemberPatchIn, request: Request, user: User = Depends(require("users:manage")),
                 db: Session = Depends(get_db)):
    m = org_service.update_member(db, user, member_id, role=body.role, is_active=body.is_active, request_id=request_id(request))
    db.commit()
    return user_out(m)


@router.get("/invitations")
def invitations(user: User = Depends(require("users:manage")), db: Session = Depends(get_db)):
    return {"items": org_service.pending_invitations(db, user.org_id)}


@router.post("/invitations", status_code=201)
def invite(body: InviteIn, request: Request, user: User = Depends(require("users:manage")), db: Session = Depends(get_db)):
    inv, delivery = org_service.create_invitation(db, user, body.email, body.role, request_id(request))
    db.commit()
    return {**inv, "delivery": {k: v for k, v in delivery.items() if k != "outbox_file"}}


@router.delete("/invitations/{inv_id}", status_code=204)
def revoke_invitation(inv_id: uuid.UUID, user: User = Depends(require("users:manage")), db: Session = Depends(get_db)):
    org_service.revoke_invitation(db, user, inv_id)
    db.commit()


@router.get("/export")
def export(user: User = Depends(require("org:manage")), db: Session = Depends(get_db)):
    data = org_service.export_org(db, _my_org(db, user), user)
    db.commit()
    return Response(json.dumps(data, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="sentinelx-workspace-export.json"'})


@router.post("/delete")
def delete(body: OrgDeleteIn, request: Request, user: User = Depends(require("org:manage")), db: Session = Depends(get_db)):
    counts = org_service.delete_org(db, get_store(), _my_org(db, user), user, body.password, body.confirm_name)
    db.commit()
    return {"deleted": True, "removed": counts, "note": "Audit records are append-only and are retained."}
