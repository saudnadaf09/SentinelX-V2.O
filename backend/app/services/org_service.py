"""Organization workspace: members, invitations, settings, export and deletion."""
from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import get_settings
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.permissions import ORG_ASSIGNABLE_ROLES
from app.db.base import utcnow
from app.domain.accounts import normalize_email, valid_email
from app.domain.tenancy import DEFAULT_ORG_ID
from app.models import (AiSetting, Alert, ApiKey, Asset, AuditLog, AuthToken, Incident, IncidentNote, Investigation,
                        Organization, OrgRuleOverride, RefreshToken, ResponseAction, SavedQuery, User, DetectionRule)
from app.services import account_service, audit


def ensure_default_org(db: Session) -> Organization:
    org = db.get(Organization, uuid.UUID(DEFAULT_ORG_ID))
    if org is None:
        org = Organization(id=uuid.UUID(DEFAULT_ORG_ID), name="Default Workspace", slug="default-workspace",
                           kind="organization", details="Platform default workspace.")
        db.add(org)
        db.flush()
    return org


def org_out(db: Session, org: Organization) -> dict:
    members = db.scalar(select(func.count()).select_from(User).where(User.org_id == org.id))
    assets = db.scalar(select(func.count()).select_from(Asset).where(Asset.org_id == org.id, Asset.deregistered_at.is_(None)))
    return {"id": org.id, "name": org.name, "slug": org.slug, "kind": org.kind, "contact_email": org.contact_email,
            "details": org.details, "is_active": org.is_active, "retention_days": org.retention_days,
            "created_at": org.created_at, "member_count": members, "endpoint_count": assets,
            "platform_default_retention_days": get_settings().event_retention_days}


def members(db: Session, org_id) -> list[User]:
    return list(db.scalars(select(User).where(User.org_id == org_id).order_by(User.created_at)))


def update_member(db: Session, actor: User, member_id, *, role: str | None, is_active: bool | None, request_id: str = "") -> User:
    m = db.get(User, member_id)
    if m is None or m.org_id != actor.org_id:
        raise NotFound("member not found")
    if m.role == "super_admin" and actor.role != "super_admin":
        raise Forbidden("platform administrators cannot be modified from an organization")
    if role is not None and role not in ORG_ASSIGNABLE_ROLES:
        raise AppError(f"role must be one of {ORG_ASSIGNABLE_ROLES}")
    admins = db.scalar(select(func.count()).select_from(User).where(User.org_id == actor.org_id, User.is_active.is_(True),
                                                                    User.role.in_(["org_admin", "super_admin"])))
    removing_admin = m.role in ("org_admin", "super_admin") and ((role and role not in ("org_admin",)) or is_active is False)
    if removing_admin and admins <= 1:
        raise Conflict("an organization needs at least one active administrator")
    if m.id == actor.id and is_active is False:
        raise Conflict("you cannot deactivate your own account")
    changes = {}
    if role and role != m.role and m.role != "super_admin":
        changes["role"] = [m.role, role]
        m.role = role
    if is_active is not None and is_active != m.is_active:
        changes["is_active"] = is_active
        m.is_active = is_active
        if not is_active:
            account_service.revoke_all_sessions(db, m)  # revoke access immediately
    if changes:
        audit.record(db, actor=actor, action="org.member_updated", target_type="user", target_id=str(m.id),
                     request_id=request_id, details=changes)
    return m


def create_invitation(db: Session, actor: User, email: str, role: str, request_id: str = "") -> tuple[dict, dict]:
    org = db.get(Organization, actor.org_id)
    if org.kind == "individual":
        raise Conflict("individual workspaces cannot have additional members; register an Organization account")
    email = normalize_email(email)
    if not valid_email(email):
        raise AppError("enter a valid email address")
    if role not in ORG_ASSIGNABLE_ROLES:
        raise AppError(f"role must be one of {ORG_ASSIGNABLE_ROLES}")
    if db.scalar(select(User.id).where(User.email == email)):
        raise Conflict("a user with this email already exists")
    raw = account_service.issue_token(db, "invite", timedelta(days=get_settings().invite_token_days), org_id=org.id,
                                      meta={"email": email, "role": role, "invited_by": str(actor.id)})
    link = account_service._link("/accept-invite", raw)
    res = account_service.mail(email, f"You are invited to {org.name} on SentinelX",
                               f"{actor.full_name} invited you to join {org.name} as {role}.\n\nAccept the invitation:\n{link}\n")
    audit.record(db, actor=actor, action="org.invited", target_type="invitation", request_id=request_id,
                 details={"email": email, "role": role})
    return {"email": email, "role": role}, {**res, "invite_link": link if res["mode"] == "console" else None}


def pending_invitations(db: Session, org_id) -> list[dict]:
    rows = db.scalars(select(AuthToken).where(AuthToken.org_id == org_id, AuthToken.purpose == "invite",
                                              AuthToken.used_at.is_(None), AuthToken.expires_at > utcnow()))
    return [{"id": r.id, "email": r.meta.get("email"), "role": r.meta.get("role"), "expires_at": r.expires_at,
             "created_at": r.created_at} for r in rows]


def revoke_invitation(db: Session, actor: User, inv_id) -> None:
    r = db.get(AuthToken, inv_id)
    if r is None or r.org_id != actor.org_id or r.purpose != "invite" or r.used_at is not None:
        raise NotFound("invitation not found")
    r.used_at = utcnow()
    audit.record(db, actor=actor, action="org.invite_revoked", target_type="invitation", target_id=str(inv_id))


def update_org(db: Session, actor: User, *, name, contact_email, details, retention_days, request_id: str = "") -> Organization:
    org = db.get(Organization, actor.org_id)
    changes = {}
    if name is not None and name.strip() and name != org.name:
        changes["name"] = True
        org.name = name.strip()
    if contact_email is not None:
        e = normalize_email(contact_email)
        if not valid_email(e):
            raise AppError("enter a valid organization email")
        changes["contact_email"] = True
        org.contact_email = e
    if details is not None:
        changes["details"] = True
        org.details = details.strip()[:2000]
    if retention_days is not None:
        if not 1 <= retention_days <= 3650:
            raise AppError("retention must be between 1 and 3650 days")
        changes["retention_days"] = retention_days
        org.retention_days = retention_days
    if changes:
        audit.record(db, actor=actor, action="org.updated", target_type="organization", target_id=str(org.id),
                     request_id=request_id, details=changes)
    return org


def export_org(db: Session, org: Organization, actor: User) -> dict:
    """Machine-readable copy of the organization's data (no secrets: no password hashes, API keys or AI keys)."""
    oid = org.id
    audit.record(db, actor=actor, action="org.exported", target_type="organization", target_id=str(oid))
    return {
        "exported_at": utcnow().isoformat(), "organization": org_out(db, org),
        "members": [{"email": u.email, "username": u.username, "full_name": u.full_name, "role": u.role,
                     "is_active": u.is_active, "created_at": u.created_at.isoformat()} for u in members(db, oid)],
        "endpoints": [{"hostname": a.hostname, "platform": a.platform, "data_class": a.data_class,
                       "created_at": a.created_at.isoformat(), "deregistered_at": a.deregistered_at and a.deregistered_at.isoformat()}
                      for a in db.scalars(select(Asset).where(Asset.org_id == oid))],
        "alerts": [{"id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status, "rule": f"{a.rule_key} v{a.rule_version}",
                    "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(), "event_ids": a.event_ids,
                    "evidence": a.evidence, "data_class": a.data_class} for a in db.scalars(select(Alert).where(Alert.org_id == oid))],
        "incidents": [{"id": str(i.id), "title": i.title, "severity": i.severity, "status": i.status, "summary": i.summary}
                      for i in db.scalars(select(Incident).where(Incident.org_id == oid))],
        "audit_log": [{"timestamp": e.timestamp.isoformat(), "actor": e.actor_email, "action": e.action, "target": e.target_id,
                       "outcome": e.outcome} for e in db.scalars(select(AuditLog).where(audit.org_clause(oid)).order_by(AuditLog.id).limit(20000))],
        "note": "Raw event records are exported separately from the Events page (JSONL).",
    }


def delete_org(db: Session, store, org: Organization, actor: User, password: str, confirm_name: str) -> dict:
    """Irreversibly delete a workspace and all its data. Audit rows are append-only and are retained."""
    if str(org.id) == DEFAULT_ORG_ID:
        raise Forbidden("the platform default workspace cannot be deleted")
    if not security.verify_password(password, actor.password_hash):
        raise Forbidden("password is incorrect")
    if confirm_name.strip() != org.name:
        raise AppError("type the exact workspace name to confirm")
    oid = org.id
    audit.record(db, actor=actor, action="org.deleted", target_type="organization", target_id=str(oid),
                 details={"name": org.name, "members": len(members(db, oid))})
    alert_ids = [a for a in db.scalars(select(Alert.id).where(Alert.org_id == oid))]
    inc_ids = [i for i in db.scalars(select(Incident.id).where(Incident.org_id == oid))]
    user_ids = [u for u in db.scalars(select(User.id).where(User.org_id == oid))]
    asset_ids = [a for a in db.scalars(select(Asset.id).where(Asset.org_id == oid))]
    counts = {"events": store.delete_org(str(oid))}
    if alert_ids:
        db.execute(delete(Investigation).where(Investigation.alert_id.in_(alert_ids)))
    db.execute(delete(ResponseAction).where(ResponseAction.org_id == oid))
    db.execute(delete(Alert).where(Alert.org_id == oid))
    if inc_ids:
        db.execute(delete(IncidentNote).where(IncidentNote.incident_id.in_(inc_ids)))
    db.execute(delete(Incident).where(Incident.org_id == oid))
    if asset_ids:
        db.execute(delete(ApiKey).where(ApiKey.asset_id.in_(asset_ids)))
    db.execute(delete(Asset).where(Asset.org_id == oid))
    db.execute(delete(DetectionRule).where(DetectionRule.org_id == oid))
    db.execute(delete(OrgRuleOverride).where(OrgRuleOverride.org_id == oid))
    db.execute(delete(AiSetting).where(AiSetting.org_id == oid))
    db.execute(delete(AuthToken).where(AuthToken.org_id == oid))
    if user_ids:
        db.execute(delete(SavedQuery).where(SavedQuery.owner_id.in_(user_ids)))
        db.execute(delete(RefreshToken).where(RefreshToken.user_id.in_(user_ids)))
    db.execute(delete(User).where(User.org_id == oid))
    db.delete(org)
    counts.update(alerts=len(alert_ids), incidents=len(inc_ids), users=len(user_ids), endpoints=len(asset_ids))
    return counts
