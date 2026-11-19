"""Approval-gated response workflow. Execution only ever goes through an allowlisted adapter."""
from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import Conflict, Forbidden, NotFound
from app.core.permissions import has_permission
from app.db.base import utcnow
from app.domain.response_actions import ActionError, get_adapter, validate_action
from app.models import Asset, Incident, ResponseAction, User
from app.services import audit


def propose(db: Session, user: User, *, asset_id: uuid.UUID, action_type: str, parameters: dict, rationale: str,
            incident_id: uuid.UUID | None, idempotency_key: str | None, request_id: str = "") -> ResponseAction:
    if idempotency_key:
        existing = db.query(ResponseAction).filter(ResponseAction.idempotency_key == idempotency_key,
                                                   ResponseAction.org_id == user.org_id).first()
        if existing:
            return existing
    asset = db.get(Asset, asset_id)
    if not asset or asset.org_id != user.org_id:
        raise NotFound("asset not found")
    if not asset.is_lab_authorized:
        raise Forbidden("asset is not registered as an authorized lab target")
    inc = db.get(Incident, incident_id) if incident_id else None
    if incident_id and (inc is None or inc.org_id != user.org_id):
        raise NotFound("incident not found")
    settings = get_settings()
    try:
        params = validate_action(action_type, parameters)
        adapter = get_adapter(settings.response_adapter)
    except ActionError as exc:
        raise Conflict(str(exc)) from exc
    act = ResponseAction(org_id=user.org_id, asset_id=asset.id, incident_id=incident_id, action_type=action_type, parameters=params,
                         rationale=rationale.strip(), requested_by=user.id, idempotency_key=idempotency_key,
                         dry_run_result=adapter.dry_run(action_type, params, asset.hostname),
                         expires_at=utcnow() + timedelta(minutes=settings.approval_ttl_minutes))
    db.add(act)
    db.flush()
    audit.record(db, actor=user, action="response.proposed", target_type="response_action", target_id=str(act.id),
                 request_id=request_id, details={"type": action_type, "asset": asset.hostname, "params": params})
    return act


def _claim(db: Session, act: ResponseAction, user: User, new_status: str, note: str | None) -> None:
    """Atomic pending_approval -> new_status so an action can never be decided/executed twice."""
    res = db.execute(update(ResponseAction)
                     .where(ResponseAction.id == act.id, ResponseAction.status == "pending_approval")
                     .values(status=new_status, decided_by=user.id, decided_at=utcnow(), decision_note=note))
    if res.rowcount != 1:
        raise Conflict("action is no longer pending approval")
    db.refresh(act)


def _same_org(act: ResponseAction, user: User) -> None:
    if act.org_id != user.org_id:
        raise NotFound("action not found")


def _check_pending(act: ResponseAction, user: User) -> None:
    if act.status != "pending_approval":
        raise Conflict(f"action is '{act.status}', not pending approval")
    if act.requested_by == user.id:
        raise Forbidden("requester cannot decide their own action (separation of duties)")


def approve(db: Session, user: User, act: ResponseAction, note: str | None, request_id: str = "") -> ResponseAction:
    _same_org(act, user)
    if not has_permission(user.role, "response:approve"):
        raise Forbidden("not allowed to approve response actions")
    if act.expires_at <= utcnow():
        act.status = "expired"
        audit.record(db, actor=user, action="response.expired", target_type="response_action",
                     target_id=str(act.id), request_id=request_id, outcome="denied")
        db.commit()
        raise Conflict("approval window expired; propose the action again")
    _check_pending(act, user)
    _claim(db, act, user, "approved", note)
    asset = db.get(Asset, act.asset_id)
    adapter = get_adapter(get_settings().response_adapter)
    try:
        result = adapter.execute(act.action_type, act.parameters, asset.hostname)
        act.status, act.result = "executed", result
        if act.action_type == "isolate_lab_host":
            asset.isolation_state = "isolated-simulated"
    except Exception as exc:  # noqa: BLE001 - never silently discard failures
        act.status, act.result = "failed", {"error": f"{type(exc).__name__}: {exc}"[:500]}
    act.executed_at = utcnow()
    audit.record(db, actor=user, action=f"response.{act.status}", target_type="response_action",
                 target_id=str(act.id), request_id=request_id,
                 outcome="success" if act.status == "executed" else "failure",
                 details={"type": act.action_type, "asset": asset.hostname, "requested_by": str(act.requested_by),
                          "result": act.result})
    return act


def reject(db: Session, user: User, act: ResponseAction, note: str | None, request_id: str = "") -> ResponseAction:
    _same_org(act, user)
    if not has_permission(user.role, "response:approve"):
        raise Forbidden("not allowed to reject response actions")
    if act.status != "pending_approval":
        raise Conflict(f"action is '{act.status}', not pending approval")
    _claim(db, act, user, "rejected", note)
    audit.record(db, actor=user, action="response.rejected", target_type="response_action", target_id=str(act.id),
                 request_id=request_id, details={"note": note})
    return act


def rollback(db: Session, user: User, act: ResponseAction, request_id: str = "") -> ResponseAction:
    _same_org(act, user)
    if not has_permission(user.role, "response:approve"):
        raise Forbidden("not allowed to roll back response actions")
    if act.status != "executed":
        raise Conflict("only executed actions can be rolled back")
    asset = db.get(Asset, act.asset_id)
    result = get_adapter(get_settings().response_adapter).rollback(act.action_type, act.parameters, asset.hostname)
    act.status, act.rolled_back_at = "rolled_back", utcnow()
    act.result = {**(act.result or {}), "rollback": result}
    if act.action_type == "isolate_lab_host":
        asset.isolation_state = "none"
    audit.record(db, actor=user, action="response.rolled_back", target_type="response_action",
                 target_id=str(act.id), request_id=request_id, details={"asset": asset.hostname})
    return act
