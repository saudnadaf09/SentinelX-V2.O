from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, request_id, require
from app.core.container import get_registry
from app.core.errors import AppError, Forbidden, NotFound
from app.core.permissions import has_permission
from app.db.session import get_db
from app.domain import mitre
from app.domain.rule_loader import parse_yaml_rule
from app.domain.rules import RuleError
from app.models import DetectionRule, OrgRuleOverride, User
from app.schemas.api import RulePatchIn, RuleYamlIn
from app.services import audit, rule_service

router = APIRouter(prefix="/rules", tags=["rules"])


def _prefix(user: User) -> str:
    return f"ORG-{user.org_id.hex[:8]}-"


def _visible(db: Session, user: User, rule_id: uuid.UUID) -> DetectionRule:
    r = db.get(DetectionRule, rule_id)
    if r is None or (r.org_id is not None and r.org_id != user.org_id):
        raise NotFound("rule not found")
    return r


def _out(r: DetectionRule, overrides: dict, with_source: bool = False) -> dict:
    d = r.definition or {}
    ov = overrides.get(r.rule_key)
    out = {"id": r.id, "rule_key": r.rule_key, "title": r.title, "version": r.version, "severity": r.severity, "type": r.rule_type,
           "scope": "organization" if r.org_id else "global", "origin": r.origin, "author": r.author, "updated_at": r.updated_at,
           "tags": d.get("tags", []), "description": d.get("description", ""), "mitre": mitre.resolve(d.get("mitre", [])),
           "enabled_global": r.enabled, "enabled_for_org": r.enabled and ov is not False,
           "enabled": r.enabled and ov is not False}
    if with_source:
        out["yaml"] = r.yaml_source
    return out


def _overrides(db: Session, user: User) -> dict:
    return {o.rule_key: o.enabled for o in db.scalars(select(OrgRuleOverride).where(OrgRuleOverride.org_id == user.org_id))}


@router.get("")
def list_rules(user: User = Depends(require("rules:read")), db: Session = Depends(get_db)):
    ov = _overrides(db, user)
    rows = db.scalars(select(DetectionRule).where(or_(DetectionRule.org_id.is_(None), DetectionRule.org_id == user.org_id))
                      .order_by(DetectionRule.rule_key))
    return {"items": [_out(r, ov) for r in rows], "org_rule_prefix": _prefix(user)}


@router.post("/validate")
def validate(body: RuleYamlIn, user: User = Depends(require("rules:org_write"))):
    try:
        _, rule = parse_yaml_rule(body.yaml)
    except RuleError as exc:
        return {"valid": False, "error": str(exc)}
    if body.scope == "organization" and not rule.key.startswith(_prefix(user)):
        return {"valid": False, "error": f"organization rule ids must start with {_prefix(user)}"}
    return {"valid": True, "rule_key": rule.key, "type": rule.type, "severity": rule.severity}


@router.get("/{rule_id}")
def get_rule(rule_id: uuid.UUID, user: User = Depends(require("rules:read")), db: Session = Depends(get_db)):
    return _out(_visible(db, user, rule_id), _overrides(db, user), with_source=True)


@router.post("", status_code=201)
def create_rule(body: RuleYamlIn, request: Request, user: User = Depends(require("rules:org_write")), db: Session = Depends(get_db)):
    global_scope = body.scope == "global"
    if global_scope and not has_permission(user.role, "rules:write"):
        raise Forbidden("only platform administrators can create global rules")
    try:
        _, parsed = parse_yaml_rule(body.yaml)
        if not global_scope and not parsed.key.startswith(_prefix(user)):
            raise AppError(f"organization rule ids must start with {_prefix(user)}")
        row = rule_service.upsert_rule_from_yaml(db, user, body.yaml, request_id(request), org_id=None if global_scope else user.org_id)
    except RuleError as exc:
        raise AppError(str(exc)) from exc
    db.commit()
    get_registry().reload()
    return _out(row, _overrides(db, user), with_source=True)


@router.patch("/{rule_id}")
def patch_rule(rule_id: uuid.UUID, body: RulePatchIn, request: Request, user: User = Depends(require("rules:read")),
               db: Session = Depends(get_db)):
    r = _visible(db, user, rule_id)
    owns = r.org_id is not None
    if body.yaml:
        need = "rules:org_write" if owns else "rules:write"
        if not has_permission(user.role, need):
            raise Forbidden("insufficient permissions to edit this rule")
        try:
            _, parsed = parse_yaml_rule(body.yaml)
            if parsed.key != r.rule_key:
                raise AppError("rule id in YAML must match the rule being edited")
            rule_service.upsert_rule_from_yaml(db, user, body.yaml, request_id(request), org_id=r.org_id)
        except RuleError as exc:
            raise AppError(str(exc)) from exc
    if body.enabled is not None:
        if owns:  # an organization's own rule: engineers/admins of that org switch it directly
            if not has_permission(user.role, "rules:org_write"):
                raise Forbidden("insufficient permissions")
            r.enabled = body.enabled
        elif body.scope == "global":
            if not has_permission(user.role, "rules:write"):
                raise Forbidden("only platform administrators can change global rules")
            r.enabled = body.enabled
        else:  # per-organization override of a global rule
            if not has_permission(user.role, "rules:override"):
                raise Forbidden("insufficient permissions")
            ov = db.get(OrgRuleOverride, (user.org_id, r.rule_key))
            if ov is None:
                db.add(OrgRuleOverride(org_id=user.org_id, rule_key=r.rule_key, enabled=body.enabled, updated_by=user.id))
            else:
                ov.enabled, ov.updated_by = body.enabled, user.id
        audit.record(db, actor=user, action="rule.enabled" if body.enabled else "rule.disabled", target_type="rule",
                     target_id=r.rule_key, request_id=request_id(request), client_ip=client_ip(request), details={"scope": "global" if (not owns and body.scope == "global") else "organization"})
    db.commit()
    get_registry().reload()
    return _out(r, _overrides(db, user), with_source=True)
