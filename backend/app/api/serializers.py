"""ORM -> JSON-friendly dicts. Secrets (hashes) are never included."""
from __future__ import annotations

from datetime import timedelta

from app.core.permissions import PERMISSIONS
from app.db.base import utcnow
from app.models import ApiKey, Alert, Asset, AuditLog, Incident, Investigation, ResponseAction, User


def user_out(u: User, org=None) -> dict:
    out = {"id": u.id, "email": u.email, "username": u.username, "full_name": u.full_name, "role": u.role,
           "is_active": u.is_active, "email_verified": u.email_verified, "created_at": u.created_at,
           "last_login_at": u.last_login_at, "permissions": sorted(PERMISSIONS.get(u.role, []))}
    if org is not None:
        out["organization"] = {"id": org.id, "name": org.name, "kind": org.kind, "is_active": org.is_active}
    return out


def asset_status(a: Asset) -> str:
    """Connection health derived only from real timestamps (events or agent heartbeats); never assumed."""
    if a.deregistered_at is not None:
        return "deregistered"
    seen = [t for t in (a.last_seen_at, a.last_heartbeat_at) if t is not None]
    if not seen:
        return "never_seen"
    age = utcnow() - max(seen)
    return "online" if age < timedelta(minutes=5) else "stale" if age < timedelta(hours=1) else "offline"


def asset_out(a: Asset) -> dict:
    return {"id": a.id, "hostname": a.hostname, "platform": a.platform, "owner": a.owner, "tags": a.tags,
            "is_lab_authorized": a.is_lab_authorized, "isolation_state": a.isolation_state,
            "created_at": a.created_at, "last_seen_at": a.last_seen_at, "status": asset_status(a),
            "events_received": a.events_received, "data_class": a.data_class or "live", "agent_version": a.agent_version,
            "os_version": a.os_version, "ip_address": a.ip_address, "source_ip": a.source_ip,
            "collection_status": a.collection_status or {}, "last_heartbeat_at": a.last_heartbeat_at,
            "enrolled_at": a.enrolled_at, "deregistered_at": a.deregistered_at}


def key_out(k: ApiKey) -> dict:
    state = "revoked" if k.revoked_at else "expired" if (k.expires_at and k.expires_at <= utcnow()) else "active"
    return {"id": k.id, "name": k.name, "prefix": k.prefix, "scopes": k.scopes, "created_at": k.created_at,
            "expires_at": k.expires_at, "revoked_at": k.revoked_at, "last_used_at": k.last_used_at, "state": state}


def alert_out(a: Alert, detail: bool = False) -> dict:
    out = {"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "rule_key": a.rule_key,
           "rule_version": a.rule_version, "first_seen": a.first_seen, "last_seen": a.last_seen,
           "event_count": a.event_count, "host_name": a.host_name, "user_name": a.user_name,
           "source_ip": a.source_ip, "assignee_id": a.assignee_id, "incident_id": a.incident_id,
           "mitre": a.mitre, "explanation": a.explanation, "correlation_reason": a.correlation_reason,
           "data_class": a.data_class}
    if detail:
        out.update({"event_ids": a.event_ids, "evidence": a.evidence, "rule_context": a.rule_context,
                    "dedupe_key": a.dedupe_key, "created_at": a.created_at})
    return out


def incident_out(i: Incident, alert_count: int | None = None) -> dict:
    return {"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "summary": i.summary,
            "assignee_id": i.assignee_id, "auto_created": i.auto_created, "created_at": i.created_at,
            "updated_at": i.updated_at, "closed_at": i.closed_at, "alert_count": alert_count}


def action_out(r: ResponseAction, asset_name: str | None = None, requester: str | None = None,
               decider: str | None = None) -> dict:
    return {"id": r.id, "incident_id": r.incident_id, "asset_id": r.asset_id, "asset": asset_name,
            "action_type": r.action_type, "parameters": r.parameters, "rationale": r.rationale, "status": r.status,
            "dry_run_result": r.dry_run_result, "result": r.result, "mode": "simulated", "requested_by": requester or r.requested_by,
            "decided_by": decider or r.decided_by, "decision_note": r.decision_note, "expires_at": r.expires_at,
            "decided_at": r.decided_at, "executed_at": r.executed_at, "rolled_back_at": r.rolled_back_at,
            "created_at": r.created_at}


def audit_out(e: AuditLog) -> dict:
    return {"id": e.id, "timestamp": e.timestamp, "actor_email": e.actor_email, "action": e.action,
            "target_type": e.target_type, "target_id": e.target_id, "outcome": e.outcome,
            "request_id": e.request_id, "client_ip": e.client_ip, "details": e.details}


def investigation_out(i: Investigation) -> dict:
    return {"id": i.id, "alert_id": i.alert_id, "mode": i.mode, "provider": i.provider, "model": i.model,
            "prompt_version": i.prompt_version, "output": i.output, "note": i.note, "created_at": i.created_at,
            "requested_by": i.requested_by}
