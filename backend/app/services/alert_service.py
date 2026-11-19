"""Alert persistence (idempotent upsert by dedupe key) and automatic correlation into incidents."""
from __future__ import annotations

import logging
import uuid
from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.domain import mitre
from app.domain.correlation import SEVERITY_RANK, AlertRef, find_relations
from app.domain.rules import Detection
from app.domain.tenancy import DEFAULT_ORG_ID
from app.models import Alert, Asset, Incident
from app.services import audit

log = logging.getLogger("sentinelx.alerts")
MAX_EVENT_IDS = 200
MAX_EVIDENCE = 50
ALERT_STATUSES = ("new", "in_review", "escalated", "resolved", "false_positive")


def _merge_evidence(old: list, new: list) -> list:
    merged = old + new
    return merged if len(merged) <= MAX_EVIDENCE else merged[:10] + merged[-(MAX_EVIDENCE - 10):]


def record_detection(db: Session, det: Detection, window: int, corr_rules: list[dict],
                     data_class: str = "live") -> tuple[Alert, bool]:
    """Create or update an alert. Returns (alert, created). Re-processing the same events is a no-op."""
    alert = db.scalar(select(Alert).where(Alert.dedupe_key == det.dedupe_key))
    if alert:
        seen = set(alert.event_ids)
        fresh = [(i, ev) for i, ev in zip(det.event_ids, det.evidence) if i not in seen]
        if not fresh:
            return alert, False
        alert.event_ids = (alert.event_ids + [i for i, _ in fresh])[-MAX_EVENT_IDS:]
        alert.evidence = _merge_evidence(alert.evidence, [e for _, e in fresh])
        alert.event_count += len(fresh)
        alert.first_seen = min(alert.first_seen, det.first_seen)
        alert.last_seen = max(alert.last_seen, det.last_seen)
        alert.explanation = det.explanation
        db.flush()
        return alert, False

    org_id = uuid.UUID(det.org_id or DEFAULT_ORG_ID)
    asset = (db.scalar(select(Asset).where(Asset.hostname == det.host, Asset.org_id == org_id))
             if det.host else None)
    alert = Alert(org_id=org_id, data_class=data_class, dedupe_key=det.dedupe_key, rule_key=det.rule_key, rule_version=det.rule_version, title=det.title,
                  severity=det.severity, explanation=det.explanation, first_seen=det.first_seen,
                  last_seen=det.last_seen, event_count=len(det.event_ids), event_ids=det.event_ids[-MAX_EVENT_IDS:],
                  evidence=_merge_evidence([], det.evidence), mitre=mitre.resolve(det.mitre),
                  rule_context=det.rule_context, host_name=det.host, user_name=det.user, source_ip=det.source_ip,
                  asset_id=asset.id if asset else None)
    db.add(alert)
    db.flush()
    audit.record(db, actor=None, action="alert.created", target_type="alert", target_id=str(alert.id), org_id=org_id,
                 details={"rule": det.rule_key, "rule_version": det.rule_version, "severity": det.severity})
    correlate(db, alert, window, corr_rules)
    return alert, True


def _ref(a: Alert) -> AlertRef:
    return AlertRef(id=str(a.id), rule_key=a.rule_key, severity=a.severity, first_seen=a.first_seen,
                    last_seen=a.last_seen, host=a.host_name, user=a.user_name, source_ip=a.source_ip, title=a.title)


def correlate(db: Session, alert: Alert, window: int, corr_rules: list[dict]) -> Incident | None:
    """Group related alerts into one incident, recording a human-readable reason for each link."""
    ents = [c for c in (Alert.host_name == alert.host_name if alert.host_name else None,
                        Alert.user_name == alert.user_name if alert.user_name else None,
                        Alert.source_ip == alert.source_ip if alert.source_ip else None) if c is not None]
    if not ents:
        return None
    lo, hi = alert.first_seen - timedelta(seconds=window), alert.last_seen + timedelta(seconds=window)
    cands = list(db.scalars(select(Alert).where(Alert.org_id == alert.org_id, Alert.id != alert.id, Alert.last_seen >= lo,
                                                Alert.first_seen <= hi, or_(*ents)).limit(200)))
    by_id = {str(c.id): c for c in cands}
    relations = find_relations(_ref(alert), [_ref(c) for c in cands], window, corr_rules)
    if not relations:
        return None

    related = [by_id[r.alert_id] for r in relations]
    incident = None
    for rel_alert in related:  # prefer an existing, not-closed incident
        if rel_alert.incident_id:
            inc = db.get(Incident, rel_alert.incident_id)
            if inc and inc.status != "closed" and inc.org_id == alert.org_id:
                incident = inc
                break
    members = [alert] + related
    if incident is None:
        sev = max((m.severity for m in members), key=lambda s: SEVERITY_RANK.get(s, 0))
        focus = alert.host_name or alert.user_name or alert.source_ip or "unknown entity"
        incident = Incident(org_id=alert.org_id, title=f"Correlated activity on {focus}", severity=sev, status="open", auto_created=True,
                            summary="Auto-created by correlation. " + " | ".join(r.reason for r in relations[:3]))
        db.add(incident)
        db.flush()
        audit.record(db, actor=None, action="incident.auto_created", target_type="incident",
                     target_id=str(incident.id), org_id=alert.org_id, details={"alerts": [str(m.id) for m in members]})
    reasons = {r.alert_id: f"[{r.correlation_id}] {r.reason}" for r in relations}
    for m in members:
        if m.incident_id is None:
            m.incident_id = incident.id
            m.correlation_reason = reasons.get(str(m.id)) or "; ".join(reasons.values())[:500]
    alert.correlation_reason = "; ".join(reasons.values())[:1000]
    incident.severity = max([m.severity for m in members] + [incident.severity],
                            key=lambda s: SEVERITY_RANK.get(s, 0))
    audit.record(db, actor=None, action="incident.alert_added", target_type="incident", target_id=str(incident.id),
                 org_id=alert.org_id,
                 details={"alert": str(alert.id), "reason": alert.correlation_reason})
    db.flush()
    return incident
