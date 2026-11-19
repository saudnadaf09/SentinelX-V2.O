"""Rule persistence, file seeding and MITRE table seeding."""
from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain import mitre
from app.domain.rule_loader import load_rule_files, parse_yaml_rule
from app.domain.rules import parse_rule
from app.models import DetectionRule, MitreTechnique, User
from app.services import audit

log = logging.getLogger("sentinelx.rules")


def seed_mitre(db: Session) -> None:
    existing = {t.technique_id for t in db.scalars(select(MitreTechnique))}
    for tid, (name, tactics) in mitre.TECHNIQUES.items():
        if tid not in existing:
            db.add(MitreTechnique(technique_id=tid, name=name, tactics=tactics,
                                  reference_url=mitre.technique_url(tid), dataset=mitre.DATASET_LABEL))
    db.commit()


def seed_rules_from_files(db: Session, rules_dir: Path) -> dict:
    """Insert new rules; upgrade file-origin rules when the file version is newer. API-edited rules are kept."""
    added = updated = 0
    for path, data, text in load_rule_files(rules_dir):
        rule = parse_rule(data)
        row = db.scalar(select(DetectionRule).where(DetectionRule.rule_key == rule.key))
        if row is None:
            db.add(DetectionRule(rule_key=rule.key, title=rule.title, version=rule.version, severity=rule.severity,
                                 rule_type=rule.type, enabled=rule.enabled, definition=data, yaml_source=text,
                                 origin="file", author="system"))
            added += 1
        elif row.origin == "file" and rule.version > row.version:
            row.title, row.version, row.severity, row.rule_type = rule.title, rule.version, rule.severity, rule.type
            row.definition, row.yaml_source = data, text
            updated += 1
    db.commit()
    return {"added": added, "updated": updated}


def upsert_rule_from_yaml(db: Session, user: User, text: str, request_id: str = "", org_id=None) -> DetectionRule:
    data, rule = parse_yaml_rule(text)
    row = db.scalar(select(DetectionRule).where(DetectionRule.rule_key == rule.key))
    if row is not None and row.org_id != org_id:
        from app.core.errors import Conflict
        raise Conflict("a rule with this id already exists")  # never reveal or overwrite another scope's rule
    if row is None:
        row = DetectionRule(rule_key=rule.key, title=rule.title, version=rule.version, severity=rule.severity,
                            rule_type=rule.type, enabled=False, definition=data, yaml_source=text, origin="api",
                            author=user.email, org_id=org_id)  # new rules start disabled until validated
        db.add(row)
        action = "rule.created"
    else:
        row.version = max(rule.version, row.version + 1) if data != row.definition else row.version
        data = {**data, "version": row.version}
        row.title, row.severity, row.rule_type = rule.title, rule.severity, rule.type
        row.definition, row.yaml_source, row.origin, row.author = data, text, "api", user.email
        action = "rule.updated"
    db.flush()
    audit.record(db, actor=user, action=action, target_type="rule", target_id=row.rule_key, request_id=request_id,
                 org_id=user.org_id,
                 details={"version": row.version})
    return row
