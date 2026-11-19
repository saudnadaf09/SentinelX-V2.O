from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.db.session import get_db
from app.domain import mitre
from app.models import Alert, DetectionRule, User

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/techniques")
def techniques(user: User = Depends(require("mitre:read")), db: Session = Depends(get_db)):
    rules: dict[str, list[dict]] = {}
    for r in db.scalars(select(DetectionRule).where(or_(DetectionRule.org_id.is_(None), DetectionRule.org_id == user.org_id))):
        for m in (r.definition or {}).get("mitre", []):
            rules.setdefault(m["technique_id"], []).append({"rule_key": r.rule_key, "title": r.title, "enabled": r.enabled})
    alerts: dict[str, int] = {}
    for a in db.scalars(select(Alert).where(Alert.org_id == user.org_id)):
        for m in a.mitre:
            alerts[m["technique_id"]] = alerts.get(m["technique_id"], 0) + 1
    items = [{"technique_id": tid, "name": name, "tactics": tactics, "url": mitre.technique_url(tid),
              "rules": rules.get(tid, []), "alert_count": alerts.get(tid, 0)} for tid, (name, tactics) in mitre.TECHNIQUES.items()]
    return {"dataset": mitre.DATASET_LABEL, "tactics": mitre.TACTICS, "items": items}
