from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.api.serializers import alert_out, asset_out, incident_out
from app.core.config import get_settings
from app.core.container import get_queue, get_store
from app.db.session import get_db
from app.domain.query import EventQuery
from app.models import Alert, Asset, Incident, User
from app.services import ai_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview")
def overview(user: User = Depends(require("dashboard:read")), db: Session = Depends(get_db), hours: int = Query(24, ge=1, le=168)):
    """Every figure is read from this organization's stored records; nothing is hardcoded or synthesized."""
    now = datetime.now(timezone.utc)
    start, org = now - timedelta(hours=hours), str(user.org_id)
    store = get_store()
    try:
        agg = store.aggregate(start, now + timedelta(minutes=1), 60 if hours > 6 else 15, org)
        recent = store.search(EventQuery(start=start, end=now + timedelta(minutes=1), size=10, org_id=org))[1]
        store_ok = True
    except Exception:  # noqa: BLE001
        agg, recent, store_ok = {"total": 0, "timeline": [], "top_hosts": [], "categories": [], "classes": {}}, [], False

    mine = Alert.org_id == user.org_id
    sev = dict(db.execute(select(Alert.severity, func.count()).where(mine).group_by(Alert.severity)).all())
    st = dict(db.execute(select(Alert.status, func.count()).where(mine).group_by(Alert.status)).all())
    cls = dict(db.execute(select(Alert.data_class, func.count()).where(mine).group_by(Alert.data_class)).all())
    open_inc = list(db.scalars(select(Incident).where(Incident.org_id == user.org_id, Incident.status != "closed")
                               .order_by(Incident.updated_at.desc()).limit(5)))
    counts = dict(db.execute(select(Alert.incident_id, func.count()).where(mine, Alert.incident_id.in_([i.id for i in open_inc]))
                             .group_by(Alert.incident_id)).all()) if open_inc else {}
    assets = [asset_out(a) for a in db.scalars(select(Asset).where(Asset.org_id == user.org_id, Asset.deregistered_at.is_(None)).order_by(Asset.hostname))]
    out = {
        "window_hours": hours, "event_store_available": store_ok,
        "events": {"total": agg["total"], "timeline": agg["timeline"], "top_hosts": agg["top_hosts"], "categories": agg["categories"],
                   "by_class": agg.get("classes", {}), "recent": recent},
        "alerts": {"by_severity": sev, "by_status": st, "by_class": cls, "total": sum(sev.values()),
                   "open": sum(v for k, v in st.items() if k in ("new", "in_review", "escalated")),
                   "latest": [alert_out(a) for a in db.scalars(select(Alert).where(mine).order_by(Alert.last_seen.desc()).limit(6))]},
        "incidents": {"open": db.scalar(select(func.count()).select_from(Incident).where(Incident.org_id == user.org_id, Incident.status != "closed")),
                      "items": [incident_out(i, counts.get(i.id, 0)) for i in open_inc]},
        "assets": assets,
        "ai": ai_service.status(db, get_settings(), user.org_id),
        "pipeline": get_queue().stats() if user.role == "super_admin" else None,  # global counters: platform admins only
    }
    return out
