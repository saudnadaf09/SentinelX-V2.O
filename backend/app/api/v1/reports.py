from __future__ import annotations

import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, request_id, require, scoped_get
from app.core.errors import NotFound
from app.db.session import get_db
from app.models import Alert, Incident, User
from app.services import audit
from app.services.report_service import build_incident_report, render_html, render_markdown, to_csv

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/incidents/{incident_id}")
def incident_report(incident_id: uuid.UUID, request: Request, format: Literal["md", "html", "json"] = "md",
                    user: User = Depends(require("reports:read")), db: Session = Depends(get_db)):
    inc = scoped_get(db, Incident, incident_id, user)
    report = build_incident_report(db, inc)
    audit.record(db, actor=user, action="report.generated", target_type="incident", target_id=str(inc.id),
                 request_id=request_id(request), client_ip=client_ip(request), details={"format": format})
    db.commit()
    name = f"incident-{str(inc.id)[:8]}"
    if format == "json":
        return Response(json.dumps(report, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    if format == "html":
        return Response(render_html(report), media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="{name}.html"'})
    return Response(render_markdown(report), media_type="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="{name}.md"'})


@router.get("/alerts.csv")
def alerts_csv(user: User = Depends(require("reports:read")), db: Session = Depends(get_db),
               severity: str | None = Query(None), status: str | None = Query(None)):
    stmt = select(Alert).where(Alert.org_id == user.org_id).order_by(Alert.last_seen.desc()).limit(10000)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    body = to_csv(["id", "title", "severity", "status", "rule", "host", "user", "source_ip", "first_seen", "last_seen",
                   "event_count", "mitre", "incident_id"],
                  [[a.id, a.title, a.severity, a.status, f"{a.rule_key} v{a.rule_version}", a.host_name, a.user_name,
                    a.source_ip, a.first_seen.isoformat(), a.last_seen.isoformat(), a.event_count,
                    ";".join(m["technique_id"] for m in a.mitre), a.incident_id] for a in db.scalars(stmt)])
    return Response(body, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})
