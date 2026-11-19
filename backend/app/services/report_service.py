"""Incident report generation (Markdown / HTML / JSON) and CSV export helpers."""
from __future__ import annotations

import csv
import html
import io
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert, Incident, IncidentNote, Investigation, ResponseAction, User
from app.services import incident_service

LIMITATIONS = [
    "Evidence is limited to bounded event snapshots stored with each alert.",
    "Detections are rule-based; AI analysis is advisory and never changes a verdict.",
    "Response actions were executed through a mock adapter and changed nothing outside SentinelX.",
    "ATT&CK mappings come from the rules and use a curated subset of the framework.",
]


def csv_safe(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(header: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow([csv_safe(c) for c in r])
    return buf.getvalue()


def build_incident_report(db: Session, inc: Incident) -> dict:
    alerts = list(db.scalars(select(Alert).where(Alert.incident_id == inc.id, Alert.org_id == inc.org_id).order_by(Alert.first_seen)))
    notes = list(db.scalars(select(IncidentNote).where(IncidentNote.incident_id == inc.id).order_by(IncidentNote.created_at)))
    actions = list(db.scalars(select(ResponseAction).where(ResponseAction.incident_id == inc.id)))
    inv = []
    for a in alerts:
        for i in db.scalars(select(Investigation).where(Investigation.alert_id == a.id).order_by(Investigation.created_at)):
            inv.append({"alert": str(a.id), "mode": i.mode, "model": i.model, "summary": i.output.get("summary", ""),
                        "created_at": i.created_at.isoformat()})
    assignee = db.get(User, inc.assignee_id) if inc.assignee_id else None
    start = min((a.first_seen for a in alerts), default=inc.created_at)
    end = max((a.last_seen for a in alerts), default=inc.updated_at)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": {"id": str(inc.id), "title": inc.title, "severity": inc.severity, "status": inc.status,
                     "assignee": assignee.email if assignee else None, "summary": inc.summary,
                     "created_at": inc.created_at.isoformat(), "auto_created": inc.auto_created},
        "time_range": {"start": start.isoformat(), "end": end.isoformat()},
        "alerts": [{"id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status,
                    "rule": f"{a.rule_key} v{a.rule_version}", "host": a.host_name, "user": a.user_name,
                    "source_ip": a.source_ip, "first_seen": a.first_seen.isoformat(),
                    "last_seen": a.last_seen.isoformat(), "event_count": a.event_count,
                    "mitre": [f"{m['technique_id']} {m['name']}" for m in a.mitre],
                    "correlation_reason": a.correlation_reason,
                    "evidence_event_ids": a.event_ids[:25]} for a in alerts],
        "notes": [{"at": n.created_at.isoformat(), "note": n.note} for n in notes],
        "response_actions": [{"type": r.action_type, "status": r.status, "parameters": r.parameters,
                              "rationale": r.rationale} for r in actions],
        "investigations": inv,
        "timeline": [{**t, "time": t["time"].isoformat()} for t in incident_service.timeline(db, inc)],
        "limitations": LIMITATIONS,
    }


def render_markdown(r: dict) -> str:
    i = r["incident"]
    L = [f"# Incident report: {i['title']}", "",
         f"- **ID:** {i['id']}", f"- **Severity:** {i['severity']}  **Status:** {i['status']}",
         f"- **Assignee:** {i['assignee'] or 'unassigned'}",
         f"- **Time range:** {r['time_range']['start']} to {r['time_range']['end']}",
         f"- **Generated:** {r['generated_at']}", "", "## Summary", "", i["summary"] or "_No summary recorded._", "",
         "## Alerts", ""]
    for a in r["alerts"]:
        L += [f"### {a['title']} ({a['severity']})",
              f"- Rule: {a['rule']}; host: {a['host']}; user: {a['user']}; source IP: {a['source_ip']}",
              f"- {a['first_seen']} to {a['last_seen']}, {a['event_count']} event(s)",
              f"- ATT&CK: {', '.join(a['mitre']) or 'none'}",
              f"- Correlation: {a['correlation_reason'] or 'n/a'}",
              f"- Evidence event IDs: {', '.join(a['evidence_event_ids']) or 'n/a'}", ""]
    L += ["## Analyst notes", ""] + ([f"- {n['at']}: {n['note']}" for n in r["notes"]] or ["_None._"])
    L += ["", "## Response actions", ""] + (
        [f"- {x['type']} - {x['status']} - {x['rationale']}" for x in r["response_actions"]] or ["_None._"])
    L += ["", "## Investigations", ""] + (
        [f"- [{x['mode']}] {x['created_at']}: {x['summary']}" for x in r["investigations"]] or ["_None._"])
    L += ["", "## Timeline", ""] + [f"- {t['time']} [{t['kind']}] {t['title']}" for t in r["timeline"]]
    L += ["", "## Limitations", ""] + [f"- {x}" for x in r["limitations"]]
    return "\n".join(L) + "\n"


def render_html(r: dict) -> str:
    md = html.escape(render_markdown(r))
    return ("<!doctype html><html><head><meta charset='utf-8'><title>Incident report</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem}"
            "pre{white-space:pre-wrap;line-height:1.5}</style></head><body><pre>" + md + "</pre></body></html>")
