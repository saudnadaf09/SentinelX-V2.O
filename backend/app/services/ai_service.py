"""AI investigation: per-organization provider settings (encrypted keys), connection tests, grounded analysis.

Nothing here ever fabricates output. If no provider is configured the investigation is refused (HTTP 503),
and any provider failure is returned as an error - never replaced by a canned analysis.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError, NotFound
from app.db.base import utcnow
from app.domain import ai_analysis as ai
from app.domain import ai_providers as prov
from app.domain import secrets_util as su
from app.domain.query import EventQuery, Filter
from app.models import AiSetting, Alert, Incident, IncidentNote, Investigation, User
from app.services import audit

log = logging.getLogger("sentinelx.ai")
DISCLAIMER = ("AI-generated analysis. Treat 'hypotheses' as unverified until confirmed against the cited evidence; "
              "it cannot change detection verdicts or execute any action.")


class AiUnavailable(AppError):
    status, code = 503, "ai_unavailable"


class AiProviderFailure(AppError):
    status, code = 502, "ai_provider_error"


def catalog() -> list[dict]:
    return [{"id": k, "label": v["label"], "default_model": v["default_model"], "models": v["models"]} for k, v in prov.PROVIDERS.items()]


def resolve_config(db: Session, s: Settings, org_id) -> dict | None:
    """Organization settings win; otherwise the platform default from environment variables (if any)."""
    row = db.get(AiSetting, org_id)
    if row and row.enabled and row.api_key_enc:
        return {"provider": row.provider, "model": row.model, "api_key": su.decrypt(s.secret_key, row.api_key_enc),
                "base_url": None, "source": "organization"}
    if s.ai_provider in prov.PROVIDERS and s.ai_api_key:
        return {"provider": s.ai_provider, "model": s.ai_model, "api_key": s.ai_api_key, "base_url": s.ai_base_url or None, "source": "platform"}
    if s.ai_provider == "openai_compatible" and s.ai_base_url:
        return {"provider": "openai_compatible", "model": s.ai_model, "api_key": s.ai_api_key, "base_url": s.ai_base_url, "source": "platform"}
    return None


def status(db: Session, s: Settings, org_id) -> dict:
    """Honest status: 'connected' only if the LAST real test succeeded; nothing is assumed."""
    row = db.get(AiSetting, org_id)
    cfg = None
    try:
        cfg = resolve_config(db, s, org_id)
    except ValueError:
        return {"configured": False, "state": "error", "message": "Stored key cannot be decrypted (SECRET_KEY changed). Re-enter the API key."}
    if cfg is None:
        return {"configured": False, "state": "unavailable", "message": "No AI provider is configured. AI features are unavailable."}
    out = {"configured": True, "provider": cfg["provider"], "model": cfg["model"], "source": cfg["source"],
           "key_hint": row.key_hint if row and cfg["source"] == "organization" else None}
    if cfg["source"] == "organization" and row.last_test_at:
        out.update(state="connected" if row.last_test_ok else "error", last_test_at=row.last_test_at, message=row.last_test_message)
    else:
        out.update(state="untested", message="Configured but not tested yet. Use Test connection.")
    return out


def save_settings(db: Session, s: Settings, actor: User, *, provider: str, model: str, api_key: str | None, enabled: bool,
                  request_id: str = "") -> AiSetting:
    if provider not in prov.PROVIDERS:
        raise AppError(f"provider must be one of {list(prov.PROVIDERS)}")
    if not re.match(prov.MODEL_PATTERN, model or ""):
        raise AppError("invalid model name")
    row = db.get(AiSetting, actor.org_id)
    if row is None:
        if not api_key:
            raise AppError("an API key is required the first time")
        row = AiSetting(org_id=actor.org_id, provider=provider, model=model)
        db.add(row)
    changed_key = bool(api_key)
    if api_key:
        if len(api_key) < 8 or len(api_key) > 500 or any(c.isspace() for c in api_key):
            raise AppError("API key format looks invalid")
        row.api_key_enc = su.encrypt(s.secret_key, api_key)
        row.key_hint = su.key_hint(api_key)
    if (row.provider, row.model) != (provider, model) or changed_key:
        row.last_test_at, row.last_test_ok, row.last_test_message = None, None, ""  # old test result no longer applies
    row.provider, row.model, row.enabled, row.updated_by = provider, model, enabled, actor.id
    db.flush()
    audit.record(db, actor=actor, action="ai.settings_updated", target_type="ai_settings", target_id=str(actor.org_id),
                 request_id=request_id, details={"provider": provider, "model": model, "enabled": enabled, "key_changed": changed_key})
    return row


def test_settings(db: Session, s: Settings, actor: User, *, candidate: dict | None, request_id: str = "") -> dict:
    """One real API call. A candidate (unsaved) key is used for the call but never stored or returned."""
    row = db.get(AiSetting, actor.org_id)
    if candidate and candidate.get("api_key"):
        provider, model, key = candidate["provider"], candidate["model"], candidate["api_key"]
    else:
        cfg = resolve_config(db, s, actor.org_id)
        if cfg is None:
            raise AiUnavailable("No AI provider is configured")
        provider, model, key = cfg["provider"], cfg["model"], cfg["api_key"]
    base = s.ai_base_url if provider == "openai_compatible" else None
    result = prov.test_connection(provider, key, model, base_url=base, timeout=min(s.ai_timeout_seconds, 20))
    saved_matches = row and (not candidate or not candidate.get("api_key")) and row.provider == provider and row.model == model
    if saved_matches:
        row.last_test_at, row.last_test_ok = utcnow(), result["ok"]
        row.last_test_message = (result["message"] if not result["ok"] else f"Connected ({result['latency_ms']} ms)")[:400]
    audit.record(db, actor=actor, action="ai.connection_tested", target_type="ai_settings", target_id=str(actor.org_id),
                 request_id=request_id, outcome="success" if result["ok"] else "failure",
                 details={"provider": provider, "model": model, "error_kind": result["error_kind"]})
    result.pop("sample", None)
    return result


def clear_settings(db: Session, actor: User, request_id: str = "") -> None:
    row = db.get(AiSetting, actor.org_id)
    if row:
        db.delete(row)
        audit.record(db, actor=actor, action="ai.settings_removed", target_type="ai_settings", target_id=str(actor.org_id), request_id=request_id)


# ------------------------------------------------------------------------------ investigation
def _alert_dict(a: Alert) -> dict:
    return {"id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status, "rule_key": a.rule_key,
            "rule_version": a.rule_version, "explanation": a.explanation, "first_seen": a.first_seen.isoformat(),
            "last_seen": a.last_seen.isoformat(), "event_count": a.event_count, "host_name": a.host_name,
            "user_name": a.user_name, "source_ip": a.source_ip, "correlation_reason": a.correlation_reason,
            "rule_context": a.rule_context, "mitre": a.mitre, "evidence": a.evidence, "data_class": a.data_class}


def build_package(db: Session, store, alert: Alert) -> dict:
    related, incident = [], None
    if alert.incident_id:
        inc = db.get(Incident, alert.incident_id)
        if inc and inc.org_id == alert.org_id:  # tenant check even for internal lookups
            notes = [n.note[:500] for n in db.scalars(select(IncidentNote).where(IncidentNote.incident_id == inc.id).limit(10))]
            incident = {"title": inc.title, "severity": inc.severity, "status": inc.status, "summary": inc.summary, "analyst_notes": notes}
        related = [_alert_dict(r) for r in db.scalars(select(Alert).where(
            Alert.incident_id == alert.incident_id, Alert.org_id == alert.org_id, Alert.id != alert.id).limit(10))]
    host_events = []
    if alert.host_name:
        try:
            q = EventQuery(start=alert.first_seen - timedelta(minutes=15), end=alert.last_seen + timedelta(minutes=15),
                           filters=[Filter("host.name", "eq", alert.host_name)], size=15, org_id=str(alert.org_id))
            from app.domain.evidence import compact_event
            host_events = [compact_event(e) for e in store.search(q)[1]]
        except Exception:  # noqa: BLE001 - extra context is best-effort; the alert evidence is already included
            log.warning("could not load surrounding host events")
    return ai.build_evidence_package(_alert_dict(alert), related, incident=incident, host_events=host_events)


def investigate(db: Session, s: Settings, store, user: User, alert: Alert, request_id: str = "") -> Investigation:
    cfg = resolve_config(db, s, user.org_id)
    if cfg is None:
        raise AiUnavailable("No AI provider is configured for this workspace. Configure one under AI Provider Settings.")
    package = build_package(db, store, alert)
    allowed = {e["event_id"] for e in package["events"] + package["recent_host_events"] if e.get("event_id")}
    try:
        text = prov.call(cfg["provider"], cfg["api_key"], cfg["model"], ai.SYSTEM_PROMPT, ai.build_user_prompt(package),
                         base_url=cfg["base_url"], timeout=s.ai_timeout_seconds)
    except prov.ProviderError as exc:
        audit.record(db, actor=user, action="ai.investigate", target_type="alert", target_id=str(alert.id), outcome="failure",
                     request_id=request_id, details={"provider": cfg["provider"], "error_kind": exc.kind})
        db.commit()
        raise AiProviderFailure(f"AI provider error ({exc.kind}): {exc.message}") from None
    try:
        output, note = ai.validate_output(text, allowed), ""
    except ValueError:  # real model text that is not valid JSON: show it as-is, labelled - never invented
        output = {"summary": text.strip()[:3000], "evidence": [], "assessment": "", "benign_explanations": [], "next_checks": [],
                  "attack_context": "", "limitations": ["The model did not return structured output; its raw text is shown unparsed."]}
        note = "Unstructured model output."
    output.update(ai_generated=True, disclaimer=DISCLAIMER)
    inv = Investigation(alert_id=alert.id, requested_by=user.id, mode="llm", provider=cfg["provider"], model=cfg["model"],
                        prompt_version=ai.PROMPT_VERSION, output=output, note=note)
    db.add(inv)
    db.flush()
    audit.record(db, actor=user, action="ai.investigate", target_type="alert", target_id=str(alert.id), request_id=request_id,
                 details={"provider": cfg["provider"], "model": cfg["model"], "prompt": ai.PROMPT_VERSION, "investigation": str(inv.id)})
    return inv


def rule_summary(db: Session, store, user: User, alert: Alert, request_id: str = "") -> Investigation:
    """Deterministic summary from rule metadata and stored evidence. NOT AI; labelled accordingly."""
    out = ai.deterministic_analysis(build_package(db, store, alert))
    out.update(ai_generated=False, disclaimer="Rule-based summary generated from rule metadata and stored evidence. No AI model was used.")
    inv = Investigation(alert_id=alert.id, requested_by=user.id, mode="rule_based", provider="none", model="",
                        prompt_version="rule-summary-v1", output=out, note="No AI used.")
    db.add(inv)
    db.flush()
    audit.record(db, actor=user, action="alert.rule_summary", target_type="alert", target_id=str(alert.id), request_id=request_id)
    return inv
