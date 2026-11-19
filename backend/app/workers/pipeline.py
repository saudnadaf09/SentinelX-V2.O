"""Event pipeline: queue -> normalize -> dedupe -> detect -> alerts (DB) -> index (store).

Ordering gives at-least-once safety: alerts are committed before the event is indexed,
the engine is idempotent per event id, and alert upserts ignore already-seen events.
A failure leaves the event un-indexed so a retry re-runs the whole path. After
3 attempts the payload moves to the dead-letter stream (never silently dropped).
"""
from __future__ import annotations

import logging
import threading
import uuid
import time
from datetime import datetime, timezone

from app.core.config import get_settings
from app.db.session import get_session_factory
from app.domain.tenancy import DEFAULT_ORG_ID
from app.domain.normalizer import NormalizationError, normalize, parse_timestamp
from sqlalchemy import select

from app.models import OrgRuleOverride
from app.services import alert_service

log = logging.getLogger("sentinelx.pipeline")
_inline_lock = threading.Lock()


class Pipeline:
    def __init__(self, queue, store, registry, session_factory=None):
        self.queue, self.store, self.registry = queue, store, registry
        self.session_factory = session_factory or get_session_factory()

    def process_payload(self, payload: dict) -> str:
        if payload.get("_corrupt"):
            raise NormalizationError("corrupt queue message")
        doc = normalize(payload["envelope"], collector_id=payload["collector_id"], host_id=payload.get("asset_id"),
                        host_name=payload["host_name"], ingested_at=parse_timestamp(payload["received_at"]),
                        org_id=payload.get("org_id") or DEFAULT_ORG_ID, data_class=payload.get("data_class") or "live")
        if self.store.exists(doc):
            return "duplicates"
        with self.registry.lock:
            detections = self.registry.engine.evaluate(doc)
        if detections:
            with self.session_factory() as db:
                disabled = {o.rule_key for o in db.scalars(select(OrgRuleOverride).where(
                    OrgRuleOverride.org_id == uuid.UUID(doc["org"]["id"]), OrgRuleOverride.enabled.is_(False)))}
                for det in detections:
                    if det.rule_key in disabled:  # this organization switched the rule off
                        continue
                    alert_service.record_detection(db, det, self.registry.correlation_window,
                                                   self.registry.correlation_rules,
                                                   data_class=(doc.get("event") or {}).get("data_class", "live"))
                db.commit()
        self.store.index(doc)
        return "processed"

    def handle(self, msg_id: str, payload: dict) -> None:
        try:
            self.queue.incr(self.process_payload(payload))
            self.queue.ack(msg_id)
        except NormalizationError as exc:
            self.queue.ack(msg_id)
            self.queue.dead_letter(payload, f"quarantined: {exc}")
            self.queue.incr("quarantined")
        except Exception as exc:  # noqa: BLE001 - infrastructure failure: retry then dead-letter
            log.exception("event processing failed")
            outcome = self.queue.retry_or_dead_letter(msg_id, payload, f"{type(exc).__name__}: {exc}")
            if outcome == "retry":
                time.sleep(min(2 ** int(payload.get("_attempt", 0)), 5))

    def run_once(self, consumer: str, count: int = 50, block_ms: int = 1000) -> int:
        batch = self.queue.consume(consumer, count=count, block_ms=block_ms)
        for msg_id, payload in batch:
            self.handle(msg_id, payload)
        return len(batch)

    def drain(self, consumer: str = "inline") -> int:
        """Process everything currently queued (used by the Docker-free in-memory mode)."""
        total = 0
        with _inline_lock:
            while True:
                n = self.run_once(consumer, block_ms=0)
                if not n:
                    return total
                total += n

    def run_forever(self, consumer: str, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        last_reload = last_reclaim = last_retention = 0.0
        self.registry.reload()
        log.info("pipeline worker started", extra={"consumer": consumer})
        while not stop.is_set():
            now = time.monotonic()
            try:
                if now - last_reload > 30:
                    self.registry.reload()
                    last_reload = now
                if now - last_reclaim > 30:
                    for msg_id, payload in self.queue.reclaim_stale(consumer):
                        self.handle(msg_id, payload)
                    last_reclaim = now
                if now - last_retention > 3600:
                    removed = self.store.delete_older_than(get_settings().event_retention_days)
                    if removed:
                        log.info("retention removed indices", extra={"count": removed})
                    last_retention = now
                self.run_once(consumer)
            except Exception:  # noqa: BLE001 - keep the worker alive through infra hiccups
                log.exception("worker loop error")
                time.sleep(2)
