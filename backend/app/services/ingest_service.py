"""Validate envelopes, publish accepted events to the queue, track collector health."""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import ApiKey, Asset
from app.schemas.ingest import EnvelopeIn


def ingest_batch(db: Session, *, queue, asset: Asset, key: ApiKey | None, events: list[dict],
                 idempotency_key: str | None, request_id: str) -> dict:
    if idempotency_key and queue.seen_idempotency(f"{asset.id}:{idempotency_key}"):
        return {"request_id": request_id, "accepted": 0, "rejected": 0, "duplicate_batch": True, "errors": []}

    accepted: list[dict] = []
    errors: list[dict] = []
    received_at = datetime.now(timezone.utc).isoformat()
    for idx, item in enumerate(events):
        try:
            env = EnvelopeIn.model_validate(item)
        except ValidationError as exc:  # report location + message only; never echo input values
            errors.append({"index": idx, "reason": "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:3])})
            continue
        accepted.append({"collector_id": f"{asset.id.hex[:8]}-{asset.hostname.lower()}", "asset_id": str(asset.id),
                         "org_id": str(asset.org_id), "data_class": asset.data_class or "live",
                         "host_name": asset.hostname, "envelope": env.model_dump(mode="json"),
                         "received_at": received_at, "request_id": request_id})
    if accepted:
        queue.publish(accepted)
    queue.incr("received", len(events))
    if errors:
        queue.incr("rejected", len(errors))

    now = utcnow()
    asset.last_seen_at = now
    asset.events_received = (asset.events_received or 0) + len(accepted)
    if key:
        key.last_used_at = now
    db.commit()
    return {"request_id": request_id, "accepted": len(accepted), "rejected": len(errors),
            "duplicate_batch": False, "errors": errors[:20]}
