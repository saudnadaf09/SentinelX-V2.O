from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy.orm import Session

from app.api.deps import get_collector, request_id
from app.core.config import get_settings
from app.core.container import get_queue, get_registry, get_store
from app.db.session import get_db
from app.schemas.ingest import BatchIn, BatchOut
from app.services.ingest_service import ingest_batch
from app.workers.pipeline import Pipeline

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("/events/batch", response_model=BatchOut)
def ingest(body: BatchIn, request: Request, collector=Depends(get_collector), db: Session = Depends(get_db),
           idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=80)):
    key, asset = collector
    max_events = get_settings().max_batch_events
    events = body.events[:max_events] if len(body.events) <= max_events else None
    if events is None:
        from app.core.errors import AppError
        raise AppError(f"batch too large (max {max_events} events)")
    queue = get_queue()
    result = ingest_batch(db, queue=queue, asset=asset, key=key, events=events,
                          idempotency_key=idempotency_key, request_id=request_id(request))
    if queue.kind == "memory":  # Docker-free mode: process inline, no separate worker
        Pipeline(queue, get_store(), get_registry()).drain()
    return result
