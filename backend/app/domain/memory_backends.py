"""In-memory queue and event store: used for tests and the Docker-free 'lite' mode.

Data is lost on restart and the in-memory queue is process-local, so lite mode
runs the pipeline inline inside the API process.
"""
from __future__ import annotations

import threading
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone

from .fields import get_field
from .query import TEXT_FIELDS, EventQuery
from .tenancy import doc_org

STAT_KEYS = ("received", "rejected", "queued", "processed", "duplicates", "failed", "dead_letter", "quarantined")


class MemoryQueue:
    kind = "memory"

    def __init__(self) -> None:
        self._q: deque[tuple[str, dict]] = deque()
        self._pending: dict[str, dict] = {}
        self._dead: list[dict] = []
        self._stats = {k: 0 for k in STAT_KEYS}
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def ensure_ready(self) -> None: ...

    def ping(self) -> bool:
        return True

    def incr(self, stat: str, n: int = 1) -> None:
        with self._lock:
            self._stats[stat] = self._stats.get(stat, 0) + n

    def publish(self, items: list[dict]) -> int:
        with self._lock:
            for it in items:
                self._q.append((uuid.uuid4().hex, it))
            self._stats["queued"] += len(items)
        return len(items)

    def consume(self, consumer: str, count: int = 50, block_ms: int = 0) -> list[tuple[str, dict]]:
        with self._lock:
            out = []
            while self._q and len(out) < count:
                mid, payload = self._q.popleft()
                self._pending[mid] = payload
                out.append((mid, payload))
            return out

    def reclaim_stale(self, consumer: str, min_idle_ms: int = 60000) -> list[tuple[str, dict]]:
        return []

    def ack(self, msg_id: str) -> None:
        with self._lock:
            self._pending.pop(msg_id, None)

    def retry_or_dead_letter(self, msg_id: str, payload: dict, reason: str, max_attempts: int = 3) -> str:
        attempt = int(payload.get("_attempt", 0)) + 1
        self.ack(msg_id)
        if attempt >= max_attempts:
            self.dead_letter(payload, reason)
            return "dead_letter"
        self.publish([{**payload, "_attempt": attempt}])
        self.incr("failed")
        return "retry"

    def dead_letter(self, payload: dict, reason: str) -> None:
        with self._lock:
            self._dead.append({"payload": payload, "reason": reason[:500],
                               "at": datetime.now(timezone.utc).isoformat()})
            self._stats["dead_letter"] += 1

    def dead_letters(self, limit: int = 50) -> list[dict]:
        return list(self._dead[-limit:])

    def requeue_dead_letters(self) -> int:
        with self._lock:
            items, self._dead = self._dead, []
        self.publish([{**i["payload"], "_attempt": 0} for i in items])
        return len(items)

    def seen_idempotency(self, key: str, ttl_seconds: int = 3600) -> bool:
        with self._lock:
            if key in self._seen:
                return True
            self._seen.add(key)
            return False

    def stats(self) -> dict:
        with self._lock:
            return {**self._stats, "depth": len(self._q), "pending": len(self._pending),
                    "dead_letter_depth": len(self._dead)}


def _match_filter(doc: dict, f) -> bool:
    v = get_field(doc, f.field)
    items = v if isinstance(v, list) else [v]
    items = [str(i).lower() for i in items if i is not None]
    needle = f.value.lower()
    if f.op == "eq":
        return needle in items
    if f.op == "ne":
        return needle not in items
    if f.op == "contains":
        return any(needle in i for i in items)
    return any(i.startswith(needle) for i in items)  # prefix


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def filter_docs(docs: list[dict], q: EventQuery) -> tuple[int, list[dict]]:
    """Shared search semantics for the memory and SQLite stores."""
    q.validate()
    hits = []
    for d in docs:
        if doc_org(d) != q.org_id:  # tenant boundary
            continue
        ts = _parse(d["@timestamp"])
        if not (q.start <= ts < q.end):
            continue
        if not all(_match_filter(d, f) for f in q.filters):
            continue
        if q.text:
            needle = q.text.lower()
            if not any(needle in str(get_field(d, p) or "").lower() for p in TEXT_FIELDS):
                continue
        hits.append(d)
    hits.sort(key=lambda d: d["@timestamp"], reverse=q.sort_desc)
    off = (q.page - 1) * q.size
    return len(hits), hits[off: off + q.size]


def aggregate_docs(docs: list[dict], start: datetime, end: datetime, interval_minutes: int, org_id: str) -> dict:
    if not org_id:
        raise ValueError("organization scope is required")
    docs = [d for d in docs if doc_org(d) == org_id and start <= _parse(d["@timestamp"]) < end]
    step = interval_minutes * 60
    buckets: dict[int, int] = {}
    hosts: dict[str, int] = {}
    cats: dict[str, int] = {}
    classes: dict[str, int] = {}
    for d in docs:
        c = get_field(d, "event.data_class") or "unclassified"
        classes[c] = classes.get(c, 0) + 1
        b = int(_parse(d["@timestamp"]).timestamp() // step) * step
        buckets[b] = buckets.get(b, 0) + 1
        h = get_field(d, "host.name")
        if h:
            hosts[h] = hosts.get(h, 0) + 1
        for c in (get_field(d, "event.category") or []):
            cats[c] = cats.get(c, 0) + 1
    return {
        "total": len(docs),
        "timeline": [{"time": datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z"), "count": n}
                     for t, n in sorted(buckets.items())],
        "top_hosts": [{"host": k, "count": v} for k, v in sorted(hosts.items(), key=lambda x: -x[1])[:5]],
        "categories": [{"category": k, "count": v} for k, v in sorted(cats.items(), key=lambda x: -x[1])],
        "classes": classes,
    }


class MemoryEventStore:
    kind = "memory"

    def __init__(self) -> None:
        self._docs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def ensure_ready(self) -> None: ...

    def ping(self) -> bool:
        return True

    def index(self, doc: dict) -> bool:
        """True if newly stored, False if a duplicate event.id already exists."""
        eid = doc["event"]["id"]
        with self._lock:
            if eid in self._docs:
                return False
            self._docs[eid] = doc
            return True

    def exists(self, doc: dict) -> bool:
        return doc["event"]["id"] in self._docs

    def get(self, event_id: str) -> dict | None:
        return self._docs.get(event_id)

    def search(self, q: EventQuery) -> tuple[int, list[dict]]:
        with self._lock:
            docs = list(self._docs.values())
        return filter_docs(docs, q)

    def aggregate(self, start: datetime, end: datetime, interval_minutes: int, org_id: str) -> dict:
        with self._lock:
            docs = list(self._docs.values())
        return aggregate_docs(docs, start, end, interval_minutes, org_id)

    def delete_older_than(self, days: int, org_id: str | None = None) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self._lock:
            old = [k for k, d in self._docs.items() if _parse(d["@timestamp"]) < cutoff
                   and (org_id is None or doc_org(d) == org_id)]
            for k in old:
                del self._docs[k]
        return len(old)

    def delete_org(self, org_id: str) -> int:
        with self._lock:
            mine = [k for k, d in self._docs.items() if doc_org(d) == org_id]
            for k in mine:
                del self._docs[k]
        return len(mine)
