"""Redis Streams queue with consumer groups, stale-message recovery, retries and a dead-letter stream."""
from __future__ import annotations

import json
import logging
import time

import redis

log = logging.getLogger("sentinelx.queue")
STREAM = "sx:events"
GROUP = "sx-workers"
DEAD = "sx:events:dead"
STATS = "sx:stats"
IDEM = "sx:idem:"
MAXLEN = 200_000  # safety cap; unconsumed backlog beyond this would be trimmed


class RedisQueue:
    kind = "redis"

    def __init__(self, url: str):
        self.r = redis.Redis.from_url(url, decode_responses=True, socket_timeout=10, socket_connect_timeout=5)

    def ensure_ready(self, retries: int = 30) -> None:
        for attempt in range(retries):
            try:
                self.r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
                return
            except redis.ResponseError as exc:
                if "BUSYGROUP" in str(exc):
                    return
                raise
            except redis.ConnectionError:
                log.warning("redis not ready, retrying", extra={"attempt": attempt})
                time.sleep(2)
        raise RuntimeError("redis unavailable")

    def ping(self) -> bool:
        try:
            return bool(self.r.ping())
        except redis.RedisError:
            return False

    def incr(self, stat: str, n: int = 1) -> None:
        self.r.hincrby(STATS, stat, n)

    def publish(self, items: list[dict]) -> int:
        pipe = self.r.pipeline()
        for it in items:
            pipe.xadd(STREAM, {"data": json.dumps(it)}, maxlen=MAXLEN, approximate=True)
        pipe.hincrby(STATS, "queued", len(items))
        pipe.execute()
        return len(items)

    @staticmethod
    def _decode(entries) -> list[tuple[str, dict]]:
        out = []
        for mid, fields in entries:
            try:
                out.append((mid, json.loads(fields["data"])))
            except (KeyError, ValueError):
                out.append((mid, {"_corrupt": True}))
        return out

    def consume(self, consumer: str, count: int = 50, block_ms: int = 1000) -> list[tuple[str, dict]]:
        # Own pending entries first (crash recovery for the same consumer name), then new ones.
        res = self.r.xreadgroup(GROUP, consumer, {STREAM: "0"}, count=count)
        entries = res[0][1] if res else []
        if entries:
            return self._decode(entries)
        res = self.r.xreadgroup(GROUP, consumer, {STREAM: ">"}, count=count, block=block_ms)
        return self._decode(res[0][1]) if res else []

    def reclaim_stale(self, consumer: str, min_idle_ms: int = 60000) -> list[tuple[str, dict]]:
        """Take over messages stuck with dead consumers."""
        res = self.r.xautoclaim(STREAM, GROUP, consumer, min_idle_time=min_idle_ms, start_id="0-0", count=50)
        return self._decode(res[1]) if res and len(res) > 1 else []

    def ack(self, msg_id: str) -> None:
        pipe = self.r.pipeline()
        pipe.xack(STREAM, GROUP, msg_id)
        pipe.xdel(STREAM, msg_id)
        pipe.execute()

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
        pipe = self.r.pipeline()
        pipe.xadd(DEAD, {"data": json.dumps({"payload": payload, "reason": reason[:500],
                                              "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})},
                  maxlen=50_000, approximate=True)
        pipe.hincrby(STATS, "dead_letter", 1)
        pipe.execute()

    def dead_letters(self, limit: int = 50) -> list[dict]:
        return [json.loads(f["data"]) for _, f in self.r.xrevrange(DEAD, count=limit)]

    def requeue_dead_letters(self) -> int:
        entries = self.r.xrange(DEAD)
        items = []
        for mid, f in entries:
            try:
                items.append({**json.loads(f["data"])["payload"], "_attempt": 0})
            except (KeyError, ValueError):
                continue
        if items:
            self.publish(items)
        if entries:
            self.r.xdel(DEAD, *[m for m, _ in entries])
        return len(items)

    def seen_idempotency(self, key: str, ttl_seconds: int = 3600) -> bool:
        return not self.r.set(IDEM + key, "1", nx=True, ex=ttl_seconds)

    def stats(self) -> dict:
        raw = self.r.hgetall(STATS)
        keys = ("received", "rejected", "queued", "processed", "duplicates", "failed", "dead_letter", "quarantined")
        out = {k: int(raw.get(k, 0)) for k in keys}
        try:
            pending = self.r.xpending(STREAM, GROUP)
            out["pending"] = int(pending["pending"]) if isinstance(pending, dict) else int(pending[0])
        except redis.RedisError:
            out["pending"] = 0
        out["depth"] = int(self.r.xlen(STREAM))
        out["dead_letter_depth"] = int(self.r.xlen(DEAD))
        return out
