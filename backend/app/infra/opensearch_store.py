"""OpenSearch-backed event store: daily indices, explicit mappings, bounded queries."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from opensearchpy import OpenSearch
from opensearchpy.exceptions import ConflictError, NotFoundError, OpenSearchException

from app.domain.query import TEXT_FIELDS, EventQuery
from app.domain.tenancy import DEFAULT_ORG_ID

log = logging.getLogger("sentinelx.store")
PREFIX = "sentinelx-events-"
PATTERN = PREFIX + "*"
TEMPLATE = "sentinelx-events"

_KW = {"type": "keyword"}
MAPPING = {
    "dynamic": False,
    "properties": {
        "@timestamp": {"type": "date"},
        "message": _KW,
        "event": {"properties": {"id": _KW, "original_id": _KW, "category": _KW, "type": _KW, "action": _KW,
                                 "code": _KW, "outcome": _KW, "dataset": _KW, "ingested": {"type": "date"},
                                 "schema_version": _KW, "data_class": _KW}},
        "host": {"properties": {"id": _KW, "name": _KW, "os": _KW}},
        "collector": {"properties": {"id": _KW, "type": _KW}},
        "org": {"properties": {"id": _KW}},
        "user": {"properties": {"name": _KW, "domain": _KW, "target": {"properties": {"name": _KW}}}},
        "process": {"properties": {"pid": {"type": "long"}, "name": _KW, "executable": _KW, "command_line": _KW,
                                   "entity_id": _KW, "hash": _KW,
                                   "parent": {"properties": {"name": _KW, "executable": _KW, "command_line": _KW}}}},
        "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
        "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}, "domain": _KW}},
        "network": {"properties": {"transport": _KW, "direction": _KW, "logon_type": _KW}},
        "file": {"properties": {"path": _KW}},
        "group": {"properties": {"name": _KW}},
        "rule": {"properties": {"id": _KW, "name": _KW}},
        "observer": {"properties": {"product": _KW}},
        "labels": {"type": "object", "dynamic": True},
        "raw": {"type": "object", "enabled": False},
    },
}
_IP_FIELDS = {"source.ip", "destination.ip"}
_NUM_FIELDS = {"destination.port"}


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _org_clause(org_id: str) -> dict:
    """Tenant filter. Pre-multi-tenancy documents have no org.id and belong to the default org."""
    if not org_id:
        raise ValueError("organization scope is required")
    if org_id == DEFAULT_ORG_ID:
        return {"bool": {"should": [{"term": {"org.id": org_id}},
                                    {"bool": {"must_not": {"exists": {"field": "org.id"}}}}], "minimum_should_match": 1}}
    return {"term": {"org.id": org_id}}


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


class OpenSearchStore:
    kind = "opensearch"

    def __init__(self, url: str):
        self.client = OpenSearch(hosts=[url], timeout=15, max_retries=2, retry_on_timeout=True)

    def ensure_ready(self, retries: int = 60) -> None:
        for attempt in range(retries):
            try:
                self.client.indices.put_index_template(name=TEMPLATE, body={
                    "index_patterns": [PATTERN], "priority": 100,
                    "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
                                 "mappings": MAPPING}})
                try:  # make today's pre-upgrade index understand the new org.id field
                    self.client.indices.put_mapping(index=PATTERN, body={"properties": {"org": MAPPING["properties"]["org"]}},
                                                    params={"ignore_unavailable": "true", "allow_no_indices": "true"})
                except OpenSearchException:
                    log.warning("could not update existing index mappings")
                return
            except OpenSearchException:
                log.warning("opensearch not ready, retrying", extra={"attempt": attempt})
                time.sleep(3)
        raise RuntimeError("opensearch unavailable")

    def ping(self) -> bool:
        try:
            return self.client.cluster.health(params={"timeout": "3s"}).get("status") in ("green", "yellow")
        except OpenSearchException:
            return False

    def index(self, doc: dict) -> bool:
        ts = datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))
        try:
            self.client.index(index=f"{PREFIX}{ts:%Y.%m.%d}", id=doc["event"]["id"], body=doc, op_type="create")
            return True
        except ConflictError:
            return False

    def exists(self, doc: dict) -> bool:
        """Realtime (refresh-independent) duplicate check using the known daily index."""
        ts = datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))
        try:
            return bool(self.client.exists(index=f"{PREFIX}{ts:%Y.%m.%d}", id=doc["event"]["id"]))
        except OpenSearchException:
            return False

    def get(self, event_id: str) -> dict | None:
        res = self.client.search(index=PATTERN, ignore_unavailable=True, allow_no_indices=True,
                                 body={"size": 1, "query": {"ids": {"values": [event_id]}}})
        hits = res["hits"]["hits"]
        return hits[0]["_source"] if hits else None

    def _query(self, q: EventQuery) -> dict:
        must: list[dict] = [_org_clause(q.org_id), {"range": {"@timestamp": {"gte": _ts(q.start), "lt": _ts(q.end)}}}]
        must_not: list[dict] = []
        for f in q.filters:
            if f.op in ("eq", "ne"):
                if f.field in _IP_FIELDS or f.field in _NUM_FIELDS:
                    clause = {"term": {f.field: f.value}}
                else:
                    clause = {"term": {f.field: {"value": f.value, "case_insensitive": True}}}
            elif f.op == "prefix":
                clause = {"prefix": {f.field: {"value": f.value, "case_insensitive": True}}}
            else:  # contains
                clause = {"wildcard": {f.field: {"value": f"*{_esc(f.value)}*", "case_insensitive": True}}}
            (must_not if f.op == "ne" else must).append(clause)
        if q.text:
            should = [{"wildcard": {p: {"value": f"*{_esc(q.text)}*", "case_insensitive": True}}}
                      for p in TEXT_FIELDS if p not in _IP_FIELDS]
            should += [{"term": {p: q.text}} for p in _IP_FIELDS if _looks_like_ip(q.text)]
            must.append({"bool": {"should": should, "minimum_should_match": 1}})
        return {"bool": {"filter": must, "must_not": must_not}}

    def search(self, q: EventQuery) -> tuple[int, list[dict]]:
        q.validate()
        body = {"query": self._query(q), "from": (q.page - 1) * q.size, "size": q.size,
                "sort": [{"@timestamp": "desc" if q.sort_desc else "asc"}], "track_total_hits": 10000,
                "_source": {"excludes": []}}
        res = self.client.search(index=PATTERN, body=body, ignore_unavailable=True, allow_no_indices=True,
                                 params={"request_timeout": 15})
        total = res["hits"]["total"]["value"]
        return total, [h["_source"] for h in res["hits"]["hits"]]

    def aggregate(self, start: datetime, end: datetime, interval_minutes: int, org_id: str) -> dict:
        body = {"size": 0, "track_total_hits": True,
                "query": {"bool": {"filter": [_org_clause(org_id),
                                              {"range": {"@timestamp": {"gte": _ts(start), "lt": _ts(end)}}}]}},
                "aggs": {"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": f"{interval_minutes}m",
                                                  "min_doc_count": 0, "extended_bounds": {"min": _ts(start), "max": _ts(end)}}},
                         "hosts": {"terms": {"field": "host.name", "size": 5}},
                         "cats": {"terms": {"field": "event.category", "size": 10}},
                         "classes": {"terms": {"field": "event.data_class", "size": 5, "missing": "unclassified"}}}}
        res = self.client.search(index=PATTERN, body=body, ignore_unavailable=True, allow_no_indices=True)
        a = res.get("aggregations", {})
        return {
            "total": res["hits"]["total"]["value"],
            "timeline": [{"time": b["key_as_string"], "count": b["doc_count"]} for b in a.get("t", {}).get("buckets", [])],
            "top_hosts": [{"host": b["key"], "count": b["doc_count"]} for b in a.get("hosts", {}).get("buckets", [])],
            "categories": [{"category": b["key"], "count": b["doc_count"]} for b in a.get("cats", {}).get("buckets", [])],
            "classes": {b["key"]: b["doc_count"] for b in a.get("classes", {}).get("buckets", [])},
        }

    def delete_older_than(self, days: int, org_id: str | None = None) -> int:
        now = datetime.now(timezone.utc)
        if org_id:  # per-organization retention: delete matching documents inside daily indices
            res = self.client.delete_by_query(index=PATTERN, ignore_unavailable=True, allow_no_indices=True, body={
                "query": {"bool": {"filter": [_org_clause(org_id),
                                              {"range": {"@timestamp": {"lt": _ts(now - timedelta(days=days))}}}]}}})
            return int(res.get("deleted", 0))
        cutoff = (now - timedelta(days=days)).date()
        deleted = 0
        try:
            names = list(self.client.indices.get(index=PATTERN).keys())
        except NotFoundError:
            return 0
        for name in names:
            try:
                day = datetime.strptime(name[len(PREFIX):], "%Y.%m.%d").date()
            except ValueError:
                continue
            if day < cutoff:
                self.client.indices.delete(index=name)
                deleted += 1
        return deleted

    def delete_org(self, org_id: str) -> int:
        res = self.client.delete_by_query(index=PATTERN, ignore_unavailable=True, allow_no_indices=True,
                                          body={"query": {"bool": {"filter": [_org_clause(org_id)]}}})
        return int(res.get("deleted", 0))


def _looks_like_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False
