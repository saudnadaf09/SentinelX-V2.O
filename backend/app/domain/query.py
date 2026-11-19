"""Validated event-search query model shared by all event stores."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

ALLOWED_FIELDS = {
    "host.name", "user.name", "source.ip", "destination.ip", "destination.port", "process.name",
    "process.executable", "process.command_line", "event.action", "event.category", "event.dataset",
    "event.outcome", "event.code", "file.path", "group.name", "rule.name", "network.transport",
    "observer.product",
}
ALLOWED_OPS = {"eq", "ne", "contains", "prefix"}
MAX_FILTERS = 10
MAX_VALUE_LEN = 256
MAX_PAGE_SIZE = 100
MAX_WINDOW = 10_000  # OpenSearch index.max_result_window default
MAX_RANGE = timedelta(days=31)
TEXT_FIELDS = ["process.command_line", "process.name", "user.name", "host.name", "message",
               "event.action", "source.ip", "destination.ip", "file.path"]


class QueryError(ValueError):
    pass


@dataclass(frozen=True)
class Filter:
    field: str
    op: str
    value: str


@dataclass
class EventQuery:
    start: datetime
    end: datetime
    filters: list[Filter] = field(default_factory=list)
    text: str | None = None
    page: int = 1
    size: int = 50
    sort_desc: bool = True
    org_id: str = ""  # REQUIRED: set by the server from the authenticated user, never from the client

    def validate(self) -> "EventQuery":
        if not self.org_id:
            raise QueryError("organization scope is required")
        if self.end <= self.start:
            raise QueryError("end must be after start")
        if self.end - self.start > MAX_RANGE:
            raise QueryError("time range may not exceed 31 days")
        if len(self.filters) > MAX_FILTERS:
            raise QueryError(f"at most {MAX_FILTERS} filters")
        for f in self.filters:
            if f.field not in ALLOWED_FIELDS:
                raise QueryError(f"field not searchable: {f.field}")
            if f.op not in ALLOWED_OPS:
                raise QueryError(f"operator not allowed: {f.op}")
            if not f.value or len(f.value) > MAX_VALUE_LEN:
                raise QueryError("filter value must be 1-256 characters")
        if self.text is not None and len(self.text) > 200:
            raise QueryError("text search limited to 200 characters")
        if not 1 <= self.size <= MAX_PAGE_SIZE:
            raise QueryError(f"size must be 1..{MAX_PAGE_SIZE}")
        if self.page < 1 or self.page * self.size > MAX_WINDOW:
            raise QueryError(f"page*size may not exceed {MAX_WINDOW}")
        return self
