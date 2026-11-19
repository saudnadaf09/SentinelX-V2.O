"""Compact, bounded snapshots of events kept with alerts as evidence.

Snapshots survive index retention, so an alert stays explainable after the
raw events have been deleted.
"""
from __future__ import annotations

from .fields import get_field

_SNAPSHOT_FIELDS = (
    "event.action", "event.dataset", "event.outcome", "host.name", "user.name",
    "source.ip", "source.port", "destination.ip", "destination.port",
    "process.name", "process.executable", "process.command_line",
    "process.parent.name", "group.name", "user.target.name", "message",
)


def compact_event(event: dict) -> dict:
    snap: dict = {
        "event_id": get_field(event, "event.id"),
        "timestamp": event.get("@timestamp"),
    }
    for path in _SNAPSHOT_FIELDS:
        value = get_field(event, path)
        if value not in (None, ""):
            snap[path] = value[:512] if isinstance(value, str) else value
    return snap
