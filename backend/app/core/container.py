"""Lazily-built singletons: queue, event store, rule registry. Tests may call set_backends()."""
from __future__ import annotations

import logging
import threading
from pathlib import Path

from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import get_session_factory
from app.domain.memory_backends import MemoryEventStore, MemoryQueue
from app.domain.rule_loader import load_correlation_config, load_rule_files
from app.domain.rules import RuleEngine, RuleError, parse_rule

log = logging.getLogger("sentinelx.container")
_lock = threading.Lock()
_queue = None
_store = None
_registry = None


def get_queue():
    global _queue
    with _lock:
        if _queue is None:
            s = get_settings()
            if s.queue_backend == "memory":
                _queue = MemoryQueue()
            else:
                from app.infra.redis_queue import RedisQueue
                _queue = RedisQueue(s.redis_url)
        return _queue


def get_store():
    global _store
    with _lock:
        if _store is None:
            s = get_settings()
            if s.store_backend == "memory":
                _store = MemoryEventStore()
            elif s.store_backend == "sqlite":
                from app.infra.sqlite_store import SqliteEventStore
                _store = SqliteEventStore(s.events_db_path)
            else:
                from app.infra.opensearch_store import OpenSearchStore
                _store = OpenSearchStore(s.opensearch_url)
        return _store


def set_backends(queue=None, store=None) -> None:
    global _queue, _store
    with _lock:
        _queue, _store = queue, store


class RuleRegistry:
    """Holds the live RuleEngine; reloads enabled rules from the database."""

    def __init__(self) -> None:
        self.engine = RuleEngine()
        self.correlation_window, self.correlation_rules = load_correlation_config(Path(get_settings().rules_dir))
        self.lock = threading.Lock()

    def reload(self) -> int:
        from app.models import DetectionRule
        rules = []
        with get_session_factory()() as db:
            for row in db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))):
                try:
                    rule = parse_rule(row.definition)
                    rule.org_id = str(row.org_id) if row.org_id else ""
                    rules.append(rule)
                except RuleError:
                    log.exception("skipping invalid stored rule", extra={"rule": row.rule_key})
        with self.lock:
            self.engine.set_rules(rules)
        return len(rules)


def get_registry() -> RuleRegistry:
    global _registry
    with _lock:
        if _registry is None:
            _registry = RuleRegistry()
        return _registry


def reset_registry() -> None:
    global _registry
    with _lock:
        _registry = None
