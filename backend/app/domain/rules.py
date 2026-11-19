"""Deterministic YAML-driven detection engine.

Rule types
  match      single event matches -> detection (deduped per group/time bucket)
  threshold  >= N matching events (or N distinct values of a field) in a window
  sequence   N events of stage 1 followed by one event of stage 2 in a window

The engine is framework-free and keeps bounded in-memory state. AI never
participates in verdicts.
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from .evidence import compact_event
from .fields import as_list, get_field

log = logging.getLogger("sentinelx.rules")

SEVERITIES = ("informational", "low", "medium", "high", "critical")
RULE_TYPES = ("match", "threshold", "sequence")
MAX_GROUP_EVENTS = 200
MAX_STATE_GROUPS = 50_000
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")

Cond = Callable[[dict], bool]


class RuleError(ValueError):
    """Raised for invalid rule definitions."""


# ----------------------------------------------------------------- conditions
_POSITIVE = {"eq", "in", "contains", "contains_any", "startswith", "endswith", "regex", "gt", "gte", "lt", "lte"}
_NEGATIVE = {"ne": "eq", "not_in": "in"}


def _sv(x: Any) -> str:
    return str(x).lower()


def _compile_leaf(node: dict) -> Cond:
    path = node.get("field")
    op = node.get("op", "eq")
    if not isinstance(path, str) or not path:
        raise RuleError(f"condition needs a 'field': {node}")
    if op == "exists":
        want = bool(node.get("value", True))
        return lambda e: (get_field(e, path) not in (None, "", [])) == want
    negate = op in _NEGATIVE
    base_op = _NEGATIVE.get(op, op)
    if base_op not in _POSITIVE:
        raise RuleError(f"unknown operator {op!r}")
    value = node.get("value")
    if value is None:
        raise RuleError(f"condition on {path!r} needs a 'value'")

    if base_op in ("in", "contains_any"):
        if not isinstance(value, list) or not value:
            raise RuleError(f"{op} on {path!r} needs a non-empty list")
        vals = [_sv(v) for v in value]
        valset = set(vals)
    elif base_op == "regex":
        if len(str(value)) > 500:
            raise RuleError("regex too long (max 500 chars)")
        try:
            pattern = re.compile(str(value), re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"invalid regex for {path!r}: {exc}") from exc
    else:
        val = _sv(value)

    def one(x: Any) -> bool:
        s = _sv(x)
        if base_op == "eq":
            return s == val
        if base_op == "in":
            return s in valset
        if base_op == "contains":
            return val in s
        if base_op == "contains_any":
            return any(v in s for v in vals)
        if base_op == "startswith":
            return s.startswith(val)
        if base_op == "endswith":
            return s.endswith(val)
        if base_op == "regex":
            return pattern.search(str(x)) is not None
        try:
            a, b = float(x), float(value)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[base_op]

    def fn(event: dict) -> bool:
        items = as_list(get_field(event, path))
        res = any(one(i) for i in items) if items else False
        return (not res) if negate else res

    return fn


def compile_condition(node: Any) -> Cond:
    if isinstance(node, list):
        subs = [compile_condition(n) for n in node]
        return lambda e: all(s(e) for s in subs)
    if not isinstance(node, dict):
        raise RuleError(f"invalid condition node: {node!r}")
    if "all" in node:
        subs = [compile_condition(n) for n in node["all"]]
        return lambda e: all(s(e) for s in subs)
    if "any" in node:
        subs = [compile_condition(n) for n in node["any"]]
        return lambda e: any(s(e) for s in subs)
    if "not" in node:
        sub = compile_condition(node["not"])
        return lambda e: not sub(e)
    return _compile_leaf(node)


# ----------------------------------------------------------------------- rule
@dataclass
class Rule:
    key: str
    title: str
    description: str
    version: int
    severity: str
    enabled: bool
    type: str
    tags: list[str]
    mitre: list[dict]
    references: list[str]
    false_positives: list[str]
    next_checks: list[str]
    group_by: list[str]
    window_seconds: int
    match: Cond
    exclude: Cond | None = None
    count: int = 1
    distinct: str | None = None
    stages: list[dict] = field(default_factory=list)  # sequence: [{name, match, count}]
    org_id: str = ""  # "" = platform rule (applies to every organization); else applies ONLY to that organization
    definition: dict = field(default_factory=dict)

    def context(self) -> dict:
        return {"description": self.description, "false_positives": self.false_positives,
                "next_checks": self.next_checks, "references": self.references, "tags": self.tags,
                "type": self.type}


def _str_list(d: dict, key: str) -> list[str]:
    v = d.get(key, [])
    if not isinstance(v, list) or not all(isinstance(i, (str, int, float)) for i in v):
        raise RuleError(f"'{key}' must be a list of strings")
    return [str(i) for i in v]


def parse_rule(d: dict) -> Rule:
    if not isinstance(d, dict):
        raise RuleError("rule must be a mapping")
    key = d.get("id")
    if not isinstance(key, str) or not _KEY_RE.match(key):
        raise RuleError("'id' is required (3-64 chars: letters, digits, . _ -)")
    title = d.get("title")
    if not isinstance(title, str) or not title.strip():
        raise RuleError("'title' is required")
    severity = str(d.get("severity", "")).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"'severity' must be one of {SEVERITIES}")
    rtype = d.get("type", "match")
    if rtype not in RULE_TYPES:
        raise RuleError(f"'type' must be one of {RULE_TYPES}")
    version = d.get("version", 1)
    if not isinstance(version, int) or version < 1:
        raise RuleError("'version' must be a positive integer")

    mitre = d.get("mitre", [])
    if not isinstance(mitre, list) or not all(isinstance(m, dict) and m.get("technique_id") for m in mitre):
        raise RuleError("'mitre' must be a list of {technique_id: ...}")

    group_by = _str_list(d, "group_by")
    window = d.get("window_seconds", d.get("dedupe_window_seconds", 300))
    thr = d.get("threshold") or {}
    if rtype == "threshold":
        window = thr.get("window_seconds", window)
    if not isinstance(window, int) or not 1 <= window <= 86400:
        raise RuleError("window must be an integer 1..86400 seconds")

    count, distinct, stages, match = 1, None, [], None
    if rtype in ("match", "threshold"):
        if "match" not in d:
            raise RuleError("'match' is required")
        match = compile_condition(d["match"])
    if rtype == "threshold":
        count = thr.get("count")
        if not isinstance(count, int) or not 1 <= count <= 100000:
            raise RuleError("threshold.count must be an integer 1..100000")
        distinct = thr.get("distinct")
        if not group_by:
            raise RuleError("threshold rules need 'group_by'")
    if rtype == "sequence":
        seq = d.get("sequence")
        if not isinstance(seq, list) or len(seq) != 2:
            raise RuleError("sequence rules need exactly 2 stages")
        if not group_by:
            raise RuleError("sequence rules need 'group_by'")
        for i, st in enumerate(seq):
            if not isinstance(st, dict) or "match" not in st:
                raise RuleError(f"sequence stage {i + 1} needs 'match'")
            c = st.get("count", 1)
            if not isinstance(c, int) or c < 1:
                raise RuleError("stage count must be a positive integer")
            stages.append({"name": str(st.get("name", f"stage{i + 1}")), "match": compile_condition(st["match"]),
                           "count": c})
        match = lambda e: False  # noqa: E731  (stages do the matching)

    exclude = compile_condition(d["exclude"]) if d.get("exclude") else None
    return Rule(key=key, title=title.strip(), description=str(d.get("description", "")).strip(), version=version,
                severity=severity, enabled=bool(d.get("enabled", True)), type=rtype, tags=_str_list(d, "tags"),
                mitre=[{"technique_id": str(m["technique_id"])} for m in mitre],
                references=_str_list(d, "references"), false_positives=_str_list(d, "false_positives"),
                next_checks=_str_list(d, "next_checks"), group_by=group_by, window_seconds=window, match=match,
                exclude=exclude, count=count, distinct=distinct, stages=stages, definition=d)


# ------------------------------------------------------------------ detection
@dataclass
class Detection:
    rule_key: str
    rule_version: int
    title: str
    severity: str
    mitre: list[dict]
    rule_context: dict
    group: dict[str, str]
    event_ids: list[str]
    evidence: list[dict]
    first_seen: datetime
    last_seen: datetime
    count: int
    dedupe_key: str
    explanation: str
    host: str | None
    user: str | None
    source_ip: str | None
    org_id: str = ""


def _parse_ts(event: dict) -> datetime:
    s = event["@timestamp"]
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class RuleEngine:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules: list[Rule] = []
        self._state: dict[tuple, deque] = {}
        self._recent: OrderedDict[str, list] = OrderedDict()  # event_id -> detections (idempotency)
        self._since_gc = 0
        self.set_rules(rules or [])

    def set_rules(self, rules: list[Rule]) -> None:
        """Swap rules; keep state only for rules whose key+version are unchanged."""
        keep = {(r.key, r.version) for r in rules}
        self._state = {k: v for k, v in self._state.items() if (k[0], k[1]) in keep}
        self.rules = list(rules)

    # -- helpers
    def _group(self, rule: Rule, event: dict) -> dict[str, str] | None:
        out: dict[str, str] = {}
        for path in rule.group_by:
            v = get_field(event, path)
            if v in (None, "", []):
                return None
            out[path] = str(as_list(v)[0])
        return out

    def _make(self, rule: Rule, group: dict, items: list[tuple], event: dict, ts: datetime,
              count: int, explanation: str) -> Detection:
        bucket = int(ts.timestamp() // rule.window_seconds)
        org = str(get_field(event, "org.id") or "")
        raw_key = f"{rule.key}|{org}|{'|'.join(group.values())}|{bucket}"
        dedupe = f"{rule.key}:{hashlib.sha1(raw_key.encode()).hexdigest()[:24]}"
        items = items[-MAX_GROUP_EVENTS:]
        return Detection(
            rule_key=rule.key, rule_version=rule.version, title=rule.title, severity=rule.severity,
            mitre=rule.mitre, rule_context=rule.context(), group=group,
            event_ids=[i[1] for i in items], evidence=[i[2] for i in items],
            first_seen=items[0][0], last_seen=items[-1][0], count=count, dedupe_key=dedupe,
            explanation=explanation, host=get_field(event, "host.name"),
            user=group.get("user.name") or get_field(event, "user.name"),
            source_ip=group.get("source.ip") or get_field(event, "source.ip"), org_id=org)

    @staticmethod
    def _skey(rule: Rule, event: dict, group: dict) -> tuple:
        """Window state is partitioned per organization so tenants can never share counters."""
        return (rule.key, rule.version, str(get_field(event, "org.id") or ""), tuple(group.values()))

    @staticmethod
    def _fmt_group(group: dict) -> str:
        return ", ".join(f"{k}={v}" for k, v in group.items()) or "n/a"

    # -- evaluation
    def evaluate(self, event: dict) -> list[Detection]:
        """Idempotent per event id: re-evaluating the same event returns the same detections
        without touching window state (safe for queue retries and duplicate deliveries)."""
        eid = get_field(event, "event.id")
        if eid is not None and eid in self._recent:
            return self._recent[eid]
        out = self._evaluate(event)
        if eid is not None:
            self._recent[eid] = out
            if len(self._recent) > 5000:
                self._recent.popitem(last=False)
        return out

    def _evaluate(self, event: dict) -> list[Detection]:
        ts = _parse_ts(event)
        out: list[Detection] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.org_id and rule.org_id != str(get_field(event, "org.id") or ""):
                continue  # another organization's custom rule never sees this event
            try:
                if rule.exclude and rule.exclude(event):
                    continue
                det = {"match": self._match, "threshold": self._threshold,
                       "sequence": self._sequence}[rule.type](rule, event, ts)
            except Exception:  # a faulty rule must never stop the pipeline
                log.exception("rule evaluation failed", extra={"rule": rule.key})
                continue
            if det:
                out.append(det)
        self._since_gc += 1
        if self._since_gc >= 2000:
            self.gc(ts)
        return out

    def _match(self, rule: Rule, event: dict, ts: datetime) -> Detection | None:
        if not rule.match(event):
            return None
        group = self._group(rule, event) if rule.group_by else {"host.name": get_field(event, "host.name") or "unknown"}
        if group is None:
            return None
        eid = get_field(event, "event.id")
        items = [(ts, eid, compact_event(event))]
        return self._make(rule, group, items, event, ts, 1, f"Event matched rule conditions ({self._fmt_group(group)}).")

    def _threshold(self, rule: Rule, event: dict, ts: datetime) -> Detection | None:
        if not rule.match(event):
            return None
        group = self._group(rule, event)
        if group is None:
            return None
        dv = None
        if rule.distinct:
            dv = get_field(event, rule.distinct)
            if dv in (None, ""):
                return None
        dq = self._state.setdefault(self._skey(rule, event, group), deque())
        cutoff = ts.timestamp() - rule.window_seconds
        while dq and dq[0][0].timestamp() < cutoff:
            dq.popleft()
        dq.append((ts, get_field(event, "event.id"), compact_event(event), dv))
        while len(dq) > MAX_GROUP_EVENTS * 5:
            dq.popleft()
        count = len({i[3] for i in dq}) if rule.distinct else len(dq)
        if count < rule.count:
            return None
        what = f"{count} distinct {rule.distinct} values" if rule.distinct else f"{count} matching events"
        return self._make(rule, group, [i[:3] for i in dq], event, ts, count,
                          f"{what} within {rule.window_seconds}s ({self._fmt_group(group)}); threshold is {rule.count}.")

    def _sequence(self, rule: Rule, event: dict, ts: datetime) -> Detection | None:
        first, second = rule.stages
        if first["match"](event):
            group = self._group(rule, event)
            if group is None:
                return None
            dq = self._state.setdefault(self._skey(rule, event, group), deque())
            dq.append((ts, get_field(event, "event.id"), compact_event(event)))
            while len(dq) > MAX_GROUP_EVENTS:
                dq.popleft()
            return None
        if second["match"](event):
            group = self._group(rule, event)
            if group is None:
                return None
            dq = self._state.get(self._skey(rule, event, group))
            if not dq:
                return None
            cutoff = ts.timestamp() - rule.window_seconds
            while dq and dq[0][0].timestamp() < cutoff:
                dq.popleft()
            if len(dq) < first["count"]:
                return None
            items = list(dq) + [(ts, get_field(event, "event.id"), compact_event(event))]
            dq.clear()
            return self._make(
                rule, group, items, event, ts, len(items),
                f"{len(items) - 1} '{first['name']}' events followed by '{second['name']}' within "
                f"{rule.window_seconds}s ({self._fmt_group(group)}).")
        return None

    def gc(self, now: datetime) -> None:
        self._since_gc = 0
        horizon = now.timestamp()
        windows = {r.key: r.window_seconds for r in self.rules}
        for k in list(self._state):
            dq = self._state[k]
            w = windows.get(k[0], 300)
            if not dq or dq[-1][0].timestamp() < horizon - w:
                del self._state[k]
        if len(self._state) > MAX_STATE_GROUPS:
            for k in list(self._state)[: len(self._state) - MAX_STATE_GROUPS]:
                del self._state[k]
