"""Transparent, explainable alert correlation.

Alerts are related when they share entities (host/user/source IP) within a
bounded time window. Every relation carries a human-readable reason. A public
(global) IP alone never correlates alerts; private/reserved/documentation IPs may.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime

DEFAULT_WINDOW = 600
DEFAULT_RULES = [
    {"id": "SX-CORR-001", "name": "Same host and user", "require": ["host", "user"]},
    {"id": "SX-CORR-002", "name": "Same non-public source IP", "require": ["source_ip"]},
]
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class AlertRef:
    id: str
    rule_key: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None
    title: str = ""


@dataclass
class Relation:
    alert_id: str
    correlation_id: str
    reason: str


def is_global_ip(ip: str | None) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _gap_seconds(a: AlertRef, b: AlertRef) -> float:
    return max(0.0, (a.first_seen - b.last_seen).total_seconds(), (b.first_seen - a.last_seen).total_seconds())


def find_relations(new: AlertRef, candidates: list[AlertRef], window_seconds: int = DEFAULT_WINDOW,
                   rules: list[dict] | None = None) -> list[Relation]:
    out: list[Relation] = []
    for cand in candidates:
        if cand.id == new.id or cand.rule_key == new.rule_key:
            continue
        gap = _gap_seconds(new, cand)
        if gap > window_seconds:
            continue
        for rule in rules or DEFAULT_RULES:
            vals = {}
            ok = True
            for key in rule["require"]:
                a, b = getattr(new, key), getattr(cand, key)
                if not a or not b or str(a).lower() != str(b).lower():
                    ok = False
                    break
                if key == "source_ip" and is_global_ip(a) and len(rule["require"]) == 1:
                    ok = False
                    break
                vals[key] = a
            if ok:
                label = {"host": "host", "user": "user", "source_ip": "source IP"}
                shared = " and ".join(f"{label[k]} '{v}'" for k, v in vals.items())
                out.append(Relation(cand.id, rule["id"],
                                    f"Shared {shared}; alerts {int(gap)}s apart (window {window_seconds}s)."))
                break
    return out
