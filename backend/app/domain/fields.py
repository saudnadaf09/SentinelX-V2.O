"""Dotted-path helpers for nested event documents."""
from __future__ import annotations

from typing import Any


def get_field(obj: dict, path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def as_list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def prune(value: Any) -> Any:
    """Recursively drop None / empty strings / empty containers."""
    if isinstance(value, dict):
        out = {k: prune(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v not in (None, "", {}, [])}
    if isinstance(value, list):
        return [v for v in (prune(i) for i in value) if v not in (None, "", {}, [])]
    return value
