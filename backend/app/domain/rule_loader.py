"""Load detection rules and correlation config from the detection-rules directory."""
from __future__ import annotations

from pathlib import Path

import yaml

from .correlation import DEFAULT_RULES, DEFAULT_WINDOW
from .rules import Rule, RuleError, parse_rule


def load_rule_files(rules_dir: Path) -> list[tuple[Path, dict, str]]:
    """Return [(path, parsed_dict, yaml_text)] for every rule file (correlation/ is skipped)."""
    out = []
    for path in sorted(Path(rules_dir).rglob("*.yml")):
        if "correlation" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        out.append((path, yaml.safe_load(text), text))
    return out


def parse_yaml_rule(text: str) -> tuple[dict, Rule]:
    if len(text) > 20000:
        raise RuleError("rule YAML too large (max 20 KB)")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"invalid YAML: {exc}") from exc
    return data, parse_rule(data)


def load_correlation_config(rules_dir: Path) -> tuple[int, list[dict]]:
    path = Path(rules_dir) / "correlation" / "correlation.yml"
    if not path.exists():
        return DEFAULT_WINDOW, DEFAULT_RULES
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return int(data.get("window_seconds", DEFAULT_WINDOW)), data.get("rules", DEFAULT_RULES)
