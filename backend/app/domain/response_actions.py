"""Allowlisted XDR-lite response actions: catalog, parameter validation, dry-run planning.

No arbitrary commands are ever accepted. Actions only target registered,
lab-authorized assets, and the default adapter is a mock that changes nothing
outside SentinelX's own database.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Protocol

RESERVED_TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
EVIDENCE_SCRIPTS = ("process_list", "network_connections", "logged_on_users")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")

CATALOG = {
    "disable_test_account": {"title": "Disable simulated test account", "params": {"account": "string"},
                             "impact": "Marks a simulated lab account as disabled (mock adapter)."},
    "isolate_lab_host": {"title": "Isolate disposable lab host", "params": {},
                         "impact": "Marks the lab asset as network-isolated (mock adapter)."},
    "collect_evidence": {"title": "Collect additional evidence", "params": {"script": "|".join(EVIDENCE_SCRIPTS)},
                         "impact": "Runs a preconfigured read-only collection (mock adapter returns a stub)."},
    "block_test_indicator": {"title": "Block reserved test indicator", "params": {"ip": "RFC 5737 test IP"},
                             "impact": "Adds a simulated block for a reserved test IP."},
}


class ActionError(ValueError):
    pass


def validate_action(action_type: str, params: dict[str, Any]) -> dict[str, Any]:
    """Return sanitized params or raise ActionError."""
    if action_type not in CATALOG:
        raise ActionError(f"action not allowed: {action_type!r}")
    params = params or {}
    allowed = set(CATALOG[action_type]["params"])
    extra = set(params) - allowed
    if extra:
        raise ActionError(f"unexpected parameters: {sorted(extra)}")
    if action_type == "disable_test_account":
        acct = str(params.get("account", ""))
        if not _ACCOUNT_RE.match(acct):
            raise ActionError("account must be 1-64 chars of letters, digits, . _ $ -")
        if acct.lower() in {"root", "administrator", "system", "admin"}:
            raise ActionError("built-in privileged accounts cannot be targeted")
        return {"account": acct}
    if action_type == "collect_evidence":
        script = str(params.get("script", ""))
        if script not in EVIDENCE_SCRIPTS:
            raise ActionError(f"script must be one of {EVIDENCE_SCRIPTS}")
        return {"script": script}
    if action_type == "block_test_indicator":
        try:
            ip = ipaddress.ip_address(str(params.get("ip", "")))
        except ValueError as exc:
            raise ActionError("ip is not a valid address") from exc
        if not any(ip in net for net in RESERVED_TEST_NETS):
            raise ActionError("only reserved test IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) may be blocked")
        return {"ip": str(ip)}
    return {}


class ResponseAdapter(Protocol):
    name: str

    def dry_run(self, action_type: str, params: dict, asset_hostname: str) -> dict: ...
    def execute(self, action_type: str, params: dict, asset_hostname: str) -> dict: ...
    def rollback(self, action_type: str, params: dict, asset_hostname: str) -> dict: ...


@dataclass
class MockAdapter:
    """Simulates actions. Nothing outside SentinelX is touched."""
    name: str = "mock"

    def _desc(self, action_type: str, params: dict, host: str, verb: str) -> str:
        return {
            "disable_test_account": f"{verb} disabling simulated account '{params.get('account')}' on {host}",
            "isolate_lab_host": f"{verb} network isolation of lab host {host}",
            "collect_evidence": f"{verb} read-only collection '{params.get('script')}' on {host}",
            "block_test_indicator": f"{verb} block of reserved test IP {params.get('ip')} for {host}",
        }[action_type]

    def dry_run(self, action_type: str, params: dict, asset_hostname: str) -> dict:
        return {"adapter": self.name, "simulated": True, "would": self._desc(action_type, params, asset_hostname, "Would perform"),
                "changes_made": False}

    def execute(self, action_type: str, params: dict, asset_hostname: str) -> dict:
        res = {"adapter": self.name, "simulated": True, "performed": self._desc(action_type, params, asset_hostname, "Simulated"),
               "changes_made_outside_sentinelx": False}
        if action_type == "collect_evidence":
            res["output"] = "[mock] no real collection performed; connect a lab collector adapter to enable"
        return res

    def rollback(self, action_type: str, params: dict, asset_hostname: str) -> dict:
        return {"adapter": self.name, "simulated": True,
                "rolled_back": self._desc(action_type, params, asset_hostname, "Simulated rollback of")}


def get_adapter(name: str) -> ResponseAdapter:
    if name == "mock":
        return MockAdapter()
    raise ActionError(f"response adapter '{name}' is not implemented; only 'mock' is available")
