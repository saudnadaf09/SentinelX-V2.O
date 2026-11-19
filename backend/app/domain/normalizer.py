"""Maps source-specific telemetry into one ECS-inspired document.

Inputs are untrusted. Every value is length-bounded and IPs/ports are validated.
Original fields are preserved under ``raw`` (size-capped).
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .fields import prune

SCHEMA_VERSION = "1.0"
MAX_RAW_BYTES = 16384
SOURCE_TYPES = ("sysmon", "windows_security", "linux_auth", "suricata", "syslog")
DATA_CLASSES = ("live", "simulated", "test")


class NormalizationError(ValueError):
    """Raised when an event cannot be normalized; the event is quarantined."""


def _s(v: Any, limit: int = 512) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s[:limit] if s else None


def _ip(v: Any) -> str | None:
    if v is None:
        return None
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def _port(v: Any) -> int | None:
    try:
        p = int(v)
    except (TypeError, ValueError):
        return None
    return p if 0 <= p <= 65535 else None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return re.split(r"[\\/]", path)[-1] or None


def _split_user(v: Any) -> tuple[str | None, str | None]:
    s = _s(v, 256)
    if not s:
        return None, None
    if "\\" in s:
        dom, name = s.split("\\", 1)
        return dom or None, name or None
    return None, s


def parse_timestamp(v: Any) -> datetime:
    if isinstance(v, datetime):
        dt = v
    elif isinstance(v, str):
        s = v.strip()
        if s[-1:] in ("Z", "z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError as exc:
            raise NormalizationError(f"invalid timestamp: {v[:40]!r}") from exc
    else:
        raise NormalizationError("timestamp must be an ISO 8601 string")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------- sysmon
def _sysmon(raw: dict) -> dict:
    eid = _int(raw.get("EventID"))
    if eid is None:
        raise NormalizationError("sysmon event missing numeric EventID")
    dom, name = _split_user(raw.get("User"))
    image = _s(raw.get("Image"), 1024)
    base = {"os": "windows", "observer": {"product": "Sysmon"}, "user": {"name": name, "domain": dom}}
    if eid == 1:
        return {**base,
                "event": {"category": ["process"], "type": ["start"], "action": "process_creation",
                          "code": "1", "dataset": "sysmon"},
                "process": {"pid": _int(raw.get("ProcessId")), "name": _basename(image), "executable": image,
                            "command_line": _s(raw.get("CommandLine"), 4096),
                            "entity_id": _s(raw.get("ProcessGuid"), 128),
                            "parent": {"executable": _s(raw.get("ParentImage"), 1024),
                                       "name": _basename(_s(raw.get("ParentImage"), 1024)),
                                       "command_line": _s(raw.get("ParentCommandLine"), 4096)},
                            "hash": _s(raw.get("Hashes"), 512)}}
    if eid == 3:
        initiated = str(raw.get("Initiated", "true")).lower() == "true"
        return {**base,
                "event": {"category": ["network"], "type": ["connection"], "action": "network_connection",
                          "code": "3", "dataset": "sysmon"},
                "process": {"pid": _int(raw.get("ProcessId")), "name": _basename(image), "executable": image},
                "source": {"ip": _ip(raw.get("SourceIp")), "port": _port(raw.get("SourcePort"))},
                "destination": {"ip": _ip(raw.get("DestinationIp")), "port": _port(raw.get("DestinationPort")),
                                "domain": _s(raw.get("DestinationHostname"), 255)},
                "network": {"transport": _s(raw.get("Protocol"), 16),
                            "direction": "egress" if initiated else "ingress"}}
    if eid == 11:
        return {**base,
                "event": {"category": ["file"], "type": ["creation"], "action": "file_created",
                          "code": "11", "dataset": "sysmon"},
                "process": {"pid": _int(raw.get("ProcessId")), "name": _basename(image), "executable": image},
                "file": {"path": _s(raw.get("TargetFilename"), 1024)}}
    return {**base,
            "event": {"category": ["host"], "type": ["info"], "action": f"sysmon_event_{eid}",
                      "code": str(eid), "dataset": "sysmon"},
            "process": {"name": _basename(image), "executable": image}}


# ---------------------------------------------------------- windows security
def _winsec(raw: dict) -> dict:
    eid = _int(raw.get("EventID"))
    if eid is None:
        raise NormalizationError("windows security event missing numeric EventID")
    base = {"os": "windows", "observer": {"product": "Windows Security"}}
    ds = "windows.security"
    target = _s(raw.get("TargetUserName"), 256)
    if eid in (4624, 4625):
        ok = eid == 4624
        return {**base,
                "event": {"category": ["authentication"], "type": ["start" if ok else "info"],
                          "action": "logon_success" if ok else "logon_failed", "code": str(eid),
                          "outcome": "success" if ok else "failure", "dataset": ds},
                "user": {"name": target, "domain": _s(raw.get("TargetDomainName"), 256)},
                "source": {"ip": _ip(raw.get("IpAddress"))},
                "network": {"logon_type": _s(raw.get("LogonType"), 8)}}
    if eid == 4720:
        return {**base,
                "event": {"category": ["iam"], "type": ["user", "creation"], "action": "user_created",
                          "code": "4720", "dataset": ds},
                "user": {"name": _s(raw.get("SubjectUserName"), 256), "target": {"name": target}}}
    if eid in (4728, 4732):
        return {**base,
                "event": {"category": ["iam"], "type": ["group", "change"], "action": "group_member_added",
                          "code": str(eid), "dataset": ds},
                "user": {"name": _s(raw.get("SubjectUserName"), 256),
                         "target": {"name": _s(raw.get("MemberName"), 256)}},
                "group": {"name": target}}
    return {**base,
            "event": {"category": ["host"], "type": ["info"], "action": f"windows_event_{eid}",
                      "code": str(eid), "dataset": ds}}


# ----------------------------------------------------------------- linux auth
_SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_OK = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
_GROUP_ADD = re.compile(r"add '(?P<member>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
_SUDO = re.compile(r"^\s*(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>.+)$")


def _linux(raw: dict) -> dict:
    msg = _s(raw.get("message"), 2048)
    if not msg:
        raise NormalizationError("linux_auth event missing 'message'")
    program = (_s(raw.get("program"), 64) or "").lower()
    base = {"os": "linux", "observer": {"product": program or "linux-auth"}, "message": msg}
    ds = "linux.auth"

    def auth(action: str, outcome: str, m: re.Match) -> dict:
        return {**base,
                "event": {"category": ["authentication"], "type": ["start" if outcome == "success" else "info"],
                          "action": action, "outcome": outcome, "dataset": ds},
                "user": {"name": _s(m.group("user"), 256)},
                "source": {"ip": _ip(m.group("ip")), "port": _port(m.groupdict().get("port"))}}

    if (m := _SSH_FAIL.search(msg)):
        return auth("ssh_login_failed", "failure", m)
    if (m := _SSH_OK.search(msg)):
        return auth("ssh_login_success", "success", m)
    if (m := _SSH_INVALID.search(msg)):
        return auth("ssh_invalid_user", "failure", m)
    if (m := _USERADD.search(msg)):
        return {**base, "event": {"category": ["iam"], "type": ["user", "creation"], "action": "user_created",
                                  "dataset": ds},
                "user": {"target": {"name": _s(m.group("user"), 256)}}}
    if (m := _GROUP_ADD.search(msg)):
        return {**base, "event": {"category": ["iam"], "type": ["group", "change"],
                                  "action": "group_member_added", "dataset": ds},
                "user": {"target": {"name": _s(m.group("member"), 256)}},
                "group": {"name": _s(m.group("group"), 256)}}
    if program == "sudo" and (m := _SUDO.match(msg)):
        return {**base, "event": {"category": ["process"], "type": ["start"], "action": "sudo_command",
                                  "dataset": ds},
                "user": {"name": _s(m.group("user"), 256)},
                "process": {"command_line": _s(m.group("cmd"), 4096)}}
    return {**base, "event": {"category": ["authentication"], "type": ["info"], "action": "linux_auth_log",
                              "dataset": ds}}


# -------------------------------------------------------------------- suricata
def _suricata(raw: dict) -> dict:
    et = _s(raw.get("event_type"), 32)
    if et not in ("alert", "flow"):
        raise NormalizationError(f"unsupported suricata event_type: {et!r}")
    base = {"observer": {"product": "Suricata"},
            "source": {"ip": _ip(raw.get("src_ip")), "port": _port(raw.get("src_port"))},
            "destination": {"ip": _ip(raw.get("dest_ip")), "port": _port(raw.get("dest_port"))},
            "network": {"transport": (_s(raw.get("proto"), 16) or "").lower() or None}}
    if et == "alert":
        a = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
        return {**base,
                "event": {"category": ["network", "intrusion_detection"], "type": ["info"],
                          "action": "ids_alert", "dataset": "suricata"},
                "rule": {"name": _s(a.get("signature"), 256), "id": _s(a.get("signature_id"), 32)}}
    return {**base, "event": {"category": ["network"], "type": ["connection"], "action": "network_flow",
                              "dataset": "suricata"}}


# ---------------------------------------------------------------------- syslog
_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
_DENY = re.compile(r"\b(deny|denied|drop|dropped|blocked?|reject(?:ed)?)\b", re.I)
_LINUX_PROGRAMS = {"sshd", "sudo", "useradd", "usermod", "gpasswd"}


def _syslog(raw: dict) -> dict:
    msg = _s(raw.get("message"), 2048)
    if not msg:
        raise NormalizationError("syslog event missing 'message'")
    program = (_s(raw.get("program"), 64) or "").lower()
    if program in _LINUX_PROGRAMS:  # host auth logs forwarded over syslog
        part = _linux({"message": msg, "program": program})
        part["observer"] = {"product": f"syslog/{program}"}
        return part
    kv = {k.lower(): v.strip('"') for k, v in _KV.findall(msg)}
    src = _ip(kv.get("src") or kv.get("srcip") or kv.get("src_ip"))
    dst = _ip(kv.get("dst") or kv.get("dstip") or kv.get("dst_ip"))
    base = {"observer": {"product": program or "syslog"}, "message": msg}
    if src or dst:
        act = (kv.get("action") or kv.get("act") or "").lower()
        denied = act in ("deny", "drop", "block", "blocked", "reject", "denied") or bool(_DENY.search(msg))
        return {**base,
                "event": {"category": ["network"], "type": ["connection", "denied" if denied else "allowed"],
                          "action": "firewall_deny" if denied else "firewall_allow", "dataset": "syslog.network"},
                "source": {"ip": src, "port": _port(kv.get("spt") or kv.get("sport") or kv.get("src_port"))},
                "destination": {"ip": dst, "port": _port(kv.get("dpt") or kv.get("dport") or kv.get("dstport") or kv.get("dst_port"))},
                "network": {"transport": (kv.get("proto") or "").lower() or None}}
    return {**base, "event": {"category": ["host"], "type": ["info"], "action": "syslog_message", "dataset": "syslog"}}


_HANDLERS: dict[str, Callable[[dict], dict]] = {
    "sysmon": _sysmon, "windows_security": _winsec, "linux_auth": _linux, "suricata": _suricata, "syslog": _syslog,
}


def normalize(envelope: dict, *, collector_id: str, host_id: str | None, host_name: str,
              ingested_at: datetime | None = None, org_id: str | None = None, data_class: str = "live",
              max_future_skew: timedelta = timedelta(hours=24)) -> dict:
    """Return a normalized event document or raise NormalizationError."""
    handler = _HANDLERS.get(envelope.get("source_type"))
    if handler is None:
        raise NormalizationError(f"unsupported source_type: {str(envelope.get('source_type'))[:40]!r}")
    raw = envelope.get("raw")
    if not isinstance(raw, dict):
        raise NormalizationError("'raw' must be an object")
    original_id = _s(envelope.get("event_id"), 128)
    if not original_id:
        raise NormalizationError("event_id is required")
    ts = parse_timestamp(envelope.get("timestamp"))
    now = ingested_at or datetime.now(timezone.utc)
    if ts > now + max_future_skew:
        raise NormalizationError("timestamp is more than 24h in the future (clock skew?)")

    part = handler(raw)
    os_name = part.pop("os", None)
    message = part.pop("message", None)
    event = part.pop("event")
    event.update({"id": f"{collector_id}:{original_id}", "original_id": original_id,
                  "ingested": iso(now), "schema_version": SCHEMA_VERSION,
                  "data_class": data_class if data_class in DATA_CLASSES else "live"})

    raw_json = json.dumps(raw, default=str)
    stored_raw: Any = raw if len(raw_json) <= MAX_RAW_BYTES else {"truncated": True, "preview": raw_json[:2000]}

    doc = {
        "@timestamp": iso(ts),
        "event": event,
        "host": {"id": host_id, "name": host_name, "os": os_name},
        "collector": {"id": collector_id, "type": envelope.get("source_type")},
        "org": {"id": org_id} if org_id else None,
        "message": message,
        "raw": stored_raw,
        **part,
    }
    rep = envelope.get("host")
    reported = _s(rep.get("name"), 255) if isinstance(rep, dict) else None
    if reported and reported.lower() != host_name.lower():
        doc["labels"] = {"reported_host": reported}
    pruned = prune(doc)
    pruned["raw"] = stored_raw
    return pruned
