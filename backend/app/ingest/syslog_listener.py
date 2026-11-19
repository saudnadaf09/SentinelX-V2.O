"""UDP syslog receiver for network devices and Linux hosts.

A device counts as connected ONLY after a datagram from its registered source IP has been received and
accepted. Datagrams from unregistered IPs are dropped and counted as ingestion failures.
Receive time is used as the event time (RFC 3164 timestamps carry no year/timezone).
"""
from __future__ import annotations

import logging
import re
import socketserver
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger("sentinelx.syslog")
_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(r"^(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]|-)\s*(.*)$", re.S)
_RFC3164 = re.compile(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Za-z0-9_.\-/]+?)(?:\[\d+\])?:\s*(.*)$", re.S)
MAX_DATAGRAM = 4096


def parse_syslog(data: bytes) -> dict | None:
    """Return {facility, severity, hostname, program, message} or None for unusable input."""
    text = data[:MAX_DATAGRAM].decode("utf-8", "replace").strip("\x00\r\n ")
    if not text:
        return None
    facility = severity = None
    m = _PRI.match(text)
    if m:
        pri = int(m.group(1))
        if pri > 191:
            return None
        facility, severity = pri // 8, pri % 8
        text = text[m.end():]
    hostname = program = None
    message = text
    m5 = _RFC5424.match(text)
    if m5:
        hostname = None if m5.group(3) == "-" else m5.group(3)
        program = None if m5.group(4) == "-" else m5.group(4)
        message = m5.group(7)
    else:
        m3 = _RFC3164.match(text)
        if m3:
            hostname, program, message = m3.group(1), m3.group(2), m3.group(3)
    message = message.strip()
    if not message:
        return None
    return {"facility": facility, "severity": severity, "hostname": hostname, "program": program, "message": message}


def build_payload(asset: dict, parsed: dict, client_ip: str, request_id: str = "syslog") -> dict:
    """Queue payload identical in shape to the HTTP ingest path (org/data class come from the asset)."""
    now = datetime.now(timezone.utc)
    return {"collector_id": f"{asset['id'].replace('-', '')[:8]}-{asset['hostname'].lower()}", "asset_id": asset["id"],
            "org_id": asset["org_id"], "data_class": asset.get("data_class", "live"), "host_name": asset["hostname"],
            "envelope": {"event_id": f"syslog-{uuid.uuid4().hex}", "timestamp": now.isoformat(), "source_type": "syslog",
                         "host": {"name": parsed.get("hostname") or asset["hostname"]},
                         "raw": {k: v for k, v in {**parsed, "source_ip": client_ip}.items() if v is not None}},
            "received_at": now.isoformat(), "request_id": request_id}


def handle_datagram(data: bytes, client_ip: str, *, resolve_asset: Callable[[str], dict | None],
                    publish: Callable[[dict, dict], None], count: Callable[[str], None],
                    allow: Callable[[str], bool]) -> str:
    """Pure decision logic (unit-tested). Returns: accepted | unknown_source | malformed | rate_limited."""
    if not allow(client_ip):
        count("rejected")
        return "rate_limited"
    asset = resolve_asset(client_ip)
    if asset is None:
        count("rejected")
        return "unknown_source"
    parsed = parse_syslog(data)
    if parsed is None:
        count("rejected")
        return "malformed"
    publish(asset, build_payload(asset, parsed, client_ip))
    return "accepted"


class SyslogServer:
    def __init__(self, host: str, port: int, handler: Callable[[bytes, str], str]):
        outer = handler

        class _H(socketserver.BaseRequestHandler):
            def handle(self):
                data, _sock = self.request
                try:
                    outer(data, self.client_address[0])
                except Exception:  # noqa: BLE001 - never let one datagram kill the listener
                    log.exception("syslog handler error")

        self.server = socketserver.ThreadingUDPServer((host, port), _H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="syslog-udp")

    def start(self) -> "SyslogServer":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
