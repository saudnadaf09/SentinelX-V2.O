#!/usr/bin/env python3
"""SentinelX endpoint agent (Windows + Linux). Python 3.9+, standard library only.

Collects ONLY security telemetry (authentication, account/privilege changes, process creation via Sysmon,
selected service/log-clear events, ssh/sudo logs). It never reads files, passwords, browser data or keys.

  python sentinelx_agent.py --config agent.json            # run continuously
  python sentinelx_agent.py --config agent.json --once     # one collection cycle (for testing)
  python sentinelx_agent.py --config agent.json --rotate-key
  python sentinelx_agent.py --config agent.json --deregister
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

VERSION = "1.0.0"
log = logging.getLogger("sentinelx-agent")
IS_WINDOWS = platform.system() == "Windows"

# Windows: channel -> event ids collected by default (all read-only queries through wevtutil)
WIN_CHANNELS = {
    "Security": [4624, 4625, 4720, 4728, 4732, 1102],
    "System": [7045, 104],
    "Microsoft-Windows-Sysmon/Operational": [1, 3, 11],
}
LINUX_AUTH_FILES = ["/var/log/auth.log", "/var/log/secure"]
LINUX_IDENTIFIERS = ["sshd", "sudo", "useradd", "usermod", "gpasswd"]
LINUX_PROGRAMS = set(LINUX_IDENTIFIERS)


# ------------------------------------------------------------------ pure parsers (unit-tested)
def parse_windows_event_xml(xml_text: str) -> dict | None:
    """Convert one <Event> XML (wevtutil /f:xml) into {event_id, record_id, channel, timestamp, raw}."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    sysn = root.find("e:System", ns)
    if sysn is None:
        return None

    def g(tag):
        el = sysn.find(f"e:{tag}", ns)
        return el

    eid_el, rec_el, ch_el, tc = g("EventID"), g("EventRecordID"), g("Channel"), g("TimeCreated")
    if eid_el is None or rec_el is None or tc is None:
        return None
    raw = {"EventID": int(eid_el.text)}
    for d in root.findall("e:EventData/e:Data", ns):
        name = d.attrib.get("Name")
        if name and d.text is not None:
            raw[name] = d.text
    return {"event_id": int(eid_el.text), "record_id": int(rec_el.text), "channel": (ch_el.text if ch_el is not None else ""),
            "timestamp": tc.attrib.get("SystemTime", ""), "raw": raw}


def windows_source_type(channel: str) -> str:
    return "sysmon" if "Sysmon" in channel else "windows_security"


def classify_wevtutil_error(returncode: int, stderr: str) -> tuple[str, str]:
    low = (stderr or "").lower()
    if returncode == 5 or "access is denied" in low:
        return "permission_denied", "Run the agent as Administrator (or add the service account to 'Event Log Readers')."
    if "cannot find" in low or "not found" in low or returncode == 15007:
        return "unavailable", "Channel not found (for Sysmon: install and configure Sysmon first)."
    return "error", (stderr or "unknown error").strip()[:200]


def make_event_id(host: str, source: str, unique: str) -> str:
    return hashlib.sha256(f"{host}|{source}|{unique}".encode()).hexdigest()[:40]


def linux_line_to_envelope(host: str, source: str, line: str, ts_iso: str, unique: str) -> dict | None:
    """Keep only ssh/sudo/account lines; ignore everything else (no unrelated log content leaves the host)."""
    m = re.search(r"\s([A-Za-z0-9_.\-]+?)(?:\[\d+\])?:\s", line)
    program = (m.group(1).lower() if m else "")
    if program not in LINUX_PROGRAMS:
        return None
    message = line.split(": ", 1)[1] if ": " in line else line
    return {"event_id": make_event_id(host, source, unique), "timestamp": ts_iso, "source_type": "linux_auth",
            "host": {"name": host}, "raw": {"program": program, "message": message[:2000]}}


# ------------------------------------------------------------------------------- state / spool
class State:
    """Persisted bookmarks and the retry spool, so nothing is lost across crashes or network outages."""

    def __init__(self, directory: Path):
        self.dir = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "state.json"
        self.spool = directory / "spool.jsonl"
        self.data = {"bookmarks": {}}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except ValueError:
                log.warning("state file unreadable; starting with empty bookmarks")

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data))
        os.replace(tmp, self.path)

    def spool_append(self, events: list[dict], max_bytes: int = 50_000_000):
        if self.spool.exists() and self.spool.stat().st_size > max_bytes:
            log.error("spool exceeds limit; dropping oldest data")
            self.spool.unlink()
        with open(self.spool, "a", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e) + "\n")

    def spool_read(self, limit: int) -> list[dict]:
        if not self.spool.exists():
            return []
        out = []
        with open(self.spool, encoding="utf-8") as fh:
            for line in fh:
                if len(out) >= limit:
                    break
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out

    def spool_drop(self, n: int):
        lines = self.spool.read_text(encoding="utf-8").splitlines(True)[n:]
        if lines:
            self.spool.write_text("".join(lines), encoding="utf-8")
        else:
            self.spool.unlink(missing_ok=True)


# ----------------------------------------------------------------------------------- collectors
def collect_windows(state: State, host: str, status: dict, max_events: int) -> list[dict]:
    out = []
    for channel, ids in WIN_CHANNELS.items():
        last = int(state.data["bookmarks"].get(f"win:{channel}", 0))
        cond = " or ".join(f"EventID={i}" for i in ids)
        query = f"*[System[({cond}) and EventRecordID>{last}]]"
        cmd = ["wevtutil", "qe", channel, f"/q:{query}", "/f:xml", f"/c:{max_events}", "/rd:false"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            status[channel] = {"status": "error", "detail": type(exc).__name__}
            continue
        if res.returncode != 0:
            st, detail = classify_wevtutil_error(res.returncode, res.stderr)
            status[channel] = {"status": st, "detail": detail}
            continue
        events = re.findall(r"<Event .*?</Event>", res.stdout, re.S)
        newest = last
        for xml in events:
            ev = parse_windows_event_xml(xml)
            if not ev:
                continue
            newest = max(newest, ev["record_id"])
            out.append({"event_id": make_event_id(host, channel, str(ev["record_id"])), "timestamp": ev["timestamp"],
                        "source_type": windows_source_type(channel), "host": {"name": host}, "raw": ev["raw"]})
        state.data["bookmarks"][f"win:{channel}"] = newest
        status[channel] = {"status": "ok", "detail": f"{len(events)} new event(s)"}
    return out


def collect_linux(state: State, host: str, status: dict, max_events: int, files: list[str] | None = None) -> list[dict]:
    out: list[dict] = []
    for path in (files or LINUX_AUTH_FILES):
        if not os.path.exists(path):
            continue
        key = f"file:{path}"
        try:
            size = os.path.getsize(path)
            pos = int(state.data["bookmarks"].get(key, -1))
            if pos < 0 or pos > size:  # first run (start at end: no historical backfill) or rotated log
                pos = size if pos < 0 else 0
            with open(path, "rb") as fh:
                fh.seek(pos)
                chunk = fh.read(2_000_000)
                new_pos = pos + len(chunk)
            text = chunk.decode("utf-8", "replace")
            if not text.endswith("\n") and "\n" in text:  # keep partial last line for next cycle
                partial = len(text) - text.rfind("\n") - 1
                text, new_pos = text[: text.rfind("\n") + 1], new_pos - len(text[text.rfind("\n") + 1:].encode())
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            count = 0
            for i, line in enumerate(text.splitlines()):
                env = linux_line_to_envelope(host, path, line, now, f"{pos}:{i}:{hashlib.md5(line.encode()).hexdigest()}")
                if env:
                    out.append(env)
                    count += 1
                    if len(out) >= max_events:
                        break
            state.data["bookmarks"][key] = new_pos
            status[path] = {"status": "ok", "detail": f"{count} relevant line(s)"}
        except PermissionError:
            status[path] = {"status": "permission_denied", "detail": "Run as root or add the user to the 'adm' group."}
        except OSError as exc:
            status[path] = {"status": "error", "detail": type(exc).__name__}
    if not out and not any(os.path.exists(p) for p in (files or LINUX_AUTH_FILES)):
        out += collect_journal(state, host, status, max_events)
    if not status:
        status["linux"] = {"status": "unavailable", "detail": "No auth log file or journalctl available."}
    return out


def collect_journal(state: State, host: str, status: dict, max_events: int) -> list[dict]:
    cmd = ["journalctl", "-o", "json", "--no-pager", "-n", str(max_events)] + [a for p in LINUX_IDENTIFIERS for a in ("-t", p)]
    cursor = state.data["bookmarks"].get("journal")
    if cursor:
        cmd += ["--after-cursor", cursor]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        status["journald"] = {"status": "unavailable", "detail": "journalctl not available"}
        return []
    if res.returncode != 0:
        status["journald"] = {"status": "permission_denied" if "permission" in res.stderr.lower() else "error",
                              "detail": res.stderr.strip()[:200] or "journalctl failed"}
        return []
    out = []
    for line in res.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        state.data["bookmarks"]["journal"] = j.get("__CURSOR", cursor)
        prog = (j.get("SYSLOG_IDENTIFIER") or "").lower()
        if prog in LINUX_PROGRAMS:
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(j.get("__REALTIME_TIMESTAMP", "0")) / 1e6))
            out.append({"event_id": make_event_id(host, "journal", j.get("__CURSOR", str(uuid.uuid4()))), "timestamp": ts,
                        "source_type": "linux_auth", "host": {"name": host},
                        "raw": {"program": prog, "message": str(j.get("MESSAGE", ""))[:2000]}})
    status["journald"] = {"status": "ok", "detail": f"{len(out)} relevant entries"}
    return out


# ------------------------------------------------------------------------------------- transport
class Unauthorized(Exception):
    pass


class Client:
    def __init__(self, server: str, key: str, timeout: int = 20, verify_tls: bool = True):
        self.server, self.key, self.timeout = server.rstrip("/"), key, timeout
        if not server.startswith("https://") and not re.match(r"^http://(localhost|127\.0\.0\.1)", server):
            log.warning("server URL is not HTTPS: telemetry and the API key travel unencrypted - use HTTPS in production")

    def post(self, path: str, body: dict, idem: str | None = None) -> dict:
        headers = {"Content-Type": "application/json", "X-API-Key": self.key, "User-Agent": f"SentinelXAgent/{VERSION}"}
        if idem:
            headers["Idempotency-Key"] = idem
        req = urllib.request.Request(f"{self.server}/api/v1{path}", data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise Unauthorized(f"server rejected the agent key (HTTP {exc.code}): revoked, expired or deregistered") from None
            raise


def heartbeat_body(status: dict, spooled: int, last_error: str | None) -> dict:
    return {"agent_version": VERSION, "hostname": socket.gethostname(), "os": platform.system().lower(),
            "os_version": platform.platform()[:120], "ip_address": local_ip(), "sources": status,
            "spooled_events": spooled, "last_error": last_error}


def local_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # no packet is sent; selects the outbound interface
            return s.getsockname()[0]
    except OSError:
        return None


def send_spool(client: Client, state: State, batch: int = 200) -> tuple[int, str | None]:
    sent = 0
    while True:
        events = state.spool_read(batch)
        if not events:
            return sent, None
        idem = hashlib.sha256(json.dumps([e["event_id"] for e in events]).encode()).hexdigest()[:40]
        try:
            res = client.post("/ingest/events/batch", {"events": events}, idem)
        except Unauthorized:
            raise
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return sent, f"send failed ({type(exc).__name__}); will retry"
        state.spool_drop(len(events))  # the server accepted/rejected them with reasons; either way do not resend
        sent += len(events)
        if res.get("rejected"):
            log.warning("server rejected %s event(s): %s", res["rejected"], str(res.get("errors"))[:300])


def cycle(cfg: dict, state: State, client: Client, host: str) -> dict:
    status: dict = {}
    max_events = int(cfg.get("max_events_per_cycle", 500))
    events = collect_windows(state, host, status, max_events) if IS_WINDOWS else collect_linux(state, host, status, max_events)
    if events:
        state.spool_append(events)
    state.save()
    sent, err = send_spool(client, state)
    spooled = len(state.spool_read(10**9)) if state.spool.exists() else 0
    reply = {}
    try:
        reply = client.post("/agent/heartbeat", heartbeat_body(status, spooled, err))
    except Unauthorized:
        raise
    except (urllib.error.URLError, OSError, ValueError) as exc:
        err = err or f"heartbeat failed ({type(exc).__name__})"
    log.info("cycle: collected=%d sent=%d spooled=%d sources=%s", len(events), sent, spooled,
             {k: v["status"] for k, v in status.items()})
    return {"collected": len(events), "sent": sent, "spooled": spooled, "error": err, "reply": reply, "status": status}


def load_config(path: str) -> dict:
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    for k in ("server_url", "api_key"):
        if not cfg.get(k):
            raise SystemExit(f"config is missing '{k}'")
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SentinelX endpoint agent")
    ap.add_argument("--config", required=True)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--rotate-key", action="store_true")
    ap.add_argument("--deregister", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(a.config)
    client = Client(cfg["server_url"], cfg["api_key"])
    state = State(Path(cfg.get("state_dir", Path(a.config).with_name("agent-state"))))
    host = cfg.get("hostname") or socket.gethostname()
    try:
        if a.deregister:
            client.post("/agent/deregister", {})
            log.info("endpoint deregistered; this agent key is now revoked")
            return 0
        if a.rotate_key:
            new = client.post("/agent/rotate-key", {})["api_key"]
            cfg["api_key"] = new
            Path(a.config).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            log.info("key rotated and config updated (the previous key is revoked)")
            return 0
        interval = int(cfg.get("interval_seconds", 30))
        backoff = 0
        while True:
            try:
                res = cycle(cfg, state, client, host)
                backoff = 0
                if res["reply"].get("key_rotation_due"):
                    log.warning("server reports key rotation is due: run with --rotate-key")
            except Unauthorized as exc:
                log.error("%s - stopping", exc)
                return 2
            except Exception:  # noqa: BLE001
                log.exception("cycle failed")
                backoff = min(max(backoff * 2, 5), 300)
            if a.once:
                return 0
            time.sleep(interval + backoff)
    except Unauthorized as exc:
        log.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
