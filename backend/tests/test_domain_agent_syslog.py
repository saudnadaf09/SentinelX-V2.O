import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent"))
import sentinelx_agent as ag  # noqa: E402

from app.domain.normalizer import normalize  # noqa: E402
from app.domain.fields import get_field  # noqa: E402
from app.domain.rule_loader import load_rule_files  # noqa: E402
from app.domain.rules import RuleEngine, parse_rule  # noqa: E402
from app.ingest import syslog_listener as sl  # noqa: E402

RULES = Path(__file__).resolve().parents[2] / "detection-rules"
BASE = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)

WIN_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>
<EventID>4625</EventID><EventRecordID>9001</EventRecordID><Channel>Security</Channel><Computer>PC1</Computer>
<TimeCreated SystemTime='2026-11-14T12:00:03.123456700Z'/></System><EventData><Data Name='TargetUserName'>labuser</Data>
<Data Name='TargetDomainName'>LAB</Data><Data Name='IpAddress'>198.51.100.77</Data><Data Name='LogonType'>3</Data><Data Name='Password'></Data></EventData></Event>"""


class SyslogParsing(unittest.TestCase):
    def test_rfc3164_and_5424_and_garbage(self):
        a = sl.parse_syslog(b"<38>Nov 14 12:00:01 fw01 sshd[123]: Failed password for root from 203.0.113.5 port 22 ssh2")
        self.assertEqual((a["hostname"], a["program"], a["facility"], a["severity"]), ("fw01", "sshd", 4, 6))
        b = sl.parse_syslog(b"<165>1 2026-11-14T12:00:00Z fw02 filterlog - ID1 - action=deny src=203.0.113.9 dst=192.0.2.5 dpt=22")
        self.assertEqual((b["hostname"], b["program"]), ("fw02", "filterlog"))
        self.assertIn("action=deny", b["message"])
        for bad in (b"", b"\x00\x00", b"<999>x", b"<13>   "):
            self.assertIsNone(sl.parse_syslog(bad))

    def _norm(self, raw):
        env = {"event_id": "s1", "timestamp": BASE.isoformat(), "source_type": "syslog", "raw": raw}
        return normalize(env, collector_id="c", host_id=None, host_name="FW01", org_id="o1", data_class="test", ingested_at=BASE + timedelta(hours=1))

    def test_firewall_and_ssh_over_syslog_normalize(self):
        d = self._norm({"program": "filterlog", "message": "action=deny src=203.0.113.9 dst=192.0.2.5 dpt=22 proto=tcp"})
        self.assertEqual((get_field(d, "event.action"), get_field(d, "destination.port"), get_field(d, "source.ip")),
                         ("firewall_deny", 22, "203.0.113.9"))
        self.assertEqual(get_field(d, "event.data_class"), "test")
        s = self._norm({"program": "sshd", "message": "Failed password for root from 203.0.113.5 port 22 ssh2"})
        self.assertEqual(get_field(s, "event.action"), "ssh_login_failed")

    def test_firewall_denies_trigger_port_scan_rule_with_evidence(self):
        eng = RuleEngine([parse_rule(d) for _, d, _ in load_rule_files(RULES) if d["id"] == "SX-NET-002"])
        dets = []
        for i in range(20):
            env = {"event_id": f"f{i}", "timestamp": (BASE + timedelta(seconds=i)).isoformat(), "source_type": "syslog",
                   "raw": {"program": "filterlog", "message": f"action=deny src=203.0.113.9 dst=192.0.2.5 dpt={1000 + i}"}}
            dets += eng.evaluate(normalize(env, collector_id="c", host_id=None, host_name="FW01", org_id="o1",
                                           ingested_at=BASE + timedelta(hours=1)))
        self.assertTrue(dets and dets[-1].count >= 15)

    def test_decision_logic_never_accepts_unregistered_sources(self):
        counts, published = [], []
        asset = {"id": "11111111-1111-1111-1111-111111111111", "org_id": "o1", "hostname": "FW01", "data_class": "live"}
        kw = dict(resolve_asset=lambda ip: asset if ip == "10.0.0.5" else None, publish=lambda a, p: published.append(p),
                  count=counts.append, allow=lambda ip: True)
        self.assertEqual(sl.handle_datagram(b"<13>hello", "10.9.9.9", **kw), "unknown_source")
        self.assertEqual(published, [])
        self.assertEqual(sl.handle_datagram(b"", "10.0.0.5", **kw), "malformed")
        self.assertEqual(sl.handle_datagram(b"<13>Nov 14 12:00:01 fw01 app: hi", "10.0.0.5", **kw), "accepted")
        self.assertEqual((published[0]["org_id"], published[0]["envelope"]["source_type"]), ("o1", "syslog"))
        self.assertEqual(counts, ["rejected", "rejected"])
        kw["allow"] = lambda ip: False
        self.assertEqual(sl.handle_datagram(b"<13>x y", "10.0.0.5", **kw), "rate_limited")

    def test_real_udp_socket_roundtrip(self):
        got = []
        srv = sl.SyslogServer("127.0.0.1", 0, lambda data, ip: got.append((data, ip)) or "accepted").start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"<13>Nov 14 12:00:01 dev1 prog: ping", ("127.0.0.1", srv.port))
            for _ in range(50):
                if got:
                    break
                time.sleep(0.05)
        finally:
            srv.stop()
        self.assertEqual(got[0][1], "127.0.0.1")


class OrgScopedRule(unittest.TestCase):
    def test_custom_rule_only_sees_its_own_organization(self):
        rule = parse_rule({"id": "ORG-aaaa-1", "title": "t", "severity": "low", "type": "match", "match": [
            {"field": "event.action", "op": "eq", "value": "ssh_login_failed"}]})
        rule.org_id = "org-a"
        eng = RuleEngine([rule])
        mk = lambda org, i: normalize({"event_id": f"e{i}", "timestamp": BASE.isoformat(), "source_type": "linux_auth",  # noqa: E731
                                       "raw": {"program": "sshd", "message": "Failed password for x from 203.0.113.1 port 1 ssh2"}},
                                      collector_id="c", host_id=None, host_name="H", org_id=org, ingested_at=BASE + timedelta(hours=1))
        self.assertEqual(len(eng.evaluate(mk("org-a", 1))), 1)
        self.assertEqual(eng.evaluate(mk("org-b", 2)), [])


class AgentParsers(unittest.TestCase):
    def test_windows_event_xml(self):
        ev = ag.parse_windows_event_xml(WIN_XML)
        self.assertEqual((ev["event_id"], ev["record_id"], ev["channel"]), (4625, 9001, "Security"))
        self.assertEqual(ev["raw"]["IpAddress"], "198.51.100.77")
        self.assertIsNone(ag.parse_windows_event_xml("<not-xml"))
        # the agent output normalizes and is detected by the server-side pipeline
        env = {"event_id": "w1", "timestamp": "2026-11-14T12:00:03Z", "source_type": ag.windows_source_type("Security"), "raw": ev["raw"]}
        d = normalize(env, collector_id="c", host_id=None, host_name="PC1", ingested_at=BASE + timedelta(hours=1))
        self.assertEqual(get_field(d, "event.action"), "logon_failed")

    def test_wevtutil_errors_are_reported_accurately(self):
        self.assertEqual(ag.classify_wevtutil_error(5, "Access is denied.")[0], "permission_denied")
        self.assertEqual(ag.classify_wevtutil_error(15007, "")[0], "unavailable")

    def test_linux_collector_filters_and_bookmarks(self):
        d = Path(tempfile.mkdtemp())
        log_file = d / "auth.log"
        log_file.write_text("old line sshd[1]: ignored on first run\n")
        st = ag.State(d / "state")
        status: dict = {}
        self.assertEqual(ag.collect_linux(st, "h1", status, 100, files=[str(log_file)]), [])  # no historical backfill
        with open(log_file, "a") as fh:
            fh.write("Nov 14 12:00:01 h1 sshd[22]: Failed password for root from 203.0.113.5 port 22 ssh2\n")
            fh.write("Nov 14 12:00:02 h1 CRON[9]: (root) CMD (secret job nobody should read)\n")
            fh.write("Nov 14 12:00:03 h1 sudo: admin : TTY=pts/0 ; COMMAND=/bin/ls\n")
        out = ag.collect_linux(st, "h1", status, 100, files=[str(log_file)])
        self.assertEqual([e["raw"]["program"] for e in out], ["sshd", "sudo"])  # CRON line never leaves the host
        self.assertEqual(status[str(log_file)]["status"], "ok")
        self.assertEqual(ag.collect_linux(st, "h1", {}, 100, files=[str(log_file)]), [])  # bookmark advanced
        n = out[0]
        self.assertEqual(ag.make_event_id("h1", "x", "1"), ag.make_event_id("h1", "x", "1"))  # stable ids = dedupe
        self.assertIn("event_id", n)

    def test_permission_denied_is_reported(self):
        d = Path(tempfile.mkdtemp()); f = d / "auth.log"; f.write_text("x\n"); f.chmod(0)
        status: dict = {}
        try:
            ag.collect_linux(ag.State(d / "s"), "h", status, 10, files=[str(f)])
        finally:
            f.chmod(0o600)
        import os
        if os.geteuid() != 0:  # root can read anything, so only assert when meaningful
            self.assertEqual(status[str(f)]["status"], "permission_denied")


class FakeServer(BaseHTTPRequestHandler):
    log_message = lambda *a: None  # noqa: E731
    seen: list = []
    mode = {"m": "ok"}

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeServer.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        if FakeServer.mode["m"] == "401":
            self.send_response(401); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"accepted": len(body.get("events", [])), "rejected": 0, "config": {}}).encode())


class AgentTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeServer)
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        FakeServer.seen.clear(); FakeServer.mode["m"] = "ok"
        self.d = Path(tempfile.mkdtemp())

    def _event(self, i):
        return {"event_id": f"e{i}", "timestamp": "2026-11-14T12:00:00Z", "source_type": "linux_auth", "host": {"name": "h"},
                "raw": {"program": "sshd", "message": "x"}}

    def test_spooled_events_survive_an_outage_and_are_sent_after_reconnect(self):
        st = ag.State(self.d)
        st.spool_append([self._event(i) for i in range(3)])
        dead = ag.Client("http://127.0.0.1:9", "sxk_k", timeout=2)  # nothing listening
        sent, err = ag.send_spool(dead, st)
        self.assertEqual(sent, 0)
        self.assertIn("will retry", err)
        self.assertEqual(len(st.spool_read(10)), 3, "events must stay spooled while the server is unreachable")
        sent, err = ag.send_spool(ag.Client(self.url, "sxk_k"), st)
        self.assertEqual((sent, err), (3, None))
        self.assertEqual(st.spool_read(10), [])
        path, headers, body = FakeServer.seen[0]
        self.assertEqual(path, "/api/v1/ingest/events/batch")
        self.assertEqual(headers["x-api-key"], "sxk_k")
        self.assertIn("idempotency-key", headers)

    def test_revoked_key_stops_the_agent(self):
        FakeServer.mode["m"] = "401"
        st = ag.State(self.d); st.spool_append([self._event(1)])
        with self.assertRaises(ag.Unauthorized):
            ag.send_spool(ag.Client(self.url, "bad"), st)
        self.assertEqual(len(st.spool_read(10)), 1)  # nothing lost

    def test_heartbeat_reports_source_status(self):
        body = ag.heartbeat_body({"Security": {"status": "permission_denied", "detail": "x"}}, 5, None)
        self.assertEqual(body["sources"]["Security"]["status"], "permission_denied")
        self.assertEqual(body["agent_version"], ag.VERSION)


if __name__ == "__main__":
    unittest.main()
