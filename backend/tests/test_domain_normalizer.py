import unittest
from datetime import datetime, timezone

from app.domain.normalizer import NormalizationError, normalize
from app.domain.fields import get_field

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


def norm(source, raw, ts="2026-11-14T11:59:00Z", eid="e1"):
    return normalize({"event_id": eid, "timestamp": ts, "source_type": source, "raw": raw,
                      "host": {"name": "SPOOFED"}}, collector_id="lab-win-01", host_id="h1",
                     host_name="LAB-WIN-01", ingested_at=NOW)


class NormalizerTests(unittest.TestCase):
    def test_sysmon_process_creation(self):
        d = norm("sysmon", {"EventID": 1, "User": "LAB\\labuser", "Image": "C:\\Windows\\System32\\powershell.exe",
                            "CommandLine": "powershell.exe -enc AAA", "ProcessId": "42"})
        self.assertEqual(get_field(d, "process.name"), "powershell.exe")
        self.assertEqual(get_field(d, "user.name"), "labuser")
        self.assertEqual(get_field(d, "user.domain"), "LAB")
        self.assertEqual(get_field(d, "process.pid"), 42)
        self.assertEqual(get_field(d, "event.id"), "lab-win-01:e1")
        self.assertEqual(d["@timestamp"], "2026-11-14T11:59:00Z")
        self.assertIn("EventID", d["raw"])  # original fields preserved

    def test_host_is_server_authoritative(self):
        d = norm("sysmon", {"EventID": 1, "Image": "a.exe"})
        self.assertEqual(get_field(d, "host.name"), "LAB-WIN-01")
        self.assertEqual(get_field(d, "labels.reported_host"), "SPOOFED")

    def test_sysmon_network(self):
        d = norm("sysmon", {"EventID": 3, "Image": "x.exe", "DestinationIp": "198.51.100.20",
                            "DestinationPort": "4444", "Initiated": "true"})
        self.assertEqual(get_field(d, "destination.port"), 4444)
        self.assertEqual(get_field(d, "network.direction"), "egress")

    def test_invalid_ip_is_dropped_not_trusted(self):
        d = norm("windows_security", {"EventID": 4625, "TargetUserName": "u", "IpAddress": "-"})
        self.assertIsNone(get_field(d, "source.ip"))
        self.assertEqual(get_field(d, "event.outcome"), "failure")

    def test_linux_ssh_failed_and_accepted(self):
        f = norm("linux_auth", {"program": "sshd",
                 "message": "Failed password for invalid user admin from 203.0.113.50 port 4242 ssh2"})
        self.assertEqual(get_field(f, "event.action"), "ssh_login_failed")
        self.assertEqual(get_field(f, "source.ip"), "203.0.113.50")
        self.assertEqual(get_field(f, "user.name"), "admin")
        a = norm("linux_auth", {"program": "sshd", "message": "Accepted password for bob from 203.0.113.50 port 22 ssh2"})
        self.assertEqual(get_field(a, "event.outcome"), "success")

    def test_linux_group_add_and_useradd(self):
        g = norm("linux_auth", {"program": "usermod", "message": "add 'svc' to group 'sudo'"})
        self.assertEqual(get_field(g, "group.name"), "sudo")
        u = norm("linux_auth", {"program": "useradd", "message": "new user: name=svc, UID=1002"})
        self.assertEqual(get_field(u, "event.action"), "user_created")

    def test_suricata_flow(self):
        d = norm("suricata", {"event_type": "flow", "src_ip": "192.0.2.99", "dest_ip": "192.0.2.10", "dest_port": 22, "proto": "TCP"})
        self.assertEqual(get_field(d, "network.transport"), "tcp")

    def test_malformed_events_are_rejected(self):
        with self.assertRaises(NormalizationError):
            norm("sysmon", {"Image": "a.exe"})  # no EventID
        with self.assertRaises(NormalizationError):
            norm("sysmon", {"EventID": 1}, ts="not-a-time")
        with self.assertRaises(NormalizationError):
            norm("sysmon", {"EventID": 1}, ts="2030-01-01T00:00:00Z")  # far future
        with self.assertRaises(NormalizationError):
            norm("unknown", {})
        with self.assertRaises(NormalizationError):
            norm("linux_auth", {"program": "sshd"})  # missing message

    def test_oversized_raw_is_truncated(self):
        d = norm("sysmon", {"EventID": 1, "Image": "a.exe", "Blob": "x" * 30000})
        self.assertTrue(d["raw"]["truncated"])


if __name__ == "__main__":
    unittest.main()
