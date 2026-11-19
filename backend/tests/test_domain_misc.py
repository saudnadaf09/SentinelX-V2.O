import json
import unittest
from datetime import datetime, timedelta, timezone

from app.domain import ai_analysis as ai
from app.domain.correlation import AlertRef, find_relations, is_global_ip
from app.domain.memory_backends import MemoryEventStore, MemoryQueue
from app.domain.query import EventQuery, Filter, QueryError
from app.domain.redaction import redact_text
from app.domain.response_actions import ActionError, MockAdapter, get_adapter, validate_action

T0 = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
ORG = "00000000-0000-0000-0000-000000000001"


def ref(i, rule, host=None, user=None, ip=None, off=0, dur=60):
    return AlertRef(id=i, rule_key=rule, severity="high", first_seen=T0 + timedelta(seconds=off),
                    last_seen=T0 + timedelta(seconds=off + dur), host=host, user=user, source_ip=ip)


class CorrelationTests(unittest.TestCase):
    def test_same_host_and_user_correlates_with_reason(self):
        rel = find_relations(ref("n", "B", "H1", "bob", off=120), [ref("a", "A", "H1", "bob")])
        self.assertEqual(len(rel), 1)
        self.assertIn("host 'H1'", rel[0].reason)
        self.assertIn("user 'bob'", rel[0].reason)

    def test_host_only_does_not_correlate(self):
        self.assertEqual(find_relations(ref("n", "B", "H1", "x"), [ref("a", "A", "H1", "y")]), [])

    def test_outside_window_does_not_correlate(self):
        self.assertEqual(find_relations(ref("n", "B", "H1", "bob", off=5000), [ref("a", "A", "H1", "bob")]), [])

    def test_same_rule_not_correlated(self):
        self.assertEqual(find_relations(ref("n", "A", "H1", "bob"), [ref("a", "A", "H1", "bob")]), [])

    def test_public_ip_alone_never_correlates_but_documentation_ip_does(self):
        self.assertTrue(is_global_ip("8.8.8.8"))
        self.assertFalse(is_global_ip("203.0.113.5"))
        self.assertEqual(find_relations(ref("n", "B", ip="8.8.8.8"), [ref("a", "A", ip="8.8.8.8")]), [])
        self.assertEqual(len(find_relations(ref("n", "B", ip="203.0.113.5"), [ref("a", "A", ip="203.0.113.5")])), 1)


class RedactionTests(unittest.TestCase):
    def test_secrets_removed(self):
        s = redact_text("net use /user:x password=Hunter2 -p secret123 mail bob@example.com Authorization: Bearer abc.def")
        for leaked in ("Hunter2", "secret123", "bob@example.com", "abc.def"):
            self.assertNotIn(leaked, s)


class ResponseActionTests(unittest.TestCase):
    def test_allowlist(self):
        with self.assertRaises(ActionError):
            validate_action("run_shell", {"cmd": "rm -rf /"})
        with self.assertRaises(ActionError):
            validate_action("isolate_lab_host", {"cmd": "x"})  # unexpected param
        with self.assertRaises(ActionError):
            validate_action("disable_test_account", {"account": "Administrator"})
        with self.assertRaises(ActionError):
            validate_action("disable_test_account", {"account": "a b; rm"})
        with self.assertRaises(ActionError):
            validate_action("block_test_indicator", {"ip": "8.8.8.8"})
        with self.assertRaises(ActionError):
            validate_action("collect_evidence", {"script": "../../etc/passwd"})
        self.assertEqual(validate_action("block_test_indicator", {"ip": "203.0.113.50"}), {"ip": "203.0.113.50"})
        self.assertEqual(validate_action("isolate_lab_host", {}), {})

    def test_mock_adapter_is_simulation_only(self):
        a = MockAdapter()
        r = a.execute("isolate_lab_host", {}, "LAB-WIN-01")
        self.assertTrue(r["simulated"])
        self.assertFalse(r["changes_made_outside_sentinelx"])
        self.assertFalse(a.dry_run("isolate_lab_host", {}, "H")["changes_made"])
        with self.assertRaises(ActionError):
            get_adapter("firewall")


class AiTests(unittest.TestCase):
    ALERT = {"id": "a1", "title": "T", "severity": "high", "status": "new", "rule_key": "R", "rule_version": 1,
             "explanation": "x", "first_seen": "t0", "last_seen": "t1", "event_count": 2, "host_name": "H",
             "user_name": "u", "source_ip": "203.0.113.5", "correlation_reason": None,
             "rule_context": {"description": "d", "false_positives": ["fp"], "next_checks": ["nc"]},
             "mitre": [{"technique_id": "T1110", "name": "Brute Force"}],
             "evidence": [{"event_id": "c:1", "event.action": "ssh_login_failed", "process.command_line": "x password=abc123"}]}

    def test_package_is_redacted_and_bounded(self):
        pkg = ai.build_evidence_package(self.ALERT, [])
        self.assertNotIn("abc123", json.dumps(pkg))
        prompt = ai.build_user_prompt(pkg)
        self.assertIn("<untrusted_evidence>", prompt)

    def test_invented_event_ids_are_dropped(self):
        out = ai.validate_output(json.dumps({"summary": "s", "hypotheses": ["maybe brute force"], "recommendations": ["reset password"], "unknowns": ["no auth log"], "evidence": [
            {"event_id": "c:1", "observation": "ok"}, {"event_id": "FAKE", "observation": "made up"}]}), {"c:1"})
        self.assertEqual([e["event_id"] for e in out["evidence"]], ["c:1"])
        self.assertEqual((out["hypotheses"], out["recommendations"], out["unknowns"]), (["maybe brute force"], ["reset password"], ["no auth log"]))
        self.assertTrue(any("unknown event IDs" in l for l in out["limitations"]))

    def test_json_fenced_output_and_garbage(self):
        ok = ai.validate_output("```json\n{\"summary\": \"hi\"}\n```", set())
        self.assertEqual(ok["summary"], "hi")
        with self.assertRaises(ValueError):
            ai.validate_output("I cannot do that", set())

    def test_deterministic_fallback_uses_rule_metadata(self):
        out = ai.deterministic_analysis(ai.build_evidence_package(self.ALERT, []))
        self.assertEqual(out["benign_explanations"], ["fp"])
        self.assertEqual(out["next_checks"], ["nc"])
        self.assertEqual(out["evidence"][0]["event_id"], "c:1")
        self.assertIn("no language model", out["assessment"])


class StoreAndQueueTests(unittest.TestCase):
    def doc(self, i, ts, host="H1", cmd="x"):
        return {"@timestamp": ts, "event": {"id": i, "category": ["process"]}, "host": {"name": host},
                "process": {"command_line": cmd}}

    def test_duplicate_event_not_indexed_twice(self):
        s = MemoryEventStore()
        self.assertTrue(s.index(self.doc("a", "2026-11-14T12:00:00Z")))
        self.assertFalse(s.index(self.doc("a", "2026-11-14T12:00:00Z")))

    def test_search_filters_time_text_pagination(self):
        s = MemoryEventStore()
        for i in range(5):
            s.index(self.doc(f"e{i}", f"2026-11-14T12:0{i}:00Z", cmd="powershell -enc" if i % 2 else "calc"))
        q = EventQuery(start=T0, end=T0 + timedelta(hours=1), text="powershell", size=10, org_id=ORG)
        total, hits = s.search(q)
        self.assertEqual(total, 2)
        q = EventQuery(start=T0, end=T0 + timedelta(hours=1), filters=[Filter("host.name", "eq", "h1")], size=2, page=2, org_id=ORG)
        total, hits = s.search(q)
        self.assertEqual((total, len(hits)), (5, 2))
        self.assertEqual(hits[0]["event"]["id"], "e2")  # newest first, page 2

    def test_query_validation(self):
        bad = [EventQuery(T0, T0 - timedelta(hours=1), org_id=ORG), EventQuery(T0, T0 + timedelta(days=40), org_id=ORG),
               EventQuery(T0, T0 + timedelta(hours=1), filters=[Filter("raw.secret", "eq", "x")], org_id=ORG),
               EventQuery(T0, T0 + timedelta(hours=1), size=1000, org_id=ORG),
               EventQuery(T0, T0 + timedelta(hours=1), page=500, size=100, org_id=ORG),
               EventQuery(T0, T0 + timedelta(hours=1))]  # no org scope -> rejected
        for q in bad:
            with self.assertRaises(QueryError):
                q.validate()

    def test_queue_retry_then_dead_letter(self):
        q = MemoryQueue()
        q.publish([{"x": 1}])
        mid, payload = q.consume("c")[0]
        self.assertEqual(q.retry_or_dead_letter(mid, payload, "boom"), "retry")
        mid, payload = q.consume("c")[0]
        q.retry_or_dead_letter(mid, payload, "boom")
        mid, payload = q.consume("c")[0]
        self.assertEqual(q.retry_or_dead_letter(mid, payload, "boom"), "dead_letter")
        self.assertEqual(q.stats()["dead_letter_depth"], 1)
        self.assertEqual(q.requeue_dead_letters(), 1)
        self.assertEqual(q.stats()["depth"], 1)

    def test_idempotency_key(self):
        q = MemoryQueue()
        self.assertFalse(q.seen_idempotency("k"))
        self.assertTrue(q.seen_idempotency("k"))


if __name__ == "__main__":
    unittest.main()


class SqliteStoreTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from app.infra.sqlite_store import SqliteEventStore
        self.dir = tempfile.mkdtemp()
        self.path = self.dir + "/e.db"
        self.s = SqliteEventStore(self.path)

    def doc(self, i, ts, host="H1", cmd="x"):
        return {"@timestamp": ts, "event": {"id": i, "category": ["process"]}, "host": {"name": host},
                "process": {"command_line": cmd}}

    def test_persistence_dedupe_search_aggregate_retention(self):
        from app.infra.sqlite_store import SqliteEventStore
        self.assertTrue(self.s.index(self.doc("a", "2026-11-14T12:00:00Z", cmd="powershell -enc")))
        self.assertFalse(self.s.index(self.doc("a", "2026-11-14T12:00:00Z")))
        self.s.index(self.doc("b", "2026-11-14T12:30:00.500000Z", host="H2"))
        reopened = SqliteEventStore(self.path)  # survives a restart
        self.assertTrue(reopened.exists(self.doc("a", "2026-11-14T12:00:00Z")))
        self.assertEqual(reopened.get("b")["host"]["name"], "H2")
        q = EventQuery(start=T0, end=T0 + timedelta(hours=1), text="powershell", size=10, org_id=ORG)
        self.assertEqual(reopened.search(q)[0], 1)
        q2 = EventQuery(start=T0, end=T0 + timedelta(hours=1), filters=[Filter("host.name", "eq", "h2")], org_id=ORG)
        self.assertEqual(reopened.search(q2)[0], 1)
        agg = reopened.aggregate(T0, T0 + timedelta(hours=2), 60, ORG)
        self.assertEqual((agg["total"], len(agg["top_hosts"])), (2, 2))
        self.assertEqual(reopened.delete_older_than(3650), 0)  # nothing is that old
        self.assertEqual(reopened.delete_older_than(0), 2)     # retention of 0 days removes everything past
