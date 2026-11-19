"""Cross-tenant isolation at the engine and storage level (runs without any web framework)."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.domain.memory_backends import MemoryEventStore
from app.domain.normalizer import normalize
from app.domain.query import EventQuery, QueryError
from app.domain.rule_loader import load_rule_files
from app.domain.rules import RuleEngine, parse_rule
from app.domain.tenancy import DEFAULT_ORG_ID
from app.infra.sqlite_store import SqliteEventStore

RULES = Path(__file__).resolve().parents[2] / "detection-rules"
BASE = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
ORG_A, ORG_B = "aaaaaaaa-0000-0000-0000-00000000000a", "bbbbbbbb-0000-0000-0000-00000000000b"


def fail_event(i, org, ip="203.0.113.9", host="H1"):
    env = {"event_id": f"{org[:1]}{i}", "timestamp": (BASE + timedelta(seconds=i)).isoformat(), "source_type": "linux_auth",
           "raw": {"program": "sshd", "message": f"Failed password for root from {ip} port 1 ssh2"}}
    return normalize(env, collector_id=f"c-{org[:1]}", host_id=None, host_name=host, org_id=org,
                     ingested_at=BASE + timedelta(hours=1))


def engine():
    return RuleEngine([parse_rule(d) for _, d, _ in load_rule_files(RULES) if d["id"] == "SX-AUTH-001"])


class EngineIsolation(unittest.TestCase):
    def test_counters_are_not_shared_between_organizations(self):
        eng = engine()
        out = []
        for i in range(3):  # 3 failures each from the SAME ip/host name in two orgs = 6 total, threshold is 5
            out += eng.evaluate(fail_event(i, ORG_A))
            out += eng.evaluate(fail_event(i + 10, ORG_B))
        self.assertEqual(out, [], "tenants must never pool events toward one threshold")

    def test_each_org_gets_its_own_alert_key_and_evidence(self):
        eng = engine()
        a = b = None
        for i in range(5):
            a = eng.evaluate(fail_event(i, ORG_A)) or a
            b = eng.evaluate(fail_event(i + 10, ORG_B)) or b
        self.assertTrue(a and b)
        da, db = a[0], b[0]
        self.assertNotEqual(da.dedupe_key, db.dedupe_key)
        self.assertEqual((da.org_id, db.org_id), (ORG_A, ORG_B))
        self.assertTrue(all(e["event_id"].startswith("c-a") for e in da.evidence))
        self.assertTrue(all(e["event_id"].startswith("c-b") for e in db.evidence))


class StoreIsolation(unittest.TestCase):
    def _fill(self, store):
        for org in (ORG_A, ORG_B, DEFAULT_ORG_ID):
            for i in range(3):
                store.index(fail_event(i, org))
        legacy = fail_event(99, ORG_A)
        legacy.pop("org")  # a document written before multi-tenancy
        legacy["event"]["id"] = "legacy-1"
        store.index(legacy)

    def _check(self, store):
        self._fill(store)
        q = lambda org: EventQuery(start=BASE - timedelta(hours=1), end=BASE + timedelta(hours=2), size=100, org_id=org)  # noqa: E731
        ta, ha = store.search(q(ORG_A))
        tb, hb = store.search(q(ORG_B))
        td, hd = store.search(q(DEFAULT_ORG_ID))
        self.assertEqual((ta, tb, td), (3, 3, 4))  # default org = 3 own + 1 legacy document
        self.assertTrue(all(h["org"]["id"] == ORG_A for h in ha))
        self.assertTrue(all(h["org"]["id"] == ORG_B for h in hb))
        self.assertNotIn("legacy-1", {h["event"]["id"] for h in ha + hb})
        agg = store.aggregate(BASE - timedelta(hours=1), BASE + timedelta(hours=2), 60, ORG_B)
        self.assertEqual(agg["total"], 3)
        with self.assertRaises((QueryError, ValueError)):
            store.search(EventQuery(start=BASE, end=BASE + timedelta(hours=1)))  # no scope -> refused
        with self.assertRaises(ValueError):
            store.aggregate(BASE, BASE + timedelta(hours=1), 60, "")

    def test_memory_store(self):
        self._check(MemoryEventStore())

    def test_sqlite_store(self):
        self._check(SqliteEventStore(tempfile.mkdtemp() + "/e.db"))

    def test_text_search_cannot_cross_tenants(self):
        s = MemoryEventStore()
        self._fill(s)
        q = EventQuery(start=BASE - timedelta(hours=1), end=BASE + timedelta(hours=2), text="203.0.113.9", size=100, org_id=ORG_A)
        self.assertEqual(s.search(q)[0], 3)


if __name__ == "__main__":
    unittest.main()
