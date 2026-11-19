import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.domain import mitre
from app.domain.normalizer import normalize
from app.domain.rule_loader import load_rule_files, parse_yaml_rule
from app.domain.rules import RuleEngine, RuleError, parse_rule
from app.samples import build_scenario

RULES_DIR = Path(__file__).resolve().parents[2] / "detection-rules"
BASE = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


def load_engine(only=None):
    rules = []
    for _, data, _ in load_rule_files(RULES_DIR):
        if only is None or data["id"] in only:
            rules.append(parse_rule(data))
    return RuleEngine(rules)


def run_scenario(engine, scenario=None, now=BASE + timedelta(minutes=30)):
    scenario = scenario or build_scenario(BASE)
    dets, events = [], []
    for host, envs in scenario.items():
        for env in envs:
            d = normalize(env, collector_id=host.lower(), host_id=None, host_name=host, ingested_at=now)
            events.append(d)
    events.sort(key=lambda e: e["@timestamp"])
    for d in events:
        dets.extend(engine.evaluate(d))
    return dets


class RuleParsingTests(unittest.TestCase):
    def test_all_shipped_rules_parse_and_map_to_known_techniques(self):
        files = load_rule_files(RULES_DIR)
        self.assertGreaterEqual(len(files), 12)
        keys = set()
        for _, data, _ in files:
            rule = parse_rule(data)
            self.assertNotIn(rule.key, keys, "duplicate rule id")
            keys.add(rule.key)
            for m in rule.mitre:
                self.assertIn(m["technique_id"], mitre.TECHNIQUES, f"{rule.key} -> {m}")

    def test_invalid_rules_rejected(self):
        bad = [
            {"id": "x", "title": "t", "severity": "high", "match": []},                      # bad id
            {"id": "SX-1", "title": "t", "severity": "bogus", "match": []},                 # bad severity
            {"id": "SX-1", "title": "t", "severity": "high", "type": "threshold", "match": [],
             "threshold": {"count": 0}, "group_by": ["a"]},                                  # bad count
            {"id": "SX-1", "title": "t", "severity": "high", "match": [{"field": "a", "op": "regex", "value": "("}]},
            {"id": "SX-1", "title": "t", "severity": "high", "match": [{"field": "a", "op": "nope", "value": 1}]},
        ]
        for b in bad:
            with self.assertRaises(RuleError, msg=str(b)):
                parse_rule(b)

    def test_yaml_parse_error(self):
        with self.assertRaises(RuleError):
            parse_yaml_rule("id: [unclosed")


class ScenarioDetectionTests(unittest.TestCase):
    """Positive cases: the synthetic scenario must trigger every shipped rule."""

    @classmethod
    def setUpClass(cls):
        cls.dets = run_scenario(load_engine())
        cls.by_rule = {}
        for d in cls.dets:
            cls.by_rule.setdefault(d.rule_key, []).append(d)

    def test_every_rule_fires(self):
        expected = {"SX-AUTH-001", "SX-AUTH-002", "SX-AUTH-003", "SX-PRIV-001", "SX-PRIV-002", "SX-EXEC-001",
                    "SX-EXEC-002", "SX-EXEC-003", "SX-EVAS-001", "SX-PERSIST-001", "SX-NET-001", "SX-NET-002"}
        self.assertEqual(expected - set(self.by_rule), set(), "rules that did not fire")

    def test_ssh_threshold_has_evidence_and_rule_version(self):
        d = self.by_rule["SX-AUTH-001"][-1]
        self.assertGreaterEqual(d.count, 5)
        self.assertEqual(d.group, {"source.ip": "203.0.113.50"})
        self.assertEqual(d.rule_version, 1)
        self.assertTrue(all(e["event_id"] for e in d.evidence))
        self.assertEqual(len(d.event_ids), len(d.evidence))

    def test_success_after_failures_includes_both_stages(self):
        d = self.by_rule["SX-AUTH-003"]
        users = {x.group["user.name"] for x in d}
        self.assertEqual(users, {"admin", "labuser"})
        lnx = [x for x in d if x.group["user.name"] == "admin"][0]
        self.assertEqual(lnx.evidence[-1]["event.action"], "ssh_login_success")
        self.assertEqual(lnx.count, 8)  # 7 failures + 1 success

    def test_distinct_port_scan(self):
        d = self.by_rule["SX-NET-002"][-1]
        self.assertGreaterEqual(d.count, 15)
        self.assertEqual(d.group["source.ip"], "192.0.2.99")

    def test_dedupe_key_stable_within_bucket(self):
        keys = {d.dedupe_key for d in self.by_rule["SX-AUTH-001"]}
        self.assertEqual(len(keys), 1, "one burst must map to one dedupe key")

    def test_exclusion_suppresses_lab_automation(self):
        # the automation PowerShell has the same flags; only the labuser one may alert
        ps = self.by_rule["SX-EXEC-001"]
        users = {d.user for d in ps}
        self.assertEqual(users, {"labuser"})
        self.assertEqual(ps[-1].count, 1)

    def test_detection_carries_mitre_and_context(self):
        d = self.by_rule["SX-EXEC-001"][0]
        self.assertEqual([m["technique_id"] for m in d.mitre], ["T1059.001", "T1027"])
        self.assertTrue(d.rule_context["next_checks"])


class NegativeFixtureTests(unittest.TestCase):
    def _events(self, source, raws, host="LAB-WIN-01", start=0, step=5):
        out = []
        for i, raw in enumerate(raws):
            env = {"event_id": f"n{i}", "timestamp": (BASE + timedelta(seconds=start + i * step)).isoformat(),
                   "source_type": source, "raw": raw}
            out.append(normalize(env, collector_id="c", host_id=None, host_name=host, ingested_at=BASE + timedelta(hours=1)))
        return out

    def test_four_failures_do_not_trigger_threshold(self):
        eng = load_engine({"SX-AUTH-001"})
        evs = self._events("linux_auth", [{"program": "sshd", "message": "Failed password for root from 203.0.113.9 port 1 ssh2"}] * 4)
        self.assertEqual([d for e in evs for d in eng.evaluate(e)], [])

    def test_failures_outside_window_do_not_trigger(self):
        eng = load_engine({"SX-AUTH-001"})
        raws = [{"program": "sshd", "message": "Failed password for root from 203.0.113.9 port 1 ssh2"}] * 5
        evs = self._events("linux_auth", raws, step=100)  # 100s apart -> never 5 within 300s? (5 events span 400s)
        got = [d for e in evs for d in eng.evaluate(e)]
        self.assertEqual(got, [])

    def test_success_without_failures_is_not_sequence_hit(self):
        eng = load_engine({"SX-AUTH-003"})
        evs = self._events("linux_auth", [{"program": "sshd", "message": "Accepted password for bob from 203.0.113.9 port 22 ssh2"}])
        self.assertEqual([d for e in evs for d in eng.evaluate(e)], [])

    def test_failures_for_other_account_do_not_pair_with_success(self):
        eng = load_engine({"SX-AUTH-003"})
        raws = [{"program": "sshd", "message": "Failed password for alice from 203.0.113.9 port 1 ssh2"}] * 6
        raws.append({"program": "sshd", "message": "Accepted password for bob from 203.0.113.9 port 22 ssh2"})
        evs = self._events("linux_auth", raws)
        self.assertEqual([d for e in evs for d in eng.evaluate(e)], [])

    def test_benign_powershell_does_not_alert(self):
        eng = load_engine({"SX-EXEC-001"})
        evs = self._events("sysmon", [{"EventID": 1, "User": "LAB\\u", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                       "CommandLine": "powershell.exe -Command Get-Date"}])
        self.assertEqual([d for e in evs for d in eng.evaluate(e)], [])

    def test_common_outbound_ports_do_not_alert(self):
        eng = load_engine({"SX-NET-001"})
        evs = self._events("sysmon", [{"EventID": 3, "Image": "powershell.exe", "DestinationIp": "198.51.100.5",
                                       "DestinationPort": 443, "Initiated": "true"}])
        self.assertEqual([d for e in evs for d in eng.evaluate(e)], [])

    def test_normal_program_from_program_files_does_not_alert(self):
        eng = load_engine({"SX-EXEC-003"})
        evs = self._events("sysmon", [{"EventID": 1, "User": "LAB\\u", "Image": "C:\\Program Files\\App\\app.exe"}])
        self.assertEqual([d for e in evs for d in eng.evaluate(e)], [])

    def test_duplicate_scenario_replay_state_does_not_double_fire_sequence(self):
        eng = load_engine({"SX-AUTH-003"})
        first = run_scenario(eng)
        self.assertEqual(len(first), 2)  # one per (user, ip) group


class IdempotencyTests(unittest.TestCase):
    def test_reevaluating_same_event_does_not_double_count(self):
        eng = load_engine({"SX-AUTH-001"})
        evs = []
        for i in range(5):
            env = {"event_id": f"d{i}", "timestamp": (BASE + timedelta(seconds=i)).isoformat(), "source_type": "linux_auth",
                   "raw": {"program": "sshd", "message": "Failed password for root from 203.0.113.9 port 1 ssh2"}}
            evs.append(normalize(env, collector_id="c", host_id=None, host_name="H", ingested_at=BASE + timedelta(hours=1)))
        for e in evs[:4]:
            self.assertEqual(eng.evaluate(e), [])
        for e in evs[:4]:  # redelivered duplicates: must not push the count to 5
            self.assertEqual(eng.evaluate(e), [])
        first = eng.evaluate(evs[4])
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].count, 5)
        self.assertIs(eng.evaluate(evs[4]), first)  # retry returns the same result


class ConditionTests(unittest.TestCase):
    def test_operators(self):
        r = parse_rule({"id": "SX-T-1", "title": "t", "severity": "low", "type": "match", "match": {"all": [
            {"field": "a.b", "op": "contains_any", "value": ["foo", "bar"]},
            {"field": "n", "op": "gte", "value": 5},
            {"not": {"field": "x", "op": "eq", "value": "no"}},
            {"field": "tags", "op": "in", "value": ["red"]},
            {"field": "missing", "op": "ne", "value": "z"},
        ]}})
        ev = {"a": {"b": "xxFOOxx"}, "n": 7, "x": "yes", "tags": ["blue", "RED"]}
        self.assertTrue(r.match(ev))
        self.assertFalse(r.match({**ev, "n": 1}))

    def test_faulty_state_never_crashes_engine(self):
        eng = load_engine()
        # event with unexpected shapes must not raise
        doc = {"@timestamp": "2026-11-14T12:00:00Z", "event": {"id": "x", "category": "weird"}, "process": "notadict"}
        self.assertEqual(eng.evaluate(doc), [])


if __name__ == "__main__":
    unittest.main()
