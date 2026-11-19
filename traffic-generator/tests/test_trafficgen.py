"""Unit tests that need no Docker: python3 -m unittest discover -s tests"""

import json
import tempfile
import unittest
from pathlib import Path

from trafficgen import activities, check, planner, scenario

ROOT = Path(__file__).resolve().parent.parent


def write(text: str) -> Path:
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write(text)
    f.close()
    return Path(f.name)


GOOD = """
scenario: t
seed: 5
duration_s: 600
hosts:
  pc1: { events_per_hour: 300, activities: { http_home: 1, dns_lookup: 1 } }
  iot1: { events_per_hour: 30, activities: { dhcp_renew: 1 } }
blocked_attempts:
  - { at_s: 100, src: pc1, dst: db1, port: 5432 }
"""


class PlannerTests(unittest.TestCase):
    def plan(self, text=GOOD, seed=None):
        sc = scenario.load(write(text))
        if seed is not None:
            sc = scenario.Scenario(sc.name, seed, sc.duration_s, sc.hosts, sc.blocked, sc.sha256, sc.path)
        return [a.to_dict() for a in planner.plan(sc)]

    def test_same_seed_same_plan(self):
        self.assertEqual(self.plan(), self.plan())

    def test_different_seed_different_plan(self):
        self.assertNotEqual(self.plan(seed=1), self.plan(seed=2))

    def test_adding_a_host_does_not_change_other_hosts(self):
        more = GOOD.replace("hosts:\n", "hosts:\n  pc2: { events_per_hour: 100, activities: { http_api: 1 } }\n")
        pc1_a = [(a["at_s"], a["activity"]) for a in self.plan() if a["src_host"] == "pc1"]
        pc1_b = [(a["at_s"], a["activity"]) for a in self.plan(more) if a["src_host"] == "pc1"]
        self.assertEqual(pc1_a, pc1_b)

    def test_plan_sorted_within_duration_and_numbered(self):
        p = self.plan()
        self.assertEqual([a["seq"] for a in p], list(range(1, len(p) + 1)))
        self.assertEqual([a["at_s"] for a in p], sorted(a["at_s"] for a in p))
        self.assertTrue(all(0 <= a["at_s"] < 600 for a in p))

    def test_blocked_attempt_is_planned_at_its_time(self):
        b = [a for a in self.plan() if a["activity"] == "blocked_probe"]
        self.assertEqual(len(b), 1)
        self.assertEqual((b[0]["at_s"], b[0]["expected"], b[0]["dst_port"]), (100, "blocked", 5432))

    def test_rate_roughly_respected(self):
        n = sum(1 for a in self.plan() if a["src_host"] == "pc1")
        self.assertTrue(25 <= n <= 80, n)  # mean 50 for 300/h over 10 min

    def test_shipped_scenarios_load(self):
        for f in (ROOT / "scenarios").glob("*.yaml"):
            self.assertTrue(planner.plan(scenario.load(f)), f)


class ScenarioValidationTests(unittest.TestCase):
    def bad(self, text, msg):
        with self.assertRaises(scenario.ScenarioError) as cm:
            scenario.load(write(text))
        self.assertIn(msg, str(cm.exception))

    def test_unknown_activity(self):
        self.bad(GOOD.replace("dns_lookup", "ftp_upload"), "unknown activity")

    def test_unknown_host(self):
        self.bad(GOOD.replace("iot1:", "web9:"), "unknown client")

    def test_blocked_outside_run(self):
        self.bad(GOOD.replace("at_s: 100", "at_s: 9000"), "within the run")

    def test_missing_seed(self):
        self.bad(GOOD.replace("seed: 5\n", ""), "missing 'seed'")


class ActivityTests(unittest.TestCase):
    def test_classify(self):
        blocked = activities.blocked_probe("pc1", "db1", 5432)
        self.assertEqual(activities.classify(blocked, 1, ""), "blocked")
        self.assertEqual(activities.classify(blocked, 0, ""), "success")  # firewall hole!
        ssh = activities.ssh_handshake("pc1", None)
        self.assertEqual(activities.classify(ssh, 255, "Permission denied (publickey)"), "success")
        self.assertEqual(activities.classify(ssh, 255, "Connection timed out"), "failed")
        self.assertEqual(activities.classify(ssh, None, ""), "timeout")

    def test_visibility(self):
        import random
        http = activities.http_home("pc1", random.Random(0))
        self.assertEqual(set(activities.expected_visibility("pc1", http)), {"probe1", "probe2"})
        blocked = activities.blocked_probe("pc1", "db1", 5432)
        self.assertEqual(activities.expected_visibility("pc1", blocked), {"probe2": ["conn:S0"]})
        dns = activities.dns_lookup("iot1", random.Random(0))
        self.assertEqual(set(activities.expected_visibility("iot1", dns)), {"probe1"})


class CheckTests(unittest.TestCase):
    def test_match_and_leak(self):
        tmp = Path(tempfile.mkdtemp())
        run, net = tmp / "R1", tmp / "network"
        run.mkdir()
        (net / "probe-logs").mkdir(parents=True)
        (net / "probe2-logs").mkdir()
        rows = [
            {"seq": 1, "activity": "http_home", "service": "http", "result": "success", "expected": "allowed",
             "as_expected": True, "ts_start": 100.0, "ts_end": 100.5, "src_ip": "10.10.10.5",
             "dst_ip": "10.10.20.20", "dst_port": 80, "proto": "tcp",
             "marker": {"http_user_agent": "NOTLINE/R1/1"},
             "expected_visibility": {"probe1": ["http"], "probe2": ["http"]}},
            {"seq": 2, "activity": "blocked_probe", "service": "tcp", "result": "blocked", "expected": "blocked",
             "as_expected": True, "ts_start": 200.0, "ts_end": 203.0, "src_ip": "10.10.10.5",
             "dst_ip": "10.10.30.10", "dst_port": 5432, "proto": "tcp",
             "expected_visibility": {"probe2": ["conn:S0"]}},
        ]
        (run / "ledger.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        (net / "probe2-logs" / "http.log").write_text(json.dumps({"ts": 100.1, "user_agent": "NOTLINE/R1/1"}) + "\n")
        conn = {"ts": 200.1, "id.orig_h": "10.10.10.5", "id.resp_h": "10.10.30.10", "id.resp_p": 5432, "proto": "tcp"}
        (net / "probe2-logs" / "conn.log").write_text(json.dumps(conn) + "\n")
        (net / "probe-logs" / "conn.log").write_text(json.dumps(conn) + "\n")  # leak past firewall
        rep = check.run_check(run, net)
        whys = sorted((m["seq"], m["probe"], m["why"]) for m in rep["misses"])
        self.assertEqual(whys, [(1, "probe1", "not found in logs"),
                                (2, "probe1", "blocked attempt visible past the firewall")])


if __name__ == "__main__":
    unittest.main()
