import json
import sqlite3
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path
from unittest.mock import patch

from discovery.db import add_change, connect_state, stable_id, transaction
from discovery.engine import (
    DEFAULT_DORMANT_AFTER_US,
    _address,
    _ensure_asset,
    _reconcile_assignment,
    maintain,
    run,
)
from discovery.export import changes, snapshot
import discovery.engine as engine


PROJECT = Path(__file__).resolve().parents[2]
MODULE4 = PROJECT / "log-ingestion/data/notline.db"


class PipelineTests(unittest.TestCase):
    def test_mac_scope_matching_is_conservative(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            con = connect_state(state)
            with transaction(con):
                unscoped = _ensure_asset(con, "unscoped", "mac:aa:bb:cc:dd:ee:ff", "identified", 1)
                lab = _ensure_asset(con, "lab", "mac:aa:bb:cc:dd:ee:ff", "identified", 2)
                private = _ensure_asset(con, "private", "mac:aa:bb:cc:dd:ee:ff", "identified", 3)
            self.assertEqual(unscoped, lab)
            self.assertNotEqual(lab, private)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 2)
            con.close()

    def test_unscoped_mac_after_scoped_evidence_reuses_only_unique_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            con = connect_state(state)
            with transaction(con):
                lab = _ensure_asset(con, "lab", "mac:aa:bb:cc:dd:ee:01", "identified", 1)
                unscoped = _ensure_asset(con, "unscoped", "mac:aa:bb:cc:dd:ee:01", "identified", 2)
                _ensure_asset(con, "private", "mac:aa:bb:cc:dd:ee:01", "identified", 3)
                _ensure_asset(con, "lab", "mac:aa:bb:cc:dd:ee:02", "identified", 5)
                _ensure_asset(con, "private", "mac:aa:bb:cc:dd:ee:02", "identified", 6)
                _ensure_asset(con, "unscoped", "mac:aa:bb:cc:dd:ee:02", "identified", 4)
            self.assertEqual(lab, unscoped)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM assets WHERE identity_key LIKE 'mac:%'").fetchone()[0], 5)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM assets WHERE identity_key=?", ("mac:aa:bb:cc:dd:ee:02",)).fetchone()[0], 3)
            con.close()

    @unittest.skipUnless(MODULE4.exists(), "the repository's real Module 4 database is unavailable")
    def test_real_module4_records_produce_useful_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            result = run(str(MODULE4), str(state), batch_size=37)
            self.assertGreater(result["processed"], 0)
            self.assertEqual(result["failed"], 0)
            data = snapshot(str(state))
            software = {(row["name"], row["unparsed_version"], row["role"]) for row in data["software"]}
            self.assertIn(("nginx", "nginx/1.30.7", "server"), software)
            self.assertIn(("OpenSSH", "OpenSSH_9.9", "server"), software)
            self.assertIn(("Express", "Express", "application_server"), software)
            self.assertTrue(any(row["name"] == "Express" and row["version"] is None
                                for row in data["software"]))
            clients = [row for row in data["software"] if row["role"] == "client"]
            self.assertTrue(clients)
            self.assertTrue(all(row["attribution"] == "client_observation" and row["port"] is None
                                for row in clients))
            self.assertTrue({"Wget", "VERIFY", "NOTLINE/R", "OpenSSH"}
                            <= {row["name"] for row in clients})
            self.assertTrue(any(row["association_state"] == "assigned" for row in data["addresses"]))
            self.assertTrue(any(row["association_state"] == "requested" for row in data["addresses"]))
            self.assertTrue(any(row["outcome"] == "target_contact_only" for row in data["interactions"]))
            self.assertEqual(len(data["assets"]), 14)
            self.assertEqual(len(data["addresses"]), 16)
            self.assertEqual(len(data["services"]), 8)
            self.assertEqual(len(data["interactions"]), 250)
            communication_counts = Counter(row["communication_id"] for row in data["interactions"])
            self.assertEqual(len(communication_counts), 211)
            self.assertEqual(sum(count > 1 for count in communication_counts.values()), 39)
            self.assertEqual(max(communication_counts.values()), 2)
            self.assertFalse(any(row["transport"] == "unknown_transport" for row in data["services"]))
            service_changes = [row for row in data["changes"]
                               if row["entity_type"] == "service" and row["action"] == "software_observed"]
            service_claim_ids = {json.loads(row["payload_json"])["software_claim_id"]
                                 for row in service_changes}
            server_claim_ids = {row["claim_id"] for row in data["software"]
                                if row["role"] in {"server", "application_server"}}
            self.assertEqual(service_claim_ids, server_claim_ids)
            self.assertEqual(len(data["evidence"]), len(data["events"]))
            self.assertEqual({row["event_id"] for row in data["evidence"]},
                             {row["event_id"] for row in data["events"]})
            self.assertTrue(all(row["role"] != "client" or row["port"] is None for row in data["software"]))
            event_probe = {row["event_id"]: row["probe_id"] for row in data["events"]}
            sightings = defaultdict(list)
            for row in data["interactions"]:
                sightings[row["communication_id"]].append(event_probe[row["event_id"]])
            self.assertTrue(all(len(set(probes)) == 2 for probes in sightings.values() if len(probes) > 1))
            endpoint_groups = defaultdict(list)
            for row in data["interactions"]:
                endpoint_groups[(row["source_ip"], row["target_ip"], row["target_port"], row["transport"])].append(row)
            self.assertTrue(any(len({row["source_port"] for row in rows}) > 1 and
                                len({row["communication_id"] for row in rows}) > 1
                                for rows in endpoint_groups.values()))
            source = sqlite3.connect(f"file:{MODULE4.resolve()}?mode=ro", uri=True)
            last_sequence = source.execute("SELECT MAX(sequence) FROM observations").fetchone()[0]
            source.close()
            self.assertEqual(data["cursor"][0]["sequence"], last_sequence)

    @unittest.skipUnless(MODULE4.exists(), "the repository's real Module 4 database is unavailable")
    def test_reprocessing_real_records_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            first = run(str(MODULE4), str(state), batch_size=1000)
            second = run(str(MODULE4), str(state), batch_size=1000)
            self.assertEqual(first["processed"], 285)
            self.assertEqual(second["processed"], 0)
            self.assertEqual(second["duplicate"], 0)
            before_changes = [dict(row) for row in snapshot(str(state))["changes"]]
            con = sqlite3.connect(state)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM events").fetchone()[0], 285)
            counts = {
                table: con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("evidence", "assets", "addresses", "services", "software_claims", "interactions", "changes")
            }
            run(str(MODULE4), str(state), batch_size=1000)
            self.assertEqual(counts, {
                table: con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in counts
            })
            con.close()
            self.assertEqual(before_changes, [dict(row) for row in snapshot(str(state))["changes"]])

    def test_assignment_moves_service_and_interaction_to_mac_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            con = connect_state(Path(directory) / "module5.db")
            with transaction(con):
                for event_id, sequence, seen in (("address", 1, 106), ("flow", 2, 106), ("dhcp", 3, 105)):
                    con.execute(
                        "INSERT INTO events(sequence,event_id,event_type,probe_id,observed_at_us,observed_at,"
                        "data_json,quality_flags_json,provenance_json,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (sequence, event_id, "network_connection", "test", seen, str(seen), "{}", "[]", "{}", "processed"),
                    )
                old = _ensure_asset(con, "lab", "ip:10.10.40.104", "provisional", 100, "10.10.40.104")
                _ensure_asset(con, "lab", "ip:10.10.40.104", "provisional", 106, "10.10.40.104")
                _address(con, old, "lab", "10.10.40.104", 106, "address", "source_observed")
                service = stable_id("service", old, "lab", "10.10.40.104", 8080, "tcp")
                con.execute(
                    "INSERT INTO services(service_id,asset_id,scope,ip,port,transport,protocol,state,first_seen_us,last_seen_us) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (service, old, "lab", "10.10.40.104", 8080, "tcp", "http", "protocol_observed", 106, 106),
                )
                con.execute(
                    "INSERT INTO interactions(interaction_id,communication_id,event_id,evidence_id,scope,source_asset_id,"
                    "target_asset_id,source_ip,target_ip,source_port,target_port,transport,protocol,outcome,observed_at_us) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("interaction-old", "communication-old", "flow", None, "lab", old, None,
                     "10.10.40.104", "10.10.10.2", 45000, 53, "tcp", "dns", "response_observed", 106),
                )
                mac = _ensure_asset(con, "lab", "mac:aa:bb:cc:dd:ee:10", "identified", 105)
                _reconcile_assignment(con, mac, "lab", "10.10.40.104", "aa:bb:cc:dd:ee:10", 105, "dhcp")
            self.assertEqual(con.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT asset_id FROM services").fetchone()[0], mac)
            self.assertEqual(con.execute("SELECT source_asset_id FROM interactions").fetchone()[0], mac)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM changes WHERE action='identity_merged'").fetchone()[0], 1)
            con.close()

    def test_old_ip_state_is_not_inherited_after_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            con = connect_state(Path(directory) / "module5.db")
            with transaction(con):
                con.execute(
                    "INSERT INTO events(sequence,event_id,event_type,probe_id,observed_at_us,observed_at,"
                    "data_json,quality_flags_json,provenance_json,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (1, "old", "network_connection", "test", 100, "100", "{}", "[]", "{}", "processed"),
                )
                old = _ensure_asset(con, "lab", "ip:10.10.40.104", "provisional", 100, "10.10.40.104")
                _address(con, old, "lab", "10.10.40.104", 100, "old", "source_observed")
                con.execute(
                    "INSERT INTO services(service_id,asset_id,scope,ip,port,transport,protocol,state,first_seen_us,last_seen_us) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    ("old-service", old, "lab", "10.10.40.104", 8080, "tcp", "http", "response_observed", 100, 100),
                )
                mac = _ensure_asset(con, "lab", "mac:aa:bb:cc:dd:ee:11", "identified", 200)
                _reconcile_assignment(con, mac, "lab", "10.10.40.104", "aa:bb:cc:dd:ee:11", 200, "old")
            self.assertNotEqual(con.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT asset_id FROM services").fetchone()[0], old)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM changes WHERE action='identity_conflict'").fetchone()[0], 1)
            con.close()

    def test_late_observation_uses_observation_time_for_asset_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            con = connect_state(Path(directory) / "module5.db")
            with transaction(con):
                asset = _ensure_asset(con, "lab", "ip:10.10.40.104", "provisional", 200, "10.10.40.104")
                _ensure_asset(con, "lab", "ip:10.10.40.104", "provisional", 100, "10.10.40.104")
            first, last = con.execute(
                "SELECT first_seen_us,last_seen_us FROM assets WHERE asset_id=?", (asset,)
            ).fetchone()
            self.assertEqual((first, last), (100, 200))
            con.close()

    def test_old_state_database_migrates_without_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            raw = sqlite3.connect(state)
            raw.execute("CREATE TABLE interactions(interaction_id TEXT PRIMARY KEY, event_id TEXT UNIQUE)")
            raw.execute("INSERT INTO interactions VALUES ('old-interaction','old-event')")
            raw.execute("PRAGMA user_version=1")
            raw.commit()
            raw.close()
            con = connect_state(state)
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual(con.execute("SELECT communication_id FROM interactions").fetchone()[0], "old-interaction")
            columns = {row[1] for row in con.execute("PRAGMA table_info(changes)")}
            self.assertTrue({"processed_at_us", "entity_version"} <= columns)
            con.close()

    def test_lifecycle_maintenance_uses_observation_time_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            con = connect_state(state)
            with transaction(con):
                asset = _ensure_asset(con, "lab", "ip:10.10.40.104", "provisional", 1_000,
                                      "10.10.40.104")
                dhcp_only = _ensure_asset(con, "lab", "mac:aa:bb:cc:dd:ee:12", "identified", 1_000,
                                          initial_lifecycle="dormant")
                con.execute(
                    "INSERT INTO events(sequence,event_id,event_type,probe_id,observed_at_us,observed_at,"
                    "data_json,quality_flags_json,provenance_json,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (1, "flow", "network_connection", "test", 1_000, "1000", "{}", "[]", "{}", "processed"),
                )
                con.execute(
                    "INSERT INTO interactions(interaction_id,communication_id,event_id,evidence_id,scope,source_asset_id,"
                    "target_asset_id,source_ip,target_ip,source_port,target_port,transport,protocol,outcome,observed_at_us) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("interaction", "communication", "flow", None, "lab", asset, None,
                     "10.10.40.104", "10.10.35.10", 40000, 22, "tcp", "ssh", "response_observed", 1_000),
                )
            con.close()

            self.assertEqual(maintain(str(state), 1_005, 10, 20), {"checked": 2, "changed": 0})
            self.assertEqual(maintain(str(state), 1_011, 10, 20), {"checked": 2, "changed": 1})
            before = snapshot(str(state))
            self.assertEqual(next(row for row in before["assets"] if row["asset_id"] == asset)["lifecycle_state"],
                             "dormant")
            change_count = len(before["changes"])
            self.assertEqual(maintain(str(state), 1_011, 10, 20), {"checked": 2, "changed": 0})
            self.assertEqual(len(snapshot(str(state))["changes"]), change_count)

            con = connect_state(state)
            with transaction(con):
                _ensure_asset(con, "lab", "ip:10.10.40.104", "provisional", 1_005, "10.10.40.104")
            con.close()
            self.assertEqual(maintain(str(state), 1_011, 10, 20), {"checked": 2, "changed": 0})
            self.assertEqual(maintain(str(state), 1_021, 10, 20), {"checked": 2, "changed": 2})
            con = sqlite3.connect(state)
            self.assertEqual(con.execute(
                "SELECT first_seen_us,last_seen_us FROM assets WHERE asset_id=?", (asset,)
            ).fetchone(), (1_000, 1_005))
            self.assertEqual(con.execute(
                "SELECT lifecycle_state FROM assets WHERE asset_id=?", (dhcp_only,)
            ).fetchone()[0], "expired")
            con.close()

    @unittest.skipUnless(MODULE4.exists(), "the repository's real Module 4 database is unavailable")
    def test_module6_consumer_reconstructs_snapshot_and_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            run(str(MODULE4), str(state), batch_size=1000)
            initial = snapshot(str(state))
            initial_change_id = max(row["change_id"] for row in initial["changes"])
            latest = max(row["observed_at_us"] for row in initial["events"])
            maintain(str(state), latest + 2 * DEFAULT_DORMANT_AFTER_US)
            current = snapshot(str(state))
            assets = {row["asset_id"]: row for row in current["assets"]}
            redirects = {}
            for change in current["changes"]:
                if change["action"] == "identity_merged":
                    payload = json.loads(change["payload_json"])
                    redirects[payload["from_asset_id"]] = payload["to_asset_id"]
                if change["action"] == "lifecycle_changed":
                    self.assertIn(change["entity_id"], assets)
                    self.assertIn("processed_at_us", change)
                    self.assertIn("entity_version", change)
            self.assertTrue(redirects)
            self.assertTrue(all(target in assets for target in redirects.values()))
            self.assertTrue(all(row["asset_id"] in assets for row in current["addresses"]))
            self.assertTrue(all(row["asset_id"] in assets for row in current["services"]))
            self.assertTrue(all(row["asset_id"] in assets for row in current["software"]))
            self.assertTrue(all(
                row["source_asset_id"] in assets if row["source_asset_id"] else True
                for row in current["interactions"]
            ))
            self.assertTrue(all(
                row["target_asset_id"] in assets if row["target_asset_id"] else True
                for row in current["interactions"]
            ))
            event_ids = {row["event_id"] for row in current["events"]}
            self.assertTrue(all(row["event_id"] in event_ids for row in current["evidence"]))
            communication_ids = {row["communication_id"] for row in current["interactions"]}
            self.assertTrue(communication_ids)
            self.assertTrue(all(row["communication_id"] in communication_ids for row in current["interactions"]))

            incremental = changes(str(state), after=initial_change_id, limit=10_000)
            self.assertEqual([row["change_id"] for row in incremental],
                             sorted(row["change_id"] for row in current["changes"]
                                    if row["change_id"] > initial_change_id))
            self.assertTrue(all(row["processed_at_us"] >= 0 and row["entity_version"] >= 1
                                for row in incremental))
            self.assertTrue(any(row["action"] == "lifecycle_changed" for row in incremental))
            consumer_assets = {row["asset_id"]: dict(row) for row in initial["assets"]}
            for change in incremental:
                if change["action"] == "lifecycle_changed":
                    consumer_assets[change["entity_id"]]["lifecycle_state"] = change["payload"]["to"]
            self.assertEqual(
                {asset_id: row["lifecycle_state"] for asset_id, row in consumer_assets.items()},
                {row["asset_id"]: row["lifecycle_state"] for row in current["assets"]},
            )
            self.assertTrue(any(row["action"] == "identity_merged" for row in current["changes"]))

    def test_snapshot_handoff_is_watermarked_atomic_and_restart_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            con = connect_state(state)

            def event(sequence, event_id, seen):
                con.execute(
                    "INSERT INTO events(sequence,event_id,event_type,probe_id,observed_at_us,observed_at,"
                    "data_json,quality_flags_json,provenance_json,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (sequence, event_id, "network_connection", "test", seen, str(seen), "{}", "[]",
                     '{"source_id":"test"}', "processed"),
                )

            with transaction(con):
                event(1, "seed", 100)
                old = _ensure_asset(con, "lab", "ip:10.10.40.104", "provisional", 100, "10.10.40.104")
                _address(con, old, "lab", "10.10.40.104", 100, "seed", "source_observed")
                con.execute(
                    "INSERT INTO evidence VALUES (?,?,?,?,?,?)",
                    ("evidence-seed", "seed", "connection", old, '{"claim":"seed"}', 100),
                )
            con.close()

            tables = (("assets", "asset_id"), ("addresses", "address_id"), ("services", "service_id"),
                      ("software", "claim_id"), ("interactions", "interaction_id"),
                      ("evidence", "evidence_id"), ("events", "event_id"), ("changes", "change_id"))

            def consumer_state(document):
                document = json.loads(json.dumps(document))
                return {
                    "change_watermark": document["change_watermark"],
                    "cursor": document["cursor"],
                    **{table: {row[key]: row for row in document[table]} for table, key in tables},
                }

            initial = json.loads(json.dumps(snapshot(str(state))))
            graph = consumer_state(initial)
            self.assertEqual(set(graph["assets"]), {old})
            initial_watermark = initial["change_watermark"]

            con = connect_state(state)
            with transaction(con):
                event(2, "merge", 105)
                target = _ensure_asset(con, "lab", "mac:aa:bb:cc:dd:ee:10", "identified", 105)
                _reconcile_assignment(con, target, "lab", "10.10.40.104",
                                      "aa:bb:cc:dd:ee:10", 105, "merge")
                service = stable_id("service", target, "lab", "10.10.40.104", 8080, "tcp")
                con.execute(
                    "INSERT INTO services VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (service, target, "lab", "10.10.40.104", 8080, "tcp", "http",
                     "protocol_observed", 105, 105),
                )
                add_change(con, "service", service, "merge", "observed", 105,
                           {"asset_id": target, "ip": "10.10.40.104", "port": 8080})
                event(3, "flow", 106)
                con.execute(
                    "INSERT INTO evidence VALUES (?,?,?,?,?,?)",
                    ("evidence-flow", "flow", "connection", target, '{"claim":"flow"}', 106),
                )
                con.execute(
                    "INSERT INTO interactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("interaction-flow", "communication-flow", "flow", "evidence-flow", "lab", target, None,
                     "10.10.40.104", "10.10.35.10", 40000, 22, "tcp", "ssh", "response_observed", 106),
                )
                add_change(con, "interaction", "interaction-flow", "flow", "observed", 106,
                           {"communication_id": "communication-flow", "outcome": "response_observed"})
                during = json.loads(json.dumps(snapshot(str(state))))
            con.close()

            self.assertEqual(during["change_watermark"], initial_watermark)
            self.assertIn(old, consumer_state(during)["assets"])
            self.assertNotIn(target, consumer_state(during)["assets"])

            refreshed = json.loads(json.dumps(snapshot(str(state))))
            self.assertGreater(refreshed["change_watermark"], initial_watermark)
            refreshed_graph = consumer_state(refreshed)
            self.assertNotIn(old, refreshed_graph["assets"])
            self.assertIn(target, refreshed_graph["assets"])
            self.assertEqual(len(refreshed_graph["assets"]), 1)
            self.assertEqual(len(refreshed_graph["services"]), 1)
            self.assertEqual(refreshed_graph["addresses"][next(iter(refreshed_graph["addresses"]))]["asset_id"], target)
            self.assertEqual(refreshed_graph["evidence"]["evidence-seed"]["subject_id"], target)
            merge_changes = [row for row in refreshed["changes"] if row["action"] == "identity_merged"]
            self.assertEqual(len(merge_changes), 1)
            merge_payload = json.loads(merge_changes[0]["payload_json"])
            self.assertEqual((merge_payload["from_asset_id"], merge_payload["to_asset_id"]), (old, target))

            self.assertEqual(maintain(str(state), 117, 10, 20), {"checked": 1, "changed": 1})
            lifecycle = json.loads(json.dumps(snapshot(str(state))))
            self.assertGreater(lifecycle["change_watermark"], refreshed["change_watermark"])
            self.assertEqual(lifecycle["assets"][0]["lifecycle_state"], "dormant")
            reconciled = consumer_state(lifecycle)
            restarted = consumer_state(json.loads(json.dumps(snapshot(str(state)))))
            self.assertEqual(reconciled, restarted)

    @unittest.skipUnless(MODULE4.exists(), "the repository's real Module 4 database is unavailable")
    def test_batch_failure_rolls_back_state_and_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            original = engine._process_one
            calls = 0

            def fail_after_first(con, observation):
                nonlocal calls
                result = original(con, observation)
                calls += 1
                if calls == 1:
                    raise sqlite3.OperationalError("forced rollback")
                return result

            with self.assertRaises(sqlite3.OperationalError):
                with patch("discovery.engine._process_one", side_effect=fail_after_first):
                    run(str(MODULE4), str(state), batch_size=2)
            con = sqlite3.connect(state)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM cursor").fetchone()[0], 0)
            con.close()
            self.assertEqual(run(str(MODULE4), str(state), batch_size=1000)["processed"], 285)

    @unittest.skipUnless(MODULE4.exists(), "the repository's real Module 4 database is unavailable")
    def test_exports_are_json_serializable_and_have_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "module5.db"
            run(str(MODULE4), str(state))
            data = snapshot(str(state))
            json.dumps(data)
            self.assertTrue(data["events"])
            self.assertTrue(data["events"][0]["provenance"]["source_id"])
            self.assertTrue(changes(str(state), limit=1)[0]["entity_type"])


if __name__ == "__main__":
    unittest.main()
