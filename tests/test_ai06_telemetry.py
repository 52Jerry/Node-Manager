import json
import shutil
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from test_next_stage import traffic
from monitor.cumulative_meter import CounterRejected, CumulativeMeter
from monitor.telemetry import admin_projection, connection_summary, sample_state


class TelemetryContractTest(unittest.TestCase):
    def test_nat_switching_connections_and_forged_identity_never_count_devices(self):
        for sources in (["192.0.2.1"] * 8, ["192.0.2.1", "192.0.2.2"], []):
            sessions = [{"sourceIp": source, "deviceId": "forged", "credentialId": "fake"}
                        for source in sources]
            result = connection_summary(sessions)
            self.assertIsNone(result["verifiedDeviceCount"])
            self.assertEqual(result["activeConnections"], len(sources))
            self.assertEqual(result["observedSourceCount"], len(set(sources)))
            self.assertEqual(result["credentialCount"], 1 if sources else 0)
        self.assertIsNone(connection_summary(None)["activeConnections"])

    def test_relay_private_missing_and_idle(self):
        with patch.object(traffic.config.monitoring, "relay_source_cidrs", "192.0.2.8/32"):
            self.assertEqual(connection_summary([{"sourceIp": "192.0.2.8"}])["sourceConfidence"], "relay")
            self.assertEqual(connection_summary([{"sourceIp": "172.16.1.1"}])["sourceConfidence"], "private")
            self.assertEqual(connection_summary([{}])["sourceConfidence"], "unknown")
            self.assertEqual(connection_summary([])["sourceConfidence"], "idle")

    def test_projection_denies_all_nonadmins_and_disabled_admin(self):
        payload = {**connection_summary([]), "host": "private.example", "sourceIp": "192.0.2.1"}
        for role in ("user", "agent", "reseller", "node_ops", "sysops", "provisioner", None, ""):
            with self.assertRaises(PermissionError):
                admin_projection(payload, role=role)
        with self.assertRaises(PermissionError):
            admin_projection(payload, role="admin", account_active=False)
        for role in ("admin", "superadmin"):
            result = admin_projection(payload, role=role)
            self.assertNotIn("host", result)
            self.assertNotIn("sourceIp", result)
            self.assertIsNone(result["verifiedDeviceCount"])

    def test_stale_absent_and_future_samples_are_unavailable(self):
        for stamp in (None, "bad", 42, (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
                      (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()):
            self.assertFalse(sample_state(stamp, True, 6)["telemetryAvailable"])
        self.assertTrue(sample_state(datetime.now(timezone.utc).isoformat(), True, 6)["telemetryAvailable"])


class CollectionFailureTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "traffic.json"
        self.patches = [patch.object(traffic, "TRAFFIC_PATH", self.path),
                        patch.object(traffic, "get_user_policies", return_value={}),
                        patch.object(traffic, "get_user_auth_map", return_value={}),
                        patch.object(traffic, "sync_user_enforcements")]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        traffic.collection_health.pop(str(self.path), None)
        traffic.connection_details.pop(str(self.path), None)
        self.directory.cleanup()

    def test_api_failure_cached_reads_do_not_reappear_fresh(self):
        with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": []}):
            traffic.collect_traffic()
        with patch.object(traffic.singbox_api, "get_connections", return_value=None):
            self.assertFalse(traffic.collect_traffic())
        result = traffic.get_user_traffic("fake", refresh=False)
        self.assertFalse(result["telemetryAvailable"])
        self.assertIsNone(result["measuredTotal"])
        self.assertIsNone(result["activeConnections"])
        self.assertTrue(result["alertRequired"])

    def test_corrupt_store_never_overwrites_or_enforces(self):
        self.path.write_text("{broken", encoding="utf-8")
        with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": []}), \
             patch.object(traffic, "sync_user_enforcements") as enforcement:
            result = traffic.get_user_traffic("fake")
        self.assertIsNone(result["measuredTotal"])
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{broken")
        enforcement.assert_not_called()

    def test_negative_persisted_counter_is_not_reset_or_enforced(self):
        self.path.write_text(json.dumps({"users": {"fake": {"upload": -1}},
                                        "connections": {}}), encoding="utf-8")
        before = self.path.read_bytes()
        with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": []}), \
             patch.object(traffic, "sync_user_enforcements") as enforcement:
            self.assertFalse(traffic.collect_traffic())
        enforcement.assert_not_called()
        self.assertEqual(self.path.read_bytes(), before)

    def test_write_failure_never_updates_baseline_or_closes(self):
        self.path.write_text(json.dumps(traffic._empty_store()), encoding="utf-8")
        before = self.path.read_bytes()
        snapshot = {"connections": [{"id": "fake", "chains": ["node-manager-out:fake"], "upload": 9}]}
        with patch.object(traffic.singbox_api, "get_connections", return_value=snapshot), \
             patch.object(traffic, "_write_store", side_effect=OSError("disk full")), \
             patch.object(traffic.singbox_api, "close_connection") as close:
            self.assertFalse(traffic.collect_traffic())
        close.assert_not_called()
        self.assertEqual(before, self.path.read_bytes())

    def test_native_counters_are_nodewide_and_not_assigned_to_users(self):
        with patch.object(traffic.singbox_api, "get_connections", return_value={
                "connections": [], "uploadTotal": 23, "downloadTotal": 45}):
            totals = traffic.get_traffic_totals()
        self.assertEqual(totals["nodeCumulativeCounters"], {"upload": 23, "download": 45})
        self.assertEqual(traffic.get_user_traffic("fake", refresh=False)["total"], 0)
        self.assertIsNone(traffic.singbox_api.cumulative_counters({"uploadTotal": True, "downloadTotal": 0}))

    def test_duplicate_invalid_and_reset_snapshots_never_enforce(self):
        connection = {"id": "fake", "chains": ["node-manager-out:fake"], "upload": 9, "download": 3}
        with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": [connection]}):
            self.assertTrue(traffic.collect_traffic())
        before = self.path.read_bytes()
        for entries in ([connection, connection], [{**connection, "upload": True}],
                        [{**connection, "upload": 8}], [{**connection, "download": -1}],
                        [{**connection, "upload": "10"}]):
            with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": entries}), \
                 patch.object(traffic, "sync_user_enforcements") as enforcement, \
                 patch.object(traffic.singbox_api, "close_connection") as close:
                self.assertFalse(traffic.collect_traffic())
                self.assertEqual(self.path.read_bytes(), before)
                enforcement.assert_not_called()
                close.assert_not_called()

    def test_nat_many_sessions_without_explicit_source_or_connection_limit_never_close(self):
        entries = [{"id": str(index), "chains": ["node-manager-out:fake"],
                    "metadata": {"sourceIP": "172.16.1.1", "deviceId": "forged"}}
                   for index in range(40)]
        with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": entries}), \
             patch.object(traffic.singbox_api, "close_connection") as close:
            result = traffic.get_user_traffic("fake")
        self.assertIsNone(result["verifiedDeviceCount"])
        self.assertEqual(result["activeConnections"], 40)
        self.assertEqual(result["observedSourceCount"], 1)
        close.assert_not_called()

    def test_unreliable_source_limit_never_guesses_devices_or_closes(self):
        for sources in (("172.16.1.1", "172.16.1.2"), (None, "192.0.2.1"),
                        ("192.0.2.8", "192.0.2.9")):
            entries = [{"id": str(index), "chains": ["node-manager-out:fake"],
                        "metadata": {"sourceIP": source, "deviceId": "forged"}}
                       for index, source in enumerate(sources)]
            with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": entries}), \
                 patch.object(traffic, "get_user_policies", return_value={"fake": {"maxSourceIps": 1}}), \
                 patch.object(traffic.config.monitoring, "relay_source_cidrs", "192.0.2.8/32"), \
                 patch.object(traffic.singbox_api, "close_connection") as close:
                result = traffic.get_user_traffic("fake")
            self.assertIsNone(result["verifiedDeviceCount"])
            self.assertEqual(result["sourceLimitDecision"], "suspended_unreliable_source_review_required")
            self.assertTrue(result["alertRequired"])
            close.assert_not_called()

    def test_destination_detail_is_not_persisted_and_failure_purges_it(self):
        entries = [{"id": "fake", "chains": ["node-manager-out:fake"],
                    "metadata": {"host": "ai06.private.example", "destinationIP": "192.0.2.1"}}]
        with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": entries}):
            result = traffic.get_user_traffic("fake")
        self.assertEqual(result["onlineConnections"][0]["host"], "ai06.private.example")
        self.assertNotIn("ai06.private.example", self.path.read_text(encoding="utf-8"))
        self.assertNotIn("destinationIp", self.path.read_text(encoding="utf-8"))
        with patch.object(traffic.singbox_api, "get_connections", return_value=None):
            result = traffic.get_user_traffic("fake")
        self.assertIsNone(result["onlineConnections"])
        self.assertNotIn(str(self.path), traffic.connection_details)

    def test_legacy_store_self_reported_device_id_is_never_returned_as_identity(self):
        store = {"users": {}, "collectedAt": datetime.now(timezone.utc).isoformat(),
                 "connections": {"fake": {"userId": "fake", "deviceId": "untrusted-legacy"}}}
        result = traffic.get_user_traffic("fake", refresh=False, store=store, available=True)
        self.assertIsNone(result["onlineConnections"][0]["deviceId"])
        self.assertIsNone(result["verifiedDeviceCount"])


class CumulativeLedgerTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "meter.sqlite"
        self.meter = CumulativeMeter(self.path)

    def tearDown(self):
        self.directory.cleanup()

    def batch(self, upload=10, download=20, **kwargs):
        return {"node": "fake-node", "epoch": "fake-process-1", "generation": 1,
                "sequence": 1, "counters": {"fake-user": {"upload": upload, "download": download}}, **kwargs}

    def test_both_directions_duplicate_rollback_and_restart(self):
        first = self.batch()
        self.assertEqual(self.meter.ingest(**first)["delta"], 30)
        self.assertFalse(self.meter.ingest(**first)["applied"])
        with self.assertRaises(CounterRejected):
            self.meter.ingest(**self.batch(generation=2))
        with self.assertRaises(CounterRejected):
            self.meter.ingest(**self.batch(upload=11))
        self.meter.ingest(**self.batch(upload=15, download=25, sequence=3))
        for batch in (self.batch(sequence=2), self.batch(upload=0, sequence=4)):
            with self.assertRaises(CounterRejected):
                self.meter.ingest(**batch)
        result = self.meter.ingest(**self.batch(upload=4, download=6, epoch="fake-process-2", generation=2))
        self.assertEqual(result["continuity"], "restart_gap_possible")
        self.assertEqual(self.meter.totals("fake-user")["total"], 50)
        with self.assertRaises(CounterRejected):
            self.meter.ingest(**self.batch(sequence=5))

    def test_independent_nodes_sum_replicas_deduplicate(self):
        first = self.batch()
        self.meter.ingest(**first)
        self.meter.ingest(**self.batch(node="fake-node-2"))
        self.meter.ingest(**first)
        self.assertEqual(self.meter.totals("fake-user")["total"], 60)
        self.assertIsNone(self.meter.totals("unknown")["total"])

    def test_concurrent_duplicate_samples_commit_once(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.meter.ingest(**self.batch()), range(24)))
        self.assertEqual(sum(result["applied"] for result in results), 1)
        self.assertEqual(self.meter.totals("fake-user")["total"], 30)

    def test_multiuser_rollback_and_disk_failure_are_atomic(self):
        self.meter.ingest(**self.batch())
        batch = self.batch(sequence=2)
        batch["counters"] = {"new": {"upload": 2, "download": 3},
                             "fake-user": {"upload": 1, "download": 20}}
        with self.assertRaises(CounterRejected):
            self.meter.ingest(**batch)
        self.assertIsNone(self.meter.totals("new")["total"])
        with patch("monitor.cumulative_meter.sqlite3.connect", side_effect=sqlite3.OperationalError("disk full")):
            with self.assertRaises(sqlite3.OperationalError):
                self.meter.ingest(**self.batch(sequence=2, upload=15))
        self.assertEqual(CumulativeMeter(self.path).totals("fake-user")["total"], 30)

    def test_restore_requires_external_checkpoint(self):
        self.meter.ingest(**self.batch())
        key = ("fake-node", "fake-process-1", "fake-user")
        self.meter.verify_restore({key: (10, 20)})
        for checkpoint in ({key: (11, 20)}, {("missing", "epoch", "user"): (0, 0)}):
            with self.assertRaises(CounterRejected):
                self.meter.verify_restore(checkpoint)

    def test_actual_database_restore_rejects_lost_usage(self):
        self.meter.ingest(**self.batch())
        backup = self.path.with_name("old-backup.sqlite")
        shutil.copyfile(self.path, backup)
        self.meter.ingest(**self.batch(upload=15, download=25, sequence=2))
        expected = {("fake-node", "fake-process-1", "fake-user"): (15, 25)}
        self.meter.verify_restore(expected)
        restored = CumulativeMeter(backup)
        with self.assertRaises(CounterRejected):
            restored.verify_restore(expected)

    def test_bad_numbers_and_missing_direction_rejected(self):
        for bad in (True, -1, "10", 2**63):
            with self.assertRaises(CounterRejected):
                self.meter.ingest(**self.batch(upload=bad))
        batch = self.batch()
        del batch["counters"]["fake-user"]["download"]
        with self.assertRaises(CounterRejected):
            self.meter.ingest(**batch)

    def test_digest_retention_is_bounded_and_old_replay_does_not_add(self):
        for sequence in range(1, 1027):
            self.meter.ingest(**self.batch(sequence=sequence))
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM batches").fetchone()[0], 1024)
        with self.assertRaises(CounterRejected):
            self.meter.ingest(**self.batch(sequence=1))
        self.assertEqual(self.meter.totals("fake-user")["total"], 30)


if __name__ == "__main__":
    unittest.main()
