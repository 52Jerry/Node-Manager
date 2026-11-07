"""Observability caching must not change native accounting or mutable writers."""
import copy
import json
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_next_stage import traffic


class ManagerReadSummaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "traffic.json"
        self.path_patch = patch.object(traffic, "TRAFFIC_PATH", self.path)
        self.path_patch.start()
        traffic._reset_read_summary_cache()
        traffic.collection_health.pop(str(self.path), None)
        projection_patch = patch.object(traffic, "get_user_monitoring_snapshot",
            side_effect=lambda: SimpleNamespace(policies=traffic.get_user_policies(),
                                                auth_map=traffic.get_user_auth_map()))
        projection_patch.start()
        self.addCleanup(projection_patch.stop)

    def tearDown(self):
        traffic._reset_read_summary_cache()
        traffic.collection_health.pop(str(self.path), None)
        traffic.connection_details.pop(str(self.path), None)
        self.path_patch.stop()
        self.directory.cleanup()

    def store(self, upload=7, download=13, connections=2):
        return {
            "version": 1,
            "users": {"alice": {"upload": upload, "download": download}},
            "connections": {
                str(index): {"userId": "alice", "upload": index + 1,
                             "download": 0, "online": True}
                for index in range(connections)
            },
            "collectedAt": datetime.now(timezone.utc).isoformat(),
            "nodeCumulativeCounters": {"upload": 31, "download": 47},
        }

    def write_external(self, store):
        replacement = self.path.with_name("external.json")
        replacement.write_text(json.dumps(store), encoding="utf-8")
        os.replace(replacement, self.path)

    def test_successful_write_publishes_summary_without_another_decode(self):
        store = self.store()
        store["connections"]["1"]["online"] = False
        traffic._write_store(store)
        with patch.object(traffic, "_read_store", side_effect=AssertionError("unexpected reread")), \
             patch.object(traffic.json, "load", side_effect=AssertionError("unexpected decode")):
            connections = traffic.get_proxy_connection_count_snapshot()
            totals = traffic.get_traffic_totals(refresh=False)
        self.assertTrue(connections["available"])
        self.assertEqual(connections["connections"], 1)
        self.assertEqual(connections["collectedAt"], store["collectedAt"])
        self.assertTrue(totals["available"])
        self.assertEqual(totals["total"], 20)

    def test_atomic_replacement_with_same_size_and_timestamp_invalidates_summary(self):
        first = self.store(upload=7)
        self.write_external(first)
        self.assertEqual(traffic.get_traffic_totals(refresh=False)["total"], 20)
        original_stat = self.path.stat()
        second = copy.deepcopy(first)
        second["users"]["alice"]["upload"] = 9
        replacement = self.path.with_name("external.json")
        replacement.write_text(json.dumps(second), encoding="utf-8")
        os.utime(replacement, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        self.assertEqual(replacement.stat().st_size, original_stat.st_size)
        os.replace(replacement, self.path)
        original_load = traffic.json.load
        with patch.object(traffic.json, "load", wraps=original_load) as load:
            counts = traffic.get_proxy_connection_count_snapshot()
            totals = traffic.get_traffic_totals(refresh=False)
        self.assertEqual(counts["connections"], 2)
        self.assertEqual(totals["total"], 22)
        self.assertEqual(load.call_count, 1)

    def test_concurrent_cold_readers_share_one_decode(self):
        self.write_external(self.store(connections=17))
        barrier = threading.Barrier(8)
        original_load = traffic.json.load

        def slow_load(handle):
            time.sleep(0.02)
            return original_load(handle)

        def read(_):
            barrier.wait(timeout=5)
            return traffic.get_proxy_connection_count_snapshot()

        with patch.object(traffic.json, "load", side_effect=slow_load) as load:
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(read, range(8)))
        self.assertEqual(load.call_count, 1)
        self.assertTrue(all(row["available"] and row["connections"] == 17 for row in results))

    def test_replacement_during_decode_cannot_poison_the_new_file_version(self):
        first = self.store(upload=7)
        self.write_external(first)
        second = copy.deepcopy(first)
        second["users"]["alice"]["upload"] = 99
        original_read = traffic._read_store
        replaced = False

        def replace_after_decode():
            nonlocal replaced
            # On Windows a plain file handle cannot be atomically replaced
            # while open. Inject after the decoded reader closes its handle,
            # before the summary cache's post-read version check.
            result = original_read()
            if not replaced:
                replaced = True
                self.write_external(second)
            return result

        with patch.object(traffic, "_read_store", side_effect=replace_after_decode):
            traffic.get_traffic_totals(refresh=False)
            result = traffic.get_traffic_totals(refresh=False)
        self.assertEqual(result["total"], 112)

    def test_corrupt_replacement_never_reuses_prior_available_summary(self):
        traffic._write_store(self.store())
        self.assertTrue(traffic.get_traffic_totals(refresh=False)["available"])
        replacement = self.path.with_name("external.json")
        replacement.write_text("{broken", encoding="utf-8")
        os.replace(replacement, self.path)
        counts = traffic.get_proxy_connection_count_snapshot()
        totals = traffic.get_traffic_totals(refresh=False)
        self.assertFalse(counts["available"])
        self.assertIsNone(counts["connections"])
        self.assertFalse(totals["available"])
        self.assertIsNone(totals["measuredTotal"])
        self.assertTrue(totals["alertRequired"])
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{broken")

    def test_missing_file_after_a_warm_read_is_unavailable(self):
        traffic._write_store(self.store())
        self.assertTrue(traffic.get_proxy_connection_count_snapshot()["available"])
        self.path.unlink()
        result = traffic.get_proxy_connection_count_snapshot()
        self.assertFalse(result["available"])
        self.assertIsNone(result["connections"])

    def test_collection_failure_is_checked_even_while_file_version_is_cached(self):
        traffic._write_store(self.store())
        self.assertTrue(traffic.get_proxy_connection_count_snapshot()["available"])
        traffic.collection_health[str(self.path)] = {"reason": "api_unavailable"}
        self.assertFalse(traffic.get_proxy_connection_count_snapshot()["available"])
        totals = traffic.get_traffic_totals(refresh=False)
        self.assertFalse(totals["available"])
        self.assertIsNone(totals["measuredTotal"])

    def test_stale_snapshot_never_reports_measured_connections_or_totals(self):
        store = self.store()
        store["collectedAt"] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        traffic._write_store(store)
        self.assertFalse(traffic.get_proxy_connection_count_snapshot()["available"])
        totals = traffic.get_traffic_totals(refresh=False)
        self.assertFalse(totals["available"])
        self.assertIsNone(totals["measuredTotal"])
        self.assertEqual(totals["lastKnownTotal"], 20)

    def test_mutating_totals_or_original_store_cannot_change_cached_counters(self):
        store = self.store()
        traffic._write_store(store)
        store["nodeCumulativeCounters"]["upload"] = 1000
        first = traffic.get_traffic_totals(refresh=False)
        self.assertEqual(first["nodeCumulativeCounters"]["upload"], 31)
        first["nodeCumulativeCounters"]["download"] = 2000
        second = traffic.get_traffic_totals(refresh=False)
        self.assertEqual(second["nodeCumulativeCounters"], {"upload": 31, "download": 47})

    def test_existing_full_store_readers_remain_fresh_mutable_and_isolated(self):
        traffic._write_store(self.store(upload=7))
        traffic.get_traffic_totals(refresh=False)
        newer = self.store(upload=99)
        self.write_external(newer)
        mutable = traffic._read_store()
        snapshot = traffic.get_traffic_store_snapshot()
        self.assertEqual(mutable["users"]["alice"]["upload"], 99)
        self.assertEqual(snapshot["users"]["alice"]["upload"], 99)
        mutable["users"]["alice"]["upload"] = 1
        snapshot["users"]["alice"]["upload"] = 2
        self.assertEqual(traffic._read_store()["users"]["alice"]["upload"], 99)

    def test_failed_accounting_write_does_not_publish_uncommitted_totals(self):
        traffic._write_store(self.store(upload=7))
        with patch.object(traffic.os, "replace", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                traffic._write_store(self.store(upload=99))
        self.assertEqual(traffic.get_traffic_totals(refresh=False)["total"], 20)
        self.assertEqual(traffic._read_store()["users"]["alice"]["upload"], 7)

    def test_archived_usage_is_requeried_even_when_hot_summary_is_cached(self):
        store = self.store()
        store["runtimeCounters"] = {"rows": {}, "counterVersion": 1}
        traffic._write_store(store)
        with patch("runtime_history.archived_totals", side_effect=[(10, 20), (30, 40)]) as archived:
            first = traffic.get_traffic_totals(refresh=False)
            second = traffic.get_traffic_totals(refresh=False)
        self.assertEqual(first["total"], 50)
        self.assertEqual(second["total"], 90)
        self.assertEqual(archived.call_count, 2)
        self.assertTrue(all(set(call.args[0]) == {"alice"} for call in archived.call_args_list))

    def test_reset_uses_fresh_baseline_and_does_not_recount_pre_reset_traffic(self):
        initial = self.store(upload=100, download=0, connections=1)
        initial["connections"]["0"]["upload"] = 100
        traffic._write_store(initial)
        traffic.get_traffic_totals(refresh=False)
        newer = copy.deepcopy(initial)
        newer["users"]["alice"]["upload"] = 240
        newer["connections"]["0"]["upload"] = 260
        self.write_external(newer)
        with patch("singbox.runtime_client.enabled", return_value=False), \
             patch.object(traffic, "sync_user_enforcements"), \
             patch.object(traffic, "get_user_policies", return_value={}), \
             patch.object(traffic, "get_user_auth_map", return_value={}):
            traffic.reset_user_traffic("alice")
            reset = traffic._read_store()
            self.assertEqual(reset["users"]["alice"]["upload"], 0)
            self.assertEqual(reset["connections"]["0"]["upload"], 260)
            sample = {"connections": [{"id": "0", "chains": ["node-manager-out:alice"],
                                       "upload": 270, "download": 0}]}
            with patch.object(traffic.singbox_api, "get_connections", return_value=sample):
                self.assertTrue(traffic.collect_traffic())
        self.assertEqual(traffic._read_store()["users"]["alice"]["upload"], 10)


if __name__ == "__main__":
    unittest.main()
