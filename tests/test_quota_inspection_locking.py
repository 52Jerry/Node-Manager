"""Quota observations stay fresh without blocking collectors on identity I/O."""
import copy
import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from test_next_stage import manager, traffic, base_singbox_config
from monitor import shared_quota as quota


class QuotaInspectionLockingTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        root = Path(directory)
        self.config_path = root / "sing-box.json"
        self.registry_path = root / "users.json"
        self.traffic_path = root / "traffic.json"
        self.config_path.write_text(json.dumps(base_singbox_config()), encoding="utf-8")
        self.registry_path.write_text(json.dumps({"users": {}}), encoding="utf-8")
        for name, value in (("CONFIG_PATH", self.config_path), ("REGISTRY_PATH", self.registry_path),
                            ("LOCK_PATH", root / "config.lock")):
            self.stack.enter_context(patch.object(manager, name, value))
        self.stack.enter_context(patch.object(traffic, "TRAFFIC_PATH", self.traffic_path))
        self.row = {"userId": "alice", "auth": [{"protocol": "vless", "credential": "old-credential"}],
                    "proxy": {"server": "192.0.2.1", "port": 1080}, "trafficLimitBytes": 1000}
        self.write_usage(70)

    def write_usage(self, upload):
        traffic._write_store({"users": {"alice": {"upload": upload, "download": 0}},
                              "connections": {"open": {"userId": "alice", "upload": 100,
                                                         "download": 0}},
                              "collectedAt": datetime.now(timezone.utc).isoformat()})

    def replace_json(self, path, data, preserve_mtime=False):
        before = path.stat()
        temporary = path.with_name(path.name + ".replacement")
        temporary.write_text(json.dumps(data), encoding="utf-8")
        if preserve_mtime:
            os.utime(temporary, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.replace(temporary, path)

    def test_waiting_for_config_lock_does_not_own_collection_or_traffic_lock(self):
        entered = threading.Event()
        original_rows = quota._rows

        def read_rows():
            entered.set()
            return original_rows()

        with patch.object(quota, "_rows", side_effect=read_rows):
            with ThreadPoolExecutor(max_workers=1) as pool:
                with manager._config_lock():
                    future = pool.submit(quota.inspect_users)
                    self.assertTrue(entered.wait(3))
                    for lock in (traffic.collection_lock, traffic.traffic_lock):
                        acquired = lock.acquire(blocking=False)
                        try:
                            self.assertTrue(acquired, "identity read blocked a collector lock")
                        finally:
                            if acquired:
                                lock.release()
                self.assertEqual(future.result(timeout=5)["users"], [])

    def test_pure_projection_runs_after_both_collector_locks_are_released(self):
        original_digest = quota.identity_digest

        def digest(row):
            for lock in (traffic.collection_lock, traffic.traffic_lock):
                acquired = lock.acquire(blocking=False)
                try:
                    self.assertTrue(acquired, "pure quota projection retained a collector lock")
                finally:
                    if acquired:
                        lock.release()
            return original_digest(row)

        with patch.object(quota, "_rows", return_value={"alice": self.row}), \
             patch.object(quota, "identity_digest", side_effect=digest):
            result = quota.inspect_users(["alice"])
        self.assertEqual(result["users"][0]["nativeTotalBytes"], 70)

    def test_parallel_inspections_keep_one_large_projection_and_leave_collector_free(self):
        first_entered, release, second_started, second_rows = (threading.Event() for _ in range(4))
        guard = threading.Lock()
        active = maximum = calls = 0

        def rows():
            nonlocal active, maximum, calls
            with guard:
                calls += 1
                index = calls
                active += 1
                maximum = max(maximum, active)
            try:
                if index == 1:
                    first_entered.set()
                    if not release.wait(5):
                        raise AssertionError("first inspection did not finish")
                else:
                    second_rows.set()
                return {"alice": copy.deepcopy(self.row)}
            finally:
                with guard:
                    active -= 1

        def inspect_second():
            second_started.set()
            return quota.inspect_users(["alice"])

        with patch.object(quota, "_rows", side_effect=rows):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(quota.inspect_users, ["alice"])
                try:
                    self.assertTrue(first_entered.wait(3))
                    second = pool.submit(inspect_second)
                    self.assertTrue(second_started.wait(3))
                    self.assertFalse(second_rows.wait(0.1))
                    for lock in (traffic.collection_lock, traffic.traffic_lock):
                        acquired = lock.acquire(blocking=False)
                        try:
                            self.assertTrue(acquired)
                        finally:
                            if acquired:
                                lock.release()
                finally:
                    release.set()
                self.assertEqual(first.result(timeout=5)["users"][0]["nativeTotalBytes"], 70)
                self.assertEqual(second.result(timeout=5)["users"][0]["nativeTotalBytes"], 70)
        self.assertEqual(calls, 2)
        self.assertEqual(maximum, 1)

    def test_identity_failure_releases_the_inspection_only_lock(self):
        with patch.object(quota, "_rows", side_effect=[quota.QuotaEvidenceRejected("IDENTITY_UNAVAILABLE"),
                                                      {"alice": self.row}]):
            with self.assertRaisesRegex(quota.QuotaEvidenceRejected, "IDENTITY_UNAVAILABLE"):
                quota.inspect_users(["alice"])
            self.assertEqual(quota.inspect_users(["alice"])["users"][0]["nativeTotalBytes"], 70)

    def test_atomic_config_replacement_during_identity_read_retries_fresh_rows(self):
        old_row = copy.deepcopy(self.row)
        new_row = copy.deepcopy(self.row)
        new_row["auth"][0]["credential"] = "new-credential"
        calls = 0

        def rows():
            nonlocal calls
            calls += 1
            if calls == 1:
                changed = json.loads(self.config_path.read_text(encoding="utf-8"))
                changed["marker"] = 1
                self.replace_json(self.config_path, changed, preserve_mtime=True)
                return {"alice": old_row}
            return {"alice": new_row}

        with patch.object(quota, "_rows", side_effect=rows):
            result = quota.inspect_users(["alice"])
        self.assertEqual(calls, 2)
        self.assertEqual(result["users"][0]["identityDigest"], quota.identity_digest(new_row))

    def test_registry_replacement_while_waiting_for_collection_lock_retries(self):
        original_versions = quota._identity_versions
        checks = 0
        calls = 0
        new_row = copy.deepcopy(self.row)
        new_row["trafficLimitBytes"] = 2000

        def versions():
            nonlocal checks
            checks += 1
            result = original_versions()
            if checks == 2:
                # The pre-lock fence was already read; replace just before
                # the inspector enters its short counter-capture section.
                self.replace_json(self.registry_path, {"users": {"alice": {"trafficLimitBytes": 2000}}})
            return result

        def rows():
            nonlocal calls
            calls += 1
            return {"alice": self.row if calls == 1 else new_row}

        with patch.object(quota, "_identity_versions", side_effect=versions), \
             patch.object(quota, "_rows", side_effect=rows):
            result = quota.inspect_users(["alice"])
        self.assertEqual(calls, 2)
        self.assertEqual(result["users"][0]["limitBytes"], 2000)

    def test_identity_change_after_counter_read_retries_instead_of_mixing_rows(self):
        original_read = traffic._read_store
        reads = 0
        rows_calls = 0
        new_row = copy.deepcopy(self.row)
        new_row["auth"][0]["credential"] = "rotated"

        def read_store():
            nonlocal reads
            reads += 1
            result = original_read()
            if reads == 1:
                changed = json.loads(self.config_path.read_text(encoding="utf-8"))
                changed["marker"] = 1
                self.replace_json(self.config_path, changed)
            return result

        def rows():
            nonlocal rows_calls
            rows_calls += 1
            return {"alice": self.row if rows_calls == 1 else new_row}

        with patch.object(quota, "_rows", side_effect=rows), \
             patch.object(traffic, "_read_store", side_effect=read_store):
            result = quota.inspect_users(["alice"])
        self.assertEqual(reads, 2)
        self.assertEqual(result["users"][0]["identityDigest"], quota.identity_digest(new_row))

    def test_continuously_replaced_identity_fails_closed_after_bounded_retries(self):
        calls = 0
        before = self.traffic_path.read_bytes()

        def unstable_rows():
            nonlocal calls
            calls += 1
            self.replace_json(self.registry_path, {"users": {}, "generation": calls})
            return {"alice": self.row}

        with patch.object(quota, "_rows", side_effect=unstable_rows), \
             patch.object(traffic, "_read_store", side_effect=AssertionError("unstable identity reached counters")):
            with self.assertRaisesRegex(quota.QuotaEvidenceRejected, "NODE_IDENTITY_CHANGED"):
                quota.inspect_users(["alice"])
        self.assertEqual(calls, 3)
        self.assertEqual(self.traffic_path.read_bytes(), before)

    def test_reset_during_identity_projection_is_seen_by_fresh_counter_capture(self):
        original_epoch = quota.epoch_token(quota.epoch(traffic._read_store()["users"]["alice"]))

        def rows():
            traffic.reset_user_traffic("alice")
            return {"alice": self.row}

        with patch.object(quota, "_rows", side_effect=rows), \
             patch("singbox.runtime_client.enabled", return_value=False), \
             patch.object(traffic, "sync_user_enforcements"):
            result = quota.inspect_users(["alice"])
        self.assertEqual(result["users"][0]["nativeTotalBytes"], 0)
        self.assertNotEqual(result["users"][0]["epochToken"], original_epoch)
        self.assertEqual(traffic._read_store()["connections"]["open"]["upload"], 100)

    def test_successive_observations_use_fresh_identity_and_usage_without_cache(self):
        row = copy.deepcopy(self.row)
        with patch.object(quota, "_rows", side_effect=lambda: {"alice": copy.deepcopy(row)}):
            first = quota.inspect_users(["alice"])
            self.write_usage(99)
            row["auth"][0]["credential"] = "new"
            second = quota.inspect_users(["alice"])
        self.assertEqual(first["users"][0]["nativeTotalBytes"], 70)
        self.assertEqual(second["users"][0]["nativeTotalBytes"], 99)
        self.assertNotEqual(first["users"][0]["identityDigest"], second["users"][0]["identityDigest"])
        self.assertGreaterEqual(second["observedAt"], first["observedAt"])


if __name__ == "__main__":
    unittest.main()
