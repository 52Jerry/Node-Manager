import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
import copy
import unittest
from monitor.runtime_counters import apply_counters

class RuntimeCounterTests(unittest.TestCase):
    def snapshot(self, upload=100, download=200, instance="first"):
        return {"instanceId": instance, "users": [{"inbound": "socks", "user": "alias", "upload": upload, "download": download}]}
    def collect(self, store, snapshot):
        apply_counters(store, snapshot, {"alias": "user"}, {})
    def test_repeated_snapshot_reset_and_process_restart_do_not_double_count(self):
        store = {"users": {}}
        self.collect(store, self.snapshot())
        self.collect(store, self.snapshot())
        self.assertEqual(store["users"]["user"]["upload"], 100)
        store["users"]["user"].update(upload=0, download=0)
        self.collect(store, self.snapshot(110, 210))
        self.assertEqual(store["users"]["user"]["upload"], 10)
        self.collect(store, self.snapshot(4, 5, "second"))
        self.assertEqual(store["users"]["user"]["upload"], 14)
        with self.assertRaisesRegex(ValueError, "retired"):
            self.collect(store, self.snapshot(120, 220))
    def test_migration_baselines_existing_sampled_usage_once(self):
        store = {"users": {"user": {"upload": 10, "download": 20}}, "collectedAt": "previous"}
        self.collect(store, self.snapshot())
        self.assertEqual(store["users"]["user"]["upload"], 10)
        self.collect(store, self.snapshot(120, 230))
        self.assertEqual(store["users"]["user"]["upload"], 30)
    def test_regression_duplicate_partial_snapshot_and_owner_reassignment_reject(self):
        store = {"users": {}}
        self.collect(store, self.snapshot())
        with self.assertRaisesRegex(ValueError, "regression"):
            self.collect(copy.deepcopy(store), self.snapshot(90, 200))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.collect(copy.deepcopy(store), {"instanceId": "first", "users": []})
        with self.assertRaisesRegex(ValueError, "owner_changed"):
            apply_counters(copy.deepcopy(store), self.snapshot(120, 220), {"alias": "other"}, {})
    def test_closed_user_can_be_attributed_from_persisted_alias(self):
        store = {"users": {}}
        apply_counters(store, self.snapshot(), {}, {"alias": "deleted-user"})
        self.assertEqual(store["users"]["deleted-user"]["upload"], 100)
