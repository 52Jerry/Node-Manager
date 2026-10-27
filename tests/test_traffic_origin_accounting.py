"""Replication, peer observations and failover must count each origin once."""
import copy
import unittest
from unittest.mock import patch

import test_next_stage as fixture
import test_user_replication as replication_fixture
from user_replication import apply_users, export_users
from monitor import shared_quota as quota
from test_next_stage import manager, traffic


class TrafficOriginAccountingTests(unittest.TestCase):
    setUp = fixture.ManagerTestCase.setUp
    tearDown = fixture.ManagerTestCase.tearDown
    _write_config = fixture.ManagerTestCase._write_config
    create = replication_fixture.UserReplicationTest.create
    reset_target = replication_fixture.UserReplicationTest.reset_target
    request = replication_fixture.UserReplicationTest.request

    def source(self, count=600):
        self.create()
        store = traffic._empty_store()
        store["users"]["primary-7"] = {"upload": count, "download": 0}
        traffic._write_store(store)
        with patch.object(manager.config.node, "id", "source-A"):
            return export_users(), quota.inspect_users()

    def test_replicated_600_and_peer_600_are_600_not_1200(self):
        snapshot, source = self.source()
        self.reset_target()
        with patch.object(manager.config.node, "id", "standby-B"):
            apply_users(self.request(snapshot))
            target = quota.inspect_users()
            self.assertEqual(target["users"][0]["nativeTotalBytes"], 0)
            self.assertEqual(target["users"][0]["peerObservedBytes"], 600)
            update = {"targetUserId": "primary-7", "source": source["users"][0],
                      "expectedTargetEpochToken": target["users"][0]["epochToken"]}
            result = quota.apply_users("source-A", source["observedAt"], [update])
            self.assertEqual(result["blockedUsers"], [])
            for _ in range(3):
                apply_users(self.request(snapshot))
                quota.apply_users("source-A", source["observedAt"], [update])
            usage = traffic._read_store()["users"]["primary-7"]
            self.assertEqual(usage["upload"] + usage["download"], 0)
            self.assertEqual(quota.peer_used_bytes(usage, 1000), 600)
            self.assertFalse(any(r.get("action") == "reject" for r in manager.read_config()["route"]["rules"]))

    def test_bidirectional_promotion_and_repeated_snapshots_preserve_origins(self):
        snapshot, _ = self.source()
        source_usage = copy.deepcopy(traffic._read_store()["users"]["primary-7"])
        self.reset_target()
        with patch.object(manager.config.node, "id", "standby-B"):
            apply_users(self.request(snapshot))
            store = traffic._read_store()
            store["users"]["primary-7"]["download"] = 100
            traffic._write_store(store)
            promoted = export_users()["users"][0]
            for _ in range(4):
                quota.import_origins(source_usage, promoted["trafficOrigins"], "source-A", None, 0)
                back = quota.export_origins(source_usage, "source-A")
                quota.import_origins(store["users"]["primary-7"], back, "standby-B", None, 0)
            self.assertEqual(source_usage["upload"], 600)
            self.assertEqual(quota.peer_used_bytes(source_usage, 1000), 100)
            self.assertEqual(store["users"]["primary-7"]["download"], 100)
            self.assertEqual(quota.peer_used_bytes(store["users"]["primary-7"], 1000), 600)
            self.assertEqual(promoted["upload"] + promoted["download"], 700)

    def test_legacy_mixed_counter_is_readonly_review_not_native_or_autozero(self):
        self.source()
        store = traffic._read_store()
        store["users"]["primary-7"]["replicationCycle"] = "legacy-cycle"
        traffic._write_store(store)
        before = self.traffic_path.read_bytes()
        result = quota.inspect_users()
        self.assertEqual(result["users"], [])
        self.assertEqual(result["issues"][0]["reason"], "LEGACY_REPLICATED_TRAFFIC_REVIEW_REQUIRED")
        with self.assertRaisesRegex(manager.SingboxConfigError, "LEGACY_REPLICATED"):
            export_users()
        self.assertEqual(before, self.traffic_path.read_bytes())
        enforcements, _ = traffic._enforce_policies(store, {}, {"primary-7": {"trafficLimitBytes": 1}}, 0)
        self.assertEqual(enforcements, {})
        self.assertEqual(store["users"]["primary-7"]["upload"], 600)

    def test_nonzero_legacy_snapshot_without_origin_is_rejected_before_writes(self):
        snapshot, _ = self.source()
        snapshot["users"][0].pop("trafficOrigins")
        self.reset_target()
        before = self.config_path.read_bytes()
        with self.assertRaisesRegex(manager.SingboxConfigError, "TRAFFIC_ORIGIN_REQUIRED"):
            apply_users(self.request(snapshot))
        self.assertEqual(self.config_path.read_bytes(), before)
        self.assertFalse(self.traffic_path.exists())

    def test_reset_retires_origins_and_stale_snapshots_cannot_restore_them(self):
        old_epoch = quota.epoch({})
        origin = {"source-A": {"upload": 600, "download": 0, "epoch": old_epoch}}
        user = {}
        quota.import_origins(user, origin, "standby-B", None, 0)
        quota.clear_for_reset(user)
        self.assertEqual(quota.peer_used_bytes(user, 1000), 0)
        reset_snapshot = quota.export_origins(user, "standby-B")
        self.assertEqual(reset_snapshot["standby-B"]["upload"], 0)
        self.assertEqual(reset_snapshot["standby-B"]["epoch"]["version"], 1)
        with self.assertRaisesRegex(quota.QuotaEvidenceRejected, "SOURCE_RESET_REQUIRED"):
            quota.import_origins(user, origin, "standby-B", None, 0)
        new_origin = copy.deepcopy(origin)
        new_origin["source-A"].update(upload=25, epoch={**old_epoch, "version": 1})
        quota.import_origins(user, new_origin, "standby-B", None, 0)
        self.assertEqual(quota.peer_used_bytes(user, 1000), 25)

    def test_new_peer_epoch_replaces_old_baseline_instead_of_taking_old_max(self):
        user = {}
        old = quota.epoch(user)
        quota.import_origins(user, {"source-A": {"upload": 600, "download": 0, "epoch": old}},
                             "standby-B", None, 0)
        user[quota.EVIDENCE_KEY] = {"source-A": {"targetEpochToken": quota.epoch_token(quota.epoch(user)),
            "limitBytes": 1000, "nativeTotalBytes": 25, "sourceEpoch": {**old, "version": 1}}}
        self.assertEqual(quota.peer_used_bytes(user, 1000), 25)
        self.assertEqual(quota.export_origins(user, "standby-B")["source-A"]["upload"], 25)

    def test_forged_aggregate_or_self_history_cannot_silently_change_usage(self):
        snapshot, _ = self.source()
        self.reset_target()
        with self.assertRaisesRegex(manager.SingboxConfigError, "LOCAL_TRAFFIC_HISTORY"):
            with patch.object(manager.config.node, "id", "source-A"):
                apply_users(self.request(snapshot))
        snapshot["users"][0]["upload"] += 1
        with self.assertRaisesRegex(manager.SingboxConfigError, "TOTAL_MISMATCH"):
            apply_users(self.request(snapshot))
