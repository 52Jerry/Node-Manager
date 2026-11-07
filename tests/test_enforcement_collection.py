"""Accepted slow writes must not stall fresh accounting or duplicate tasks."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_manager_read_snapshot as fixture
from test_next_stage import traffic
from monitor.enforcement_wait import PendingEnforcement
from runtime_write_queue import TaskPending


class EnforcementCollectionTests(unittest.TestCase):
    setUp = fixture.ManagerReadSummaryTests.setUp
    tearDown = fixture.ManagerReadSummaryTests.tearDown

    def test_pending_enforcement_keeps_sampling_without_resubmitting_or_recounting(self):
        state = {"state": "QUEUED", "taskId": "accepted-task"}
        writer = SimpleNamespace(status=Mock(side_effect=lambda task_id: dict(state)))
        queue = SimpleNamespace(current=lambda: writer, TaskPending=TaskPending)
        gate = PendingEnforcement(lambda: queue)
        synchronize = Mock(side_effect=[TaskPending("accepted-task"), False])
        snapshots = [{"connections": [{"id": "session", "chains": ["node-manager-out:alice"],
                        "upload": upload, "download": 0}]} for upload in (4, 9, 15)]
        with patch.object(traffic, "_enforcement_wait", gate), \
             patch("singbox.runtime_client.enabled", return_value=False), \
             patch.object(traffic, "get_user_policies", return_value={}), \
             patch.object(traffic, "get_user_auth_map", return_value={}), \
             patch.object(traffic, "sync_user_enforcements", synchronize), \
             patch.object(traffic.singbox_api, "get_connections", side_effect=snapshots):
            self.assertFalse(traffic.collect_traffic())
            self.assertFalse(traffic.collect_traffic())
            self.assertEqual(synchronize.call_count, 1)
            self.assertEqual(traffic._read_store()["users"]["alice"]["upload"], 9)
            self.assertFalse(traffic.get_traffic_totals(refresh=False)["available"])
            state["state"] = "SUCCEEDED"
            self.assertTrue(traffic.collect_traffic())
        self.assertEqual(synchronize.call_count, 2)
        self.assertEqual(traffic._read_store()["users"]["alice"]["upload"], 15)
        self.assertTrue(traffic.get_traffic_totals(refresh=False)["available"])

    def test_unknown_receipt_still_persists_new_traffic_without_a_second_write(self):
        writer = SimpleNamespace(status=Mock(side_effect=OSError("receipt temporarily unavailable")))
        queue = SimpleNamespace(current=lambda: writer, TaskPending=TaskPending)
        gate = PendingEnforcement(lambda: queue)
        synchronize = Mock(side_effect=TaskPending("accepted-task"))
        snapshots = [{"connections": [{"id": "session", "chains": ["node-manager-out:alice"],
                        "upload": upload, "download": 0}]} for upload in (4, 17)]
        with patch.object(traffic, "_enforcement_wait", gate), \
             patch("singbox.runtime_client.enabled", return_value=False), \
             patch.object(traffic, "get_user_policies", return_value={}), \
             patch.object(traffic, "get_user_auth_map", return_value={}), \
             patch.object(traffic, "sync_user_enforcements", synchronize), \
             patch.object(traffic.singbox_api, "get_connections", side_effect=snapshots):
            self.assertFalse(traffic.collect_traffic())
            self.assertFalse(traffic.collect_traffic())
        self.assertEqual(synchronize.call_count, 1)
        self.assertEqual(traffic._read_store()["users"]["alice"]["upload"], 17)
        self.assertEqual(gate.reason, "enforcement_task_query_failed")
        self.assertFalse(traffic.get_traffic_totals(refresh=False)["available"])
