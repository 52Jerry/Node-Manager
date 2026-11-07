"""Slow accepted writes must not freeze accounting or misdate telemetry."""
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Condition
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest

import test_manager_read_snapshot as fixtures
from test_next_stage import traffic
from monitor.enforcement_wait import PendingEnforcement
import runtime_write_queue as queue


def pending_writer():
    writer = queue.RuntimeWriteQueue.__new__(queue.RuntimeWriteQueue)
    writer.cv = Condition()
    future = Future()
    writer.live = {"accepted": SimpleNamespace(future=future)}
    return writer, future


def test_collector_returns_before_accepted_write_finishes_and_follows_one_receipt():
    writer, publication = pending_writer()
    receipt = {"taskId": "accepted", "state": "QUEUED"}
    writer.status = Mock(side_effect=lambda task_id: dict(receipt))
    gate = PendingEnforcement(lambda: queue)
    desired = {"alice": {"trafficBlocked": True}}
    synchronize = Mock(side_effect=lambda payload: writer.wait("accepted"))

    def collect():
        return traffic.collect_traffic(), queue.wait_timeout.get()

    with patch.object(traffic, "_sample_traffic", return_value=(desired, set())), \
         patch.object(traffic, "_enforcement_wait", gate), \
         patch.object(traffic, "sync_user_enforcements", synchronize), \
         patch("singbox.runtime_client.enabled", return_value=True), \
         patch.object(queue, "current", return_value=writer), \
         patch.object(traffic, "collection_health", {}), \
         ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(collect)
        try:
            assert first.result(timeout=2) == (False, 60)
            assert not publication.done()
            assert gate.pending_task_id == "accepted"
            assert executor.submit(collect).result(timeout=2) == (False, 60)
            assert synchronize.call_count == 1
            # An uncertain accepted result must never be blindly submitted again.
            receipt["state"] = "UNKNOWN"
            assert executor.submit(collect).result(timeout=2) == (False, 60)
            assert synchronize.call_count == 1
            publication.set_result(False)
            receipt["state"] = "SUCCEEDED"
            assert executor.submit(collect).result(timeout=2) == (True, 60)
            assert synchronize.call_count == 2
            assert gate.pending_task_id is None
        finally:
            if not publication.done():
                publication.set_result(False)


def test_explicit_wait_budget_and_completed_receipt_survive_collector_override():
    writer, future = pending_writer()
    token = queue.wait_timeout.set(0)
    try:
        try:
            writer.wait("accepted")
            raise AssertionError("incomplete work must retain its receipt")
        except queue.TaskPending as pending:
            assert pending.task_id == "accepted"
        future.set_result({"success": True})
        assert writer.wait("accepted") == {"success": True}
        assert writer.wait("accepted", timeout=None) == {"success": True}
    finally:
        queue.wait_timeout.reset(token)
    assert queue.wait_timeout.get() == 60


class ConnectionObservationTests(unittest.TestCase):
    setUp = fixtures.ManagerReadSummaryTests.setUp
    tearDown = fixtures.ManagerReadSummaryTests.tearDown
    store = fixtures.ManagerReadSummaryTests.store
    def test_pending_enforcement_does_not_hide_a_fresh_observation(self):
        traffic._write_store(self.store())
        traffic.collection_health[str(self.path)] = {
            "reason": "enforcement_task_pending", "observationReason": None}
        observation = traffic.get_proxy_connection_count_snapshot()
        assert observation["connections"] == 2
        assert observation["observationAvailable"] is True
        assert observation["telemetryAvailable"] is True
        assert observation["available"] is False
        assert observation["enforcementAvailable"] is False
        assert observation["enforcementReason"] == "enforcement_task_pending"
        # Accounting and quota APIs keep their stricter existing contract.
        assert traffic.get_traffic_totals(refresh=False)["available"] is False

    def test_slow_sample_remains_visible_with_its_real_age(self):
        store = self.store()
        store["collectedAt"] = (datetime.now(timezone.utc) - timedelta(seconds=8)).isoformat()
        traffic._write_store(store)
        observation = traffic.get_proxy_connection_count_snapshot()
        assert observation["connections"] == 2
        assert observation["observationAvailable"] is True
        assert observation["telemetryAvailable"] is False
        assert observation["stale"] is True
        assert observation["stalenessSeconds"] >= 8
        assert observation["staleAfterSeconds"] == 6

    def test_native_only_update_cannot_refresh_retained_connection_timestamp(self):
        store = self.store()
        old = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        store["collectedAt"] = old
        traffic._write_store(store)
        with patch("singbox.runtime_client.enabled", return_value=True), \
             patch("singbox.runtime_client.RuntimeClient.counters", return_value={}), \
             patch.object(traffic, "get_user_monitoring_snapshot", return_value=SimpleNamespace(auth_map={})), \
             patch.object(traffic.singbox_api, "get_connections", return_value=None), \
             patch.object(traffic, "_apply_native_counters"), \
             patch.object(traffic, "_archive_inactive_usage"):
            assert traffic.collect_traffic() is False
        written = traffic._read_store()
        assert written["collectedAt"] > old
        assert written["connectionsCollectedAt"] == old
        observation = traffic.get_proxy_connection_count_snapshot()
        assert observation["collectedAt"] == old
        assert observation["unavailableReason"] == "api_unavailable"
        assert observation["telemetryAvailable"] is False
