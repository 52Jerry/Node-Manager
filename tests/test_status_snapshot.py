"""Status requests must not multiply full host/connection scans."""
from __future__ import annotations

import importlib.util
import sys
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest


STATUS_PATH = Path(__file__).resolve().parents[1] / "node-manager/monitor/status.py"


@pytest.fixture
def status_module():
    manager = types.ModuleType("singbox.manager")
    manager.is_singbox_running = Mock(return_value=True)
    manager.singbox_api = types.SimpleNamespace(
        get_connections=Mock(side_effect=AssertionError("request must not fetch live connections")),
    )
    traffic = types.ModuleType("monitor.traffic")
    traffic.snapshot = {"connections": 7, "collectedAt": datetime.now(timezone.utc).isoformat(), "available": True}
    traffic.get_proxy_connection_count_snapshot = Mock(side_effect=lambda: dict(traffic.snapshot))
    with patch.dict(sys.modules, {"singbox.manager": manager, "monitor.traffic": traffic}):
        spec = importlib.util.spec_from_file_location("_isolated_node_status", STATUS_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.get_cpu_usage = Mock(return_value=12.5)
        module.get_memory_usage = Mock(return_value=40.0)
        module._measure_system_connections = Mock(return_value=123)
        module._status_sampler = module._StatusSampler(interval=60)
        try:
            yield module, manager, traffic
        finally:
            module.stop_status_sampler()


def wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        threading.Event().wait(0.005)
    raise AssertionError("background status sample did not finish")


def test_import_does_not_start_a_thread(status_module):
    status, manager, traffic = status_module
    assert status._status_sampler._thread is None
    manager.is_singbox_running.assert_not_called()
    traffic.get_proxy_connection_count_snapshot.assert_not_called()


def test_concurrent_requests_share_one_slow_background_scan(status_module):
    status, manager, traffic = status_module
    entered, release = threading.Event(), threading.Event()

    def slow_scan():
        entered.set()
        assert release.wait(2)
        return 321

    status._measure_system_connections.side_effect = slow_scan
    try:
        first = status.get_node_status("node-a")
        assert entered.wait(1)
        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = [executor.submit(status.get_node_status, "node-%s" % i) for i in range(36)]
            values = [future.result(timeout=1) for future in futures]
        # Every request completed while the one socket scan remained blocked.
        assert not release.is_set()
        assert all(value["systemConnections"] == -1 for value in values)
        assert first["sampleAvailable"] is False
        status._measure_system_connections.assert_called_once()
        manager.is_singbox_running.assert_called_once()
        assert status._status_sampler._thread.is_alive()
    finally:
        release.set()
    wait_until(lambda: status._status_sampler.read("node-a")["sampleAvailable"])
    ready = status.get_node_status("node-a")
    assert ready["systemConnections"] == 321
    assert ready["connections"] == 7
    assert ready["sampledAt"] is not None
    assert ready["connectionsCollectedAt"] == traffic.snapshot["collectedAt"]
    assert ready["sampleStale"] is False
    manager.singbox_api.get_connections.assert_not_called()


def test_failed_component_retains_value_and_reports_unavailable(status_module):
    status, _, _ = status_module
    now = [10.0]
    sampler = status._StatusSampler(clock=lambda: now[0])
    stop = threading.Event()
    sampler._sample_once(stop)
    before = sampler.read("node-a")
    now[0] = 40.0
    status._measure_system_connections.side_effect = OSError("unavailable")
    sampler._sample_once(stop)
    after = sampler.read("node-a")
    assert after["systemConnections"] == 123
    assert after["sampleAgeSeconds"] == 0.0
    assert after["lastSuccessfulSampledAt"] == before["lastSuccessfulSampledAt"]
    assert after["metricSamples"]["cpu"]["sampleAgeSeconds"] == 0
    assert after["metricSamples"]["systemConnections"]["sampleAgeSeconds"] == 30
    assert after["sampleAvailable"] is False
    assert after["sampleStale"] is True
    assert after["metricsUnavailable"] == ["systemConnections"]
    assert after["sampleError"] == "sample_unavailable:systemConnections"
    assert after["systemConnectionsSampledAt"] == before["systemConnectionsSampledAt"]
    assert after["systemConnectionsSampleAgeSeconds"] == 30.0
    assert after["systemConnectionsStale"] is True


def test_cold_failure_is_unknown_instead_of_measured_zero(status_module):
    status, manager, traffic = status_module
    manager.is_singbox_running.side_effect = OSError("missing service controller")
    status.get_cpu_usage.side_effect = OSError("unavailable")
    status.get_memory_usage.side_effect = OSError("unavailable")
    status._measure_system_connections.side_effect = OSError("unavailable")
    traffic.snapshot.update(connections=None, collectedAt=None, available=False)
    sampler = status._StatusSampler()
    sampler._sample_once(threading.Event())
    snapshot = sampler.read("node-a")
    assert snapshot["singbox"] == "unknown"
    assert [snapshot[k] for k in ("cpu", "memory", "connections", "systemConnections")] == [-1, -1, -1, -1]
    assert snapshot["sampledAt"] is None
    assert snapshot["lastSuccessfulSampledAt"] is None
    assert snapshot["metricSamples"]["connections"]["sampledAt"] is None
    assert snapshot["sampleAvailable"] is False
    assert set(snapshot["metricsUnavailable"]) == {"singbox", "cpu", "memory", "connections", "systemConnections"}


def test_expired_sample_is_marked_stale_without_request_refresh(status_module):
    status, manager, _ = status_module
    now = [10.0]
    sampler = status._StatusSampler(stale_after=9, clock=lambda: now[0])
    sampler._sample_once(threading.Event())
    now[0] = 20.0
    snapshot = sampler.read("node-a")
    assert snapshot["sampleAgeSeconds"] == 10
    assert snapshot["sampleStale"] is True
    assert snapshot["sampleAvailable"] is False
    assert snapshot["sampleError"] == "sample_stale"
    assert snapshot["systemConnections"] == 123
    manager.is_singbox_running.assert_called_once()


def test_unavailable_traffic_does_not_fall_back_to_live_clash(status_module):
    status, manager, traffic = status_module
    sampler = status._StatusSampler()
    sampler._sample_once(threading.Event())
    traffic.snapshot.update(connections=0, available=False)
    sampler._sample_once(threading.Event())
    snapshot = sampler.read("node-a")
    assert snapshot["connections"] == 7
    assert snapshot["metricsUnavailable"] == ["connections"]
    assert snapshot["sampleAvailable"] is False
    manager.singbox_api.get_connections.assert_not_called()


def test_cold_stale_traffic_keeps_observed_count_without_claiming_freshness(status_module):
    status, manager, traffic = status_module
    traffic.snapshot.update(connections=537, collectedAt="2026-11-06T08:00:00Z", available=False)
    sampler = status._StatusSampler()
    sampler._sample_once(threading.Event())
    snapshot = sampler.read("node-a")
    assert snapshot["connections"] == 537
    assert snapshot["connectionsCollectedAt"] == "2026-11-06T08:00:00Z"
    assert snapshot["sampleAvailable"] is False
    assert snapshot["sampleStale"] is True
    assert snapshot["metricsUnavailable"] == ["connections"]
    assert snapshot["sampledAt"] is not None
    assert snapshot["lastSuccessfulSampledAt"] is None
    assert snapshot["connectionsStale"] is True
    assert snapshot["sampleError"] == "sample_unavailable:connections"
    manager.singbox_api.get_connections.assert_not_called()


def test_stale_helper_does_not_replace_last_good_connection_count_or_time(status_module):
    status, _, traffic = status_module
    sampler = status._StatusSampler()
    sampler._sample_once(threading.Event())
    good = sampler.read("node-a")
    traffic.snapshot.update(connections=999, collectedAt="2026-11-06T07:00:00Z", available=False)
    sampler._sample_once(threading.Event())
    stale = sampler.read("node-a")
    assert stale["connections"] == good["connections"] == 7
    assert stale["connectionsCollectedAt"] == good["connectionsCollectedAt"]
    assert stale["lastSuccessfulSampledAt"] == good["lastSuccessfulSampledAt"]
    assert stale["sampleAvailable"] is False
    assert stale["sampleStale"] is True
    assert stale["metricsUnavailable"] == ["connections"]


@pytest.mark.parametrize("count,collected_at", [(None, None), (None, "2026-11-06T08:00:00Z"), (0, None), (12, ""), (True, "2026-11-06T08:00:00Z")])
def test_cold_incomplete_traffic_remains_unknown(status_module, count, collected_at):
    status, _, traffic = status_module
    traffic.snapshot.update(connections=count, collectedAt=collected_at, available=False)
    sampler = status._StatusSampler()
    sampler._sample_once(threading.Event())
    snapshot = sampler.read("node-a")
    assert snapshot["connections"] == -1
    assert snapshot["connectionsCollectedAt"] is None
    assert snapshot["sampleAvailable"] is False
    assert snapshot["sampleStale"] is True
    assert snapshot["metricsUnavailable"] == ["connections"]


def test_worker_refreshes_without_new_requests_and_stops(status_module):
    status, _, traffic = status_module
    sampler = status._StatusSampler(interval=0.02)
    sampler.start()
    try:
        wait_until(lambda: sampler.read("node-a")["connections"] == 7)
        traffic.snapshot["connections"] = 19
        wait_until(lambda: sampler.read("node-a")["connections"] == 19)
        assert traffic.get_proxy_connection_count_snapshot.call_count >= 2
        status._measure_system_connections.assert_called_once()
    finally:
        sampler.stop()
    assert not sampler._thread.is_alive()
    count = traffic.get_proxy_connection_count_snapshot.call_count
    threading.Event().wait(0.04)
    assert traffic.get_proxy_connection_count_snapshot.call_count == count


def test_host_socket_count_has_an_independent_30_second_sample(status_module):
    status, manager, traffic = status_module
    now = [10.0]
    sampler = status._StatusSampler(clock=lambda: now[0])
    stop = threading.Event()
    sampler._sample_once(stop)
    first = sampler.read("node-a")
    for instant in (13.0, 16.0, 25.0, 39.9):
        now[0] = instant
        sampler._sample_once(stop)
    cached = sampler.read("node-a")
    status._measure_system_connections.assert_called_once()
    assert manager.is_singbox_running.call_count == 5
    assert traffic.get_proxy_connection_count_snapshot.call_count == 5
    assert cached["sampleAvailable"] is True
    assert cached["sampleAgeSeconds"] == 0
    assert cached["systemConnectionsSampledAt"] == first["systemConnectionsSampledAt"]
    assert cached["systemConnectionsSampleAgeSeconds"] == pytest.approx(29.9)
    assert cached["systemConnectionsSampleIntervalSeconds"] == 30
    assert cached["systemConnectionsStale"] is False
    now[0] = 40.0
    status._measure_system_connections.return_value = 456
    sampler._sample_once(stop)
    refreshed = sampler.read("node-a")
    assert status._measure_system_connections.call_count == 2
    assert refreshed["systemConnections"] == 456
    assert refreshed["systemConnectionsSampleAgeSeconds"] == 0
    assert refreshed["sampleAvailable"] is True


def test_failed_host_count_retries_next_normal_cycle_without_advancing_time(status_module):
    status, _, _ = status_module
    now = [10.0]
    sampler = status._StatusSampler(clock=lambda: now[0])
    stop = threading.Event()
    sampler._sample_once(stop)
    initial = sampler.read("node-a")
    now[0] = 40.0
    status._measure_system_connections.side_effect = OSError("temporary failure")
    sampler._sample_once(stop)
    failed = sampler.read("node-a")
    assert failed["systemConnections"] == 123
    assert failed["systemConnectionsSampledAt"] == initial["systemConnectionsSampledAt"]
    assert failed["systemConnectionsSampleAgeSeconds"] == 30
    assert failed["systemConnectionsStale"] is True
    now[0] = 43.0
    status._measure_system_connections.side_effect = None
    status._measure_system_connections.return_value = 789
    sampler._sample_once(stop)
    recovered = sampler.read("node-a")
    assert status._measure_system_connections.call_count == 3
    assert recovered["systemConnections"] == 789
    assert recovered["systemConnectionsSampleAgeSeconds"] == 0
    assert recovered["systemConnectionsStale"] is False
    assert recovered["sampleAvailable"] is True


def test_host_count_expiry_is_explicit_even_without_a_new_cycle(status_module):
    status, _, _ = status_module
    now = [10.0]
    sampler = status._StatusSampler(clock=lambda: now[0])
    sampler._sample_once(threading.Event())
    now[0] = 50.0
    snapshot = sampler.read("node-a")
    assert snapshot["systemConnectionsSampleAgeSeconds"] == 40
    assert snapshot["systemConnectionsStale"] is True
    assert snapshot["systemConnections"] == 123
    status._measure_system_connections.assert_called_once()


def test_returned_metadata_cannot_mutate_cached_snapshot(status_module):
    status, _, traffic = status_module
    traffic.snapshot["available"] = False
    sampler = status._StatusSampler()
    sampler._sample_once(threading.Event())
    first = sampler.read("node-a")
    first["metricsUnavailable"].clear()
    first["cpu"] = 100
    second = sampler.read("node-b")
    assert second["node"] == "node-b"
    assert second["metricsUnavailable"] == ["connections"]
    assert second["cpu"] == 12.5


def test_stop_discards_an_inflight_sample(status_module):
    status, _, _ = status_module
    entered, release = threading.Event(), threading.Event()

    def slow_scan():
        entered.set()
        assert release.wait(2)
        return 123

    status._measure_system_connections.side_effect = slow_scan
    sampler = status._StatusSampler(interval=0.02)
    sampler.start()
    try:
        assert entered.wait(1)
        sampler.stop(timeout=0.01)
        release.set()
        wait_until(lambda: not sampler._thread.is_alive())
        assert sampler.read("node-a")["sampledAt"] is None
    finally:
        release.set()
        sampler.stop()


def test_newer_slow_observation_replaces_count_without_claiming_freshness(status_module):
    status, _, traffic = status_module
    origin = datetime(2026, 11, 7, tzinfo=timezone.utc)
    now = [0.0]
    wall = lambda: origin + timedelta(seconds=now[0])
    traffic.snapshot.update(collectedAt=wall().isoformat(), observationAvailable=True,
                            telemetryAvailable=True, staleAfterSeconds=6,
                            enforcementAvailable=True, enforcementReason=None)
    sampler = status._StatusSampler(clock=lambda: now[0], wall_clock=wall)
    sampler._sample_once(threading.Event())
    first = sampler.read("node-a")

    # The next collection took 7.3 s before persistence, longer than its 6 s
    # evidence TTL. Its count is newer, but cannot justify execution as fresh.
    now[0] = 30.0
    traffic.snapshot.update(connections=937, collectedAt=(wall() - timedelta(seconds=7.3)).isoformat(),
                            available=False, telemetryAvailable=False, stale=True,
                            stalenessSeconds=7.3, unavailableReason="sample_stale")
    sampler._sample_once(threading.Event())
    latest = sampler.read("node-a")
    assert latest["connections"] == 937
    assert latest["connectionsCollectedAt"] != first["connectionsCollectedAt"]
    assert latest["connectionsSampleAgeSeconds"] == pytest.approx(7.3)
    assert latest["connectionsStale"] is True
    assert latest["connectionsAvailable"] is False
    assert latest["connectionsUnavailableReason"] == "sample_stale"
    assert latest["sampleAvailable"] is False
    assert latest["sampleAgeSeconds"] == 0
    assert latest["sampledAt"] == wall().isoformat()
    assert latest["metricSamples"]["cpu"]["sampleAgeSeconds"] == 0
    assert latest["lastSuccessfulSampledAt"] == first["lastSuccessfulSampledAt"]


def test_pending_policy_does_not_invalidate_fresh_connection_observation(status_module):
    status, _, traffic = status_module
    traffic.snapshot.update(connections=83, available=False, observationAvailable=True,
                            telemetryAvailable=True, stale=False, staleAfterSeconds=6,
                            enforcementAvailable=False, enforcementReason="enforcement_task_pending")
    sampler = status._StatusSampler()
    sampler._sample_once(threading.Event())
    snapshot = sampler.read("node-a")
    assert snapshot["connections"] == 83
    assert snapshot["connectionsAvailable"] is True
    assert snapshot["connectionsStale"] is False
    assert snapshot["connectionsUnavailableReason"] is None
    assert snapshot["enforcementAvailable"] is False
    assert snapshot["enforcementReason"] == "enforcement_task_pending"
    assert snapshot["sampleAvailable"] is True
    assert snapshot["metricsUnavailable"] == []


def test_single_failed_metric_keeps_its_own_time_while_other_metrics_advance(status_module):
    status, _, traffic = status_module
    origin = datetime(2026, 11, 7, tzinfo=timezone.utc)
    now = [0.0]
    wall = lambda: origin + timedelta(seconds=now[0])
    traffic.snapshot["collectedAt"] = wall().isoformat()
    sampler = status._StatusSampler(clock=lambda: now[0], wall_clock=wall)
    sampler._sample_once(threading.Event())
    before = sampler.read("node-a")
    now[0] = 3.0
    status.get_cpu_usage.side_effect = OSError("do not expose this exception")
    status.get_memory_usage.return_value = 51.0
    traffic.snapshot["collectedAt"] = wall().isoformat()
    sampler._sample_once(threading.Event())
    after = sampler.read("node-a")
    assert after["cpu"] == before["cpu"]
    assert after["metricSamples"]["cpu"]["sampledAt"] == before["metricSamples"]["cpu"]["sampledAt"]
    assert after["metricSamples"]["cpu"]["sampleAgeSeconds"] == 3
    assert after["metricSamples"]["cpu"]["available"] is False
    assert after["metricSamples"]["cpu"]["unavailableReason"] == "sample_failed"
    assert after["memory"] == 51
    assert after["metricSamples"]["memory"]["sampleAgeSeconds"] == 0
    assert after["sampledAt"] == wall().isoformat()
    assert after["lastSuccessfulSampledAt"] == before["lastSuccessfulSampledAt"]
    assert after["sampleAttemptedAt"] == wall().isoformat()
    assert after["metricsUnavailable"] == ["cpu"]


@pytest.mark.parametrize("invalid_stamp", [
    "2026-11-06T23:59:59+00:00",  # valid, but older than the accepted value
    "2026-11-07T00:00:10+00:00",  # future
    "2026-11-07T00:00:01",       # naive
    "not-a-timestamp",
])
def test_older_or_invalid_connection_time_cannot_replace_a_valid_observation(status_module, invalid_stamp):
    status, _, traffic = status_module
    origin = datetime(2026, 11, 7, tzinfo=timezone.utc)
    now = [0.0]
    wall = lambda: origin + timedelta(seconds=now[0])
    traffic.snapshot.update(collectedAt=wall().isoformat(), observationAvailable=True,
                            telemetryAvailable=True, staleAfterSeconds=6)
    sampler = status._StatusSampler(clock=lambda: now[0], wall_clock=wall)
    sampler._sample_once(threading.Event())
    now[0] = 2.0
    traffic.snapshot.update(connections=9999, collectedAt=invalid_stamp)
    sampler._sample_once(threading.Event())
    snapshot = sampler.read("node-a")
    assert snapshot["connections"] == 7
    assert snapshot["connectionsCollectedAt"] == origin.isoformat()
    assert snapshot["connectionsSampleAgeSeconds"] == 2
    assert snapshot["connectionsAvailable"] is False


def test_cached_connection_freshness_expires_using_source_ttl_without_new_sample(status_module):
    status, _, traffic = status_module
    now = [0.0]
    traffic.snapshot.update(telemetryAvailable=True, observationAvailable=True, staleAfterSeconds=6)
    sampler = status._StatusSampler(clock=lambda: now[0])
    sampler._sample_once(threading.Event())
    now[0] = 7.0
    snapshot = sampler.read("node-a")
    assert snapshot["connections"] == 7
    assert snapshot["connectionsStale"] is True
    assert snapshot["connectionsAvailable"] is False
    assert snapshot["connectionsUnavailableReason"] == "sample_stale"
    assert snapshot["metricsUnavailable"] == ["connections"]
    traffic.get_proxy_connection_count_snapshot.assert_called_once()


def test_slow_host_scan_does_not_advance_earlier_cpu_memory_measurement_time(status_module):
    status, _, traffic = status_module
    origin = datetime(2026, 11, 7, tzinfo=timezone.utc)
    now = [0.0]
    wall = lambda: origin + timedelta(seconds=now[0])
    traffic.snapshot.update(collectedAt=origin.isoformat(), observationAvailable=True,
                            telemetryAvailable=False, available=False, staleAfterSeconds=6,
                            stalenessSeconds=7.3, unavailableReason="sample_stale")

    def scan():
        now[0] += 7.3
        return 456

    status._measure_system_connections.side_effect = scan
    sampler = status._StatusSampler(clock=lambda: now[0], wall_clock=wall)
    sampler._sample_once(threading.Event())
    snapshot = sampler.read("node-a")
    assert snapshot["metricSamples"]["cpu"]["sampledAt"] == origin.isoformat()
    assert snapshot["metricSamples"]["cpu"]["sampleAgeSeconds"] == pytest.approx(7.3)
    assert snapshot["metricSamples"]["memory"]["sampleAgeSeconds"] == pytest.approx(7.3)
    assert snapshot["systemConnectionsSampleAgeSeconds"] == 0
    assert snapshot["connectionsSampleAgeSeconds"] == pytest.approx(7.3)
    assert snapshot["sampleAgeSeconds"] == 0
    assert snapshot["sampleAvailable"] is False


def test_metric_metadata_is_detached_and_diagnostic_reason_is_not_free_text(status_module):
    status, _, traffic = status_module
    traffic.snapshot.update(available=False, enforcementAvailable=False,
                            enforcementReason="user Alice at 192.0.2.1 failed",
                            unavailableReason="password: user-secret")
    sampler = status._StatusSampler()
    sampler._sample_once(threading.Event())
    first = sampler.read("node-a")
    first["metricSamples"]["cpu"]["available"] = False
    second = sampler.read("node-a")
    assert second["metricSamples"]["cpu"]["available"] is True
    assert second["enforcementReason"] is None
    assert second["connectionsUnavailableReason"] == "proxy_connection_sample_unavailable"
