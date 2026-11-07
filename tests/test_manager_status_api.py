"""HTTP projections preserve sampler freshness and lifecycle guarantees."""
from contextlib import ExitStack, nullcontext
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_next_stage import main, manager, TestClient


class ManagerStatusApiTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("singbox.runtime_client.enabled", return_value=False))
        self.stack.enter_context(patch.object(main, "is_api_available", return_value=True))
        self.read_registry = self.stack.enter_context(patch.object(main, "read_registry", return_value={"users": {}}))
        self.socks_port = self.stack.enter_context(patch.object(main, "get_socks_inbound_port", return_value=9999))
        self.monitoring_snapshot = self.stack.enter_context(patch.object(
            main, "get_user_monitoring_snapshot",
            return_value=SimpleNamespace(registry_user_count=0, listed_user_count=0, socks_port=9999),
        ))
        self.stack.enter_context(patch.object(main, "_manager_version", return_value="test-manager"))
        self.stack.enter_context(patch.object(main, "_singbox_version", return_value="test-core"))
        self.stack.enter_context(patch.object(main, "get_dead_outbounds", return_value=[]))
        self.stack.enter_context(patch.object(main, "get_traffic_totals", return_value={
            "upload": 10, "download": 20, "total": 30, "available": True,
            "source": "singbox-runtime-cumulative", "collectedAt": None,
        }))
        self.stack.enter_context(patch.object(main.config.security, "token", "test-token"))
        self.stack.enter_context(patch.object(main.config.security, "allowed_cidrs", ""))
        self.client = TestClient(main.app)
        self.headers = {"Authorization": "Bearer test-token"}

    def snapshot(self, **changes):
        stamp = datetime.now(timezone.utc).isoformat()
        result = {
            "node": main.config.node.id, "singbox": "running", "cpu": 12.0,
            "memory": 34.0, "connections": 42, "systemConnections": 73,
            "sampledAt": stamp, "sampleAgeSeconds": 1.5,
            "sampleStale": False, "sampleAvailable": True, "sampleError": None,
            "metricsUnavailable": [], "connectionsCollectedAt": stamp,
            "systemConnectionsSampledAt": stamp,
            "systemConnectionsSampleAgeSeconds": 18.0,
            "systemConnectionsSampleIntervalSeconds": 30.0,
            "systemConnectionsStale": False,
        }
        result.update(changes)
        return result

    def test_node_status_keeps_sample_and_slow_socket_metric_metadata(self):
        snapshot = self.snapshot()
        with patch.object(main, "get_node_status", return_value=snapshot):
            response = self.client.get("/api/node/status", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["sampleAvailable"])
        self.assertFalse(body["sampleStale"])
        self.assertEqual(body["sampleAgeSeconds"], 1.5)
        self.assertEqual(body["connections"], 42)
        self.assertEqual(body["systemConnectionsSampleIntervalSeconds"], 30.0)
        self.assertEqual(body["systemConnectionsSampleAgeSeconds"], 18.0)
        self.assertFalse(body["systemConnectionsStale"])
        self.assertIsNotNone(body["sampledAt"])
        self.assertIsNotNone(body["connectionsCollectedAt"])
        self.assertIsNotNone(body["systemConnectionsSampledAt"])

    def test_node_status_retains_last_known_values_with_explicit_unavailability(self):
        snapshot = self.snapshot(sampleStale=True, sampleAvailable=False,
                                 sampleAgeSeconds=99.0,
                                 sampleError="sample_unavailable:connections",
                                 metricsUnavailable=["connections"])
        with patch.object(main, "get_node_status", return_value=snapshot):
            response = self.client.get("/api/node/status", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["connections"], 42)
        self.assertFalse(body["sampleAvailable"])
        self.assertTrue(body["sampleStale"])
        self.assertEqual(body["sampleAgeSeconds"], 99.0)
        self.assertEqual(body["metricsUnavailable"], ["connections"])
        self.assertEqual(body["sampleError"], "sample_unavailable:connections")

    def test_heartbeat_preserves_freshness_fields_through_its_response_model(self):
        with patch.object(main, "get_node_status", return_value=self.snapshot()):
            response = self.client.get("/api/agent/heartbeat", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["status"], "online")
        self.assertTrue(body["sampleAvailable"])
        self.assertFalse(body["sampleStale"])
        self.assertEqual(body["systemConnectionsSampleAgeSeconds"], 18.0)
        self.assertEqual(body["systemConnectionsSampleIntervalSeconds"], 30.0)
        self.assertIsNotNone(body["connectionsCollectedAt"])

    def test_monitoring_endpoints_use_paired_projection_without_independent_user_reads(self):
        self.monitoring_snapshot.return_value = SimpleNamespace(
            registry_user_count=8, listed_user_count=5, socks_port=1777,
        )
        with patch.object(main, "get_node_status", return_value=self.snapshot()), \
             patch.object(main, "list_users") as list_users:
            heartbeat = self.client.get("/api/agent/heartbeat", headers=self.headers)
            nodes = self.client.get("/api/nodes", headers=self.headers)
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        self.assertEqual(nodes.status_code, 200, nodes.text)
        self.assertEqual(heartbeat.json()["userCount"], 8)
        self.assertEqual(heartbeat.json()["socksPort"], 1777)
        self.assertEqual(nodes.json()["items"][0]["userCount"], 5)
        self.assertEqual(self.monitoring_snapshot.call_count, 2)
        self.read_registry.assert_not_called()
        self.socks_port.assert_not_called()
        list_users.assert_not_called()

    def test_node_status_preserves_metric_times_and_policy_state_without_user_details(self):
        stamp = datetime.now(timezone.utc).isoformat()
        snapshot = self.snapshot(
            sampleAttemptedAt=stamp, lastSuccessfulSampledAt=stamp,
            connectionsAvailable=False, connectionsStale=True,
            connectionsSampleAgeSeconds=7.3, connectionsUnavailableReason="sample_stale",
            enforcementAvailable=False, enforcementReason="enforcement_task_pending",
            metricSamples={
                "cpu": {"sampledAt": stamp, "sampleAgeSeconds": 0.0,
                        "stale": False, "available": True,
                        "userId": "not-for-heartbeats", "sourceIp": "192.0.2.1"},
                "connections": {"sampledAt": stamp, "sampleAgeSeconds": 7.3,
                                "stale": True, "available": False,
                                "unavailableReason": "sample_stale"},
            },
        )
        with patch.object(main, "get_node_status", return_value=snapshot):
            response = self.client.get("/api/node/status", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertFalse(body["connectionsAvailable"])
        self.assertTrue(body["connectionsStale"])
        self.assertEqual(body["connectionsSampleAgeSeconds"], 7.3)
        self.assertEqual(body["enforcementReason"], "enforcement_task_pending")
        self.assertEqual(body["metricSamples"]["cpu"]["sampleAgeSeconds"], 0)
        self.assertEqual(body["metricSamples"]["connections"]["sampleAgeSeconds"], 7.3)
        self.assertNotIn("userId", body["metricSamples"]["cpu"])
        self.assertNotIn("sourceIp", body["metricSamples"]["cpu"])

    def test_heartbeat_preserves_latest_observation_and_independent_policy_state(self):
        stamp = datetime.now(timezone.utc).isoformat()
        snapshot = self.snapshot(
            sampleAttemptedAt=stamp, lastSuccessfulSampledAt=stamp,
            connectionsAvailable=True, connectionsStale=False,
            connectionsSampleAgeSeconds=2.0, connectionsUnavailableReason=None,
            enforcementAvailable=False, enforcementReason="enforcement_task_pending",
            metricSamples={"connections": {
                "sampledAt": stamp, "sampleAgeSeconds": 2.0,
                "stale": False, "available": True, "unavailableReason": None,
            }},
        )
        with patch.object(main, "get_node_status", return_value=snapshot):
            response = self.client.get("/api/agent/heartbeat", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["connectionsAvailable"])
        self.assertFalse(body["connectionsStale"])
        self.assertEqual(body["connectionsSampleAgeSeconds"], 2.0)
        self.assertFalse(body["enforcementAvailable"])
        self.assertEqual(body["enforcementReason"], "enforcement_task_pending")
        self.assertIsNotNone(body["sampleAttemptedAt"])
        self.assertIsNotNone(body["lastSuccessfulSampledAt"])
        self.assertTrue(body["metricSamples"]["connections"]["available"])

    def test_heartbeat_traffic_model_preserves_freshness_but_drops_user_payloads(self):
        stamp = datetime.now(timezone.utc).isoformat()
        totals = {
            "upload": 10, "download": 20, "total": 30, "available": False,
            "source": "singbox-runtime-cumulative", "collectedAt": stamp,
            "sampleTime": stamp, "stalenessSeconds": 7.3, "staleAfterSeconds": 6,
            "stale": True, "telemetryStatus": "unavailable", "telemetryAvailable": False,
            "unavailableReason": "sample_stale", "observationAvailable": True,
            "enforcementAvailable": False, "enforcementReason": "enforcement_task_pending",
            "measurementQuality": "runtime_cumulative_since_baseline",
            "measuredTotal": None, "lastKnownTotal": 30, "alertRequired": True,
            "users": {"alice": {"password": "secret"}},
            "connections": [{"sourceIp": "192.0.2.1", "userId": "alice"}],
            "activeSourceIps": ["192.0.2.1"],
        }
        with patch.object(main, "get_node_status", return_value=self.snapshot()), \
             patch.object(main, "get_traffic_totals", return_value=totals):
            response = self.client.get("/api/agent/heartbeat", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()["traffic"]
        for field in ("stalenessSeconds", "staleAfterSeconds", "stale", "telemetryStatus",
                      "telemetryAvailable", "unavailableReason", "observationAvailable",
                      "enforcementAvailable", "enforcementReason", "measurementQuality",
                      "measuredTotal", "lastKnownTotal", "alertRequired"):
            self.assertEqual(result[field], totals[field], field)
        self.assertIsNotNone(result["sampleTime"])
        self.assertNotIn("users", result)
        self.assertNotIn("connections", result)
        self.assertNotIn("activeSourceIps", result)

    def test_traffic_model_invalid_time_boundary_is_unavailable_without_response_failure(self):
        from models.request import TrafficTotals

        values = ["not-a-date", "2026-11-07T00:00:00",
                  (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()]
        for stamp in values:
            with self.subTest(stamp=stamp):
                original = {"collectedAt": stamp, "sampleTime": stamp, "total": 30,
                            "available": True, "telemetryAvailable": True,
                            "observationAvailable": True, "stale": False,
                            "telemetryStatus": "fresh", "measuredTotal": 30,
                            "lastKnownTotal": 30, "enforcementAvailable": True}
                result = TrafficTotals.model_validate(original).model_dump(mode="json")
                self.assertIsNone(result["sampleTime"])
                self.assertIsNone(result["collectedAt"])
                self.assertFalse(result["available"])
                self.assertFalse(result["telemetryAvailable"])
                self.assertFalse(result["observationAvailable"])
                self.assertTrue(result["enforcementAvailable"])
                self.assertEqual(result["unavailableReason"], "sample_time_invalid")
                self.assertIsNone(result["measuredTotal"])
                self.assertEqual(result["lastKnownTotal"], 30)
                self.assertEqual(original["collectedAt"], stamp)

        with patch.object(main, "get_node_status", return_value=self.snapshot()), \
             patch.object(main, "get_traffic_totals", return_value={
                 "total": 30, "available": True, "telemetryAvailable": True,
                 "sampleTime": "invalid", "collectedAt": "invalid", "measuredTotal": 30,
             }):
            response = self.client.get("/api/agent/heartbeat", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNone(response.json()["traffic"]["sampleTime"])
        self.assertFalse(response.json()["traffic"]["available"])
        self.assertIsNone(response.json()["traffic"]["measuredTotal"])

    def test_traffic_model_keeps_legacy_fields_and_filters_free_text_reasons(self):
        from models.request import TrafficTotals

        result = TrafficTotals.model_validate({
            "upload": 1, "download": 2, "total": 3, "available": True,
            "source": "clash-api-sampled", "collectedAt": None,
            "enforcementReason": "Alice from 192.0.2.1 password=secret",
        }).model_dump(mode="json")
        self.assertEqual(result["total"], 3)
        self.assertTrue(result["available"])
        self.assertIsNone(result["enforcementReason"])

    def test_cold_snapshot_is_unknown_and_heartbeat_does_not_report_offline(self):
        snapshot = self.snapshot(singbox="unknown", cpu=-1.0, memory=-1.0,
                                 connections=-1, systemConnections=-1,
                                 sampledAt=None, sampleAgeSeconds=None,
                                 sampleStale=True, sampleAvailable=False,
                                 sampleError="sample_pending",
                                 metricsUnavailable=["singbox", "connections"],
                                 connectionsCollectedAt=None,
                                 systemConnectionsSampledAt=None,
                                 systemConnectionsSampleAgeSeconds=None,
                                 systemConnectionsStale=True)
        with patch.object(main, "get_node_status", return_value=snapshot):
            status = self.client.get("/api/node/status", headers=self.headers)
            heartbeat = self.client.get("/api/agent/heartbeat", headers=self.headers)
        self.assertEqual(status.status_code, 200, status.text)
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        self.assertEqual(status.json()["singbox"], "unknown")
        self.assertEqual(status.json()["connections"], -1)
        self.assertFalse(status.json()["sampleAvailable"])
        self.assertEqual(heartbeat.json()["status"], "degraded")
        self.assertEqual(heartbeat.json()["connections"], -1)
        self.assertFalse(heartbeat.json()["sampleAvailable"])

    def test_unauthorized_requests_cannot_trigger_status_sampling(self):
        with patch.object(main, "get_node_status") as sample:
            for path in ("/api/node/status", "/api/agent/heartbeat"):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 401, response.text)
        sample.assert_not_called()

    def test_cold_node_list_reports_degraded_and_does_not_match_offline_filter(self):
        snapshot = self.snapshot(singbox="unknown", cpu=-1.0, memory=-1.0,
                                 connections=-1, systemConnections=-1,
                                 sampleStale=True, sampleAvailable=False)
        with patch.object(main, "get_node_status", return_value=snapshot), \
             patch.object(main, "list_users", return_value=[]):
            response = self.client.get("/api/nodes", headers=self.headers)
            offline = self.client.get("/api/nodes?status=offline", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(offline.status_code, 200, offline.text)
        self.assertEqual(response.json()["items"][0]["status"], "degraded")
        self.assertEqual(response.json()["items"][0]["singbox"], "unknown")
        self.assertEqual(offline.json()["items"], [])

    def test_shutdown_hook_stops_the_status_sampler(self):
        with patch.object(main, "stop_status_sampler") as stop_status, \
             patch.object(main, "stop_reconciler"), \
             patch.object(main, "stop_expiration_scheduler"), \
             patch.object(main, "stop_health_checker"), \
             patch.object(main, "stop_traffic_collector"), \
             patch("runtime_write_queue.stop"):
            main.shutdown_tasks()
        stop_status.assert_called_once_with()

    def test_startup_hook_starts_sampler_after_required_recovery(self):
        with patch("revision.recover_pending_revision") as recovery, \
             patch.object(manager, "_config_lock", return_value=nullcontext()), \
             patch("runtime_publication.initialize_locked"), \
             patch.object(main, "migrate_user_expirations", return_value=0), \
             patch.object(main, "migrate_legacy_socks_usernames", return_value=0), \
             patch.object(main, "ensure_user_outbounds", return_value=0), \
             patch.object(main, "start_traffic_collector"), \
             patch.object(main, "start_status_sampler") as start_status, \
             patch.object(main, "start_health_checker"), \
             patch.object(main, "start_expiration_scheduler"), \
             patch.object(main, "start_reconciler"):
            main.startup_tasks()
        recovery.assert_called_once_with()
        start_status.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
