import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from test_next_stage import base_singbox_config  # initializes the test config environment
from test_next_stage import idempotency, main, manager, traffic
from user_replication import ReplicationRequest, apply_users, export_users


class UserAccessApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.config_path = root / "sing-box.json"
        self.registry_path = root / "users.json"
        self.idempotency_path = root / "idempotency.json"
        self.traffic_path = root / "traffic.json"
        self.config_path.write_text(json.dumps(base_singbox_config()), encoding="utf-8")
        self.config_patch = patch.object(manager, "CONFIG_PATH", self.config_path)
        self.registry_patch = patch.object(manager, "REGISTRY_PATH", self.registry_path)
        self.idempotency_patch = patch.object(idempotency, "STORE_PATH", self.idempotency_path)
        self.traffic_patch = patch.object(traffic, "TRAFFIC_PATH", self.traffic_path)
        self.write_patch = patch.object(manager, "_write_and_reload", self._write_config)
        self.config_patch.start()
        self.registry_patch.start()
        self.idempotency_patch.start()
        self.traffic_patch.start()
        self.write_patch.start()
        self.get_connections = patch.object(manager.singbox_api, "get_connections")
        self.close_connection = patch.object(manager.singbox_api, "close_connection", return_value=True)
        self.get_connections.start()
        self.close_connection.start()
        self.client = TestClient(main.app)
        self.headers = {"Authorization": "Bearer test-token"}
        manager.create_user("access-user", ["vless", "vmess", "socks"],
                            socks_username="access-login", socks_password="test-password")

    def tearDown(self):
        self.close_connection.stop()
        self.get_connections.stop()
        self.write_patch.stop()
        self.idempotency_patch.stop()
        self.traffic_patch.stop()
        self.registry_patch.stop()
        self.config_patch.stop()
        self.temp_dir.cleanup()

    def _write_config(self, data):
        self.config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def test_disable_is_idempotent_closes_sessions_and_hides_credentials(self):
        active = {"connections": [{
            "id": "session-1", "metadata": {"inboundUser": "node-manager:access-user"}
        }]}
        manager.singbox_api.get_connections.side_effect = [active, {"connections": []}]
        response = self.client.patch("/api/user/access-user/access", headers={
            **self.headers, "Idempotency-Key": "suspend-access-user"
        }, json={"enabled": False})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["blockedProtocols"], ["vless", "vmess", "socks"])
        self.assertEqual(body["activeConnectionsClosed"], 1)
        self.assertTrue(manager.singbox_api.close_connection.called)
        self.assertEqual(self.client.get("/api/user/access-user/connections", headers=self.headers).status_code, 409)
        self.assertEqual(self.client.get("/api/user/access-user/proxy", headers=self.headers).status_code, 409)
        listing = self.client.get("/api/users", headers=self.headers).json()["items"][0]
        self.assertFalse(listing["accessEnabled"])
        self.assertEqual(listing["status"], "suspended")
        replay = self.client.patch("/api/user/access-user/access", headers={
            **self.headers, "Idempotency-Key": "suspend-access-user"
        }, json={"enabled": False})
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.headers["Idempotency-Replayed"], "true")

    def test_failure_keeps_reject_rule_and_returns_retryable_503(self):
        manager.singbox_api.get_connections.return_value = {"connections": [{
            "id": "session-2", "metadata": {"inboundUser": "access-login"}
        }]}
        manager.singbox_api.close_connection.return_value = False
        response = self.client.patch("/api/user/access-user/access", headers={
            **self.headers, "Idempotency-Key": "suspend-retry"
        }, json={"enabled": False})
        self.assertEqual(response.status_code, 503, response.text)
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertFalse(registry["users"]["access-user"]["accessEnabled"])
        rules = json.loads(self.config_path.read_text(encoding="utf-8"))["route"]["rules"]
        self.assertTrue(any(rule.get("action") == "reject" for rule in rules))
        manager.singbox_api.get_connections.return_value = {"connections": []}
        retry = self.client.patch("/api/user/access-user/access", headers={
            **self.headers, "Idempotency-Key": "suspend-retry"
        }, json={"enabled": False})
        self.assertEqual(retry.status_code, 200, retry.text)
        self.assertEqual(retry.headers["Idempotency-Replayed"], "false")

    def test_enable_removes_only_the_access_owned_reject_rule(self):
        manager.singbox_api.get_connections.return_value = {"connections": []}
        stopped = self.client.patch("/api/user/access-user/access", headers={
            **self.headers, "Idempotency-Key": "suspend-before-enable"
        }, json={"enabled": False})
        self.assertEqual(stopped.status_code, 200, stopped.text)
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["route"]["rules"].append(dict(config["route"]["rules"][0]))
        self._write_config(config)
        enabled = self.client.patch("/api/user/access-user/access", headers={
            **self.headers, "Idempotency-Key": "enable-access-user"
        }, json={"enabled": True})
        self.assertEqual(enabled.status_code, 200, enabled.text)
        rules = json.loads(self.config_path.read_text(encoding="utf-8"))["route"]["rules"]
        self.assertEqual(sum(rule.get("action") == "reject" for rule in rules), 1)
        listing = self.client.get("/api/users", headers=self.headers)
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertTrue(listing.json()["items"][0]["accessEnabled"])

    def test_replication_exports_and_applies_access_state(self):
        manager.singbox_api.get_connections.return_value = {"connections": []}
        manager.set_user_access("access-user", False)
        snapshot = export_users()
        self.assertFalse(snapshot["users"][0]["accessEnabled"])
        applied = apply_users(ReplicationRequest(groupKey="access-group", users=snapshot["users"]))
        self.assertTrue(applied["success"])
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertFalse(registry["users"]["access-user"]["accessEnabled"])
        rules = json.loads(self.config_path.read_text(encoding="utf-8"))["route"]["rules"]
        self.assertTrue(any(rule.get("action") == "reject" for rule in rules))

    def test_access_snapshot_includes_legacy_users_and_does_not_mutate(self):
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["inbounds"][0]["users"].append({
            "name": "node-manager:legacy-only",
            "uuid": "4a7d5ba1-31b8-43a4-9619-a6de1102a391",
        })
        self._write_config(config)
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        registry["users"]["access-user"]["accessEnabled"] = False
        self.registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
        config_before = self.config_path.read_bytes()
        registry_before = self.registry_path.read_bytes()

        with patch.object(manager, "process_user_expirations") as expirations:
            response = self.client.get("/api/users/access-snapshot", headers=self.headers)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.json(), {"access-user": False, "legacy-only": True})
        expirations.assert_not_called()
        self.assertEqual(self.config_path.read_bytes(), config_before)
        self.assertEqual(self.registry_path.read_bytes(), registry_before)

    def test_idempotency_key_is_required(self):
        response = self.client.patch("/api/user/access-user/access", headers=self.headers,
                                     json={"enabled": False})
        self.assertEqual(response.status_code, 428)


if __name__ == "__main__":
    unittest.main()
