import copy
import subprocess
import unittest
from unittest.mock import patch

import test_next_stage as fixture
from test_next_stage import manager, traffic, main, TestClient, base_singbox_config
from replication_snapshot import capture, inspect_users
from user_replication import export_users, ReplicationRequest, apply_users

real_write_and_reload = manager._write_and_reload


class ReplicationInspectionTest(unittest.TestCase):
    setUp = fixture.ManagerTestCase.setUp
    tearDown = fixture.ManagerTestCase.tearDown
    _write_config = fixture.ManagerTestCase._write_config

    def create(self):
        manager.create_user("primary-7", ["vless", "socks"], socks_username="customer", socks_password="test-secret",
                            proxy={"server": "192.0.2.1", "port": 1080, "username": "proxy", "password": "proxy-secret"})

    def test_missing_dates_inspection_is_readonly_and_returns_partial_record(self):
        self.create()
        registry = manager.read_registry()
        registry["users"]["primary-7"].pop("expiresAt")
        manager._write_registry(registry)
        before = self.config_path.read_bytes(), self.registry_path.read_bytes()
        with patch.object(manager, "process_user_expirations", side_effect=AssertionError("must not expire")), \
             patch.object(manager, "mutate_config", side_effect=AssertionError("must not write")), \
             patch.object(traffic, "get_traffic_store_snapshot", side_effect=AssertionError("no traffic locks")):
            snapshot = inspect_users()
        self.assertIsNone(snapshot["users"][0]["expiresAt"])
        self.assertEqual(len(snapshot["users"][0]["auth"]), 2)
        self.assertEqual(before, (self.config_path.read_bytes(), self.registry_path.read_bytes()))

    def test_authentication_cache_control_and_sanitized_export_reason(self):
        self.create()
        registry = manager.read_registry()
        registry["users"]["primary-7"].pop("expiresAt")
        manager._write_registry(registry)
        client = TestClient(main.app)
        self.assertEqual(client.get("/api/users/replication/inspection").status_code, 401)
        headers = {"Authorization": "Bearer test-token"}
        result = client.get("/api/users/replication/inspection", headers=headers)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["cache-control"], "no-store")
        result = client.get("/api/users/replication", headers=headers)
        self.assertEqual(result.json()["code"], "MISSING_EXPIRATION")
        self.assertNotIn("test-secret", result.text)
        self.assertNotIn("proxy-secret", result.text)

    def test_5600_users_use_index_and_keep_multi_proxy_detection(self):
        data = base_singbox_config()
        registry = {"users": {}}
        for number in range(5600):
            user_id = f"primary-{number}"
            registry["users"][user_id] = {"socksUsername": f"customer-{number}", "expiresAt": "2030-01-01T00:00:00Z"}
            data["inbounds"][0]["users"].append({"name": manager._auth_name(user_id), "uuid": str(number)})
            data["outbounds"].append({"tag": manager.USER_OUTBOUND_PREFIX + user_id, "type": "direct"})
        with patch.object(manager, "_is_user_proxy_outbound_tag", side_effect=AssertionError("quadratic scan")):
            result = capture(data, registry)
        self.assertEqual(len(result["users"]), 5600)
        self.assertTrue(all(not row["serializationIssues"] for row in result["users"]))
        data["outbounds"].append({"tag": manager.USER_OUTBOUND_PREFIX + "primary-7-1", "type": "direct"})
        result = capture(data, registry)
        row = next(row for row in result["users"] if row["userId"] == "primary-7")
        self.assertIn("MULTI_PROXY_UNSUPPORTED", row["serializationIssues"])

    def test_reload_only_context_never_falls_back_to_restart_and_restores_context(self):
        failed = subprocess.CompletedProcess([], 1, "", "not supported")
        with patch.object(manager, "_run", return_value=failed) as run:
            with manager.without_restart():
                self.assertFalse(manager.reload_singbox())
            self.assertEqual([call.args[0] for call in run.call_args_list], [["systemctl", "reload", "sing-box"]])
            run.reset_mock()
            manager.reload_singbox()
            self.assertEqual(len(run.call_args_list), 2)

    def test_replication_applies_with_restart_forbidden(self):
        self.create()
        snapshot = export_users()
        with patch.object(manager, "mutate_config", wraps=manager.mutate_config) as mutate:
            def inspect_flag(mutator):
                self.assertFalse(manager._restart_allowed.get())
                return 1
            mutate.side_effect = inspect_flag
            apply_users(ReplicationRequest(groupKey="test", users=snapshot["users"]))
        self.assertTrue(manager._restart_allowed.get())

    def test_duplicate_protocol_tags_and_ambiguous_auth_are_reported_without_secrets(self):
        self.create()
        with patch.object(manager.config.singbox, "vmess_tag", manager.config.singbox.vless_tag):
            self.assertIn("DUPLICATE_MANAGED_INBOUND", inspect_users()["errors"])
        data = manager.read_config()
        data["inbounds"][0]["users"].append(copy.deepcopy(data["inbounds"][0]["users"][0]))
        result = capture(data, manager.read_registry())
        self.assertIn("AMBIGUOUS_AUTH", result["users"][0]["serializationIssues"])
        self.assertNotIn("test-secret", str(result["users"][0]["serializationIssues"]))

    def test_failed_reload_restores_config_registry_and_traffic_without_restart(self):
        self.create()
        snapshot = export_users()
        apply_users(ReplicationRequest(groupKey="test", users=snapshot["users"]))
        paths = (self.config_path, self.registry_path, self.traffic_path)
        before = tuple(path.read_bytes() if path.exists() else None for path in paths)
        snapshot["users"][0]["auth"][0]["credential"] = "changed-test-credential"
        failed = subprocess.CompletedProcess([], 1, "", "reload unsupported")
        with patch.object(manager, "_write_and_reload", real_write_and_reload), \
             patch.object(manager, "check_config", return_value=(True, "")), \
             patch.object(manager, "_run", return_value=failed) as run:
            with self.assertRaises(manager.SingboxConfigError):
                apply_users(ReplicationRequest(groupKey="test", users=snapshot["users"]))
        self.assertEqual(before, tuple(path.read_bytes() if path.exists() else None for path in paths))
        self.assertEqual([call.args[0] for call in run.call_args_list], [["systemctl", "reload", "sing-box"]] * 2)
