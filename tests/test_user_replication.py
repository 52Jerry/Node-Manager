import copy
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import test_next_stage as fixture
from test_next_stage import base_singbox_config, manager, traffic, main, TestClient
from user_replication import ReplicationRequest, export_users, apply_users


class UserReplicationTest(unittest.TestCase):
    setUp = fixture.ManagerTestCase.setUp
    tearDown = fixture.ManagerTestCase.tearDown
    _write_config = fixture.ManagerTestCase._write_config

    def create(self, user_id="primary-7"):
        return manager.create_user(user_id, ["vless", "vmess", "socks"],
                                   socks_username="customer", socks_password="secret",
                                   proxy={"server": "203.0.113.50", "port": 1080, "username": "upstream",
                                          "password": "upstream-secret", "countryCode": "US", "cityName": "Seattle"},
                                   traffic_limit_bytes=1000, max_source_ips=2)

    def reset_target(self):
        self.registry_path.unlink(missing_ok=True)
        self.traffic_path.unlink(missing_ok=True)
        data = base_singbox_config()
        data["inbounds"][0]["listen_port"] = 443
        data["inbounds"][0]["tls"]["reality"]["short_id"] = ["abcdef1234567890"]
        data["inbounds"].append({"type": "mixed", "tag": "independent", "listen_port": 8888})
        data["outbounds"].append({"type": "direct", "tag": "independent-out"})
        self._write_config(data)
        return copy.deepcopy(data)

    def request(self, snapshot, **extra):
        return ReplicationRequest(groupKey="test-group", users=snapshot["users"], **extra)

    def test_portable_snapshot_preserves_credentials_proxy_region_and_target_listeners(self):
        self.create()
        store = traffic._empty_store()
        store["users"]["primary-7"] = {"upload": 17, "download": 23}
        traffic._write_store(store)
        snapshot = export_users()
        target = self.reset_target()
        result = apply_users(self.request(snapshot))
        self.assertEqual(result["userCount"], 1)
        self.assertEqual(export_users(), snapshot)
        data = manager.read_config()
        self.assertEqual(data["inbounds"][0]["tls"], target["inbounds"][0]["tls"])
        self.assertEqual(data["inbounds"][0]["listen_port"], 443)
        self.assertEqual(data["inbounds"][-1], target["inbounds"][-1])
        self.assertIn(target["outbounds"][0], data["outbounds"])

    def test_trojan_only_credential_is_preserved(self):
        data = manager.read_config()
        data["inbounds"].append({"type": "trojan", "tag": "trojan", "listen_port": 1443, "users": [],
                                 "tls": copy.deepcopy(data["inbounds"][0]["tls"])})
        self._write_config(data)
        manager.create_user("trojan-user", ["trojan"])
        snapshot = export_users()
        self.registry_path.unlink()
        data["inbounds"][-1]["listen_port"] = 2443
        self._write_config(data)
        apply_users(self.request(snapshot))
        self.assertEqual(export_users(), snapshot)
        self.assertEqual(manager.read_config()["inbounds"][-1]["listen_port"], 2443)

    def test_repeated_sync_does_not_reload_or_reset_target_usage(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        apply_users(self.request(snapshot))
        store = traffic._read_store()
        store["users"]["primary-7"].update(upload=600, download=100)
        traffic._write_store(store)
        before = manager.read_config()
        with patch.object(manager, "_write_and_reload", wraps=self._write_config) as reload:
            apply_users(self.request(snapshot))
            reload.assert_not_called()
        self.assertEqual(manager.read_config(), before)
        self.assertEqual(traffic._read_store()["users"]["primary-7"]["upload"], 600)

    def test_quota_cannot_be_bypassed_by_sync(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        apply_users(self.request(snapshot))
        store = traffic._read_store()
        store["users"]["primary-7"].update(upload=950, download=100)
        traffic._write_store(store)
        apply_users(self.request(snapshot))
        self.assertTrue(any(r.get("action") == "reject" for r in manager.read_config()["route"]["rules"]))

    def test_local_device_block_is_preserved_with_multiple_users_and_noop_sync(self):
        self.create()
        manager.create_user("second", ["vless"])
        snapshot = export_users()
        self.reset_target()
        apply_users(self.request(snapshot))
        manager.sync_user_enforcements({"primary-7": {"trafficBlocked": False, "blockedSourceIps": ["198.51.100.1"]}})
        before = manager.read_config()
        with patch.object(manager, "_write_and_reload", wraps=self._write_config) as reload:
            apply_users(self.request(snapshot))
            reload.assert_not_called()
        self.assertEqual(manager.read_config(), before)
        self.assertTrue(any(rule.get("source_ip_cidr") == ["198.51.100.1/32"] for rule in before["route"]["rules"]))

    def test_renewed_copy_removes_old_expiration_rule_and_starts_new_cycle(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        apply_users(self.request(snapshot))
        registry = manager.read_registry()
        registry["users"]["primary-7"]["expiresAt"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        manager._write_registry(registry)
        manager.process_user_expirations()
        store = traffic._read_store()
        store["users"]["primary-7"].update(upload=9999, replicationCycle="old-cycle")
        traffic._write_store(store)
        self.assertTrue(any(r.get("action") == "reject" for r in manager.read_config()["route"]["rules"]))
        apply_users(self.request(snapshot))
        self.assertFalse(any(r.get("action") == "reject" for r in manager.read_config()["route"]["rules"]))
        self.assertEqual(traffic._read_store()["users"]["primary-7"]["upload"], 0)

    def test_traffic_write_failure_never_enables_users(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        before = self.config_path.read_bytes()
        with patch.object(traffic, "_write_store", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                apply_users(self.request(snapshot))
        self.assertEqual(self.config_path.read_bytes(), before)
        self.assertFalse(self.registry_path.exists())

    def test_invalid_replication_payload_does_not_echo_credentials(self):
        result = TestClient(main.app).post("/api/users/replication", headers={"Authorization": "Bearer test-token"},
                                           json={"groupKey": "group", "users": [], "secret": "private-password"})
        self.assertEqual(result.status_code, 422)
        self.assertNotIn("private-password", result.text)

    def test_source_deletion_only_removes_group_owned_accounts(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        manager.create_user("independent", ["socks"], socks_username="other", socks_password="other-secret")
        apply_users(self.request(snapshot))
        apply_users(ReplicationRequest(groupKey="test-group", users=[]))
        self.assertEqual(set(manager.read_registry()["users"]), {"independent"})

    def test_conflicting_target_credentials_roll_back_entire_batch(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        manager.create_user("primary-7", ["socks"], socks_password="different")
        before = self.config_path.read_bytes(), self.registry_path.read_bytes()
        with self.assertRaises(manager.SingboxConfigError):
            apply_users(self.request(snapshot))
        self.assertEqual(before, (self.config_path.read_bytes(), self.registry_path.read_bytes()))

    def test_primary_backup_alias_renames_id_without_changing_credentials(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        user = copy.deepcopy(snapshot["users"][0])
        user["userId"] = "backup-7"
        apply_users(ReplicationRequest(groupKey="test-group", users=[user]))
        apply_users(self.request(snapshot, aliases={"backup-7": "primary-7"}))
        self.assertEqual(set(manager.read_registry()["users"]), {"primary-7"})
        self.assertEqual(export_users(), snapshot)

    def test_retired_alias_is_removed_on_initial_sync(self):
        self.create()
        snapshot = export_users()
        manager_user = snapshot["users"][0]
        self.reset_target()
        old = copy.deepcopy(manager_user)
        old["userId"] = "backup-7"
        apply_users(ReplicationRequest(groupKey="test-group", users=[old]))
        apply_users(ReplicationRequest(groupKey="test-group", users=[], retired=[manager_user],
                                       aliases={"backup-7": "primary-7"}))
        self.assertEqual(manager.read_registry()["users"], {})

    def test_expired_snapshot_never_resurrects_account(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        snapshot["users"][0]["expiresAt"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        result = apply_users(self.request(snapshot))
        self.assertEqual(result["userCount"], 0)
        self.assertEqual(manager.read_registry()["users"], {})

    def test_reload_failure_keeps_registry_and_usage_unchanged(self):
        self.create()
        snapshot = export_users()
        self.reset_target()
        before = self.config_path.read_bytes()
        with patch.object(manager, "_write_and_reload", side_effect=RuntimeError("reload failed")):
            with self.assertRaises(RuntimeError):
                apply_users(self.request(snapshot))
        self.assertEqual(self.config_path.read_bytes(), before)
        self.assertFalse(self.registry_path.exists())
        self.assertFalse(self.traffic_path.exists())

    def test_authentication_and_sensitive_export_cache_control(self):
        self.create()
        client = TestClient(main.app)
        self.assertEqual(client.get("/api/users/replication").status_code, 401)
        result = client.get("/api/users/replication", headers={"Authorization": "Bearer test-token"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["cache-control"], "no-store")
        self.assertEqual(result.json()["version"], 1)

    def test_missing_historical_expiry_refuses_export(self):
        self.create()
        registry = manager.read_registry()
        registry["users"]["primary-7"].pop("expiresAt")
        manager._write_registry(registry)
        with self.assertRaises(manager.SingboxConfigError):
            export_users()


if __name__ == "__main__":
    unittest.main()
