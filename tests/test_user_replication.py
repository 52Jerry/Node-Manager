import copy
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import test_next_stage as fixture
from test_next_stage import base_singbox_config, manager, traffic, main, TestClient
from user_replication import ReplicationRequest, export_users, apply_users
import ha_readiness
from pydantic import ValidationError


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

    def ha_request(self, snapshot, generation=100, **extra):
        return self.request(snapshot, sharedConfig=snapshot["sharedConfig"], generation=generation, **extra)

    def test_ha_copies_reality_ports_and_transport_but_not_local_settings(self):
        self.create()
        source = manager.read_config()
        source["inbounds"][1]["transport"] = {"type": "ws", "path": "/proxy"}
        self._write_config(source)
        registry = manager.read_registry()
        registry["users"]["primary-7"].update(remark="customer remark", tags=["premium"])
        manager._write_registry(registry)
        snapshot = export_users(shared_config=True)
        self.assertNotIn("users", snapshot["sharedConfig"]["vless"])
        self.assertNotIn("tag", snapshot["sharedConfig"]["vless"])
        self.reset_target()
        data = manager.read_config()
        data["inbounds"][0]["listen"] = "10.0.0.2"
        data["experimental"] = {"clash_api": {"secret": "target-api-secret"}}
        self._write_config(data)
        apply_users(self.ha_request(snapshot))
        self.assertEqual(export_users(shared_config=True), snapshot)
        actual = manager.read_config()
        self.assertEqual(actual["inbounds"][0]["listen"], "10.0.0.2")
        self.assertEqual(actual["experimental"], data["experimental"])
        self.assertEqual(actual["inbounds"][-1], data["inbounds"][-1])

    def test_ha_noop_does_not_reload_and_old_generations_cannot_overwrite(self):
        self.create()
        snapshot = export_users(shared_config=True)
        self.reset_target()
        apply_users(self.ha_request(snapshot))
        with patch.object(manager, "_write_and_reload", wraps=self._write_config) as reload:
            apply_users(self.ha_request(snapshot))
            apply_users(self.ha_request(snapshot, generation=101))
            reload.assert_not_called()
        with self.assertRaises(manager.SingboxConfigError):
            apply_users(self.ha_request(snapshot, generation=99))
        changed = copy.deepcopy(snapshot)
        changed["users"][0]["auth"][0]["credential"] = "new-credential"
        with self.assertRaises(manager.SingboxConfigError):
            apply_users(self.ha_request(changed, generation=101))
        with self.assertRaises(manager.SingboxConfigError):
            apply_users(self.request(snapshot))
        self.assertEqual(export_users(shared_config=True), snapshot)

    def test_ha_does_not_change_independent_customer_listener(self):
        self.create()
        snapshot = export_users(shared_config=True)
        self.reset_target()
        manager.create_user("independent", ["socks"], socks_username="other", socks_password="different")
        before = self.config_path.read_bytes(), self.registry_path.read_bytes()
        with self.assertRaises(manager.SingboxConfigError):
            apply_users(self.ha_request(snapshot))
        self.assertEqual(before, (self.config_path.read_bytes(), self.registry_path.read_bytes()))

    def test_ha_rejects_port_conflict_and_preserves_versions_on_reload_failure(self):
        self.create()
        snapshot = export_users(shared_config=True)
        self.reset_target()
        bad = copy.deepcopy(snapshot)
        bad["sharedConfig"]["vless"]["listen_port"] = 8888
        with self.assertRaises(manager.SingboxConfigError):
            apply_users(self.ha_request(bad))
        before = self.config_path.read_bytes()
        with patch.object(manager, "_write_and_reload", side_effect=manager.SingboxConfigError("reload failed")):
            with self.assertRaises(manager.SingboxConfigError):
                apply_users(self.ha_request(snapshot))
        self.assertEqual(before, self.config_path.read_bytes())
        self.assertFalse(self.registry_path.exists())
        self.assertFalse(self.traffic_path.exists())

    def test_ha_rejects_tls_local_files_and_api_port_collision(self):
        self.create()
        snapshot = export_users(shared_config=True)
        for options in [{"tls": {"key_path": "/source/private.pem"}}, {"listen_port": 8088},
                        {"tls": "invalid"}, {"listen_port": True}, {"type": "hysteria2"},
                        {"tls": {"reality": {"private_key": "bad", "short_id": ["00"]}}}]:
            bad = copy.deepcopy(snapshot)
            bad["sharedConfig"]["vless"].update(options)
            with self.assertRaises(manager.SingboxConfigError):
                apply_users(self.ha_request(bad))

    def test_ha_can_install_missing_managed_inbounds(self):
        self.create()
        snapshot = export_users(shared_config=True)
        self.reset_target()
        data = manager.read_config()
        data["inbounds"] = [data["inbounds"][-1]]
        self._write_config(data)
        apply_users(self.ha_request(snapshot))
        self.assertEqual(export_users(shared_config=True), snapshot)

    def test_ha_readiness_requires_runtime_ports_and_exact_generation(self):
        self.create()
        snapshot = export_users(shared_config=True)
        self.reset_target()
        apply_users(self.ha_request(snapshot))
        request = ha_readiness.ReadinessRequest(groupKey="test-group", generation=100)
        with patch.object(manager, "is_singbox_running", return_value=True), \
                patch.object(ha_readiness, "tcp_reachable", return_value=True):
            self.assertTrue(ha_readiness.readiness(request)["ready"])
            self.assertFalse(ha_readiness.readiness(request.model_copy(update={"generation": 99}))["ready"])
        with patch.object(manager, "is_singbox_running", return_value=True), \
                patch.object(ha_readiness, "tcp_reachable", return_value=False):
            self.assertFalse(ha_readiness.readiness(request)["ready"])

    def test_ha_export_authentication_and_validation_never_echo_keys(self):
        self.create()
        client = TestClient(main.app)
        response = client.get("/api/users/replication?sharedConfig=true")
        self.assertEqual(response.status_code, 401)
        headers = {"Authorization": "Bearer test-token"}
        response = client.get("/api/users/replication?sharedConfig=true", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("sharedConfig", response.json())
        response = client.post("/api/users/replication/readiness", headers=headers,
                               json={"groupKey": "group", "generation": "private-key-secret"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("private-key-secret", response.text)
        with patch.object(main, "export_users", side_effect=manager.SingboxConfigError("private-key-secret")):
            response = client.get("/api/users/replication?sharedConfig=true", headers=headers)
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("private-key-secret", response.text)

    def test_ha_requires_generation(self):
        with self.assertRaises(ValidationError):
            ReplicationRequest(groupKey="test-group", users=[], sharedConfig={})

    def test_ha_removes_omitted_managed_protocol_without_leaving_credentials(self):
        self.create()
        snapshot = export_users(shared_config=True)
        self.reset_target()
        apply_users(self.ha_request(snapshot))
        snapshot["sharedConfig"].pop("vmess")
        snapshot["users"][0]["auth"] = [entry for entry in snapshot["users"][0]["auth"]
                                         if entry["protocol"] != "vmess"]
        apply_users(self.ha_request(snapshot, generation=101))
        self.assertEqual(export_users(shared_config=True), snapshot)
        self.assertFalse(any(item["type"] == "vmess" for item in manager.read_config()["inbounds"]))

    def test_ha_omitted_protocol_with_independent_accounts_blocks_adoption(self):
        self.create()
        snapshot = export_users(shared_config=True)
        snapshot["sharedConfig"].pop("vmess")
        snapshot["users"][0]["auth"] = [entry for entry in snapshot["users"][0]["auth"]
                                         if entry["protocol"] != "vmess"]
        self.reset_target()
        manager.create_user("independent", ["vmess"])
        before = self.config_path.read_bytes(), self.registry_path.read_bytes()
        with self.assertRaises(manager.SingboxConfigError):
            apply_users(self.ha_request(snapshot))
        self.assertEqual(before, (self.config_path.read_bytes(), self.registry_path.read_bytes()))

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

    def test_custom_outbound_options_are_not_silently_discarded(self):
        self.create()
        data = manager.read_config()
        outbound = next(item for item in data["outbounds"]
                        if item.get("tag") == manager.USER_OUTBOUND_PREFIX + "primary-7")
        outbound["bind_interface"] = "eth-private"
        self._write_config(data)
        with self.assertRaises(manager.SingboxConfigError):
            export_users(shared_config=True)


if __name__ == "__main__":
    unittest.main()
