import copy
from concurrent.futures import ThreadPoolExecutor
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
import test_next_stage as fixtures
from test_next_stage import manager, main


class ResidentialOwnershipTests(unittest.TestCase):
    setUp = fixtures.ManagerTestCase.setUp
    tearDown = fixtures.ManagerTestCase.tearDown
    _write_config = fixtures.ManagerTestCase._write_config

    def prepare(self):
        proxy = {"server": "203.0.113.50", "port": 1080,
                 "username": "provider-user", "password": "provider-secret"}
        created = manager.create_user("res-legacy", ["vless", "vmess", "socks"], proxy=proxy)
        return {"sourceUserId": "res-legacy", "targetUserId": "primary-7",
                "resourceId": 11, "subscriptionId": 70, "accessProfileId": 7,
                "targetUuid": "aaaa0000-0000-4000-8000-000000000007",
                "expectedProxy": proxy,
                "expiresAt": (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()}

    def snapshot(self):
        return self.config_path.read_bytes(), self.registry_path.read_bytes()

    def assert_conflict_unchanged(self, payload):
        before = self.snapshot()
        with patch.object(manager, "_write_and_reload") as reload:
            with self.assertRaises(manager.SingboxConfigError):
                manager.migrate_residential_ownership(payload)
            reload.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_transfer_one_lock_one_reload_and_idempotent_retry(self):
        payload = self.prepare()
        original = manager.get_user_connection("res-legacy")
        with patch.object(manager, "_config_lock", wraps=manager._config_lock) as lock, patch.object(
                manager, "_write_and_reload", wraps=self._write_config) as reload:
            result = manager.migrate_residential_ownership(payload)
            self.assertTrue(result["migrated"])
            self.assertEqual(lock.call_count, 1)
            self.assertEqual(reload.call_count, 1)
            replay = manager.migrate_residential_ownership(payload)
            self.assertFalse(replay["migrated"])
            self.assertEqual(lock.call_count, 2)
            self.assertEqual(reload.call_count, 1)
        users = manager.read_registry()["users"]
        self.assertNotIn("res-legacy", users)
        self.assertEqual(users["primary-7"]["resourceId"], 11)
        connection = manager.get_user_connection("primary-7")
        self.assertEqual(connection["uuid"], payload["targetUuid"])
        self.assertNotEqual(connection["uuid"], original["uuid"])
        self.assertEqual(connection["socks"]["password"], original["socks"]["password"])
        self.assertEqual(connection["socks"]["username"], "primary-7")
        config = manager.read_config()
        self.assertNotIn("res-legacy", json.dumps(config))
        self.assertEqual(manager.get_user_proxy("primary-7")["password"], "provider-secret")

    def test_random_legacy_user_id_can_be_migrated(self):
        payload = self.prepare()
        source = "lltunNUKeauj"
        config = manager.read_config()
        registry = manager.read_registry()
        config_text = json.dumps(config).replace("res-legacy", source)
        registry_text = json.dumps(registry).replace("res-legacy", source)
        self._write_config(json.loads(config_text))
        manager._write_registry(json.loads(registry_text))
        payload["sourceUserId"] = source

        result = manager.migrate_residential_ownership(payload)

        self.assertTrue(result["migrated"])
        self.assertNotIn(source, manager.read_registry()["users"])
        self.assertEqual(manager.get_user_proxy("primary-7")["server"], "203.0.113.50")

    def test_same_source_and_target_is_invalid(self):
        payload = self.prepare()
        payload["sourceUserId"] = payload["targetUserId"]
        with self.assertRaises(manager.SingboxConfigError):
            manager.migrate_residential_ownership(payload)

    def test_each_proxy_identity_component_must_match(self):
        payload = self.prepare()
        for key, value in (("server", "203.0.113.51"), ("port", 1081),
                           ("username", "other"), ("password", "other")):
            with self.subTest(key=key):
                changed = copy.deepcopy(payload)
                changed["expectedProxy"][key] = value
                self.assert_conflict_unchanged(changed)

    def test_shared_source_or_target_uuid_is_rejected(self):
        payload = self.prepare()
        source_uuid = manager.get_user_connection("res-legacy")["uuid"]
        for user_uuid in (source_uuid, payload["targetUuid"]):
            manager.create_user("another", ["vless"], user_uuid=user_uuid)
            self.assert_conflict_unchanged(payload)
            manager.delete_user("another")

    def test_expiration_block_can_be_renewed_but_policy_is_preserved(self):
        payload = self.prepare()
        registry = manager.read_registry()
        metadata = registry["users"]["res-legacy"]
        metadata["expirationBlocked"] = True
        metadata["expirationAuthUsers"] = ["node-manager:res-legacy", "res-legacy"]
        metadata["expiresAt"] = "2020-01-01T00:00:00+00:00"
        config = manager.read_config()
        config["route"]["rules"].insert(0, {"auth_user": metadata["expirationAuthUsers"], "action": "reject"})
        manager._write_registry(registry)
        self._write_config(config)
        manager.migrate_residential_ownership(payload)
        self.assertNotIn("expirationBlocked", manager.read_registry()["users"]["primary-7"])
        self.assertFalse(any(rule.get("action") == "reject" for rule in manager.read_config()["route"]["rules"]))

    def test_trojan_credentials_rotate_with_uuid(self):
        payload = self.prepare()
        config = manager.read_config()
        source_uuid = manager.get_user_connection("res-legacy")["uuid"]
        config["inbounds"].append({"type": "trojan", "tag": manager.config.singbox.trojan_tag,
                                   "users": [{"name": "node-manager:res-legacy", "password": source_uuid}]})
        self._write_config(config)
        manager.migrate_residential_ownership(payload)
        trojan = manager.read_config()["inbounds"][-1]["users"][0]
        self.assertEqual(trojan, {"name": "node-manager:primary-7", "password": payload["targetUuid"]})

    def test_concurrent_competing_claims_have_one_owner_and_one_reload(self):
        payload = self.prepare()
        other = dict(payload, targetUserId="primary-8", accessProfileId=8)
        def invoke(value):
            try:
                return manager.migrate_residential_ownership(value)["success"]
            except manager.SingboxConfigError:
                return False
        with patch.object(manager, "_write_and_reload", wraps=self._write_config) as reload:
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(invoke, [payload, other]))
            self.assertEqual(sorted(results), [False, True])
            self.assertEqual(reload.call_count, 1)
        self.assertEqual(len(manager.read_registry()["users"]), 1)

    def test_existing_unbound_target_is_merged_without_rotating_target_uuid(self):
        payload = self.prepare()
        manager.create_user("primary-7", ["vless", "vmess", "socks"], user_uuid=payload["targetUuid"])
        result = manager.migrate_residential_ownership(payload)
        self.assertTrue(result["migrated"])
        self.assertNotIn("res-legacy", manager.read_registry()["users"])
        connection = manager.get_user_connection("primary-7")
        self.assertEqual(connection["uuid"], payload["targetUuid"])
        self.assertTrue(connection["proxyBound"])
        self.assertEqual(manager.get_user_proxy("primary-7")["password"], "provider-secret")

    def test_existing_target_with_wrong_uuid_cannot_be_overwritten(self):
        payload = self.prepare()
        manager.create_user("primary-7", ["vless", "vmess", "socks"])
        self.assert_conflict_unchanged(payload)

    def test_existing_target_with_proxy_cannot_be_overwritten(self):
        payload = self.prepare()
        manager.create_user("primary-7", ["vless", "vmess", "socks"],
                            user_uuid=payload["targetUuid"],
                            proxy={"server": "203.0.113.51", "port": 1080,
                                   "username": "other", "password": "other-secret"})
        self.assert_conflict_unchanged(payload)

    def test_cross_resource_registry_cannot_be_claimed(self):
        payload = self.prepare()
        registry = manager.read_registry()
        registry["users"]["res-legacy"]["resourceId"] = 12
        manager._write_registry(registry)
        self.assert_conflict_unchanged(payload)

    def test_duplicate_proxy_on_other_owner_is_rejected(self):
        payload = self.prepare()
        config = manager.read_config()
        duplicate = copy.deepcopy(next(item for item in config["outbounds"] if item["type"] == "socks"))
        duplicate["tag"] = "node-manager-out:another-resource"
        config["outbounds"].append(duplicate)
        self._write_config(config)
        self.assert_conflict_unchanged(payload)

    def test_shared_route_is_rejected(self):
        payload = self.prepare()
        config = manager.read_config()
        config["route"]["rules"][0]["auth_user"].append("another-resource")
        self._write_config(config)
        self.assert_conflict_unchanged(payload)

    def test_blocked_owner_is_not_reenabled(self):
        payload = self.prepare()
        registry = manager.read_registry()
        registry["users"]["res-legacy"]["accessEnabled"] = False
        manager._write_registry(registry)
        self.assert_conflict_unchanged(payload)

    def test_reload_failure_restores_registry_and_config(self):
        payload = self.prepare()
        before = self.snapshot()
        with patch.object(manager, "_write_and_reload", side_effect=manager.SingboxConfigError("reload failed")):
            with self.assertRaises(manager.SingboxConfigError):
                manager.migrate_residential_ownership(payload)
        self.assertEqual(before, self.snapshot())

    def test_retry_with_different_resource_or_drift_is_rejected(self):
        payload = self.prepare()
        manager.migrate_residential_ownership(payload)
        self.assert_conflict_unchanged(dict(payload, resourceId=12))
        config = manager.read_config()
        config["outbounds"][0]["password"] = "drift"
        self._write_config(config)
        self.assert_conflict_unchanged(payload)

    def test_api_auth_key_replay_and_secret_redaction(self):
        payload = self.prepare()
        client = TestClient(main.app)
        endpoint = "/api/user/migrate-residential-ownership"
        headers = {"Authorization": "Bearer test-token", "Idempotency-Key": "ownership-1"}
        self.assertEqual(client.post(endpoint, json=payload).status_code, 401)
        self.assertEqual(client.post(endpoint, json=payload,
                         headers={"Authorization": "Bearer test-token"}).status_code, 428)
        first = client.post(endpoint, json=payload, headers=headers)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.headers["Cache-Control"], "no-store")
        second = client.post(endpoint, json=payload, headers=headers)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(second.headers["Idempotency-Replayed"], "true")
        changed = dict(payload, resourceId=12)
        self.assertEqual(client.post(endpoint, json=changed, headers=headers).status_code, 409)
        invalid = copy.deepcopy(payload)
        invalid["expectedProxy"]["password"] = "provider-secret" * 100
        response = client.post(endpoint, json=invalid, headers=headers)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("provider-secret", response.text)
        self.assertNotIn("provider-secret", self.idempotency_path.read_text())


if __name__ == "__main__":
    unittest.main()
