"""Offline proof and endpoint checks for adopting an existing residential owner."""
import base64
import copy
import json
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from test_wireguard_migration_recovery import RecoveryFixture, digest, main
import wireguard_owner_adoption as adoption
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient


class AdoptionFixture(RecoveryFixture):
    def setUp(self):
        super().setUp()
        old_target = self.target
        self.target = "res-" + "a" * 32
        self.target_tag = adoption.manager.USER_OUTBOUND_PREFIX + self.target
        self.auth_name = adoption.manager._auth_name(self.target)
        self.registry["users"][self.target] = self.registry["users"].pop(old_target)
        self.registry["users"][self.target].pop("residentialOwnershipMigration")
        for inbound in self.data["inbounds"]:
            inbound["users"][0]["name"] = self.auth_name
        self.data["outbounds"][0]["tag"] = self.target_tag
        self.data["route"]["rules"] = [{"auth_user": [self.auth_name], "outbound": self.target_tag}]
        self.request = adoption.AdoptionCheck(
            subscriptionId=41, resourceId=43, accessProfileId=42,
            nodeUserId=self.target, previousNodeUserId=self.source,
            uuidSha256=digest(self.uuid),
            proxySha256=digest(json.dumps(self.identity, ensure_ascii=False, separators=(",", ":"))),
            expiresAt=self.expiry)

    def evaluate(self):
        before = copy.deepcopy((self.data, self.registry, self.runtime))
        result = adoption.evaluate(self.request, self.data, self.registry, self.runtime)
        self.assertEqual((self.data, self.registry, self.runtime), before)
        return result

    def assert_rejected(self, check):
        result = self.evaluate()
        self.assertFalse(result["checks"][check], result)
        self.assertFalse(result["ready"], result)
        self.assert_redacted(result)


class EvaluateAdoptionTests(AdoptionFixture):
    def test_valid_owner_is_ready_redacted_and_read_only(self):
        result = self.evaluate()
        self.assertTrue(result["ready"], result)
        self.assertEqual(result["nodeUserId"], self.target)
        self.assertEqual(result["previousNodeUserId"], self.source)
        self.assert_redacted(result)

    def test_exact_matching_registry_scope_is_allowed(self):
        self.registry["users"][self.target].update(
            resourceId="43", userIpResourceId=43, subscriptionId=41, accessProfileId=42)
        self.assertTrue(self.evaluate()["ready"])

    def test_absent_or_empty_optional_registry_scope_is_allowed(self):
        self.registry["users"][self.target].update(
            resourceId=None, userIpResourceId="", subscriptionId=None, accessProfileId="")
        self.assertTrue(self.evaluate()["ready"])

    def test_existing_active_wg_peer_is_left_for_java_identity_check(self):
        self.old.update(nodeUserId=self.target, status="ACTIVE", stateReason=None, kernelPresent=True)
        self.assertTrue(self.evaluate()["ready"])

    def test_same_previous_and_target_owner_is_idempotent(self):
        self.request = self.request.model_copy(update={"previousNodeUserId": self.target})
        self.assertTrue(self.evaluate()["ready"])

    def test_present_previous_owner_is_rejected(self):
        self.registry["users"][self.source] = {"expiresAt": self.expiry.isoformat()}
        self.assert_rejected("previousOwnerAbsentOrTarget")

    def test_previous_owner_orphan_outbound_is_rejected(self):
        self.data["outbounds"].append({"tag": adoption.manager.USER_OUTBOUND_PREFIX + self.source, "type": "direct"})
        self.assert_rejected("previousOwnerAbsentOrTarget")

    def test_previous_owner_bare_auth_is_rejected(self):
        self.data["inbounds"][0]["users"].append({"name": self.source, "uuid": "different"})
        self.assert_rejected("previousOwnerAbsentOrTarget")

    def test_existing_canonical_owner_is_rejected(self):
        self.registry["users"]["primary-42"] = {"expiresAt": self.expiry.isoformat()}
        self.assert_rejected("canonicalTargetAbsent")

    def test_canonical_orphan_outbound_is_rejected(self):
        self.data["outbounds"].append({"tag": adoption.manager.USER_OUTBOUND_PREFIX + "primary-42", "type": "direct"})
        self.assert_rejected("canonicalTargetAbsent")

    def test_canonical_bare_auth_is_rejected(self):
        self.data["inbounds"][0]["users"].append({"name": "primary-42", "uuid": "different"})
        self.assert_rejected("canonicalTargetAbsent")

    def test_missing_target_registry_is_rejected(self):
        self.registry["users"].pop(self.target)
        self.assert_rejected("targetPresent")

    def test_each_conflicting_scope_field_is_rejected(self):
        for field in ("resourceId", "userIpResourceId", "subscriptionId", "accessProfileId"):
            with self.subTest(field=field):
                self.registry["users"][self.target][field] = 999
                self.assert_rejected("scopeMatches")
                self.registry["users"][self.target].pop(field)

    def test_incomplete_proxy_credentials_are_rejected(self):
        for field in ("username", "password", "server"):
            for value in (None, "", " "):
                with self.subTest(field=field, value=value):
                    original = self.data["outbounds"][0][field]
                    self.data["outbounds"][0][field] = value
                    self.assert_rejected("proxyComplete")
                    self.data["outbounds"][0][field] = original

    def test_invalid_proxy_port_is_rejected(self):
        for value in (None, True, "1080", 0, 65536):
            with self.subTest(value=value):
                self.data["outbounds"][0]["server_port"] = value
                self.assert_rejected("proxyComplete")

    def test_ambiguous_target_outbounds_are_rejected(self):
        self.data["outbounds"].append(copy.deepcopy(self.data["outbounds"][0]))
        self.assert_rejected("proxyComplete")

    def test_proxy_owned_by_another_user_is_rejected(self):
        for kind in ("socks", "socks5"):
            with self.subTest(kind=kind):
                self.data["outbounds"].append({**self.data["outbounds"][0], "type": kind,
                    "tag": adoption.manager.USER_OUTBOUND_PREFIX + "another-owner"})
                self.assert_rejected("proxyUnique")
                self.data["outbounds"].pop()

    def test_proxy_hash_mismatch_is_rejected(self):
        self.data["outbounds"][0]["password"] = "different-secret"
        self.assert_rejected("proxyMatches")

    def test_uuid_hash_mismatch_is_rejected(self):
        self.request = self.request.model_copy(update={"uuidSha256": digest("different")})
        self.assert_rejected("uuidMatches")

    def test_conflicting_vless_and_vmess_uuid_is_rejected(self):
        self.data["inbounds"][1]["users"][0]["uuid"] = "different"
        self.assert_rejected("uuidMatches")

    def test_missing_uuid_in_owned_inbound_is_rejected(self):
        self.data["inbounds"][0]["users"][0].pop("uuid")
        self.assert_rejected("authenticationUnique")

    def test_shared_uuid_is_rejected(self):
        self.data["inbounds"][0]["users"].append({"name": "another-owner", "uuid": self.uuid})
        self.assert_rejected("authenticationUnique")

    def test_foreign_trojan_reusing_uuid_is_rejected(self):
        self.data["inbounds"][2]["users"].append({"name": "another-owner", "password": self.uuid})
        self.assert_rejected("authenticationUnique")

    def test_changed_owned_trojan_password_is_rejected(self):
        self.data["inbounds"][2]["users"][0]["password"] = "different"
        self.assert_rejected("authenticationUnique")

    def test_shared_registry_auth_alias_is_rejected(self):
        self.registry["users"]["other"] = {"socksUsername": self.target}
        self.assert_rejected("authenticationUnique")

    def test_owned_auth_on_unmanaged_inbound_is_rejected(self):
        self.data["inbounds"][0]["tag"] = "unmanaged-inbound"
        self.assert_rejected("authenticationUnique")

    def test_wrong_type_on_managed_inbound_is_rejected(self):
        self.data["inbounds"][0]["type"] = "other"
        self.assert_rejected("authenticationUnique")

    def test_duplicate_auth_or_managed_tag_is_rejected(self):
        self.data["inbounds"][0]["users"].append(dict(self.data["inbounds"][0]["users"][0]))
        self.assert_rejected("authenticationUnique")
        self.data["inbounds"][0]["users"].pop()
        self.data["inbounds"].append(copy.deepcopy(self.data["inbounds"][0]))
        self.assert_rejected("authenticationUnique")

    def test_missing_owned_route_is_rejected(self):
        self.data["route"]["rules"] = []
        self.assert_rejected("routesOwned")

    def test_foreign_auth_in_owned_route_is_rejected(self):
        self.data["route"]["rules"][0]["auth_user"].append("another-owner")
        self.assert_rejected("routesOwned")

    def test_owned_auth_routed_to_another_outbound_is_rejected(self):
        self.data["route"]["rules"].insert(0, {"auth_user": [self.auth_name], "outbound": "another"})
        self.assert_rejected("routesOwned")

    def test_unrestricted_target_route_is_rejected(self):
        self.data["route"]["rules"].append({"outbound": self.target_tag})
        self.assert_rejected("routesOwned")

    def test_target_as_global_final_is_rejected(self):
        self.data["route"]["final"] = self.target_tag
        self.assert_rejected("routesOwned")

    def test_target_as_shared_selector_or_detour_is_rejected(self):
        for field, value in (("outbounds", [self.target_tag]), ("detour", self.target_tag)):
            with self.subTest(field=field):
                self.data["outbounds"].append({"tag": "shared", "type": "selector", field: value})
                self.assert_rejected("routesOwned")
                self.data["outbounds"].pop()

    def test_expired_request_is_rejected(self):
        self.request = self.request.model_copy(update={"expiresAt": datetime.now(timezone.utc) - timedelta(days=1)})
        self.assert_rejected("entitlementCurrent")

    def test_request_cannot_outlive_current_owner(self):
        self.registry["users"][self.target]["expiresAt"] = (self.expiry - timedelta(hours=1)).isoformat()
        self.assert_rejected("entitlementCurrent")

    def test_disabled_or_blocked_owner_is_rejected(self):
        for key, value in (("accessEnabled", False), ("accessBlocked", True),
                ("enforcementTrafficBlocked", True), ("expirationBlocked", True)):
            with self.subTest(key=key):
                original = self.registry["users"][self.target].get(key)
                self.registry["users"][self.target][key] = value
                self.assert_rejected("targetEligible")
                self.registry["users"][self.target][key] = original

    def test_runtime_not_ready_is_rejected(self):
        for key, value in (("success", False), ("routingReady", False), ("runtimeReason", "blocked"),
                ("recoveryReason", "blocked"), ("serverPublicKey", None)):
            with self.subTest(key=key):
                original = self.runtime.get(key)
                self.runtime[key] = value
                self.assert_rejected("runtimeReady")
                self.runtime[key] = original


class AdoptionEndpointTests(AdoptionFixture):
    def setUp(self):
        super().setUp()
        app = FastAPI()
        app.add_exception_handler(RequestValidationError, main.validation_error_handler)
        app.include_router(adoption.router)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.enterContext(patch.object(adoption.config.security, "token", "offline-test-token"))
        self.enterContext(patch.object(adoption.config.security, "allowed_cidrs", ""))
        self.enterContext(patch.object(adoption.manager, "_config_lock", side_effect=nullcontext))
        self.read_config = self.enterContext(patch.object(
            adoption.manager, "read_config", side_effect=lambda: copy.deepcopy(self.data)))
        self.read_registry = self.enterContext(patch.object(
            adoption.manager, "read_registry", side_effect=lambda: copy.deepcopy(self.registry)))
        self.read_runtime = self.enterContext(patch.object(
            adoption.wireguard, "status", side_effect=lambda: copy.deepcopy(self.runtime)))

    def post(self, headers=None, payload=None):
        return self.client.post("/api/wireguard/owner-adoption/check",
            headers=headers if headers is not None else {"Authorization": "Bearer offline-test-token"},
            json=payload if payload is not None else self.request.model_dump(mode="json"))

    def test_authenticated_response_is_redacted_no_store_and_read_only(self):
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        self.assertTrue(response.json()["ready"], response.json())
        self.assertTrue(response.json()["checks"]["snapshotUnchanged"])
        self.assert_redacted(response.json())

    def test_missing_or_wrong_token_does_not_read_snapshots(self):
        for headers in ({}, {"Authorization": "Bearer wrong-token"}):
            with self.subTest(headers=headers):
                self.assertIn(self.post(headers=headers).status_code, (401, 403))
                self.read_config.assert_not_called()
                self.read_registry.assert_not_called()
                self.read_runtime.assert_not_called()

    def test_real_main_mount_requires_authentication(self):
        real_client = TestClient(main.app)
        self.addCleanup(real_client.close)
        response = real_client.post("/api/wireguard/owner-adoption/check", json=self.request.model_dump(mode="json"))
        self.assertIn(response.status_code, (401, 403))
        self.read_config.assert_not_called()
        self.read_registry.assert_not_called()
        self.read_runtime.assert_not_called()

    def test_changed_registry_snapshot_is_rejected(self):
        changed = copy.deepcopy(self.registry)
        changed["users"][self.source] = {"expiresAt": self.expiry.isoformat()}
        self.read_registry.side_effect = [copy.deepcopy(self.registry), changed]
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["ready"])
        self.assertFalse(response.json()["checks"]["snapshotUnchanged"])

    def test_changed_config_snapshot_is_rejected(self):
        changed = copy.deepcopy(self.data)
        changed["route"]["rules"] = []
        self.read_config.side_effect = [copy.deepcopy(self.data), changed]
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["ready"])
        self.assertFalse(response.json()["checks"]["snapshotUnchanged"])

    def test_runtime_error_is_redacted(self):
        self.read_runtime.side_effect = adoption.wireguard.WireguardError(self.password)
        response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assert_redacted(response.json())

    def test_invalid_ids_and_hashes_are_redacted_without_reads(self):
        for field, value in (("nodeUserId", "primary-42"), ("nodeUserId", "res-../bad"),
                ("previousNodeUserId", "../bad"), ("uuidSha256", self.password),
                ("proxySha256", self.username)):
            with self.subTest(field=field):
                payload = self.request.model_dump(mode="json")
                payload[field] = value
                response = self.post(payload=payload)
                self.assertEqual(response.status_code, 422)
                self.assert_redacted(response.json())
                self.read_config.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
