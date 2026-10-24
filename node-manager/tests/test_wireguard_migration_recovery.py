"""Synthetic, offline tests for the read-only WG migration proof endpoint."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Config's default factory probes a public address even with an explicit host.
# Block both its HTTP probe and UDP fallback before importing application code.
with tempfile.TemporaryDirectory() as import_temp, \
        patch.dict(os.environ, {"NODE_MANAGER_CONFIG": str(Path(import_temp) / "absent.yaml")}), \
        patch.object(requests, "get", side_effect=requests.RequestException("offline import")), \
        patch.object(socket.socket, "connect", side_effect=OSError("offline import")):
    import wireguard_migration_recovery as recovery
    import main

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RecoveryFixture(unittest.TestCase):
    def setUp(self):
        self.expiry = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=2)
        self.target = "primary-42"
        self.source = "res-retired-fixture"
        self.uuid = "12345678-1234-4234-8234-123456789abc"
        self.password = "fixture-residential-password-DO-NOT-RETURN"
        self.username = "fixture-residential-username-DO-NOT-RETURN"
        self.identity = ["192.0.2.42", 1080, self.username, self.password]
        self.auth_name = recovery.manager._auth_name(self.target)
        self.target_tag = recovery.manager.USER_OUTBOUND_PREFIX + self.target
        self.proof_hash = digest(json.dumps(
            [self.identity, self.uuid, recovery.manager._iso(self.expiry)],
            ensure_ascii=True, separators=(",", ":")))
        self.registry = {"users": {self.target: {
            "expiresAt": self.expiry.isoformat(), "accessEnabled": True,
            "residentialOwnershipMigration": {
                "sourceUserId": self.source, "resourceId": 43, "subscriptionId": 41,
                "accessProfileId": 42, "fingerprint": self.proof_hash,
            },
        }}}
        self.data = {
            "inbounds": [
                {"type": "vless", "tag": recovery.config.singbox.vless_tag,
                 "users": [{"name": self.auth_name, "uuid": self.uuid}]},
                {"type": "vmess", "tag": recovery.config.singbox.vmess_tag,
                 "users": [{"name": self.auth_name, "uuid": self.uuid}]},
                {"type": "trojan", "tag": recovery.config.singbox.trojan_tag,
                 "users": [{"name": self.auth_name, "password": self.uuid}]},
            ],
            "outbounds": [{"type": "socks", "tag": self.target_tag,
                           "server": self.identity[0], "server_port": self.identity[1],
                           "username": self.username, "password": self.password}],
            "route": {"rules": [{"auth_user": [self.auth_name], "outbound": self.target_tag}]},
        }
        self.old = {
            "peerId": "sub-41-node-6", "publicKey": base64.b64encode(bytes([1]) * 32).decode(),
            "address": "10.77.0.42/32", "allowedIps": ["10.77.0.42/32"],
            "nodeUserId": self.source, "expiresAt": self.expiry.isoformat(),
            "status": "BLOCKED", "stateReason": "NODE_USER_MISSING", "kernelPresent": False,
        }
        self.runtime = {
            "success": True, "routingReady": True, "runtimeReason": None,
            "recoveryReason": None, "interface": "wg0",
            "serverPublicKey": base64.b64encode(bytes([2]) * 32).decode(),
            "peers": [self.old], "occupiedAddresses": [],
        }
        self.request = recovery.RecoveryCheck(
            subscriptionId=41, resourceId=43, accessProfileId=42,
            peerId=self.old["peerId"], uuidSha256=digest(self.uuid),
            proxySha256=digest(json.dumps(self.identity, ensure_ascii=False, separators=(",", ":"))),
            expiresAt=self.expiry)
        self.mutations = []
        for target, name in (
                (recovery.manager, "mutate_config"), (recovery.manager, "_write_registry"),
                (recovery.manager, "_write_and_reload"), (recovery.wireguard, "_write"),
                (recovery.wireguard, "apply_peer"), (recovery.wireguard, "apply_peers"),
                (recovery.wireguard, "revoke_peer"), (subprocess, "run"),
                (requests.sessions.Session, "request")):
            self.mutations.append(self.enterContext(patch.object(
                target, name, side_effect=AssertionError("read-only proof attempted forbidden I/O"))))
        self.addCleanup(self.assert_no_mutations)

    def assert_no_mutations(self):
        for mocked in self.mutations:
            mocked.assert_not_called()

    def evaluate(self):
        before = copy.deepcopy((self.data, self.registry, self.runtime))
        result = recovery.evaluate(self.request, self.data, self.registry, self.runtime)
        self.assertEqual((self.data, self.registry, self.runtime), before)
        return result

    def assert_redacted(self, result):
        rendered = json.dumps(result, sort_keys=True)
        for sensitive in (self.uuid, self.username, self.password, self.proof_hash,
                          self.request.uuidSha256, self.request.proxySha256):
            self.assertNotIn(sensitive, rendered)
        self.assertNotIn("uuidSha256", rendered)
        self.assertNotIn("proxySha256", rendered)
        self.assertNotIn("fingerprint", rendered)


class EvaluateRecoveryTests(RecoveryFixture):
    def test_valid_missing_source_proof_is_ready_and_redacted_without_mutation(self):
        result = self.evaluate()
        self.assertTrue(result["ready"], result["checks"])
        self.assertEqual(result["oldPeer"], self.old)
        self.assert_redacted(result)

    def test_formally_revoked_old_peer_can_resume(self):
        self.old.update(status="REVOKED", stateReason="PEER_REVOKED")
        self.assertTrue(self.evaluate()["ready"])

    def test_missing_source_migration_proof_is_rejected(self):
        self.registry["users"][self.target].pop("residentialOwnershipMigration")
        self.assertFalse(self.evaluate()["ready"])

    def test_forged_nonempty_migration_fingerprint_is_rejected(self):
        self.registry["users"][self.target]["residentialOwnershipMigration"]["fingerprint"] = "a" * 64
        self.assertFalse(self.evaluate()["ready"])

    def test_wrong_resource_proof_is_rejected(self):
        self.registry["users"][self.target]["residentialOwnershipMigration"]["resourceId"] = 999
        self.assertFalse(self.evaluate()["ready"])

    def test_source_still_present_is_rejected(self):
        self.registry["users"][self.source] = {"expiresAt": self.expiry.isoformat()}
        self.assertFalse(self.evaluate()["ready"])

    def test_wrong_uuid_is_rejected(self):
        self.request = self.request.model_copy(update={"uuidSha256": digest("different-uuid")})
        self.assertFalse(self.evaluate()["ready"])

    def test_changed_residential_password_is_rejected(self):
        self.data["outbounds"][0]["password"] = "changed-secret"
        self.assertFalse(self.evaluate()["ready"])

    def test_duplicate_residential_owner_is_rejected(self):
        self.data["outbounds"].append({**self.data["outbounds"][0],
                                       "tag": recovery.manager.USER_OUTBOUND_PREFIX + "another-owner"})
        self.registry["users"]["another-owner"] = {"expiresAt": self.expiry.isoformat()}
        self.assertFalse(self.evaluate()["ready"])

    def test_real_traffic_block_is_not_bypassed(self):
        self.registry["users"][self.target]["enforcementTrafficBlocked"] = True
        result = self.evaluate()
        self.assertFalse(result["ready"])
        self.assertFalse(result["checks"]["targetEligible"])

    def test_disabled_user_is_not_bypassed(self):
        self.registry["users"][self.target]["accessEnabled"] = False
        self.assertFalse(self.evaluate()["ready"])

    def test_expired_entitlement_is_rejected(self):
        self.request = self.request.model_copy(update={"expiresAt": datetime.now(timezone.utc) - timedelta(days=1)})
        self.assertFalse(self.evaluate()["ready"])

    def test_peer_cannot_outlive_target_entitlement(self):
        self.registry["users"][self.target]["expiresAt"] = (self.expiry - timedelta(hours=1)).isoformat()
        self.assertFalse(self.evaluate()["ready"])

    def test_duplicate_old_public_key_is_rejected(self):
        self.runtime["peers"].append({**self.old, "peerId": "another-peer", "address": "10.77.0.43/32"})
        self.assertFalse(self.evaluate()["ready"])

    def test_duplicate_old_peer_id_is_rejected(self):
        self.runtime["peers"].append(dict(self.old))
        self.assertFalse(self.evaluate()["ready"])

    def test_duplicate_old_address_is_rejected(self):
        self.runtime["peers"].append({**self.old, "peerId": "another-peer",
                                      "publicKey": base64.b64encode(bytes([3]) * 32).decode()})
        self.assertFalse(self.evaluate()["ready"])

    def test_old_peer_belonging_to_another_source_is_rejected(self):
        self.old["nodeUserId"] = "different-old-owner"
        self.assertFalse(self.evaluate()["ready"])

    def test_other_block_reason_is_rejected(self):
        self.old["stateReason"] = "NODE_USER_TRAFFIC_BLOCKED"
        self.assertFalse(self.evaluate()["ready"])

    def test_unready_runtime_is_rejected(self):
        self.runtime["routingReady"] = False
        self.assertFalse(self.evaluate()["ready"])

    def test_missing_routes_are_rejected(self):
        self.data["route"]["rules"] = []
        self.assertFalse(self.evaluate()["ready"])

    def test_shared_target_uuid_is_rejected(self):
        self.data["inbounds"][0]["users"].append({"name": "another-owner", "uuid": self.uuid})
        self.assertFalse(self.evaluate()["ready"])

    def test_changed_target_trojan_password_is_rejected(self):
        self.data["inbounds"][2]["users"][0]["password"] = "changed-trojan-secret"
        self.assertFalse(self.evaluate()["ready"])

    def test_foreign_trojan_password_reusing_target_uuid_is_rejected(self):
        self.data["inbounds"][2]["users"].append({"name": "another-owner", "password": self.uuid})
        self.assertFalse(self.evaluate()["ready"])


class HistoricalExpiryRecoveryTests(EvaluateRecoveryTests):
    """Run every ownership/auth/entitlement negative case with historical proof."""

    def setUp(self):
        super().setUp()
        self.historical_expiry = self.expiry + timedelta(seconds=1, microseconds=192000)
        self.old["expiresAt"] = self.historical_expiry.isoformat()
        self.set_proof_expiry(self.historical_expiry)

    def set_proof_expiry(self, expiry):
        self.proof_hash = digest(json.dumps(
            [self.identity, self.uuid, recovery.manager._iso(expiry)],
            ensure_ascii=True, separators=(",", ":")))
        self.registry["users"][self.target]["residentialOwnershipMigration"]["fingerprint"] = self.proof_hash

    def test_exact_historical_expiry_allows_shorter_current_entitlement(self):
        result = self.evaluate()
        self.assertTrue(result["ready"], result["checks"])
        self.assertEqual(self.request.expiresAt, self.expiry)
        self.assertEqual(self.registry["users"][self.target]["expiresAt"], self.expiry.isoformat())
        self.assert_redacted(result)

    def test_exact_current_expiry_still_matches_when_old_expiry_differs(self):
        self.set_proof_expiry(self.expiry)
        self.assertTrue(self.evaluate()["ready"])

    def test_caller_expiry_cannot_supply_historical_proof_candidate(self):
        caller_expiry = self.expiry - timedelta(hours=1)
        self.request = self.request.model_copy(update={"expiresAt": caller_expiry})
        self.set_proof_expiry(caller_expiry)
        result = self.evaluate()
        self.assertTrue(result["checks"]["entitlementCurrent"])
        self.assertFalse(result["checks"]["proofFingerprintMatches"])
        self.assertFalse(result["ready"])

    def test_historical_expiry_near_match_has_no_tolerance(self):
        self.set_proof_expiry(self.historical_expiry + timedelta(microseconds=1))
        result = self.evaluate()
        self.assertFalse(result["checks"]["proofFingerprintMatches"])
        self.assertFalse(result["ready"])

    def test_current_expiry_near_match_has_no_tolerance(self):
        self.set_proof_expiry(self.expiry + timedelta(microseconds=1))
        self.assertFalse(self.evaluate()["checks"]["proofFingerprintMatches"])

    def test_second_truncated_historical_expiry_is_rejected(self):
        self.set_proof_expiry(self.historical_expiry.replace(microsecond=0))
        result = self.evaluate()
        self.assertFalse(result["checks"]["proofFingerprintMatches"])
        self.assertFalse(result["ready"])

    def test_missing_historical_expiry_is_rejected(self):
        self.old.pop("expiresAt")
        self.assertFalse(self.evaluate()["checks"]["proofFingerprintMatches"])

    def test_invalid_historical_expiry_is_rejected(self):
        self.old["expiresAt"] = "not-a-date"
        self.assertFalse(self.evaluate()["checks"]["proofFingerprintMatches"])

    def test_wrong_old_source_cannot_supply_historical_expiry(self):
        self.old["nodeUserId"] = "another-source"
        result = self.evaluate()
        self.assertFalse(result["checks"]["proofFingerprintMatches"])
        self.assertFalse(result["ready"])

    def test_another_peer_cannot_supply_historical_expiry(self):
        another = {**self.old, "peerId": "another-peer", "address": "10.77.0.43/32",
                   "publicKey": base64.b64encode(bytes([3]) * 32).decode()}
        self.runtime["peers"].append(another)
        self.old["expiresAt"] = self.expiry.isoformat()
        result = self.evaluate()
        self.assertTrue(result["checks"]["oldIdentityUnique"])
        self.assertFalse(result["checks"]["proofFingerprintMatches"])
        self.assertFalse(result["ready"])

    def test_duplicate_selected_peer_cannot_supply_historical_expiry(self):
        self.runtime["peers"].append(dict(self.old))
        result = self.evaluate()
        self.assertFalse(result["checks"]["proofFingerprintMatches"])
        self.assertFalse(result["ready"])


class RecoveryEndpointTests(RecoveryFixture):
    def setUp(self):
        super().setUp()
        app = FastAPI()
        app.add_exception_handler(RequestValidationError, main.validation_error_handler)
        app.include_router(recovery.router)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.enterContext(patch.object(recovery.config.security, "token", "offline-test-token"))
        self.enterContext(patch.object(recovery.config.security, "allowed_cidrs", ""))
        self.enterContext(patch.object(recovery.manager, "_config_lock", side_effect=nullcontext))
        self.read_config = self.enterContext(patch.object(
            recovery.manager, "read_config", side_effect=lambda: copy.deepcopy(self.data)))
        self.read_registry = self.enterContext(patch.object(
            recovery.manager, "read_registry", side_effect=lambda: copy.deepcopy(self.registry)))
        self.read_runtime = self.enterContext(patch.object(
            recovery.wireguard, "status", side_effect=lambda: copy.deepcopy(self.runtime)))

    def post(self, *, headers=None, payload=None):
        return self.client.post("/api/wireguard/migration-recovery/check",
                                headers=headers if headers is not None else {"Authorization": "Bearer offline-test-token"},
                                json=payload if payload is not None else self.request.model_dump(mode="json"))

    def test_main_app_mounts_authenticated_migration_route_without_startup(self):
        path = "/api/wireguard/migration-recovery/check"
        # Some FastAPI versions retain an included-router wrapper in app.routes;
        # verify the public schema and actual dispatch instead of private layout.
        self.assertIn(path, main.app.openapi()["paths"])
        self.assertIn("post", main.app.openapi()["paths"][path])
        # Deliberately do not enter TestClient: application startup must not run.
        with patch.object(main.app.router, "lifespan_context",
                          side_effect=AssertionError("main lifespan must not start")) as lifespan:
            client = TestClient(main.app)
            try:
                response = client.post(path, json=self.request.model_dump(mode="json"))
            finally:
                client.close()
        self.assertIn(response.status_code, (401, 403))
        lifespan.assert_not_called()
        self.read_config.assert_not_called()
        self.read_registry.assert_not_called()
        self.read_runtime.assert_not_called()

    def test_authenticated_check_is_no_store_redacted_and_read_only(self):
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        self.assertTrue(response.json()["ready"], response.json())
        self.assertTrue(response.json()["checks"]["snapshotUnchanged"])
        self.assert_redacted(response.json())
        self.assertEqual(self.read_config.call_count, 2)
        self.assertEqual(self.read_registry.call_count, 2)

    def test_missing_token_does_not_read_sensitive_snapshots(self):
        response = self.post(headers={})
        self.assertIn(response.status_code, (401, 403))
        self.read_config.assert_not_called()
        self.read_registry.assert_not_called()
        self.read_runtime.assert_not_called()

    def test_wrong_token_does_not_read_sensitive_snapshots(self):
        response = self.post(headers={"Authorization": "Bearer wrong-token"})
        self.assertEqual(response.status_code, 401)
        self.read_config.assert_not_called()
        self.read_registry.assert_not_called()
        self.read_runtime.assert_not_called()

    def test_registry_change_during_check_is_not_ready(self):
        changed = copy.deepcopy(self.registry)
        changed["users"][self.target]["enforcementTrafficBlocked"] = True
        self.read_registry.side_effect = [copy.deepcopy(self.registry), changed]
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["ready"])
        self.assertFalse(response.json()["checks"]["snapshotUnchanged"])

    def test_configuration_change_during_check_is_not_ready(self):
        changed = copy.deepcopy(self.data)
        changed["route"]["rules"] = []
        self.read_config.side_effect = [copy.deepcopy(self.data), changed]
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["ready"])
        self.assertFalse(response.json()["checks"]["snapshotUnchanged"])

    def test_runtime_failure_returns_redacted_503(self):
        self.read_runtime.side_effect = recovery.wireguard.WireguardError(self.password)
        response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assert_redacted(response.json())

    def test_invalid_hash_input_does_not_echo_hash_or_credentials(self):
        payload = self.request.model_dump(mode="json")
        payload["uuidSha256"] = self.password
        response = self.post(payload=payload)
        self.assertEqual(response.status_code, 422)
        self.assert_redacted(response.json())
        self.read_config.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
