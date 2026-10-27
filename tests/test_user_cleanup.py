import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_next_stage import base_singbox_config, manager, main
from fastapi.testclient import TestClient
import user_cleanup as cleanup


class UserCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = root / "sing-box.json"
        self.registry = root / "users.json"
        self.config.write_text(json.dumps(base_singbox_config()), encoding="utf-8")
        self.patches = [patch.object(manager, "CONFIG_PATH", self.config),
                        patch.object(manager, "REGISTRY_PATH", self.registry),
                        patch.object(manager, "_write_and_reload", self.write)]
        for value in self.patches:
            value.start()
        for user_id in ("expired", "other"):
            manager.create_user(user_id, ["vless", "vmess", "socks"], socks_username="login-" + user_id, socks_password="test-only-password")
            manager.bind_proxy(user_id, {"type": "socks", "server": "198.51.100.1" if user_id == "expired" else "198.51.100.2",
                                         "port": 1080, "username": "upstream-" + user_id, "password": "test-upstream"})
        self.set_expiry("expired", datetime.now(timezone.utc) - timedelta(hours=25))
        self.client = TestClient(main.app)
        self.headers = {"Authorization": "Bearer test-token"}

    def tearDown(self):
        for value in reversed(self.patches): value.stop()
        self.temp.cleanup()

    def write(self, data): self.config.write_text(json.dumps(data), encoding="utf-8")
    def set_expiry(self, user_id, value):
        data = json.loads(self.registry.read_text()); data["users"][user_id]["expiresAt"] = value.isoformat()
        self.registry.write_text(json.dumps(data), encoding="utf-8")
    def prepare(self): return cleanup.snapshot("expired")
    def invalid(self, snapshot):
        with patch.object(cleanup, "_probe_once", return_value=("INVALID", "PROXY_AUTH_REJECTED")):
            return cleanup.probe("expired", cleanup.ProbeRequest(fingerprint=snapshot["fingerprint"], archiveId=19))
    def command(self, snapshot, result):
        return cleanup.DetachItem(userId="expired", fingerprint=snapshot["fingerprint"], archiveId=19, proof=result["proof"])

    def test_invalid_retirement_removes_only_owned_config_and_keeps_database_reference(self):
        before_other = json.loads(self.registry.read_text())["users"]["other"]
        snapshot = self.prepare(); result = cleanup.detach([self.command(snapshot, self.invalid(snapshot))])
        self.assertEqual(result["removed"], ["expired"])
        data, registry = json.loads(self.config.read_text()), json.loads(self.registry.read_text())
        self.assertNotIn("expired", registry["users"]); self.assertEqual(registry["users"]["other"], before_other)
        self.assertEqual(registry["expiredUsers"]["expired"]["databaseArchiveId"], 19)
        self.assertFalse(any(outbound.get("tag") == manager.USER_OUTBOUND_PREFIX + "expired" for outbound in data["outbounds"]))
        self.assertTrue(any(outbound.get("tag") == manager.USER_OUTBOUND_PREFIX + "other" for outbound in data["outbounds"]))
        self.assertTrue(snapshot["snapshot"]["inbounds"])
        self.assertEqual(snapshot["snapshot"]["outbounds"][0]["password"], "test-upstream")

    def test_valid_probe_cannot_create_removal_proof(self):
        snapshot = self.prepare()
        with patch.object(cleanup, "_probe_once", return_value=("VALID", "SOCKS_TLS_HTTP_OK")):
            result = cleanup.probe("expired", cleanup.ProbeRequest(fingerprint=snapshot["fingerprint"], archiveId=19))
        self.assertEqual(result["outcome"], "VALID"); self.assertIsNone(result["proof"])
        self.assertIn("expired", json.loads(self.registry.read_text())["users"])

    def test_read_snapshot_does_not_wait_for_wireguard_mutation_lock(self):
        with patch.object(cleanup, "_wireguard_state", side_effect=AssertionError("must not lock WG for reads")), \
                patch.object(manager, "_config_lock", side_effect=AssertionError("must not wait for publication")), \
                patch.object(cleanup, "_read_wireguard_peers", return_value={}):
            snapshot = self.prepare()
        self.assertEqual(snapshot["snapshot"]["userId"], "expired")

    def test_wireguard_changes_during_snapshot_fail_closed_without_mutation(self):
        before_config, before_registry = self.config.read_bytes(), self.registry.read_bytes()
        with patch.object(cleanup, "_read_wireguard_peers", side_effect=[{}, {"unrelated": {"nodeUserId": "other"}}] * 3):
            with self.assertRaises(cleanup.HTTPException) as raised:
                self.prepare()
        self.assertEqual(raised.exception.detail, "WIREGUARD_STATE_CHANGED_RECHECK_REQUIRED")
        self.assertEqual(self.config.read_bytes(), before_config)
        self.assertEqual(self.registry.read_bytes(), before_registry)

    def test_configuration_replaced_during_snapshot_is_not_accepted(self):
        with patch.object(cleanup, "_snapshot_version", side_effect=[(1,), (2,)] * 3):
            with self.assertRaises(cleanup.HTTPException) as raised:
                self.prepare()
        self.assertEqual(raised.exception.detail, "CONFIGURATION_CHANGED_RECHECK_REQUIRED")
        self.assertIn("expired", json.loads(self.registry.read_text())["users"])

    def test_unchanged_snapshot_reuses_reads_but_returns_independent_owned_fields(self):
        with patch.object(manager, "read_config", wraps=manager.read_config) as config_reads, \
                patch.object(manager, "read_registry", wraps=manager.read_registry) as registry_reads:
            first = self.prepare()
            first["snapshot"]["outbounds"][0]["server"] = "198.51.100.99"
            second = self.prepare()
        self.assertEqual(config_reads.call_count, 1)
        self.assertEqual(registry_reads.call_count, 1)
        self.assertEqual(second["snapshot"]["outbounds"][0]["server"], "198.51.100.1")

    def test_cached_snapshot_is_invalidated_by_atomic_renewal(self):
        self.prepare()
        data = json.loads(self.registry.read_text())
        data["users"]["expired"]["expiresAt"] = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        replacement = self.registry.with_suffix(".replacement.json")
        replacement.write_text(json.dumps(data), encoding="utf-8")
        replacement.replace(self.registry)
        with self.assertRaises(cleanup.HTTPException):
            self.prepare()

    def test_timeout_and_disagreeing_failures_are_not_deletable(self):
        snapshot = self.prepare()
        for observations in [[("UNKNOWN", "TIMEOUT")] * 2, [("INVALID", "PROXY_AUTH_REJECTED"), ("UNKNOWN", "TIMEOUT")]]:
            with self.subTest(observations=observations), patch.object(cleanup, "_probe_once", side_effect=observations):
                result = cleanup.probe("expired", cleanup.ProbeRequest(fingerprint=snapshot["fingerprint"], archiveId=19))
            self.assertEqual(result["outcome"], "UNKNOWN"); self.assertIsNone(result["proof"])

    def test_success_on_second_target_is_valid_even_after_first_refusal(self):
        snapshot = self.prepare()
        with patch.object(cleanup, "_probe_once", side_effect=[("INVALID", "PROXY_AUTH_REJECTED"), ("VALID", "SOCKS_TLS_HTTP_OK")]):
            result = cleanup.probe("expired", cleanup.ProbeRequest(fingerprint=snapshot["fingerprint"], archiveId=19))
        self.assertEqual(result["outcome"], "VALID")

    def test_renewal_during_probe_or_before_detach_preserves_config(self):
        snapshot = self.prepare(); result = self.invalid(snapshot); before = self.config.read_bytes()
        self.set_expiry("expired", datetime.now(timezone.utc) + timedelta(days=30))
        with self.assertRaises(cleanup.HTTPException): cleanup.detach([self.command(snapshot, result)])
        self.assertEqual(self.config.read_bytes(), before)

    def test_proxy_change_after_probe_is_not_removed(self):
        snapshot = self.prepare(); result = self.invalid(snapshot)
        manager.bind_proxy("expired", {"server": "198.51.100.9", "port": 1081, "username": "new", "password": "new"})
        before = self.config.read_bytes()
        with self.assertRaises(cleanup.HTTPException): cleanup.detach([self.command(snapshot, result)])
        self.assertEqual(self.config.read_bytes(), before)

    def test_tampered_proof_archive_id_and_restarted_agent_are_rejected(self):
        snapshot = self.prepare(); result = self.invalid(snapshot)
        for change in ({"proof": result["proof"] + "x"}, {"archiveId": 20}):
            with self.assertRaises(cleanup.HTTPException): cleanup.detach([self.command(snapshot, result).model_copy(update=change)])
        with patch.object(cleanup, "_proof_key", b"different-process-key"):
            with self.assertRaises(cleanup.HTTPException): cleanup.detach([self.command(snapshot, result)])

    def test_legacy_manual_delete_cannot_bypass_backup_or_probe(self):
        response = self.client.delete("/api/user/delete/expired", headers={**self.headers, "Idempotency-Key": "guarded-cleanup-test"})
        self.assertEqual(response.status_code, 409); self.assertIn("expired", json.loads(self.registry.read_text())["users"])

    def test_unexpired_unknown_expiry_and_authless_requests_are_rejected(self):
        self.assertEqual(self.client.get("/api/users/cleanup/expired/snapshot").status_code, 401)
        with self.assertRaises(cleanup.HTTPException): cleanup.snapshot("other")
        data = json.loads(self.registry.read_text()); data["users"]["expired"]["expiresAt"] = None
        self.registry.write_text(json.dumps(data))
        with self.assertRaises(cleanup.HTTPException): cleanup.snapshot("expired")

    def test_shared_or_multiple_proxy_configuration_requires_review(self):
        data = json.loads(self.config.read_text())
        data["outbounds"].append({"tag": "shared-selector", "type": "selector", "outbounds": [manager.USER_OUTBOUND_PREFIX + "expired"]})
        self.write(data)
        with self.assertRaises(cleanup.HTTPException): cleanup.snapshot("expired")

    def test_proxy_endpoint_refusal_is_distinguished_from_timeout(self):
        proxy = {"server": "198.51.100.1", "server_port": 1080}
        with patch.object(cleanup.socket, "create_connection", side_effect=ConnectionRefusedError()):
            self.assertEqual(cleanup._probe_once(proxy, cleanup._targets[0])[0], "INVALID")
        with patch.object(cleanup.socket, "create_connection", side_effect=TimeoutError()):
            self.assertEqual(cleanup._probe_once(proxy, cleanup._targets[0])[0], "UNKNOWN")

    def test_failed_config_apply_leaves_user_and_routes_recoverable(self):
        snapshot = self.prepare(); result = self.invalid(snapshot)
        before_config, before_registry = self.config.read_bytes(), self.registry.read_bytes()
        with patch.object(manager, "_write_and_reload", side_effect=manager.SingboxConfigError("apply failed")):
            with self.assertRaises(manager.SingboxConfigError): cleanup.detach([self.command(snapshot, result)])
        self.assertEqual(self.config.read_bytes(), before_config); self.assertEqual(self.registry.read_bytes(), before_registry)

    def test_entire_batch_is_checked_before_any_configuration_is_changed(self):
        snapshot = self.prepare(); result = self.invalid(snapshot)
        self.set_expiry("other", datetime.now(timezone.utc) - timedelta(hours=25))
        other = cleanup.snapshot("other")
        with patch.object(cleanup, "_probe_once", return_value=("INVALID", "PROXY_AUTH_REJECTED")):
            proof = cleanup.probe("other", cleanup.ProbeRequest(fingerprint=other["fingerprint"], archiveId=20))
        self.set_expiry("other", datetime.now(timezone.utc) + timedelta(days=10))
        before = self.config.read_bytes()
        with self.assertRaises(cleanup.HTTPException):
            cleanup.detach([self.command(snapshot, result), cleanup.DetachItem(userId="other", fingerprint=other["fingerprint"], archiveId=20, proof=proof["proof"])])
        self.assertEqual(self.config.read_bytes(), before)
        self.assertIn("expired", json.loads(self.registry.read_text())["users"])

    def test_inventory_snapshot_is_authenticated_and_never_contains_passwords(self):
        with patch.object(manager, "EXPIRATION_ENABLED", False):
            response = self.client.get("/api/users/cleanup/inventory", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 2)
        self.assertNotIn("password", response.text)
        self.assertNotIn("test-only-password", response.text)

    def test_shared_authentication_alias_is_not_removed(self):
        data = json.loads(self.registry.read_text())
        data["users"]["other"]["socksUsername"] = data["users"]["expired"]["socksUsername"]
        self.registry.write_text(json.dumps(data))
        with self.assertRaises(cleanup.HTTPException): cleanup.snapshot("expired")

    def test_detach_batch_cap_matches_the_bounded_website_worker(self):
        from pydantic import ValidationError
        items = [cleanup.DetachItem(userId="user-" + str(i), fingerprint="a" * 64, archiveId=i + 1, proof="dummy-proof") for i in range(200)]
        self.assertEqual(len(cleanup.DetachRequest(items=items).items), 200)
        with self.assertRaises(ValidationError):
            cleanup.DetachRequest(items=items + [items[0]])

    def test_peer_validation_cache_tracks_atomic_registry_version_and_protects_renewed_peers(self):
        import base64
        import wireguard
        from config import config
        peer_path = self.registry.with_name("peers.json")
        expiry = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        peer = {"peerId": "peer-expired", "nodeUserId": "expired", "publicKey": base64.b64encode(b"a" * 32).decode(),
                "address": "10.7.0.2/32", "allowedIps": ["10.7.0.2/32"], "exitFingerprint": "existing-exit",
                "expiresAt": expiry, "status": "EXPIRED"}
        body = {"version": 1, "interface": config.wireguard.interface, "peers": {"peer-expired": peer}}
        peer_path.write_text(json.dumps(body), encoding="utf-8")
        with patch.object(config.wireguard, "enabled", True), patch.object(wireguard, "REGISTRY_PATH", peer_path), \
                patch.object(wireguard, "_read", wraps=wireguard._read) as reads:
            self.prepare(); self.prepare()
            self.assertEqual(reads.call_count, 1)
            body["peers"]["peer-expired"]["expiresAt"] = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
            replacement = peer_path.with_suffix(".new.json")
            replacement.write_text(json.dumps(body), encoding="utf-8"); replacement.replace(peer_path)
            with self.assertRaises(cleanup.HTTPException) as raised:
                self.prepare()
            self.assertEqual(raised.exception.detail, "WIREGUARD_EXPIRY_REQUIRES_REVIEW")
            self.assertEqual(reads.call_count, 2)

    def test_disabled_wireguard_is_not_read_reconciled_or_revoked_during_cleanup(self):
        import wireguard
        from config import config
        with patch.object(config.wireguard, "enabled", False), \
                patch.object(wireguard, "_read", side_effect=AssertionError("WG remains untouched")), \
                patch.object(wireguard, "_locked", side_effect=AssertionError("WG remains untouched")), \
                patch.object(wireguard, "_sync_routes", side_effect=AssertionError("WG remains untouched")), \
                patch.object(wireguard, "_remove", side_effect=AssertionError("WG remains untouched")):
            snapshot = self.prepare()
            self.assertEqual(snapshot["snapshot"]["wireguardPeers"], [])
            result = cleanup.detach([self.command(snapshot, self.invalid(snapshot))])
        self.assertEqual(result["removed"], ["expired"])
        self.assertIn("other", json.loads(self.registry.read_text())["users"])


if __name__ == "__main__": unittest.main()
