import base64
from concurrent.futures import ThreadPoolExecutor
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from test_next_stage import idempotency, main
from wireguard import WireguardError


class WireguardBatchApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.idempotency_path = Path(self.temp.name) / "idempotency.json"
        self.idempotency_patch = patch.object(idempotency, "STORE_PATH", self.idempotency_path)
        self.apply_patch = patch.object(main, "apply_peers")
        self.idempotency_patch.start()
        self.apply = self.apply_patch.start()
        self.addCleanup(self.apply_patch.stop)
        self.addCleanup(self.idempotency_patch.stop)
        self.client = TestClient(main.app)
        self.headers = {"Authorization": "Bearer test-token", "Idempotency-Key": "wg-batch-test-1"}
        self.peer = self.make_peer()

    @staticmethod
    def make_peer(index=1):
        address = f"10.77.0.{index}/32"
        return {
            "peerId": f"peer-{index}",
            "publicKey": base64.b64encode(index.to_bytes(32, "big")).decode("ascii"),
            "address": address,
            "allowedIps": [address],
            "nodeUserId": f"user-{index}",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        }

    @staticmethod
    def receipt(peer):
        return {
            "success": True,
            "interface": "wg0",
            "serverPublicKey": base64.b64encode(bytes([255]) * 32).decode("ascii"),
            "peerId": peer["peerId"],
            "publicKey": peer["publicKey"],
            "address": peer["address"],
            "allowedIps": peer["allowedIps"],
            "nodeUserId": peer["nodeUserId"],
            "expiresAt": peer["expiresAt"],
            "status": "ACTIVE",
        }

    def set_success(self, peers=None):
        peers = peers if peers is not None else [self.peer]
        self.apply.return_value = {"success": True, "peers": [self.receipt(peer) for peer in peers]}

    def test_batch_requires_bearer_token(self):
        response = self.client.post(
            "/api/wireguard/peers/apply",
            headers={"Idempotency-Key": "auth-check"},
            json={"peers": [self.peer]},
        )

        self.assertEqual(response.status_code, 401, response.text)
        self.apply.assert_not_called()

    def test_wireguard_access_snapshot_is_read_only_and_typed(self):
        with patch.object(main, "wireguard_access_snapshot", return_value={
                "usable-user": True, "blocked-user": False}) as snapshot:
            response = self.client.get("/api/wireguard/access-snapshot", headers={
                "Authorization": "Bearer test-token"})

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.json(), {"usable-user": True, "blocked-user": False})
        snapshot.assert_called_once_with()

    def test_delivery_status_is_authenticated_bounded_and_read_only(self):
        with patch('wireguard.peer_delivery_status', return_value={
                'success': True, 'peers': [], 'accessByUser': {'user-1': False}}) as read:
            path = '/api/wireguard/peer-status?peerId=peer-1&nodeUserId=user-1&includeRuntime=false'
            denied = self.client.get(path)
            self.assertEqual(denied.status_code, 401)
            read.assert_not_called()
            response = self.client.get(path, headers={'Authorization': 'Bearer test-token'})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers['cache-control'], 'no-store')
            read.assert_called_once_with('peer-1', 'user-1', False)

    def test_delivery_changed_state_is_conflict_and_invalid_input_is_rejected(self):
        with patch('wireguard.peer_delivery_status', side_effect=WireguardError('state changed')) as read:
            response = self.client.get('/api/wireguard/peer-status?peerId=peer-1&nodeUserId=user-1',
                                       headers={'Authorization': 'Bearer test-token'})
            self.assertEqual(response.status_code, 409)
            read.assert_called_once_with('peer-1', 'user-1', True)
            read.reset_mock()
            invalid = self.client.get('/api/wireguard/peer-status?peerId=../other&nodeUserId=user-1',
                                      headers={'Authorization': 'Bearer test-token'})
            self.assertEqual(invalid.status_code, 422)
            read.assert_not_called()

    def test_success_is_live_reconciled_on_same_key_retry(self):
        self.set_success()
        first = self.client.post("/api/wireguard/peers/apply", headers=self.headers,
                                 json={"peers": [self.peer]})
        second = self.client.post("/api/wireguard/peers/apply", headers=self.headers,
                                  json={"peers": [self.peer]})

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.headers["Idempotency-Replayed"], "false")
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(second.headers["Idempotency-Replayed"], "true")
        self.assertEqual(self.apply.call_count, 2)
        self.assertEqual(first.json()["peers"][0]["status"], "ACTIVE")
        stored = self.idempotency_path.read_text(encoding="utf-8")
        self.assertNotIn(self.peer["publicKey"], stored)
        self.assertNotIn("responseEncrypted", stored)

    def test_same_key_with_different_batch_is_conflict(self):
        self.set_success()
        first = self.client.post("/api/wireguard/peers/apply", headers=self.headers,
                                 json={"peers": [self.peer]})
        changed = dict(self.peer, address="10.77.0.9/32", allowedIps=["10.77.0.9/32"])
        second = self.client.post("/api/wireguard/peers/apply", headers=self.headers,
                                  json={"peers": [changed]})

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 409, second.text)
        self.apply.assert_called_once()

    def test_batch_over_limit_is_rejected_without_echoing_keys(self):
        peers = [self.make_peer(index) for index in range(1, 4002)]
        response = self.client.post("/api/wireguard/peers/apply", headers=self.headers,
                                    json={"peers": peers})

        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json(), {"detail": "invalid WireGuard request"})
        self.apply.assert_not_called()

    def test_private_key_field_is_rejected_without_echoing_request(self):
        request_peer = dict(self.peer, privateKey="do-not-accept-or-echo")
        response = self.client.post("/api/wireguard/peers/apply", headers=self.headers,
                                    json={"peers": [request_peer]})

        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json(), {"detail": "invalid WireGuard request"})
        self.assertNotIn("do-not-accept-or-echo", response.text)
        self.apply.assert_not_called()

    def test_slow_batch_key_does_not_hold_global_idempotency_store_lock(self):
        started = threading.Event()
        release = threading.Event()
        first_key, second_key = "slow-wireguard-batch", "other-idempotent-write"
        self.assertIsNot(idempotency._request_lock(first_key), idempotency._request_lock(second_key))

        def slow_apply():
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test did not release slow apply")
            return {"success": True}

        with ThreadPoolExecutor(max_workers=2) as executor:
            slow = executor.submit(
                idempotency.execute_reconciling_idempotent,
                first_key,
                "wireguard-apply-batch",
                {"peers": [self.peer]},
                slow_apply,
            )
            self.assertTrue(started.wait(timeout=1))
            try:
                other_future = executor.submit(
                    idempotency.execute_reconciling_idempotent,
                    second_key,
                    "other-operation",
                    {"value": 1},
                    lambda: {"success": True},
                )
                other, replayed = other_future.result(timeout=1)
                self.assertEqual(other, {"success": True})
                self.assertFalse(replayed)
            finally:
                release.set()
            self.assertEqual(slow.result(timeout=1), ({"success": True}, False))

    def test_failed_apply_is_explicit_and_same_key_can_retry(self):
        self.set_success()
        self.apply.side_effect = [
            WireguardError("WireGuard batch application failed; peers disabled"),
            self.apply.return_value,
        ]
        failed = self.client.post("/api/wireguard/peers/apply", headers=self.headers,
                                  json={"peers": [self.peer]})
        retried = self.client.post("/api/wireguard/peers/apply", headers=self.headers,
                                   json={"peers": [self.peer]})

        self.assertEqual(failed.status_code, 503, failed.text)
        self.assertIn("peers disabled", failed.json()["detail"])
        self.assertEqual(retried.status_code, 200, retried.text)
        self.assertEqual(retried.headers["Idempotency-Replayed"], "false")
        self.assertEqual(self.apply.call_count, 2)

    def test_idempotency_key_is_required(self):
        response = self.client.post(
            "/api/wireguard/peers/apply",
            headers={"Authorization": "Bearer test-token"},
            json={"peers": [self.peer]},
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
