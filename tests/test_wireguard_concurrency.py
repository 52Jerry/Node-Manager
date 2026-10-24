import base64
import copy
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
import wireguard as wg


class WireguardConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.now = datetime.now(timezone.utc)
        self.expiry = self.now + timedelta(days=1)
        self.key = base64.b64encode(bytes([31]) * 32).decode()
        self.user_id = "concurrent-user"
        self.address = "10.77.9.9/32"
        self.source = {
            "outbounds": [{
                "type": "socks",
                "tag": wg.manager.USER_OUTBOUND_PREFIX + self.user_id,
                "server": "192.0.2.31",
                "server_port": 1080,
                "username": "fixture",
                "password": "fixture",
            }]
        }
        self.users = {
            "users": {
                self.user_id: {
                    "expiresAt": (self.now + timedelta(days=2)).isoformat(),
                    "accessEnabled": True,
                }
            }
        }
        identity = {key: self.source["outbounds"][0].get(key) for key in (
            "type", "server", "server_port", "version", "username", "password", "detour"
        )}
        peer = {
            "peerId": "concurrent-peer",
            "publicKey": self.key,
            "address": self.address,
            "allowedIps": [self.address],
            "nodeUserId": self.user_id,
            "expiresAt": self.expiry.isoformat(),
            "exitFingerprint": hashlib.sha256(
                json.dumps(identity, sort_keys=True).encode()
            ).hexdigest(),
            "status": "ACTIVE",
        }
        self.registry_path = root / "peers.json"
        self.registry_path.write_text(json.dumps({
            "version": 1,
            "interface": "wg0",
            "peers": {peer["peerId"]: peer},
        }), encoding="utf-8")
        self.kernel = {self.key: [self.address]}
        self.config_mutex = threading.Lock()
        for target, attr, value in (
                (wg, "REGISTRY_PATH", self.registry_path),
                (wg, "LOCK_PATH", root / "peers.lock"),
                (wg.config.wireguard, "enabled", True),
                (wg.config.wireguard, "interface", "wg0")):
            patcher = patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.enterContext(patch.object(wg, "_now", return_value=self.now))
        self.enterContext(patch.object(wg, "_recovery_error", None))
        self.enterContext(patch.object(wg, "_quarantine_inactive"))
        self.enterContext(patch.object(wg, "_runtime_ready", return_value=True))
        self.enterContext(patch.object(
            wg.manager, "read_config", side_effect=lambda: copy.deepcopy(self.source)))
        self.enterContext(patch.object(
            wg.manager, "read_registry", side_effect=lambda: copy.deepcopy(self.users)))
        self.enterContext(patch.object(wg.manager, "_config_lock", side_effect=self._config_lock))
        self.enterContext(patch.object(wg, "_kernel", side_effect=lambda: copy.deepcopy(self.kernel)))
        self.enterContext(patch.object(wg, "_invoke", side_effect=self._invoke))

    @contextmanager
    def _config_lock(self):
        with self.config_mutex:
            yield

    def _invoke(self, args):
        if args[0] == "set" and args[4] == "remove":
            self.kernel.pop(args[3], None)
        elif args[0] == "set":
            self.kernel[args[3]] = [args[5]]
        return ""

    def test_slow_route_sync_does_not_hold_singbox_config_lock(self):
        route_started = threading.Event()
        release_route = threading.Event()

        def slow_sync(*_args):
            route_started.set()
            if not release_route.wait(2):
                raise TimeoutError("test did not release route synchronization")

        with patch.object(wg, "_sync_routes", side_effect=slow_sync):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(wg.reconcile)
                self.assertTrue(route_started.wait(1))
                acquired = self.config_mutex.acquire(timeout=0.5)
                if acquired:
                    self.config_mutex.release()
                release_route.set()
                future.result(timeout=2)

        self.assertTrue(acquired)

    def test_binding_change_during_reconcile_blocks_and_retains_peer(self):
        sync_calls = 0

        def changing_sync(*_args):
            nonlocal sync_calls
            sync_calls += 1
            if sync_calls == 1:
                self.source["outbounds"][0]["server"] = "192.0.2.99"

        with patch.object(wg, "_sync_routes", side_effect=changing_sync):
            with self.assertRaises(wg.WireguardError):
                wg.reconcile()

        self.assertEqual(wg._read()["peers"]["concurrent-peer"]["status"], "BLOCKED")
        self.assertIn(self.key, self.kernel)
        self.assertEqual(sync_calls, 2)


if __name__ == "__main__":
    unittest.main()
