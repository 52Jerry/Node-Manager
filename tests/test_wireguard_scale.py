import base64
import hashlib
import json
import sys
import tempfile
import unittest
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
import wireguard as wg
import wireguard_routes as routes


PEER_COUNT = 4000


def _fixtures(count):
    now = datetime.now(timezone.utc)
    peer_expiry = now + timedelta(days=1)
    user_expiry = now + timedelta(days=2)
    outbounds = []
    users = {}
    peers = {}
    kernel = {}
    for index in range(count):
        user_id = f"user-{index:04d}"
        address = f"10.88.{index // 254}.{index % 254 + 1}/32"
        public_key = base64.b64encode((index + 1).to_bytes(32, "big")).decode()
        outbound = {
            "type": "socks", "tag": wg.manager.USER_OUTBOUND_PREFIX + user_id,
            "server": "192.0.2.10", "server_port": 1080,
            "username": "fixture", "password": "fixture",
        }
        identity = {key: outbound.get(key) for key in (
            "type", "server", "server_port", "version", "username", "password", "detour")}
        fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        outbounds.append(outbound)
        users[user_id] = {"expiresAt": user_expiry.isoformat()}
        peers[f"peer-{index:04d}"] = {
            "peerId": f"peer-{index:04d}", "publicKey": public_key,
            "address": address, "allowedIps": [address], "nodeUserId": user_id,
            "expiresAt": peer_expiry.isoformat(), "exitFingerprint": fingerprint,
            "status": "ACTIVE",
        }
        kernel[public_key] = [address]
    return now, peers, {"outbounds": outbounds}, {"users": users}, kernel


class CountingList(list):
    def __init__(self, values):
        super().__init__(values)
        self.iterations = 0

    def __iter__(self):
        for value in super().__iter__():
            self.iterations += 1
            yield value


class WireguardScaleTests(unittest.TestCase):
    def test_kernel_prefix_index_finds_overlaps_and_ignores_same_peer(self):
        own = base64.b64encode(bytes([7]) * 32).decode()
        other = base64.b64encode(bytes([8]) * 32).decode()
        index = wg._KernelAddressIndex({
            own: ["10.90.1.4/32"],
            other: ["10.91.0.0/16"],
        })

        self.assertFalse(index.conflicts("10.90.1.4/32", own))
        self.assertTrue(index.conflicts("10.90.1.4/32", other))
        self.assertTrue(index.conflicts("10.91.2.3/32", own))
        self.assertFalse(index.conflicts("10.92.2.3/32", own))

    def test_4000_peer_route_build_indexes_outbounds_once(self):
        now, peers, source, registry, _ = _fixtures(PEER_COUNT)
        source["outbounds"] = CountingList(source["outbounds"])

        rendered = routes.build_config(peers, source, registry, now)

        self.assertEqual(source["outbounds"].iterations, PEER_COUNT)
        self.assertEqual(len(rendered["outbounds"]), PEER_COUNT + 1)
        self.assertEqual(len(rendered["route"]["rules"]), PEER_COUNT + 2)

    def test_4000_peer_reconcile_uses_constant_snapshot_reads(self):
        now, peers, source, registry, kernel = _fixtures(PEER_COUNT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "peers.json"
            registry_path.write_text(json.dumps({
                "version": 1, "interface": "wg0", "peers": peers,
            }), encoding="utf-8")
            reads_config = Mock(return_value=source)
            reads_registry = Mock(return_value=registry)
            kernel_snapshot = Mock(return_value=kernel)
            route_sync = Mock()
            with patch.object(wg, "REGISTRY_PATH", registry_path), \
                    patch.object(wg, "LOCK_PATH", root / "lock"), \
                    patch.object(wg.config.wireguard, "enabled", True), \
                    patch.object(wg.config.wireguard, "interface", "wg0"), \
                    patch.object(wg, "_now", return_value=now), \
                    patch.object(wg, "_kernel", kernel_snapshot), \
                    patch.object(wg, "_runtime_ready", return_value=True), \
                    patch.object(wg, "_sync_routes", route_sync), \
                    patch.object(wg.manager, "read_config", reads_config), \
                    patch.object(wg.manager, "read_registry", reads_registry), \
                    patch.object(wg.manager, "_config_lock", return_value=nullcontext()):
                wg.reconcile()

        self.assertEqual(reads_config.call_count, 2)
        self.assertEqual(reads_registry.call_count, 2)
        self.assertEqual(kernel_snapshot.call_count, 1)
        self.assertEqual(route_sync.call_count, 1)
        self.assertIs(route_sync.call_args.args[1], source)
        self.assertIs(route_sync.call_args.args[2], registry)


if __name__ == "__main__":
    unittest.main()
