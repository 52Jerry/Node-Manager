import base64
import copy
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


def _make_items(count, now):
    expires_at = now + timedelta(days=1)
    user_expires_at = now + timedelta(days=2)
    items = []
    users = {}
    outbounds = []
    for index in range(count):
        user_id = f"batch-user-{index:04d}"
        address = f"10.89.{index // 254}.{index % 254 + 1}/32"
        public_key = base64.b64encode((index + 1).to_bytes(32, "big")).decode()
        outbound = {
            "type": "socks", "tag": wg.manager.USER_OUTBOUND_PREFIX + user_id,
            "server": "192.0.2.20", "server_port": 1080,
            "username": "fixture", "password": "fixture",
        }
        outbounds.append(outbound)
        users[user_id] = {"expiresAt": user_expires_at.isoformat()}
        items.append({
            "peerId": f"batch-peer-{index:04d}",
            "publicKey": public_key,
            "address": address,
            "allowedIps": [address],
            "nodeUserId": user_id,
            "expiresAt": expires_at.isoformat(),
        })
    return items, {"users": users}, {"outbounds": outbounds}


class WireguardLegacyUserRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.user_id = "legacy-user"
        self.expiry = self.now + timedelta(days=7)
        self.registry = {"version": 2, "users": {}, "expiredUsers": {}}
        self.config_data = {
            "inbounds": [
                {
                    "tag": wg.manager.config.singbox.vless_tag,
                    "users": [{"name": f"node-manager:{self.user_id}", "uuid": "fixture"}],
                },
                {
                    "tag": wg.manager.config.singbox.socks_tag,
                    "users": [{"username": self.user_id, "password": "client-secret"}],
                },
            ],
            "outbounds": [{
                "type": "socks",
                "tag": wg.manager.USER_OUTBOUND_PREFIX + self.user_id,
                "server": "192.0.2.50",
                "server_port": 1080,
                "username": "upstream-secret-user",
                "password": "upstream-secret-password",
            }],
        }

    def recover(self):
        def mutate(mutator):
            return mutator(self.config_data, self.registry)

        with patch.object(wg.manager, "mutate_config", side_effect=mutate):
            return wg.manager.recover_wireguard_user_metadata({self.user_id: self.expiry})

    def test_missing_metadata_with_exact_config_and_socks_route_is_recovered(self):
        self.assertEqual(self.recover(), 1)

        metadata = self.registry["users"][self.user_id]
        self.assertEqual(metadata["expiresAt"], self.expiry.isoformat())
        self.assertTrue(metadata["accessEnabled"])
        self.assertEqual(metadata["socksUsername"], self.user_id)
        self.assertEqual(metadata["sourceAddress"], "192.0.2.50")
        self.assertEqual(metadata["sourcePort"], 1080)

    def test_created_at_only_legacy_stub_is_completed(self):
        created_at = (self.now - timedelta(days=30)).isoformat()
        self.registry["users"][self.user_id] = {"createdAt": created_at}

        self.assertEqual(self.recover(), 1)
        metadata = self.registry["users"][self.user_id]
        self.assertEqual(metadata["createdAt"], created_at)
        self.assertEqual(metadata["expiresAt"], self.expiry.isoformat())
        self.assertTrue(metadata["accessEnabled"])

    def test_missing_config_user_is_rejected(self):
        self.config_data["inbounds"] = []

        with self.assertRaisesRegex(
                wg.manager.SingboxConfigError, "absent from managed inbounds"):
            self.recover()
        self.assertNotIn(self.user_id, self.registry["users"])

    def test_missing_or_non_socks_outbound_is_rejected(self):
        for outbound in (None, {
            "type": "direct",
            "tag": wg.manager.USER_OUTBOUND_PREFIX + self.user_id,
        }):
            with self.subTest(outbound=outbound):
                self.registry["users"].clear()
                self.config_data["outbounds"] = [] if outbound is None else [outbound]
                with self.assertRaisesRegex(
                        wg.manager.SingboxConfigError, "no residential SOCKS outbound"):
                    self.recover()
                self.assertNotIn(self.user_id, self.registry["users"])

    def test_expired_command_is_rejected(self):
        self.expiry = self.now - timedelta(seconds=1)

        with self.assertRaisesRegex(
                wg.manager.SingboxConfigError, "requires a future expiration"):
            self.recover()
        self.assertNotIn(self.user_id, self.registry["users"])

    def test_existing_blocked_metadata_is_preserved(self):
        original = {
            "expiresAt": self.expiry.isoformat(),
            "accessEnabled": False,
            "expirationBlocked": True,
        }
        self.registry["users"][self.user_id] = copy.deepcopy(original)

        self.assertEqual(self.recover(), 0)
        self.assertEqual(self.registry["users"][self.user_id], original)

    def test_recovery_result_and_audit_do_not_expose_secrets(self):
        with patch.object(wg.manager.logger, "info") as log_info:
            self.assertEqual(self.recover(), 1)

        audit_text = str(log_info.call_args_list)
        self.assertNotIn("client-secret", audit_text)
        self.assertNotIn("upstream-secret-user", audit_text)
        self.assertNotIn("upstream-secret-password", audit_text)


class WireguardBatchApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.now = datetime.now(timezone.utc)
        self.server_key = base64.b64encode(bytes([250]) * 32).decode()
        self.kernel = {}
        self.commands = []
        self.items, self.users, self.config_data = _make_items(2, self.now)
        for target, attr, value in (
                (wg, "REGISTRY_PATH", root / "peers.json"),
                (wg, "LOCK_PATH", root / "peers.lock"),
                (wg.config.wireguard, "enabled", True),
                (wg.config.wireguard, "interface", "wg0")):
            p = patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.read_config = self.enterContext(patch.object(
            wg.manager, "read_config", return_value=self.config_data))
        self.read_registry = self.enterContext(patch.object(
            wg.manager, "read_registry", return_value=self.users))
        self.config_lock = self.enterContext(patch.object(
            wg.manager, "_config_lock", return_value=nullcontext()))
        self.recover_users = self.enterContext(patch.object(
            wg.manager, "recover_wireguard_user_metadata", return_value=0))
        self.enterContext(patch.object(wg, "_recovery_error", None))
        self.quarantine = self.enterContext(patch.object(wg, "_quarantine_inactive"))
        self.route_sync = self.enterContext(patch.object(wg, "_sync_routes"))
        self.runtime = self.enterContext(patch.object(wg, "_runtime_ready", return_value=True))
        self.invoke = self.enterContext(patch.object(wg, "_invoke", side_effect=self._command))
        self.write = self.enterContext(patch.object(wg, "_write", wraps=wg._write))

    def _command(self, args):
        self.commands.append(args)
        if args[0] == "show":
            if args[-1] == "public-key":
                return self.server_key
            if args[-1] == "allowed-ips":
                return "\n".join(f"{key}\t{','.join(values)}" for key, values in self.kernel.items())
        if args[0] == "set":
            if args[4] == "remove":
                self.kernel.pop(args[3], None)
            else:
                self.kernel[args[3]] = [args[5]]
        return ""

    def test_batch_validates_then_syncs_once_and_returns_only_verified_active(self):
        result = wg.apply_peers(self.items)

        self.assertTrue(result["success"])
        self.assertEqual(len(result["peers"]), 2)
        self.assertTrue(all(peer["status"] == "ACTIVE" for peer in result["peers"]))
        self.assertEqual(len(self.kernel), 2)
        self.assertEqual(self.write.call_count, 2)  # APPLYING intent, then verified ACTIVE state.
        self.assertEqual(self.route_sync.call_count, 1)
        self.assertEqual(self.read_config.call_count, 2)
        self.assertEqual(self.read_registry.call_count, 2)
        self.recover_users.assert_called_once()
        show_allowed = [call for call in self.commands if call[:3] == ["show", "wg0", "allowed-ips"]]
        show_key = [call for call in self.commands if call[-1:] == ["public-key"]]
        self.assertEqual(len(show_allowed), 2)
        self.assertEqual(len(show_key), 1)
        self.assertEqual(len([call for call in self.commands if call[0] == "set"]), 2)

    def test_duplicate_address_rejects_whole_batch_before_side_effects(self):
        duplicate = copy.deepcopy(self.items[1])
        duplicate["address"] = self.items[0]["address"]
        duplicate["allowedIps"] = [duplicate["address"]]

        with self.assertRaises(wg.WireguardError):
            wg.apply_peers([self.items[0], duplicate])

        self.assertEqual(self.write.call_count, 0)
        self.route_sync.assert_not_called()
        self.assertFalse(self.kernel)
        self.assertFalse(any(call[0] == "set" for call in self.commands))

    def test_batch_can_adopt_exact_legacy_kernel_peer_when_enabled(self):
        first = self.items[0]
        self.kernel[first["publicKey"]] = [first["address"]]

        with patch.object(wg.config.wireguard, "allow_legacy_peer_adoption", True):
            result = wg.apply_peers([first])

        self.assertEqual(result["peers"][0]["status"], "ACTIVE")
        self.assertEqual(self.kernel[first["publicKey"]], [first["address"]])
        self.assertFalse(any(call[0] == "set" for call in self.commands))

    def test_partial_kernel_apply_quarantines_new_peers_without_active_receipts(self):
        original_command = self._command
        failed_key = self.items[1]["publicKey"]

        def fail_second_set(args):
            if args[0] == "set" and args[3] == failed_key and args[4] == "allowed-ips":
                raise wg.WireguardError("simulated wg failure")
            return original_command(args)

        self.invoke.side_effect = fail_second_set
        with self.assertRaises(wg.WireguardError):
            wg.apply_peers(self.items)

        state = wg._read()["peers"]
        self.assertEqual({peer["status"] for peer in state.values()}, {"FAILED"})
        self.assertEqual(set(self.kernel), {self.items[0]["publicKey"]})
        self.quarantine.assert_called_once()
        self.assertEqual(self.write.call_count, 2)
        self.assertEqual(self.route_sync.call_count, 2)

    def test_registry_activation_failure_quarantines_retained_kernel_batch(self):
        original_write = self.write._mock_wraps
        writes = 0

        def fail_activation_write(data):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("simulated registry failure")
            return original_write(data)

        self.write.side_effect = fail_activation_write
        with self.assertRaises(wg.WireguardError):
            wg.apply_peers(self.items)

        state = wg._read()["peers"]
        self.assertEqual({peer["status"] for peer in state.values()}, {"FAILED"})
        self.assertEqual(len(self.kernel), 2)
        self.quarantine.assert_called_once()
        self.assertEqual(writes, 3)
        self.assertEqual(self.route_sync.call_count, 2)

    def test_binding_change_during_apply_fails_closed_before_activation(self):
        changed_config = copy.deepcopy(self.config_data)
        changed_config["outbounds"][0]["server"] = "192.0.2.99"
        self.read_config.side_effect = [self.config_data, changed_config, changed_config]

        with self.assertRaises(wg.WireguardError):
            wg.apply_peers(self.items)

        state = wg._read()["peers"]
        self.assertEqual({peer["status"] for peer in state.values()}, {"FAILED"})
        self.assertEqual(len(self.kernel), 2)
        self.quarantine.assert_called_once()
        self.assertEqual(self.route_sync.call_count, 2)

    def test_batch_reissue_after_verified_revoke_keeps_tombstone(self):
        first = copy.deepcopy(self.items[0])
        wg.apply_peers([first])
        wg.revoke_peer(first["peerId"], first["publicKey"])
        replacement = copy.deepcopy(first)
        replacement.update({
            "peerId": "batch-peer-replacement",
            "publicKey": base64.b64encode(bytes([240]) * 32).decode(),
            "address": "10.89.9.9/32",
            "allowedIps": ["10.89.9.9/32"],
        })

        result = wg.apply_peers([replacement])

        self.assertEqual(result["peers"][0]["status"], "ACTIVE")
        peers = wg._read()["peers"]
        self.assertEqual(peers[first["peerId"]]["status"], "REVOKED")
        self.assertEqual(peers[replacement["peerId"]]["status"], "ACTIVE")
        self.assertNotIn(first["publicKey"], self.kernel)
        self.assertEqual(self.kernel[replacement["publicKey"]], [replacement["address"]])

    def test_4000_peer_batch_has_one_route_sync_and_one_kernel_readback(self):
        items, users, source_config = _make_items(4000, self.now)
        self.read_config.return_value = source_config
        self.read_registry.return_value = users

        result = wg.apply_peers(items)

        self.assertEqual(len(result["peers"]), 4000)
        self.assertEqual(self.write.call_count, 2)
        self.assertEqual(self.route_sync.call_count, 1)
        self.assertEqual(self.read_config.call_count, 2)
        self.assertEqual(self.read_registry.call_count, 2)
        show_allowed = [call for call in self.commands if call[:3] == ["show", "wg0", "allowed-ips"]]
        show_key = [call for call in self.commands if call[-1:] == ["public-key"]]
        self.assertEqual(len(show_allowed), 2)
        self.assertEqual(len(show_key), 1)
        self.assertEqual(len([call for call in self.commands if call[0] == "set"]), 4000)
        self.assertEqual(len(self.kernel), 4000)
        self.assertTrue(all(peer["status"] == "ACTIVE" for peer in result["peers"]))


class WireguardAccessSnapshotTests(unittest.TestCase):
    def test_reports_only_currently_usable_users_without_mutation(self):
        now = datetime.now(timezone.utc)
        items, users, source_config = _make_items(2, now)
        future = (now + timedelta(days=2)).isoformat()
        blocked_id = "blocked-user"
        expired_id = "expired-user"
        no_outbound_id = "no-outbound-user"
        users["users"][blocked_id] = {"expiresAt": future, "accessEnabled": False}
        users["users"][expired_id] = {
            "expiresAt": (now - timedelta(days=1)).isoformat(), "accessEnabled": True,
        }
        users["users"][no_outbound_id] = {"expiresAt": future, "accessEnabled": True}
        for user_id in (blocked_id, expired_id):
            source_config["outbounds"].append({
                "type": "socks", "tag": wg.manager.USER_OUTBOUND_PREFIX + user_id,
                "server": "192.0.2.20", "server_port": 1080,
                "username": "fixture", "password": "fixture",
            })
        config_before = copy.deepcopy(source_config)
        registry_before = copy.deepcopy(users)

        with patch.object(wg.config.wireguard, "enabled", True), \
                patch.object(wg, "_locked", return_value=nullcontext()), \
                patch.object(wg, "_now", return_value=now), \
                patch.object(wg, "_read_binding_snapshot", return_value=(source_config, users)):
            snapshot = wg.wireguard_access_snapshot()

        self.assertTrue(snapshot[items[0]["nodeUserId"]])
        self.assertTrue(snapshot[items[1]["nodeUserId"]])
        self.assertFalse(snapshot[blocked_id])
        self.assertFalse(snapshot[expired_id])
        self.assertFalse(snapshot[no_outbound_id])
        self.assertEqual(source_config, config_before)
        self.assertEqual(users, registry_before)


if __name__ == "__main__":
    unittest.main()
