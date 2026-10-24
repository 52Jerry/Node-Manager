import base64
import copy
import sys
import tempfile
import unittest
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'node-manager'))
import wireguard as wg


class WireguardLifecycleTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.now = datetime.now(timezone.utc)
        self.expiry = self.now + timedelta(days=1)
        self.key = base64.b64encode(bytes([1]) * 32).decode()
        self.key2 = base64.b64encode(bytes([2]) * 32).decode()
        self.key3 = base64.b64encode(bytes([3]) * 32).decode()
        self.kernel = {}
        self.commands = []
        self.ignore_sets = False
        self.users = {'users': {u: {'expiresAt': (self.now + timedelta(days=2)).isoformat()} for u in ('user-1', 'user-2')}}
        self.sb = {'outbounds': [{'type': 'socks', 'tag': 'node-manager-out:' + u,
                                 'server': '192.0.2.1', 'server_port': 1080, 'password': 'fixture'} for u in self.users['users']]}
        for target, attr, value in ((wg, 'REGISTRY_PATH', root / 'peers.json'), (wg, 'LOCK_PATH', root / 'peers.lock'),
                                   (wg.config.wireguard, 'enabled', True), (wg.config.wireguard, 'interface', 'wg0')):
            p = patch.object(target, attr, value); p.start(); self.addCleanup(p.stop)
        for target, attr, options in ((wg, '_invoke', {'side_effect': self.command}),
            (wg.manager, '_config_lock', {'side_effect': nullcontext}),
            (wg.manager, 'read_registry', {'side_effect': lambda: copy.deepcopy(self.users)}),
            (wg.manager, 'read_config', {'side_effect': lambda: copy.deepcopy(self.sb)})):
            p = patch.object(target, attr, **options); p.start(); self.addCleanup(p.stop)
        self.enterContext(patch.object(wg, '_recovery_error', None))
        self.quarantine = self.enterContext(patch.object(wg, '_quarantine_inactive'))
        self.routes = self.enterContext(patch.object(wg, '_sync_routes'))
        self.ready = self.enterContext(patch.object(wg, '_runtime_ready', return_value=True))

    def command(self, args):
        self.commands.append(args)
        if args[0] == 'show':
            if args[-1] == 'public-key': return self.key2
            if args[-1] == 'latest-handshakes': return '\n'.join(k + '\t123' for k in self.kernel)
            if args[-1] == 'transfer': return '\n'.join(k + '\t30\t40' for k in self.kernel)
            return '\n'.join(k + '\t' + ','.join(a) for k, a in self.kernel.items())
        if args[0] == 'set' and not self.ignore_sets:
            if args[4] == 'remove': self.kernel.pop(args[3], None)
            else: self.kernel[args[3]] = [args[5]]
        return ''

    def apply(self, peer='peer-1', key=None, address='10.77.0.2/32', user='user-1', expiry=None):
        return wg.apply_peer(peer, key or self.key, address, [address], user, expiry or self.expiry)

    def test_apply_and_restart_restore(self):
        self.assertEqual(self.apply()['status'], 'ACTIVE')
        self.assertNotIn('fixture', wg.REGISTRY_PATH.read_text())
        self.kernel.clear(); wg.reconcile()
        self.assertEqual(self.kernel[self.key], ['10.77.0.2/32'])

    def test_repeat_apply_rechecks_live_kernel(self):
        self.apply(); self.kernel.clear(); self.apply()
        self.assertIn(self.key, self.kernel)

    def test_single_address_only(self):
        for allowed in ([], ['0.0.0.0/0'], ['10.77.0.2/32', '10.77.0.3/32']):
            with self.assertRaises(wg.WireguardError):
                wg.apply_peer('peer-1', self.key, '10.77.0.2/32', allowed, 'user-1', self.expiry)
        self.assertFalse(self.commands)

    def test_duplicate_registry_identity_rejected(self):
        self.apply()
        for values in ((self.key2, '10.77.0.2/32', 'user-2'), (self.key, '10.77.0.3/32', 'user-2'),
                       (self.key2, '10.77.0.3/32', 'user-1')):
            with self.assertRaises(wg.WireguardError): self.apply('peer-2', *values)

    def test_unmanaged_kernel_peer_cannot_be_adopted_stolen_or_revoked(self):
        self.kernel[self.key3] = ['10.77.0.0/24']
        with self.assertRaises(wg.WireguardError): self.apply()
        with self.assertRaises(wg.WireguardError): wg.revoke_peer('unknown', self.key3)
        self.assertEqual(self.kernel[self.key3], ['10.77.0.0/24'])

    def test_exact_legacy_kernel_peer_can_be_adopted_only_when_enabled(self):
        self.kernel[self.key] = ['10.77.0.2/32']
        with patch.object(wg.config.wireguard, 'allow_legacy_peer_adoption', True):
            result = self.apply()

        self.assertEqual(result['status'], 'ACTIVE')
        self.assertEqual(wg._read()['peers']['peer-1']['publicKey'], self.key)
        self.assertEqual(self.kernel[self.key], ['10.77.0.2/32'])

    def test_legacy_adoption_rejects_non_exact_allowed_ips(self):
        self.kernel[self.key] = ['10.77.0.0/24']
        with patch.object(wg.config.wireguard, 'allow_legacy_peer_adoption', True):
            with self.assertRaises(wg.WireguardError):
                self.apply()

        self.assertFalse(wg._read()['peers'])

    def test_expired_peer_removed(self):
        self.apply()
        with patch.object(wg, '_now', return_value=self.expiry + timedelta(seconds=1)): wg.reconcile()
        self.assertNotIn(self.key, self.kernel)
        self.assertEqual(wg._read()['peers']['peer-1']['status'], 'EXPIRED')

    def test_deleted_user_blocked_but_kernel_retained(self):
        self.apply(); self.users['users'].pop('user-1'); wg.reconcile()
        self.assertIn(self.key, self.kernel)
        self.assertEqual(wg._read()['peers']['peer-1']['status'], 'BLOCKED')

    def test_changed_exit_blocked(self):
        self.apply(); self.sb['outbounds'][0]['server'] = '192.0.2.22'
        with self.assertRaises(wg.WireguardError): self.apply()
        wg.reconcile(); self.assertIn(self.key, self.kernel)

    def test_revoke_tombstone_prevents_restart_and_cache_resurrection(self):
        self.apply(); wg.revoke_peer('peer-1', self.key)
        self.kernel[self.key] = ['10.77.0.2/32']
        wg.revoke_peer('peer-1', self.key); wg.reconcile()
        self.assertNotIn(self.key, self.kernel)
        with self.assertRaises(wg.WireguardError): self.apply()

    def test_replacement_peer_allowed_after_revoke_is_verified(self):
        self.apply()
        wg.revoke_peer('peer-1', self.key)

        result = self.apply('peer-2', self.key3, '10.77.0.3/32', 'user-1')

        self.assertEqual(result['status'], 'ACTIVE')
        peers = wg._read()['peers']
        self.assertEqual(peers['peer-1']['status'], 'REVOKED')
        self.assertEqual(peers['peer-2']['status'], 'ACTIVE')
        self.assertNotIn(self.key, self.kernel)
        self.assertEqual(self.kernel[self.key3], ['10.77.0.3/32'])

    def test_replacement_peer_blocked_when_old_peer_removal_was_not_verified(self):
        self.apply()
        self.ignore_sets = True

        with self.assertRaises(wg.WireguardError):
            wg.revoke_peer('peer-1', self.key)
        with self.assertRaises(wg.WireguardError):
            self.apply('peer-2', self.key3, '10.77.0.3/32', 'user-1')

        self.assertIn(self.key, self.kernel)
        self.assertNotIn(self.key3, self.kernel)
        self.assertEqual(wg._read()['peers']['peer-1']['status'], 'REVOKED')

    def test_replacement_peer_stays_uninstalled_when_revoke_route_cleanup_failed(self):
        self.apply()
        self.routes.side_effect = wg.WireguardError('simulated route cleanup failure')

        with self.assertRaises(wg.WireguardError):
            wg.revoke_peer('peer-1', self.key)
        self.assertNotIn(self.key, self.kernel)
        with self.assertRaises(wg.WireguardError):
            self.apply('peer-2', self.key3, '10.77.0.3/32', 'user-1')

        self.assertNotIn(self.key3, self.kernel)
        peers = wg._read()['peers']
        self.assertEqual(peers['peer-1']['status'], 'REVOKED')
        self.assertEqual(peers['peer-2']['status'], 'FAILED')

    def test_retired_peer_key_and_address_are_never_reused(self):
        self.apply()
        wg.revoke_peer('peer-1', self.key)
        with self.assertRaises(wg.WireguardError):
            self.apply('peer-2', self.key, '10.77.0.3/32', 'user-1')
        with self.assertRaises(wg.WireguardError):
            self.apply('peer-3', self.key3, '10.77.0.2/32', 'user-1')

    def test_command_success_without_kernel_change_is_failure(self):
        self.ignore_sets = True
        with self.assertRaises(wg.WireguardError): self.apply()
        self.assertEqual(wg._read()['peers']['peer-1']['status'], 'FAILED')

    def test_disk_failure_does_not_install(self):
        with patch.object(wg, '_write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.apply()
        self.assertFalse(self.kernel)

    def test_crash_pending_apply_quarantined_and_retained(self):
        self.apply(); data = wg._read(); data['peers']['peer-1']['status'] = 'APPLYING'; wg._write(data)
        wg.reconcile(); self.assertIn(self.key, self.kernel)
        self.assertEqual(wg._read()['peers']['peer-1']['status'], 'FAILED')

    def test_disabled_does_not_touch_kernel(self):
        wg.config.wireguard.enabled = False
        with self.assertRaises(wg.WireguardError): self.apply()
        with self.assertRaises(wg.WireguardError): wg.revoke_peer('peer-1', self.key)
        wg.reconcile(); self.assertFalse(self.commands)

    def test_invalid_registry_preserved(self):
        wg.REGISTRY_PATH.write_text('{broken', encoding='utf-8')
        with self.assertRaises(wg.WireguardError): self.apply()
        self.assertEqual(wg.REGISTRY_PATH.read_text(), '{broken')

    def test_direct_outbound_rejected(self):
        self.sb['outbounds'][0]['type'] = 'direct'
        with self.assertRaises(wg.WireguardError): self.apply()
        self.assertFalse(self.kernel)

    def test_routes_must_be_ready(self):
        self.ready.return_value = False
        with self.assertRaises(wg.WireguardError): self.apply()
        self.assertFalse(self.kernel)

    def test_recovery_retains_active_peer_if_runtime_goes_down(self):
        self.apply()
        self.ready.return_value = False
        with self.assertRaises(wg.WireguardError): wg.reconcile()
        self.assertIn(self.key, self.kernel)
        self.assertEqual(wg._read()['peers']['peer-1']['status'], 'ACTIVE')

    def test_route_apply_failure_does_not_install(self):
        self.routes.side_effect = wg.WireguardError('route failed')
        with self.assertRaises(wg.WireguardError): self.apply()
        self.assertFalse(self.kernel)

    def test_status_has_occupied_addresses_and_no_dump_private_keys(self):
        self.apply(); self.kernel[self.key3] = ['10.77.0.9/32']
        with patch.object(wg, '_interface_addresses', return_value=['10.77.0.1/16']):
            result = wg.status()
        self.assertEqual(result['serverPublicKey'], self.key2)
        self.assertEqual(result['interfaceAddresses'], ['10.77.0.1/16'])
        self.assertIn('10.77.0.9/32', result['occupiedAddresses'])
        self.assertEqual(result['peers'][0]['receiveBytes'], 30)
        self.assertFalse(any('dump' in cmd or 'private-key' in cmd for cmd in self.commands))

    def test_interface_address_probe_returns_only_ipv4_cidr_values(self):
        result = type('Result', (), {
            'returncode': 0,
            'stdout': '7: wg0 inet 10.77.0.1/16 scope global wg0\n'
                      '7: wg0 inet6 fd00::1/64 scope global\n'
                      '7: wg0 inet malformed scope global\n'})()
        with patch.object(wg.subprocess, 'run', return_value=result) as run:
            self.assertEqual(wg._interface_addresses(), ['10.77.0.1/16'])
        run.assert_called_once_with(
            ['ip', '-o', '-4', 'addr', 'show', 'dev', 'wg0'],
            capture_output=True, text=True, timeout=15, check=False)


if __name__ == '__main__': unittest.main()
