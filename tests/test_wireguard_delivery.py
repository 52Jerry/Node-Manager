"""Delivery reads under reconciliation load and concurrent registry changes."""
import copy
import json
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_wireguard_scale import _fixtures
import wireguard as wg


class WireguardDeliveryTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.now, peers, source, users, kernel = _fixtures(4000)
        self.data = {"version": 1, "interface": "wg0", "peers": peers}
        self.peer = peers['peer-0001']
        self.registry = root / 'peers.json'
        self.registry.write_text(json.dumps(self.data))
        for obj, name, value in (
                (wg, 'REGISTRY_PATH', self.registry),
                (wg, '_recovery_error', None),
                (wg.manager, 'CONFIG_PATH', root / 'source.json'),
                (wg.manager, 'REGISTRY_PATH', root / 'users.json'),
                (wg.config.wireguard, 'enabled', True),
                (wg.config.wireguard, 'interface', 'wg0')):
            self.enterContext(patch.object(obj, name, value))
        wg.manager.CONFIG_PATH.write_text(json.dumps(source))
        wg.manager.REGISTRY_PATH.write_text(json.dumps(users))
        self.source, self.users = source, users
        self.snapshot = self.enterContext(patch.object(wg, '_read_binding_snapshot',
                                            side_effect=lambda: (self.source, self.users)))
        self.kernel = self.enterContext(patch.object(wg, '_kernel', return_value=kernel))
        self.enterContext(patch.object(wg, '_invoke', return_value=self.peer['publicKey']))
        self.ready = self.enterContext(patch.object(wg, '_runtime_ready', return_value=True))
        self.enterContext(patch.object(wg, '_runtime_failure_reason', return_value='RUNTIME_TEST'))
        self.enterContext(patch.object(wg, '_now', return_value=self.now))
        self.write = self.enterContext(patch.object(wg, '_write', side_effect=AssertionError('write')))
        self.sync = self.enterContext(patch.object(wg, '_sync_routes', side_effect=AssertionError('routes')))

    def read(self, runtime=True):
        return wg.peer_delivery_status('peer-0001', 'user-0001', runtime)

    def test_4000_peers_returns_one_without_waiting_for_reconcile_mutex(self):
        # Run a real read thread while a writer owns the exact global mutex.
        result, errors = [], []
        def reader():
            try:
                result.append(self.read())
            except Exception as exc:
                errors.append(exc)
        with wg._mutex:
            thread = threading.Thread(target=reader, daemon=True)
            thread.start()
            thread.join(timeout=3)
            completed_while_locked = not thread.is_alive()
        thread.join(timeout=3)
        self.assertTrue(completed_while_locked)
        self.assertFalse(errors)
        self.assertEqual(len(result[0]['peers']), 1)
        self.assertTrue(result[0]['accessByUser']['user-0001'])
        self.assertTrue(result[0]['peers'][0]['kernelPresent'])
        serialized = json.dumps(result)
        self.assertLess(len(serialized), 1500)
        self.assertNotIn('exitFingerprint', serialized)
        self.assertNotIn('password', serialized)
        self.write.assert_not_called()
        self.sync.assert_not_called()

    def test_relaxed_mode_skips_runtime_without_skipping_kernel_identity(self):
        result = self.read(False)
        self.ready.assert_not_called()
        self.assertFalse(result['runtimeChecked'])
        self.kernel.assert_called_once()
        self.assertTrue(result['peers'][0]['kernelPresent'])

    def test_six_simultaneous_exports_complete_while_sync_holds_mutex(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            with wg._mutex:
                futures = [pool.submit(self.read, False) for _ in range(6)]
                results = [future.result(timeout=8) for future in futures]
        self.assertEqual(len(results), 6)
        self.assertTrue(all(r['accessByUser']['user-0001'] for r in results))
        self.write.assert_not_called()
        self.sync.assert_not_called()

    def test_expiry_revocation_binding_and_access_changes_are_not_cached(self):
        self.assertTrue(self.read()['accessByUser']['user-0001'])
        for failure in ('expired', 'revoked', 'binding', 'disabled'):
            with self.subTest(failure=failure):
                data, source, users = copy.deepcopy((self.data, self.source, self.users))
                if failure == 'expired':
                    data['peers']['peer-0001']['expiresAt'] = self.now.isoformat()
                elif failure == 'revoked':
                    data['peers']['peer-0001']['status'] = 'REVOKED'
                elif failure == 'binding':
                    source['outbounds'][1]['server'] = '192.0.2.99'
                else:
                    users['users']['user-0001']['accessEnabled'] = False
                self.registry.write_text(json.dumps(data))
                with patch.object(wg, '_read_binding_snapshot', return_value=(source, users)):
                    self.assertFalse(self.read()['accessByUser']['user-0001'])
        self.registry.write_text(json.dumps(self.data))
        self.assertTrue(self.read()['accessByUser']['user-0001'])

    def test_missing_peer_or_wrong_user_never_returns_another_identity(self):
        for peer, user in (('missing', 'user-0001'), ('peer-0001', 'user-9999')):
            result = wg.peer_delivery_status(peer, user)
            self.assertEqual(result['peers'], [])
            self.assertEqual(result['accessByUser'], {user: False})

    def test_retries_changed_generation_then_uses_new_revocation(self):
        def snapshot():
            revoked = copy.deepcopy(self.data)
            revoked['peers']['peer-0001']['status'] = 'REVOKED'
            self.registry.write_text(json.dumps(revoked))
            return self.source, self.users
        self.snapshot.side_effect = snapshot
        # Only the first snapshot mutates, so second attempt is a stable generation.
        def once():
            self.snapshot.side_effect = None
            self.snapshot.return_value = (self.source, self.users)
            return snapshot()
        self.snapshot.side_effect = once
        result = self.read()
        self.assertEqual(result['peers'][0]['status'], 'REVOKED')
        self.assertFalse(result['accessByUser']['user-0001'])

    def test_repeated_concurrent_changes_fail_explicitly(self):
        with patch.object(wg, '_delivery_versions', side_effect=range(4)):
            with self.assertRaises(wg.WireguardError) as caught:
                self.read()
        self.assertEqual(caught.exception.code, 'DELIVERY_SNAPSHOT_CHANGED')

    def test_corrupt_or_duplicate_registry_is_not_accepted(self):
        self.data['peers']['peer-0002']['address'] = self.peer['address']
        self.data['peers']['peer-0002']['allowedIps'] = self.peer['allowedIps']
        self.registry.write_text(json.dumps(self.data))
        with self.assertRaises(wg.WireguardError):
            self.read()


if __name__ == '__main__':
    unittest.main()
