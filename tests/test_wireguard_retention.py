"""Regression tests for preserving live sessions across refresh/recovery failures."""
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

import test_wireguard_batch as fixtures
import wireguard as wg
import wireguard_routes as routes


class WireguardRetentionTests(unittest.TestCase):
    setUp = fixtures.WireguardBatchApplyTests.setUp
    _command = fixtures.WireguardBatchApplyTests._command

    def seed(self):
        wg.apply_peers(self.items)
        self.commands.clear()
        self.route_sync.reset_mock()
        self.quarantine.reset_mock()
        self.write.reset_mock()

    def assert_no_removal(self):
        self.assertFalse(any(c[0] == "set" and c[4] == "remove" for c in self.commands))

    def test_repeat_batch_never_persists_applying_for_existing_active(self):
        self.seed()
        snapshots = []
        original = self.write._mock_wraps

        def record(data):
            snapshots.append(copy.deepcopy(data))
            return original(data)

        self.write.side_effect = record
        wg.apply_peers(self.items)
        self.assertTrue(snapshots)
        self.assertTrue(all(p['status'] == 'ACTIVE' for s in snapshots for p in s['peers'].values()))
        self.assertFalse(any(c[0] == 'set' for c in self.commands))

    def test_repeat_single_apply_also_keeps_active_during_route_sync(self):
        self.seed()
        states = []
        self.route_sync.side_effect = lambda peers, *args: states.append(copy.deepcopy(peers))
        p = self.items[0]
        wg.apply_peer(p['peerId'], p['publicKey'], p['address'], p['allowedIps'], p['nodeUserId'], p['expiresAt'])
        self.assertEqual(states[0][p['peerId']]['status'], 'ACTIVE')
        self.assert_no_removal()

    def test_failed_refresh_restores_previous_expiry_and_all_kernel_sessions(self):
        self.seed()
        before = wg.REGISTRY_PATH.read_bytes()
        old_kernel = copy.deepcopy(self.kernel)
        items = copy.deepcopy(self.items)
        items[0]['expiresAt'] = (self.now + timedelta(hours=23)).isoformat()
        self.route_sync.side_effect = [wg.WireguardError('simulated timeout'), None]
        with self.assertRaises(wg.WireguardError):
            wg.apply_peers(items)
        self.assertEqual(wg.REGISTRY_PATH.read_bytes(), before)
        self.assertEqual(self.kernel, old_kernel)
        self.assert_no_removal()

    def test_failed_mixed_batch_preserves_existing_active_only_new_intent_failed(self):
        wg.apply_peers(self.items[:1])
        self.commands.clear()
        self.route_sync.side_effect = [wg.WireguardError('simulated timeout'), None]
        with self.assertRaises(wg.WireguardError):
            wg.apply_peers(self.items)
        state = wg._read()['peers']
        self.assertEqual(state[self.items[0]['peerId']]['status'], 'ACTIVE')
        self.assertEqual(state[self.items[1]['peerId']]['status'], 'FAILED')
        self.assertEqual(set(self.kernel), {self.items[0]['publicKey']})
        self.quarantine.assert_called_once()
        self.assert_no_removal()

    def test_runtime_outage_recovers_without_registry_or_kernel_churn(self):
        self.seed()
        before = wg.REGISTRY_PATH.read_bytes()
        self.runtime.return_value = False
        with self.assertRaises(wg.WireguardRecoveryPending):
            wg.reconcile()
        self.assertEqual(wg.REGISTRY_PATH.read_bytes(), before)
        self.assertIsNotNone(wg._recovery_error)
        self.runtime.return_value = True
        wg.reconcile()
        self.assertIsNone(wg._recovery_error)
        self.assertEqual(wg.REGISTRY_PATH.read_bytes(), before)
        self.assert_no_removal()

    def test_binding_snapshot_io_error_preserves_previous_active_until_retry(self):
        self.seed()
        before = wg.REGISTRY_PATH.read_bytes()
        self.read_config.side_effect = OSError('simulated read error')
        with self.assertRaises(wg.WireguardRecoveryPending):
            wg.reconcile()
        self.assertEqual(wg.REGISTRY_PATH.read_bytes(), before)
        self.assertEqual(wg._recovery_error, 'BINDING_SNAPSHOT_UNAVAILABLE')
        self.read_config.side_effect = None
        wg.reconcile()
        self.assertIsNone(wg._recovery_error)
        self.assert_no_removal()

    def test_one_late_binding_change_does_not_block_other_peer(self):
        self.seed()
        changed = copy.deepcopy(self.config_data)
        changed['outbounds'][0]['server'] = '192.0.2.99'
        self.read_config.side_effect = [self.config_data, changed]
        with self.assertRaises(wg.WireguardRecoveryPending):
            wg.reconcile()
        state = wg._read()['peers']
        self.assertEqual(state[self.items[0]['peerId']]['status'], 'BLOCKED')
        self.assertEqual(state[self.items[0]['peerId']]['stateReason'], 'RESIDENTIAL_BINDING_CHANGED')
        self.assertEqual(state[self.items[1]['peerId']]['status'], 'ACTIVE')
        self.assertEqual(len(self.kernel), 2)
        self.assertIsNone(wg._recovery_error)
        self.quarantine.assert_called_once()
        self.assert_no_removal()

    def test_current_binding_used_after_failed_apply_not_stale_preapply_snapshot(self):
        self.seed()
        changed = copy.deepcopy(self.users)
        changed['users'][self.items[0]['nodeUserId']]['accessEnabled'] = False
        self.read_registry.side_effect = [self.users, changed, changed]
        with self.assertRaises(wg.WireguardError):
            wg.apply_peers(self.items)
        state = wg._read()['peers']
        self.assertEqual(state[self.items[0]['peerId']]['stateReason'], 'NODE_USER_ACCESS_DISABLED')
        self.assertEqual(state[self.items[1]['peerId']]['status'], 'ACTIVE')
        self.assertIs(self.route_sync.call_args.args[2], changed)
        self.assert_no_removal()

    def test_blocked_peer_is_retained_but_absent_from_residential_routes(self):
        self.seed()
        self.users['users'].pop(self.items[0]['nodeUserId'])
        wg.reconcile()
        state = wg._read()['peers']
        rendered = routes.build_config(state, self.config_data, self.users)
        allowed = routes._eligible_sources(rendered)
        self.assertNotIn(self.items[0]['address'], allowed)
        self.assertIn(self.items[1]['address'], allowed)
        self.assertEqual(state[self.items[0]['peerId']]['stateReason'], 'NODE_USER_MISSING')
        self.assertEqual(len(self.kernel), 2)
        self.assert_no_removal()

    def test_expiry_is_enforced_even_when_runtime_unavailable(self):
        self.seed()
        self.runtime.return_value = False
        with patch.object(wg, '_now', return_value=self.now + timedelta(days=1, seconds=1)):
            wg.reconcile()
        self.assertFalse(self.kernel)
        self.assertEqual({p['status'] for p in wg._read()['peers'].values()}, {'EXPIRED'})

    def test_kernel_install_failure_is_local_and_retried(self):
        self.seed()
        first = self.items[0]
        self.kernel.pop(first['publicKey'])
        original = self._command

        def failed_install(args):
            if args[0] == 'set' and args[3] == first['publicKey']:
                raise wg.WireguardError('simulated install error')
            return original(args)

        self.invoke.side_effect = failed_install
        with self.assertRaises(wg.WireguardRecoveryPending):
            wg.reconcile()
        state = wg._read()['peers']
        self.assertEqual(state[first['peerId']]['stateReason'], 'KERNEL_INSTALL_FAILED')
        self.assertEqual(state[self.items[1]['peerId']]['status'], 'ACTIVE')
        self.invoke.side_effect = original
        wg.reconcile()
        self.assertEqual(wg._read()['peers'][first['peerId']]['status'], 'ACTIVE')
        self.assertEqual(len(self.kernel), 2)
        self.assert_no_removal()

    def test_status_requires_exact_kernel_address_and_exposes_safe_reason(self):
        self.seed()
        first = self.items[0]
        self.kernel[first['publicKey']] = ['10.0.0.0/8']
        with patch.object(wg, '_interface_addresses', return_value=[]):
            status = wg.status()
        p = next(p for p in status['peers'] if p['peerId'] == first['peerId'])
        self.assertFalse(p['kernelPresent'])
        self.assertNotIn('exitFingerprint', p)

    def test_startup_temporary_failure_still_starts_retry_worker(self):
        with patch.object(wg, '_thread', None), patch.object(wg, 'reconcile', side_effect=wg.WireguardRecoveryPending('test')), \
                patch.object(wg.threading, 'Thread') as thread:
            wg.start_reconciler()
        thread.return_value.start.assert_called_once()


if __name__ == '__main__':
    unittest.main()
