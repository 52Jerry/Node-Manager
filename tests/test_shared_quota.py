import copy
import sys
import unittest
import importlib.util
import tempfile
import types
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
from monitor.shared_quota import (apply_observation, clear_for_reset, epoch,
    epoch_token, identity_digest, peer_used_bytes, QuotaEvidenceRejected)


class SharedQuotaTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.row = {"auth": [{"protocol": "vless", "credential": "example-uuid"}],
                    "proxy": {"server": "192.0.2.1", "port": 80, "username": "example", "password": "example"},
                    "trafficLimitBytes": 100}
        self.rows = {"target-1": self.row, "target-2": self.row}
        self.store = {"users": {"target-1": {"upload": 3, "download": 7}},
                      "connections": {"open-1": {"upload": 200, "download": 300}}}

    def update(self, used=100, source_epoch=None, target="target-1", store=None):
        source_epoch = source_epoch or epoch({})
        return {"targetUserId": target,
                "expectedTargetEpochToken": epoch_token(epoch((store or self.store)["users"].get(target, {}))),
                "source": {"userId": "source-1", "identityDigest": identity_digest(self.row),
                           "limitBytes": 100, "nativeTotalBytes": used, "epoch": source_epoch,
                           "epochToken": epoch_token(source_epoch)}}

    def apply(self, updates=None, store=None, observed=None):
        return apply_observation(store or self.store, self.rows, "B", "A",
                                 observed or self.now.isoformat(), updates or [self.update()], self.now)

    def test_remote_exhaustion_blocks_without_changing_native_or_connection_baseline(self):
        staged, desired = self.apply()
        self.assertTrue(desired["target-1"]["trafficBlocked"])
        self.assertEqual(staged["users"]["target-1"]["upload"], 3)
        self.assertEqual(staged["users"]["target-1"]["download"], 7)
        self.assertEqual(staged["connections"], self.store["connections"])
        self.assertEqual(self.store["users"]["target-1"], {"upload": 3, "download": 7})

    def test_native_and_peer_partial_usage_share_one_limit(self):
        staged, desired = self.apply([self.update(91)])
        self.assertTrue(desired["target-1"]["trafficBlocked"])
        self.assertEqual(peer_used_bytes(staged["users"]["target-1"], 100), 91)

    def test_replay_is_idempotent(self):
        first, _ = self.apply()
        second, _ = self.apply(store=first)
        self.assertEqual(first, second)

    def test_stale_source_is_rejected(self):
        with self.assertRaisesRegex(QuotaEvidenceRejected, "STALE_OBSERVATION"):
            self.apply(observed=(self.now - timedelta(seconds=121)).isoformat())

    def test_future_source_is_rejected(self):
        with self.assertRaisesRegex(QuotaEvidenceRejected, "STALE_OBSERVATION"):
            self.apply(observed=(self.now + timedelta(seconds=16)).isoformat())

    def test_wrong_identity_is_rejected(self):
        update = self.update(); update["source"]["identityDigest"] = "0" * 64
        with self.assertRaisesRegex(QuotaEvidenceRejected, "IDENTITY_MISMATCH"):
            self.apply([update])

    def test_proxy_password_is_part_of_identity(self):
        other = copy.deepcopy(self.row); other["proxy"]["password"] = "different"
        self.assertNotEqual(identity_digest(other), identity_digest(self.row))

    def test_limit_mismatch_is_rejected(self):
        update = self.update(); update["source"]["limitBytes"] = 101
        with self.assertRaisesRegex(QuotaEvidenceRejected, "LIMIT_MISMATCH"):
            self.apply([update])

    def test_concurrent_target_reset_is_cas_rejected(self):
        update = self.update(); changed = copy.deepcopy(self.store)
        clear_for_reset(changed["users"]["target-1"])
        with self.assertRaisesRegex(QuotaEvidenceRejected, "TARGET_RESET_CHANGED"):
            self.apply([update], changed)

    def test_local_reset_clears_and_retires_old_source_proof(self):
        staged, _ = self.apply(); user = staged["users"]["target-1"]
        clear_for_reset(user)
        self.assertEqual(peer_used_bytes(user, 100), 0)
        fresh_target_request = self.update(store=staged)
        with self.assertRaisesRegex(QuotaEvidenceRejected, "SOURCE_RESET_REQUIRED"):
            self.apply([fresh_target_request], staged)

    def test_peer_epoch_advance_retires_old_quota_without_native_reset(self):
        staged, _ = self.apply()
        new_epoch = dict(epoch({}), cycleStart=1000, version=1)
        updated, desired = self.apply([self.update(0, new_epoch, store=staged)], staged)
        self.assertFalse(desired["target-1"]["trafficBlocked"])
        self.assertEqual(peer_used_bytes(updated["users"]["target-1"], 100), 0)
        self.assertEqual(updated["users"]["target-1"]["download"], 7)

    def test_old_source_snapshot_cannot_reinstall_after_source_cycle_advance(self):
        staged,_=self.apply()
        new_epoch=dict(epoch({}),cycleStart=1000,version=1)
        advanced,_=self.apply([self.update(0,new_epoch,store=staged)],staged)
        with self.assertRaisesRegex(QuotaEvidenceRejected,'SOURCE_RESET_REQUIRED'):
            self.apply([self.update(100,store=advanced)],advanced)

    def test_counter_rollback_inside_epoch_is_rejected(self):
        staged, _ = self.apply()
        with self.assertRaisesRegex(QuotaEvidenceRejected, "COUNTER_ROLLBACK"):
            self.apply([self.update(99, store=staged)], staged)

    def test_wrong_cycle_without_prior_proof_is_rejected(self):
        with self.assertRaisesRegex(QuotaEvidenceRejected, "CYCLE_MISMATCH"):
            self.apply([self.update(source_epoch=dict(epoch({}), cycleStart=1))])

    def test_batch_is_atomic_if_later_user_is_invalid(self):
        before = copy.deepcopy(self.store)
        with self.assertRaisesRegex(QuotaEvidenceRejected, "USER_NOT_FOUND"):
            self.apply([self.update(), self.update(target="not-found")])
        self.assertEqual(self.store, before)

    def test_duplicate_target_is_rejected(self):
        with self.assertRaisesRegex(QuotaEvidenceRejected, "DUPLICATE_TARGET"):
            self.apply([self.update(), self.update()])

    def test_changed_limit_does_not_keep_old_foreign_block(self):
        staged, _ = self.apply()
        self.assertEqual(peer_used_bytes(staged["users"]["target-1"], 200), 0)

    def test_source_epoch_tampering_is_rejected(self):
        update = self.update(); update["source"]["epoch"]["version"] = 1
        with self.assertRaisesRegex(QuotaEvidenceRejected, "INVALID_SOURCE_EPOCH"):
            self.apply([update])

    def test_no_feedback_from_peer_evidence_into_native_usage(self):
        staged, _ = self.apply()
        native = staged["users"]["target-1"]["upload"] + staged["users"]["target-1"]["download"]
        self.assertEqual(native, 10)

    def test_next_billing_cycle_can_retire_prior_manual_reset_epoch(self):
        old=dict(epoch({}),manualResetAt=1234,version=1)
        source_update=self.update(source_epoch=old)
        local=copy.deepcopy(self.store)
        local['users']['target-1']['lastManualTrafficResetAt']=1234
        local['users']['target-1']['sharedQuotaResetVersion']=1
        source_update['expectedTargetEpochToken']=epoch_token(epoch(local['users']['target-1']))
        staged,_=self.apply([source_update],local)
        new=dict(epoch({}),cycleStart=2000,version=2)
        staged,desired=self.apply([self.update(0,new,store=staged)],staged)
        self.assertFalse(desired['target-1']['trafficBlocked'])


if __name__ == "__main__":
    unittest.main()


class ProductionCollectorOverlayTests(unittest.TestCase):
    """Run the actual minimal production candidate, not a mirrored condition."""
    setUp = SharedQuotaTests.setUp
    update = SharedQuotaTests.update
    apply = SharedQuotaTests.apply
    def collector(self):
        root=Path(__file__).resolve().parents[2]
        source=root/'outputs/ha-consistency-fix-20261025/quota/production-candidate/monitor/traffic.py'
        cfg=types.ModuleType('config')
        cfg.config=types.SimpleNamespace(monitoring=types.SimpleNamespace(
            traffic_sample_interval_seconds=2,device_active_window_seconds=60))
        manager=types.ModuleType('singbox.manager')
        for name in ['get_user_auth_map','get_user_policies','sync_user_enforcements']:
            setattr(manager,name,lambda *args,**kwargs: {})
        manager.USER_OUTBOUND_PREFIX='node-manager-out:'
        manager.singbox_api=types.SimpleNamespace()
        spec=importlib.util.spec_from_file_location('production_quota_candidate',source)
        module=importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules,{'config':cfg,'singbox.manager':manager}):spec.loader.exec_module(module)
        return module

    def test_repeated_production_collector_passes_keep_foreign_exhaustion(self):
        module=self.collector();store,_=self.apply()
        baseline=copy.deepcopy(store)
        for _ in range(3):
            desired,closed=module._enforce_policies(store,{}, {'target-1':{'trafficLimitBytes':100,'maxSourceIps':5}},self.now.timestamp())
            self.assertTrue(desired['target-1']['trafficBlocked'])
        self.assertEqual(store['users']['target-1']['upload'],baseline['users']['target-1']['upload'])
        self.assertEqual(store['users']['target-1']['download'],baseline['users']['target-1']['download'])
        self.assertEqual(store['connections'],baseline['connections'])

    def test_native_reset_keeps_connection_baseline_and_retires_shared_proof(self):
        module=self.collector();store,_=self.apply()
        with tempfile.TemporaryDirectory() as folder:
            module.TRAFFIC_PATH=Path(folder)/'traffic.json'
            module._write_store(store)
            module.reset_user_traffic('target-1')
            result=module._read_store()
        self.assertEqual(result['connections'],store['connections'])
        self.assertEqual(result['users']['target-1']['upload'],0)
        self.assertEqual(peer_used_bytes(result['users']['target-1'],100),0)
        self.assertGreater(result['users']['target-1']['lastManualTrafficResetAt'],0)


class CoordinatorPlanTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[2]
        spec=importlib.util.spec_from_file_location('quota_sync_candidate',root/'outputs/ha-consistency-fix-20261025/quota/shared_quota_sync.py')
        self.sync=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.sync)
        self.source={'userId':'primary-1','identityDigest':'same','limitBytes':100,'nativeTotalBytes':60,
                     'epoch':epoch({}),'epochToken':epoch_token(epoch({})),'peerEvidenceCount':0}
        self.target=dict(self.source,userId='backup-1',nativeTotalBytes=50)
        self.snapshots={6:{'users':[self.source]},8:{'users':[self.target]}}
        self.bindings=[{'nodeId':6,'profileId':1,'userId':'primary-1'},{'nodeId':8,'profileId':1,'userId':'backup-1'}]

    def test_combined_partial_usage_creates_both_observations(self):
        updates,issues,pairs=self.sync.build_updates(self.snapshots,self.bindings)
        self.assertEqual(pairs,1);self.assertEqual(issues,[])
        self.assertEqual(updates[6][0]['source']['nativeTotalBytes'],50)
        self.assertEqual(updates[8][0]['source']['nativeTotalBytes'],60)

    def test_same_exit_different_auth_identity_is_never_linked(self):
        self.target['identityDigest']='different'
        updates,issues,pairs=self.sync.build_updates(self.snapshots,self.bindings)
        self.assertEqual(updates,{6:[],8:[]});self.assertEqual(pairs,0)
        self.assertEqual(issues[0]['code'],'BINDING_IDENTITY_MISMATCH')

    def test_unbound_history_requires_unique_complete_identity(self):
        updates,issues,pairs=self.sync.build_updates(self.snapshots,[])
        self.assertEqual(pairs,1)
        self.snapshots[8]['users'].append(dict(self.target,userId='history-copy'))
        updates,issues,pairs=self.sync.build_updates(self.snapshots,[])
        self.assertEqual(pairs,0)

    def test_below_limit_refreshes_existing_proof_to_retire_after_source_reset(self):
        self.source['nativeTotalBytes']=0;self.target['nativeTotalBytes']=0
        self.target['peerEvidenceCount']=1
        updates,issues,pairs=self.sync.build_updates(self.snapshots,self.bindings)
        self.assertEqual(len(updates[8]),1)
