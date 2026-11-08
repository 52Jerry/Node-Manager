"""Real single-writer tests: safe pending SET reuse and immutable generation barriers."""
import unittest
import concurrent.futures
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
import test_runtime_publication as fixtures
from test_runtime_publication import manager
import runtime_write_queue as queue


class TestPendingMutationIntents(unittest.TestCase):
    setUp = fixtures.RuntimePublicationTests.setUp
    create = fixtures.RuntimePublicationTests.create

    def writer(self, **kwargs):
        writer = queue.RuntimeWriteQueue(self.root/'intent-queue', merge_seconds=.05, **kwargs)
        self.addCleanup(writer.close)
        return writer

    @staticmethod
    def renewal(user='same', expiry='2027-01-01T00:00:00+00:00', limit=100):
        return {'kind':'renewal-state','parameters':{'userIds':[user], 'expiresAt':expiry,
                'trafficLimitBytes':limit,'maxSourceIps':5}}

    def test_thousand_legacy_retries_without_keys_share_one_pending_task(self):
        writer=self.writer()
        with writer.cv:
            first=writer.submit(lambda d,r:{'ok':True},keys={'same'},pending_intent=self.renewal())[0]
            statements=[];writer.db.set_trace_callback(statements.append)
            task_ids=[writer.submit(lambda d,r:{'ok':True},payload={'request':i},keys={'same'},
                                   pending_intent=self.renewal())[0] for i in range(1000)]
            writer.db.set_trace_callback(None)
            self.assertEqual(set(task_ids),{first})
            self.assertEqual(len(writer.pending),1)
            self.assertEqual(writer.snapshot()['pendingIntentCoalesced'],1000)
            self.assertFalse(any(sql.startswith(('INSERT','UPDATE','DELETE','BEGIN','COMMIT')) for sql in statements))
        writer.wait(task_ids[0],10)

    def test_different_desired_values_and_intervening_user_change_are_not_merged(self):
        writer=self.writer()
        with writer.cv:
            a=writer.submit(lambda d,r:1,keys={'same'},pending_intent=self.renewal())[0]
            b=writer.submit(lambda d,r:2,keys={'same'},pending_intent=self.renewal(limit=200))[0]
            c=writer.submit(lambda d,r:3,keys={'same'},pending_intent=self.renewal())[0]
            self.assertEqual(len({a,b,c}),3)
            writer.submit(lambda d,r:4,keys=set())
            self.assertNotEqual(c,writer.submit(lambda d,r:5,keys={'same'},pending_intent=self.renewal())[0])

    def test_completed_result_does_not_suppress_new_generation(self):
        writer=self.writer()
        first=writer.submit(lambda d,r:1,keys={'same'},pending_intent=self.renewal())[0]
        writer.wait(first,10)
        second=writer.submit(lambda d,r:2,keys={'same'},pending_intent=self.renewal())[0]
        self.assertNotEqual(first,second)
        self.assertEqual(writer.wait(second,10),2)

    def test_old_diagnostic_without_intent_hash_is_never_assumed_equivalent(self):
        writer=self.writer()
        with writer.cv:
            first=writer.submit(lambda d,r:1,keys={'same'},pending_intent=self.renewal())[0]
            writer.db.execute('UPDATE task_diagnostic SET intent_hash=NULL WHERE task_id=?',(first,))
            writer.db.commit()
            second=writer.submit(lambda d,r:2,keys={'same'},pending_intent=self.renewal())[0]
            self.assertNotEqual(first,second)

    def test_scope_and_kind_validation_refuse_unsafe_generic_dedup(self):
        writer=self.writer()
        with pytest.raises(ValueError):writer.submit(lambda d,r:1,keys={'different'},pending_intent=self.renewal())
        with pytest.raises(ValueError):writer.submit(lambda d,r:1,keys={'same'},pending_intent={'kind':'delete','parameters':{}})

    def test_related_or_isolated_transactions_never_share_an_intent(self):
        writer=self.writer()
        with writer.cv:
            first=writer.submit(lambda d,r:1,keys={'same'},pending_intent=self.renewal(),isolated=True)[0]
            second=writer.submit(lambda d,r:2,keys={'same'},pending_intent=self.renewal(),isolated=True)[0]
            self.assertNotEqual(first,second)
            third=writer.submit(lambda d,r:3,keys={'same'},pending_intent=self.renewal())[0]
            self.assertNotEqual(second,third)

    def test_same_key_with_changed_declared_intent_is_a_conflict(self):
        from idempotency import IdempotencyConflict
        writer=self.writer()
        with writer.cv:
            writer.submit(lambda d,r:1,key='one-request',payload={},keys={'same'},pending_intent=self.renewal())
            with pytest.raises(IdempotencyConflict):
                writer.submit(lambda d,r:2,key='one-request',payload={},keys={'same'},pending_intent=self.renewal(limit=200))

    def test_parallel_unkeyed_producers_share_one_pending_task(self):
        writer=self.writer();entered=threading.Event();release=threading.Event()
        self.addCleanup(release.set)
        blocking=writer.submit(lambda d,r:(entered.set(),release.wait(10)),isolated=True)[0]
        self.assertTrue(entered.wait(2))
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            ids=list(pool.map(lambda n:writer.submit(lambda d,r:1,keys={'same'},pending_intent=self.renewal())[0],range(1000)))
        self.assertEqual(len(set(ids)),1);self.assertEqual(len(writer.pending),1)
        release.set();writer.wait(blocking,10);writer.wait(ids[0],10)

    def test_different_keys_replay_the_original_fingerprint_after_archive_and_restart(self):
        writer=self.writer(hot_history=1)
        with writer.cv:
            first=writer.submit(lambda d,r:123,key='first',payload={'original':1},keys={'same'},pending_intent=self.renewal())[0]
            alias,replayed=writer.submit(lambda d,r:456,key='alias',payload={'original':2},keys={'same'},pending_intent=self.renewal())
            self.assertEqual(alias,first);self.assertTrue(replayed)
        self.assertEqual(writer.wait(alias,10),123)
        writer.wait(writer.submit(lambda d,r:0,key='tail')[0],10);writer.close()
        again=self.writer(hot_history=1)
        self.assertEqual(again.submit(lambda d,r:999,key='alias',payload={'original':2},keys={'same'},pending_intent=self.renewal())[0],first)
        self.assertEqual(again.wait(first,0),123)

    def test_actual_renew_wrapper_declares_single_user_scope_and_coalesces(self):
        self.create('renewed')
        writer=self.writer();expiry=datetime.now(timezone.utc)+timedelta(days=45)
        ids=[]
        with patch.object(queue,'current',return_value=writer),writer.cv:
            token=queue.wait_timeout.set(0)
            try:
                for _ in range(100):
                    with pytest.raises(queue.TaskPending) as pending:manager.renew_user('renewed',expiry,1000,5)
                    ids.append(pending.value.task_id)
            finally:queue.wait_timeout.reset(token)
            self.assertEqual(len(set(ids)),1)
            self.assertEqual(writer.live[ids[0]].keys,frozenset({'renewed'}))
            self.assertFalse(writer.live[ids[0]].isolated)
        self.assertEqual(writer.wait(ids[0],10)['items'][0]['expiresAt'],manager._iso(expiry))

    def test_actual_proxy_binding_coalesces_but_credential_change_is_a_new_intent(self):
        self.create('bound');writer=self.writer();proxy={'type':'socks5','server':'192.0.2.80','port':1080,'username':'synthetic','password':'never-store-intent-password'}
        ids=[]
        with patch.object(queue,'current',return_value=writer),writer.cv:
            token=queue.wait_timeout.set(0)
            try:
                for _ in range(50):
                    with pytest.raises(queue.TaskPending) as pending:manager.bind_proxy('bound',proxy)
                    ids.append(pending.value.task_id)
                with pytest.raises(queue.TaskPending) as different:manager.bind_proxy('bound',{**proxy,'password':'changed-synthetic'})
            finally:queue.wait_timeout.reset(token)
            self.assertEqual(len(set(ids)),1);self.assertNotEqual(ids[0],different.value.task_id)
            self.assertNotIn('never-store-intent-password','\n'.join(str(row) for row in writer.db.execute('SELECT * FROM task_diagnostic')))
        writer.wait(ids[0],10);writer.wait(different.value.task_id,10)

    def test_renewal_with_related_accounting_files_retains_global_barrier(self):
        import runtime_publication as publication
        self.create('accounting');writer=self.writer();expiry=datetime.now(timezone.utc)+timedelta(days=45)
        with patch.object(queue,'current',return_value=writer),writer.cv,publication.related_transaction():
            token=queue.wait_timeout.set(0)
            try:
                with pytest.raises(queue.TaskPending) as pending:manager.renew_user('accounting',expiry)
            finally:queue.wait_timeout.reset(token)
            item=writer.live[pending.value.task_id]
            self.assertFalse(item.keys);self.assertTrue(item.isolated)
            row=writer.db.execute('SELECT intent_hash FROM task_diagnostic WHERE task_id=?',(item.task_id,)).fetchone()
            self.assertIsNone(row[0])
        writer.wait(pending.value.task_id,10)
