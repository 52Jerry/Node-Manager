"""Scheduling, durable access-intent dedup, and loss/rollback safety."""
from collections import deque
from types import SimpleNamespace
import concurrent.futures
import json
import sqlite3
import unittest
from unittest.mock import patch

import test_runtime_publication as fixtures
from test_runtime_publication import manager
import runtime_write_queue as queue
from runtime_queue_policy import select_batch, error_category
from test_next_stage import idempotency


def item(name, priority, keys, isolated=False):
    return SimpleNamespace(task_id=name, priority=priority, keys=frozenset(keys),
                           isolated=isolated, units=1, size=100)


class SelectionTests(unittest.TestCase):
    def test_security_then_purchase_then_maintenance(self):
        pending=deque([item('scan',2,{'a'}),item('buy',1,{'b'}),item('close',0,{'c'})])
        self.assertEqual([i.task_id for i in select_batch(pending,128,10)],['close'])
        pending.pop()
        self.assertEqual([i.task_id for i in select_batch(pending,128,10)],['buy'])

    def test_same_user_order_cannot_be_reversed_by_priority(self):
        pending=deque([item('enable',2,{'a'}),item('disable',0,{'a'}),item('buy',1,{'b'})])
        self.assertEqual([i.task_id for i in select_batch(pending,128,10)],['enable'])
        pending.pop()
        self.assertEqual([i.task_id for i in select_batch(pending,128,10)],['enable'])

    def test_unknown_scope_is_a_global_barrier(self):
        pending=deque([item('a',2,{'a'}),item('global',1,set()),item('later',0,{'b'})])
        self.assertEqual([i.task_id for i in select_batch(pending,128,10)],['a'])
        pending.popleft()
        self.assertEqual([i.task_id for i in select_batch(pending,128,10)],['global'])

    def test_bounded_maintenance_fairness_does_not_delay_security(self):
        pending=deque([item('scan',2,{'a'}),item('buy',1,{'b'})])
        self.assertEqual([i.task_id for i in select_batch(pending,128,10,True)],['scan'])
        pending.append(item('close',0,{'c'}))
        self.assertEqual([i.task_id for i in select_batch(pending,128,10,True)],['close'])
        self.assertEqual(len(select_batch(deque(item(str(i),2,{str(i)}) for i in range(50)),128,10)),10)

    def test_isolation_and_limits_still_apply(self):
        pending=deque([item('a',1,{'a'},True),item('b',1,{'b'})])
        self.assertEqual(len(select_batch(pending,128,10)),1)
        self.assertEqual(len(select_batch(deque(item(str(i),1,{str(i)}) for i in range(50)),20,10)),20)


class DurableIntentTests(unittest.TestCase):
    setUp=fixtures.RuntimePublicationTests.setUp

    def writer(self, **kwargs):
        w=queue.RuntimeWriteQueue(self.root/'policy-queue',merge_seconds=.05,**kwargs)
        self.addCleanup(w.close)
        return w

    def access(self,w,key,target=True,scope='same',version=None,callback=None):
        command={'action':'access','userId':scope,'enabled':target}
        if version is not None:command['expectedUserVersion']=version
        return w.submit(callback or (lambda d,r:{'success':True}),key=key,
                        payload={'commands':[command]},keys={scope})

    def test_one_thousand_parallel_retries_share_one_pending_task(self):
        w=self.writer()
        # Holding admission lock fences the writer, not the independent callers.
        # Concurrent callers then race while an isolated first job blocks apply.
        import threading
        entered,release=threading.Event(),threading.Event()
        self.addCleanup(release.set)
        blocking=w.submit(lambda d,r:(entered.set(),release.wait(10)),isolated=True)[0]
        self.assertTrue(entered.wait(2))
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            tasks=list(pool.map(lambda i:self.access(w,'task:acceleration-access:7:'+str(i))[0],range(1000)))
        self.assertEqual(len(set(tasks)),1)
        self.assertEqual(len(w.pending),1)
        self.assertEqual(w.db.execute('SELECT COUNT(*) FROM task_request_alias').fetchone()[0],999)
        release.set();w.wait(blocking,15);w.wait(tasks[0],15)
        self.assertEqual(w.snapshot()['outstandingOperations'],0)

    def test_durable_alias_replay_after_archive_and_restart(self):
        w=self.writer(hot_history=1)
        with w.cv:
            task,_=self.access(w,'first')
            alias,replayed=self.access(w,'alias')
            self.assertEqual(alias,task);self.assertTrue(replayed)
        w.wait(task,10)
        tail=w.submit(lambda d,r:{'ok':True},key='tail')[0];w.wait(tail,10)
        w.close()
        again=self.writer(hot_history=1)
        self.assertEqual(self.access(again,'alias')[0],task)
        # A prior reader which does not know the new alias table still finds a
        # verified terminal receipt under this request key after a drained rollback.
        legacy=again.db.execute('SELECT state,fingerprint,result FROM task_archive WHERE request_key=?',('alias',)).fetchone()
        self.assertEqual(legacy[0],'SUCCEEDED')
        self.assertIsNotNone(legacy[2])
        with self.assertRaises(idempotency.IdempotencyConflict):self.access(again,'alias',False)
        self.assertEqual(again.wait(task,0),{'success':True})

    def test_desired_toggle_and_intervening_commands_create_new_generation(self):
        w=self.writer()
        with w.cv:
            a=self.access(w,'a',True)[0];b=self.access(w,'b',False)[0];c=self.access(w,'c',True)[0]
            self.assertEqual(len({a,b,c}),3)
            other=w.submit(lambda d,r:{'ok':True},key='route',payload={'commands':[{'action':'route'}]},keys={'same'})[0]
            d=self.access(w,'d',True)[0]
            self.assertEqual(len({a,b,c,other,d}),5)

    def test_unscoped_or_multi_user_command_prevents_cross_barrier_dedup(self):
        w=self.writer()
        with w.cv:
            first=self.access(w,'first')[0]
            w.submit(lambda d,r:{'ok':True},key='global',keys=set())
            second=self.access(w,'second')[0]
            self.assertNotEqual(first,second)
            w.submit(lambda d,r:{'ok':True},key='multi',keys={'same','another'})
            self.assertNotEqual(second,self.access(w,'third')[0])

    def test_cas_version_is_not_deduplicated_across_different_expected_versions(self):
        w=self.writer()
        with w.cv:
            self.assertNotEqual(self.access(w,'a',version=1)[0],self.access(w,'b',version=2)[0])

    def test_completed_or_failed_task_is_not_reused_for_new_request(self):
        w=self.writer()
        first=self.access(w,'a')[0];w.wait(first,10)
        second=self.access(w,'b')[0];self.assertNotEqual(first,second);w.wait(second,10)
        def bad(d,r):raise manager.SingboxConfigError('synthetic failure password=DO-NOT-STORE')
        failed=self.access(w,'c',callback=bad)[0]
        with self.assertRaises(manager.SingboxConfigError):w.wait(failed,10)
        self.assertEqual(self.access(w,'c')[0],failed)
        self.assertNotEqual(self.access(w,'d')[0],failed)
        self.assertEqual(w.status(failed)['errorCategory'],'MUTATION_REJECTED')
        self.assertNotIn('DO-NOT-STORE',json.dumps(w.status(failed)))

    def test_interactive_request_promotes_equivalent_queued_maintenance(self):
        w=self.writer()
        with w.cv:
            first=self.access(w,'task:acceleration-access:7:a')[0]
            self.assertEqual(w.live[first].priority,2)
            self.assertEqual(self.access(w,'explicit-click')[0],first)
            self.assertEqual(w.live[first].priority,1)

    def test_maintenance_limit_keeps_room_for_create_and_security(self):
        w=self.writer(maintenance_limit=2)
        with w.cv:
            self.access(w,'task:acceleration-access:1:a',scope='a')
            self.access(w,'task:acceleration-access:2:b',scope='b')
            with self.assertRaises(queue.QueueBusy):self.access(w,'task:acceleration-access:3:c',scope='c')
            self.access(w,'create-order',scope='d')
            self.access(w,'close',False,scope='e')
            self.assertEqual(len(w.pending),4)

    def test_alias_transaction_failure_does_not_publish_a_false_replay(self):
        w=self.writer()
        with w.cv:
            first=self.access(w,'first')[0]
            w.db.execute("CREATE TRIGGER reject_alias BEFORE INSERT ON task_request_alias BEGIN SELECT RAISE(ABORT,'storage unavailable'); END")
            w.db.commit()
            with self.assertRaises(sqlite3.IntegrityError):self.access(w,'alias')
            self.assertEqual(len(w.pending),1)
            self.assertIsNone(w.policy.alias('alias'))
            w.db.execute('DROP TRIGGER reject_alias');w.db.commit()
            self.assertEqual(self.access(w,'alias')[0],first)

    def test_actual_execution_order_and_task_timing(self):
        w=self.writer()
        order=[]
        with w.cv:
            low=self.access(w,'task:acceleration-access:1:low',scope='a',callback=lambda d,r:order.append('low'))[0]
            normal=self.access(w,'buy',scope='b',callback=lambda d,r:order.append('buy'))[0]
            close=self.access(w,'close',False,scope='c',callback=lambda d,r:order.append('close'))[0]
        for task in [low,normal,close]:w.wait(task,10)
        self.assertEqual(order,['close','buy','low'])
        self.assertGreaterEqual(w.status(low)['queueWaitMs'],0)
        self.assertGreaterEqual(w.status(low)['executionMs'],0)
        self.assertEqual(w.status(low)['queuePolicyVersion'],1)
        self.assertEqual(w.snapshot()['queuePolicyVersion'],1)
        self.assertIn('mutation',w.status(low)['phaseTimesMs'])

    def test_publication_failure_keeps_phase_and_safe_category(self):
        w=self.writer()
        self.fake.mode='reject'
        def changed(data,registry):
            data['inbounds'][2].setdefault('users',[]).append({'username':'not-applied','password':'NEVER-PERSIST-ERROR'})
            registry['users']['not-applied']={'password':'NEVER-PERSIST-ERROR'}
            return {'ok':True}
        task=w.submit(changed,keys={'not-applied'})[0]
        with self.assertRaises(manager.SingboxConfigError):w.wait(task,10)
        result=w.status(task)
        self.assertEqual(result['state'],'FAILED')
        self.assertEqual(result['reason'],'PUBLICATION_FAILED')
        self.assertEqual(result['errorCategory'],'RUNTIME_REJECTED_RESTORED')
        self.assertEqual(result['failedPhase'],'publication')
        self.assertIn('native_apply',result['phaseTimesMs'])
        self.assertNotIn('NEVER-PERSIST-ERROR',json.dumps(result))

    def test_priority_inheritance_follows_multi_user_dependency(self):
        pending=deque([item('early',2,{'a'}),item('join',2,{'a','b'}),
                       item('close',0,{'b'}),item('buy',1,{'c'})])
        self.assertEqual([i.task_id for i in select_batch(pending,128,10)],['early'])

    def test_error_categories_never_include_exception_values(self):
        self.assertEqual(error_category(ValueError('password:super-secret')),'INTERNAL_ERROR')
        from singbox.runtime_client import RuntimeRejected
        self.assertEqual(error_category(RuntimeRejected(409)),'RUNTIME_HTTP_409')
