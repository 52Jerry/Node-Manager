"""Rejected commands roll back locally, never force sibling native publishes."""
import json
import unittest
from unittest.mock import patch

import test_runtime_publication as fixtures
from test_runtime_publication import manager, publication
import runtime_write_queue as queue
import runtime_task_api
from fastapi import Response
from runtime_queue_policy import select_batch, error_category
from runtime_metrics import rejection_category
from singbox.runtime_client import RuntimeRejected


class RuntimeBatchIsolationTests(unittest.TestCase):
    setUp = fixtures.RuntimePublicationTests.setUp
    create = fixtures.RuntimePublicationTests.create

    def writer(self):
        writer=queue.RuntimeWriteQueue(self.root/'queue',merge_seconds=.08)
        self.addCleanup(writer.close)
        return writer

    def mutation(self,name):
        return manager.capture_mutation(lambda:self.create(name))

    def paused_batch(self,writer,callbacks):
        with writer.cv:
            ids=[writer.submit(callback,keys={str(index)})[0] for index,callback in enumerate(callbacks)]
            writer.paused=True
            items=[writer.live[task] for task in ids]
            writer.pending.clear()
        return ids,items

    def test_good_bad_good_publish_once_and_do_not_retain_partial_mutation(self):
        writer=self.writer()
        def bad(data,registry):
            data['outbounds'].clear();registry['users']['leaked']={}
            raise manager.SingboxConfigError('user not found: synthetic-private-user')
        ids,items=self.paused_batch(writer,[self.mutation('before'),bad,self.mutation('after')])
        writer._process(items)
        self.assertEqual(self.fake.puts,1)
        self.assertEqual(set(manager.read_registry()['users']),{'before','after'})
        self.assertEqual([writer.status(task)['state'] for task in ids],['SUCCEEDED','FAILED','SUCCEEDED'])
        self.assertEqual(writer.status(ids[1])['errorCategory'],'USER_NOT_FOUND')
        self.assertEqual(writer.status(ids[1])['failedPhase'],'mutation')
        self.assertIsNone(items[1].future.exception().__traceback__)
        raw=(self.root/'queue/tasks.sqlite3').read_bytes()+(self.root/'queue/tasks.sqlite3-wal').read_bytes()
        self.assertNotIn(b'synthetic-private-user',raw)

    def test_rejected_related_files_and_versions_are_not_promoted(self):
        self.create('u')
        writer=self.writer();target=self.root/'extra.json'
        def first(data,registry):
            registry['runtimeUserVersions']={'u':1}
            publication.stage_related(target,{'owner':'accepted'})
            return {'version':1}
        def bad(data,registry):
            registry['runtimeUserVersions']['u']=2
            publication.stage_related(target,{'owner':'rejected'})
            raise manager.SingboxConfigError('user not found')
        def later(data,registry):
            self.assertEqual(registry['runtimeUserVersions']['u'],1)
            self.assertEqual(json.loads(publication.related_targets.get()[target]),{'owner':'accepted'})
            registry['runtimeUserVersions']['u']=2
            return {'version':2}
        ids,items=self.paused_batch(writer,[first,bad,later]);writer._process(items)
        self.assertEqual(json.loads(target.read_text()),{'owner':'accepted'})
        self.assertEqual(manager.read_registry()['runtimeUserVersions']['u'],2)
        self.assertEqual([writer.status(task)['state'] for task in ids],['SUCCEEDED','FAILED','SUCCEEDED'])

    def test_all_rejected_batch_does_not_publish_and_keeps_rejections_on_recovery(self):
        writer=self.writer()
        def bad(data,registry):
            registry['users']['leak']={}
            raise manager.SingboxConfigError('user not found')
        ids,items=self.paused_batch(writer,[bad,bad]);writer._process(items)
        self.assertEqual(self.fake.puts,0)
        self.assertFalse(manager.read_registry()['users'])
        writer.recover_receipts()
        self.assertEqual([writer.status(task)['state'] for task in ids],['FAILED','FAILED'])

    def test_unknown_publication_pauses_only_good_siblings_and_recovers_receipts(self):
        writer=self.writer();self.fake.mode='disconnect_after'
        def bad(data,registry):
            registry['users']['leak']={}
            raise manager.SingboxConfigError('user not found')
        ids,items=self.paused_batch(writer,[self.mutation('before'),bad,self.mutation('after')])
        writer._process(items)
        self.assertEqual([writer.status(task)['state'] for task in ids],['UNKNOWN','FAILED','UNKNOWN'])
        self.assertTrue(writer.paused)
        self.fake.offline=False;self.fake.mode='normal'
        with manager._config_lock():publication.initialize_locked()
        writer.recover_receipts()
        self.assertEqual([writer.status(task)['state'] for task in ids],['SUCCEEDED','FAILED','SUCCEEDED'])
        self.assertEqual(set(manager.read_registry()['users']),{'before','after'})
        self.assertEqual(self.fake.puts,1)

    def test_crash_after_publication_never_gives_bad_item_a_success_receipt(self):
        writer=self.writer()
        def bad(data,registry):raise manager.SingboxConfigError('user not found')
        ids,items=self.paused_batch(writer,[self.mutation('before'),bad,self.mutation('after')])
        with patch.object(writer,'_finish_many',side_effect=SystemExit('fixture lost process')):
            with self.assertRaises(SystemExit):writer._process(items)
        self.assertEqual(writer.status(ids[1])['state'],'FAILED')
        with writer.cv:
            for task in ids:writer.live.pop(task,None)
        writer.recover_receipts()
        self.assertEqual([writer.status(task)['state'] for task in ids],['SUCCEEDED','FAILED','SUCCEEDED'])
        self.assertEqual(self.fake.puts,1)

    def test_failed_multicommand_task_is_atomic_for_following_task(self):
        writer=self.writer()
        create_first=self.mutation('compound-first')
        def compound(data,registry):
            create_first(data,registry)
            raise manager.SingboxConfigError('user not found: compound-second')
        def later(data,registry):
            self.assertNotIn('compound-first',registry['users'])
            return self.mutation('following')(data,registry)
        ids,items=self.paused_batch(writer,[compound,later]);writer._process(items)
        self.assertEqual(set(manager.read_registry()['users']),{'following'})
        self.assertEqual(self.fake.puts,1)
        self.assertEqual([writer.status(task)['state'] for task in ids],['FAILED','SUCCEEDED'])

    def test_real_task_versions_and_same_user_fifo_survive_rejected_sibling(self):
        self.create('versioned')
        writer=self.writer()
        commands=[
            {'action':'create','expectedUserVersion':0,
             'user':{'userId':'before','protocols':['socks'],'socksUsername':'before','socksPassword':'fixture'}},
            {'action':'access','userId':'versioned','enabled':True,'expectedUserVersion':999},
            {'action':'create','expectedUserVersion':0,
             'user':{'userId':'after','protocols':['socks'],'socksUsername':'after','socksPassword':'fixture'}},
            {'action':'access','userId':'versioned','enabled':True,'expectedUserVersion':0},
        ]
        with writer.cv, patch.object(queue,'start',return_value=writer):
            ids=[runtime_task_api.submit(runtime_task_api.Submission(commands=[command]),Response(),str(index))['taskId']
                 for index,command in enumerate(commands)]
            writer.paused=True
            first=select_batch(writer.pending,128,32)
            self.assertEqual([item.task_id for item in first],ids[:3])
            writer.pending=queue.deque(item for item in writer.pending if item not in first)
        puts=self.fake.puts
        writer._process(first)
        self.assertEqual(self.fake.puts,puts+1)
        self.assertEqual(writer.status(ids[1])['errorCategory'],'USER_VERSION_CONFLICT')
        self.assertEqual(writer.status(ids[3])['state'],'QUEUED')
        with writer.cv:
            second=select_batch(writer.pending,128,32);writer.pending.clear()
        writer._process(second)
        self.assertEqual([writer.status(task)['state'] for task in ids],['SUCCEEDED','FAILED','SUCCEEDED','SUCCEEDED'])
        self.assertEqual(manager.read_registry()['runtimeUserVersions']['versioned'],1)

    def test_timeout_before_native_apply_keeps_rejection_and_fences_delayed_good_request(self):
        writer=self.writer();self.fake.mode='timeout_before'
        def bad(data,registry):raise manager.SingboxConfigError('user not found')
        ids,items=self.paused_batch(writer,[self.mutation('before'),bad,self.mutation('after')])
        writer._process(items)
        self.assertEqual([writer.status(task)['state'] for task in ids],['FAILED','FAILED','FAILED'])
        self.assertEqual(writer.status(ids[1])['errorCategory'],'USER_NOT_FOUND')
        self.assertFalse(manager.read_registry()['users'])
        with self.assertRaises(RuntimeRejected):self.fake.apply(self.fake.pending)
        writer.recover_receipts()
        self.assertEqual(writer.status(ids[1])['state'],'FAILED')

    def test_native_cas_conflict_preserves_bad_request_category_and_rolls_back_good_siblings(self):
        writer=self.writer()
        def bad(data,registry):raise manager.SingboxConfigError('user not found')
        ids,items=self.paused_batch(writer,[self.mutation('before'),bad,self.mutation('after')])
        with patch.object(self.fake,'apply',side_effect=RuntimeRejected(409)):
            writer._process(items)
        self.assertEqual([writer.status(task)['state'] for task in ids],['FAILED','FAILED','FAILED'])
        self.assertEqual(writer.status(ids[1])['errorCategory'],'USER_NOT_FOUND')
        self.assertFalse(manager.read_registry()['users'])
        self.assertEqual(self.fake.puts,1)

    def test_persisted_mutation_categories_share_safe_fixed_mapping(self):
        for message in ['user not found: private','user already exists: private',
                        'SOCKS username already exists','user version changed; private',
                        'queued user expiration private',
                        'EXPIRED_USER_REQUIRES_private','runtime authentication name belongs to private',
                        'proxy loop: private','当前已有这条住宅IP的连接了 private']:
            with self.subTest(message=message):
                error=manager.SingboxConfigError(message)
                self.assertEqual(error_category(error),rejection_category(error))
                self.assertNotIn('private',error_category(error))
        self.assertEqual(error_category(manager.SingboxConfigError('PROVISIONING_private')),'LISTENER_NOT_READY')
        self.assertEqual(error_category(manager.SingboxConfigError('unrecognized private')),'MUTATION_REJECTED')
