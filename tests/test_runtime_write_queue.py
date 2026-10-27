"""Queue/WAL/HTTP contract tests, synthetic files and fault-injected core."""
import concurrent.futures
import json
import os
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from fastapi import HTTPException, Response
import test_runtime_publication as fixtures
from test_runtime_publication import manager, main, publication
from test_next_stage import idempotency
import runtime_write_queue as queue
import runtime_task_api


class RuntimeQueueTests(unittest.TestCase):
    setUp = fixtures.RuntimePublicationTests.setUp
    create = fixtures.RuntimePublicationTests.create

    def writer(self, **kwargs):
        writer = queue.RuntimeWriteQueue(self.root / "queue", merge_seconds=.08, **kwargs)
        self.addCleanup(writer.close)
        return writer

    def mutation(self, name):
        return manager.capture_mutation(lambda: self.create(name))

    def test_legacy_mode_advertises_task_route_as_unavailable_without_mutation(self):
        request = runtime_task_api.Submission(commands=[runtime_task_api.Delete(action="delete", userId="u1")])
        with patch("singbox.runtime_client.enabled", return_value=False), \
             patch.object(queue, "start") as writer:
            with self.assertRaises(HTTPException) as raised:
                runtime_task_api.submit(request, Response(), "stable-key")
            self.assertEqual(raised.exception.status_code, 404)
            writer.assert_not_called()

    def test_32_mutations_coalesce_into_one_durable_publication(self):
        writer = self.writer()
        with writer.cv:
            tasks = [writer.submit(self.mutation("u%d" % i), keys={"u%d" % i})[0] for i in range(32)]
        for task in tasks: self.assertTrue(writer.wait(task, 10)["success"])
        self.assertEqual(self.fake.puts, 1)
        self.assertEqual(len(manager.read_registry()["users"]), 32)
        self.assertTrue(all(writer.status(task)["state"] == "SUCCEEDED" for task in tasks))
        self.assertEqual(writer.snapshot()["outstandingOperations"], 0)
        self.assertNotIn(b"fixture-password", (self.root / "queue/tasks.sqlite3-wal").read_bytes())

    def test_delete_recreate_same_user_is_a_publication_barrier(self):
        self.create("same")
        writer = self.writer()
        delete = manager.capture_mutation(lambda: manager.delete_user("same"))
        tasks = [writer.submit(delete, keys={"same"})[0], writer.submit(self.mutation("same"), keys={"same"})[0]]
        for task in tasks: writer.wait(task, 10)
        self.assertEqual(self.fake.puts, 3)
        self.assertIn("same", manager.read_registry()["users"])

    def test_guarded_creates_compare_the_transaction_baseline_and_coalesce(self):
        import provisioning_readiness as readiness
        writer = self.writer()
        listeners = [{'network':'tcp','address':'::','port':port,'pids':{42}} for port in (20168,20169,5001)]
        with patch.object(readiness,'_pid',return_value=42), patch.object(readiness,'_identity',return_value=123), \
                patch.object(readiness,'_listeners',return_value=listeners), \
                patch.dict(os.environ,{'NODE_MANAGER_VLESS_PUBLICATION_SPEC':''}):
            tasks=[]
            with writer.cv:
                for index in range(16):
                    name='guarded-batch-%d'%index
                    callback=manager.capture_mutation(lambda name=name:manager.create_user(name,['socks'],require_readiness=True))
                    tasks.append(writer.submit(callback,keys={name})[0])
            for task in tasks:self.assertTrue(writer.wait(task,15)['success'])
        self.assertEqual(self.fake.puts,1)
        self.assertEqual(len(manager.read_registry()['users']),16)
        self.assertTrue(all(writer.status(task)['state']=='SUCCEEDED' for task in tasks))
        self.assertIsNone(manager._mutation_baseline.get())

    def test_bad_partial_mutation_does_not_leak_or_fail_other_jobs(self):
        writer = self.writer()
        def bad(data, registry):
            registry["users"]["leaked"] = {}
            raise manager.SingboxConfigError("fixture bad input")
        a = writer.submit(self.mutation("before"))[0]
        b = writer.submit(bad)[0]
        c = writer.submit(self.mutation("after"))[0]
        writer.wait(a, 10)
        with self.assertRaises(manager.SingboxConfigError): writer.wait(b, 10)
        writer.wait(c, 10)
        self.assertNotIn("leaked", manager.read_registry()["users"])
        self.assertEqual(set(manager.read_registry()["users"]), {"before", "after"})
        self.assertEqual(writer.status(b)["state"], "FAILED")

    def test_queue_is_bounded_including_running_jobs(self):
        writer = self.writer(capacity=2)
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def blocked(data, registry): entered.set(); release.wait(5); return {"ok": True}
        a = writer.submit(blocked, isolated=True)[0]
        self.assertTrue(entered.wait(2))
        b = writer.submit(self.mutation("later"))[0]
        with self.assertRaises(queue.QueueBusy): writer.submit(self.mutation("overflow"))
        release.set(); writer.wait(a, 10); writer.wait(b, 10)

    def test_timeout_replay_does_not_enqueue_twice(self):
        writer = self.writer()
        task, replayed = writer.submit(self.mutation("only"), key="stable", payload={"user": "only"})
        with self.assertRaises(queue.TaskPending): writer.wait(task, 0)
        again, replayed = writer.submit(self.mutation("must-not-run"), key="stable", payload={"user": "only"})
        self.assertEqual(again, task); self.assertTrue(replayed)
        writer.wait(task, 10)
        with self.assertRaises(idempotency.IdempotencyConflict):
            writer.submit(self.mutation("different"), key="stable", payload={"user": "different"})
        self.assertEqual(set(manager.read_registry()["users"]), {"only"})

    def test_unknown_pauses_writer_then_recovers_same_receipt(self):
        writer = self.writer()
        self.fake.mode = "disconnect_after"
        task = writer.submit(self.mutation("uncertain"))[0]
        with self.assertRaises(publication.RuntimeRecoveryRequired): writer.wait(task, 10)
        self.assertEqual(writer.status(task)["state"], "UNKNOWN")
        with self.assertRaises(queue.QueueBusy): writer.submit(self.mutation("blocked"))
        self.fake.offline = False; self.fake.mode = "normal"
        with manager._config_lock(): publication.initialize_locked()
        writer.recover_receipts()
        self.assertEqual(writer.status(task)["state"], "SUCCEEDED")
        self.assertEqual(writer.wait(task)["userId"], "uncertain")
        self.assertEqual(self.fake.puts, 1)

    def test_second_writer_cannot_own_same_node(self):
        self.writer()
        with self.assertRaises(queue.QueueBusy): queue.RuntimeWriteQueue(self.root / "queue")

    def test_start_rejects_core_without_paired_configuration_endpoint(self):
        from singbox.runtime_client import RuntimeClient, RuntimeRejected
        original = self.fake.request
        def old_core(method, path, body=None):
            if path == "configuration": raise RuntimeRejected(404)
            return original(method, path, body)
        with patch.object(queue, "_instance", None), patch.object(RuntimeClient, "_request", side_effect=old_core):
            with self.assertRaises(RuntimeRejected): queue.start()
            self.assertIsNone(queue.current())

    def test_legacy_keys_can_batch_and_keep_both_receipts(self):
        writer = self.writer()
        barrier = threading.Barrier(2)
        with patch.object(queue, "_instance", writer), patch.object(idempotency, "STORE_PATH", self.root / "idem.json"):
            def call(name):
                def perform(): barrier.wait(3); return self.create(name)
                return idempotency.execute_idempotent(name, "create", {"user": name}, perform)[0]
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                values = list(pool.map(call, ["a", "b"]))
            self.assertEqual({v["userId"] for v in values}, {"a", "b"})
            self.assertEqual(self.fake.puts, 1)
            self.assertEqual(set(idempotency._read_store()["entries"]), {"a", "b"})

    def test_compound_related_files_are_committed_by_isolated_job(self):
        writer = self.writer()
        target = self.root / "associated.json"
        with patch.object(queue, "_instance", writer), publication.related_transaction():
            publication.stage_related(target, {"revision": 1})
            self.create("associated")
        self.assertEqual(json.loads(target.read_text()), {"revision": 1})
        self.assertEqual(self.fake.puts, 1)

    def test_replication_with_traffic_lock_uses_queue_without_deadlock(self):
        from datetime import datetime, timedelta, timezone
        from user_replication import ReplicationRequest, apply_users
        from monitor import traffic
        writer = self.writer()
        now = datetime.now(timezone.utc)
        request = ReplicationRequest.model_validate({"groupKey": "queue-replication", "generation": 1,
            "users": [{"userId": "replica-user", "auth": [{"protocol": "socks", "username": "replica-user", "credential": "fixture"}],
                       "createdAt": now, "expiresAt": now + timedelta(days=30)}]})
        with patch.object(queue, "_instance", writer):
            result = apply_users(request)
        self.assertTrue(result["success"])
        self.assertEqual(manager.read_registry()["users"]["replica-user"]["replicationOwner"], "queue-replication")
        self.assertIn("replica-user", json.loads(traffic.TRAFFIC_PATH.read_text())["users"])
        self.assertFalse(publication.paths()[0].exists())

    def test_multiple_mutations_under_one_legacy_key_have_distinct_receipts(self):
        writer = self.writer()
        with patch.object(queue, "_instance", writer), patch.object(idempotency, "STORE_PATH", self.root / "idem.json"):
            def perform():
                return {"items": [self.create("first"), self.create("second")]}
            result, _ = idempotency.execute_idempotent("two", "create-two", {}, perform)
            self.assertEqual([item["userId"] for item in result["items"]], ["first", "second"])
            self.assertEqual(set(manager.read_registry()["users"]), {"first", "second"})

    def test_completed_runtime_receipt_survives_worker_restart_before_db_ack(self):
        writer = self.writer()
        task = writer.submit(self.mutation("committed"))[0]
        writer.wait(task, 10)
        with writer.cv:
            writer.db.execute("UPDATE tasks SET state='RUNNING',result=NULL WHERE id=?", (task,))
            writer.db.commit()
        writer.close()
        replacement = self.writer()
        self.assertEqual(replacement.status(task)["state"], "SUCCEEDED")
        self.assertEqual(replacement.wait(task)["userId"], "committed")
        self.assertEqual(self.fake.puts, 1)

    def test_queued_tasks_are_cancelled_on_shutdown_not_replayed(self):
        writer = self.writer()
        task = writer.submit(self.mutation("not-started"))[0]
        writer.close()
        replacement = self.writer()
        self.assertEqual(replacement.status(task)["state"], "CANCELLED")
        self.assertNotIn("not-started", manager.read_registry()["users"])

    def test_runtime_mode_change_cannot_fall_back_to_service_reload(self):
        writer = self.writer()
        task = writer.submit(self.mutation("mode-change"))[0]
        with patch.dict(os.environ, {"NODE_MANAGER_SINGBOX_RUNTIME_SOCKET": ""}):
            with self.assertRaises(publication.RuntimeRecoveryRequired): writer.wait(task, 10)
        self.assertEqual(writer.status(task)["state"], "UNKNOWN")
        self.assertNotIn("mode-change", manager.read_registry()["users"])

    def test_http_credentials_direct_and_access_use_same_task_transaction(self):
        import uuid
        writer = self.writer()
        client = TestClient(main.app)
        auth = {"Authorization": "Bearer test-token"}
        commands = [
            {"action": "create", "user": {"userId": "all-actions", "protocols": ["socks", "vmess"], "socksUsername": "all-actions", "socksPassword": "initial"}},
            {"action": "credentials", "userId": "all-actions", "uuid": str(uuid.uuid4()), "socksUsername": "rotated-name", "socksPassword": "rotated-password"},
            {"action": "direct", "userId": "all-actions"},
            {"action": "access", "userId": "all-actions", "enabled": False},
            {"action": "access", "userId": "all-actions", "enabled": True},
        ]
        with patch.object(queue, "start", return_value=writer):
            for index, command in enumerate(commands):
                response = client.post("/api/singbox/tasks", json={"commands": [command]}, headers={**auth, "Idempotency-Key": "action-" + str(index)})
                self.assertEqual(response.status_code, 202, response.text)
                writer.wait(response.json()["taskId"], 10)
        self.assertEqual(manager.read_registry()["users"]["all-actions"]["socksUsername"], "rotated-name")
        self.assertIs(manager.read_registry()["users"]["all-actions"]["accessEnabled"], True)
        socks = manager.read_config()["inbounds"][2]["users"]
        self.assertEqual(socks, [{"username": "rotated-name", "password": "rotated-password"}])

    def test_http_async_create_route_delete_and_version_tombstone(self):
        writer = self.writer()
        client = TestClient(main.app)
        headers = {"Authorization": "Bearer test-token", "Idempotency-Key": "create"}
        with patch.object(queue, "start", return_value=writer):
            body = {"commands": [{"action": "create", "expectedUserVersion": 0,
                     "user": {"userId": "http-user", "protocols": ["socks"], "socksUsername": "http-user", "socksPassword": "fixture"}}]}
            response = client.post("/api/singbox/tasks", json=body, headers=headers)
            self.assertEqual(response.status_code, 202, response.text)
            task = response.json()["taskId"]
            writer.wait(task, 10)
            status = client.get("/api/singbox/tasks/" + task, headers=headers)
            self.assertNotIn("fixture", status.text)
            self.assertEqual(status.json()["state"], "SUCCEEDED")
            for index, command in enumerate([
                {"action": "route", "expectedUserVersion": 1, "binding": {"userId": "http-user", "proxy": {"server": "198.51.100.1", "port": 1080, "username": "upstream", "password": "fixture"}}},
                {"action": "delete", "userId": "http-user", "expectedUserVersion": 2},
            ]):
                response = client.post("/api/singbox/tasks", json={"commands": [command]}, headers={**headers, "Idempotency-Key": str(index)})
                self.assertEqual(response.status_code, 202, response.text)
                writer.wait(response.json()["taskId"], 10)
            response = client.post("/api/singbox/tasks", json=body, headers={**headers, "Idempotency-Key": "stale-create"})
            task = response.json()["taskId"]
            with self.assertRaises(manager.SingboxConfigError): writer.wait(task, 10)
            self.assertNotIn("http-user", manager.read_registry()["users"])
        import runtime_history
        self.assertNotIn("http-user", manager.read_registry()["runtimeUserVersions"])
        self.assertEqual(runtime_history.user_version("http-user", manager.read_registry()), 3)

    def test_http_body_limit_rejects_before_decoding(self):
        response = TestClient(main.app).post("/api/singbox/tasks", content=b" " * ((1 << 20) + 1))
        self.assertEqual(response.status_code, 413)
