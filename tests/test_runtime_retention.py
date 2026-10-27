"""Bounded hot state must not discard accounting or replay/ownership evidence."""
import copy
import json
import unittest
from unittest.mock import patch

import test_runtime_publication as fixtures
import test_runtime_write_queue as queue_fixtures
from test_runtime_publication import manager, traffic
from singbox.runtime_client import RuntimeClient, RuntimeUnavailable
from monitor.runtime_counters import apply_counters, finalize_retirements
import runtime_history as history
import runtime_publication as publication
import runtime_write_queue as queue


def snapshot(counter_id="1", upload=13, retirable=True, instance="epoch"):
    return {"instanceId": instance, "counterVersion": 2, "users": [{
        "inbound": "socks", "user": "alias", "id": counter_id,
        "upload": upload, "download": 17, "retirable": retirable}]}


class CounterRetirementTests(unittest.TestCase):
    setUp = fixtures.RuntimePublicationTests.setUp

    def test_lost_ack_reply_retries_without_lost_or_duplicate_usage(self):
        store = {"users": {}}
        sample = snapshot()
        apply_counters(store, sample, {"alias": "uid"}, {})
        disk = copy.deepcopy(store)
        class Client:
            calls = 0
            def acknowledge_counters(self, instance, rows):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeUnavailable("reply lost after core deleted the ID")
                return rows
            def counters(self):
                return {**sample, "users": []}
        client = Client()
        with self.assertRaises(RuntimeUnavailable):
            finalize_retirements(store, sample, client, lambda value: None)
        restarted = copy.deepcopy(disk)
        saved = []
        fresh = finalize_retirements(restarted, {**sample, "users": []}, client,
                                     lambda value: saved.append(copy.deepcopy(value)))
        apply_counters(restarted, fresh, {}, {})
        self.assertEqual(restarted["users"]["uid"]["upload"], 13)
        self.assertEqual(restarted["runtimeCounters"]["rows"], {})
        self.assertEqual(len(saved), 1)
        # A recreated identical name belongs to a new cumulative-counter ID.
        apply_counters(restarted, snapshot("2", 5), {"alias": "uid"}, {})
        self.assertEqual(restarted["users"]["uid"]["upload"], 18)

    def test_ack_persistence_failure_recovers_from_original_intent(self):
        store = {"users": {}}
        apply_counters(store, snapshot(), {"alias": "uid"}, {})
        disk = copy.deepcopy(store)
        client = unittest.mock.Mock()
        client.acknowledge_counters.side_effect = lambda instance, rows: rows
        client.counters.return_value = {**snapshot(), "users": []}
        with self.assertRaises(OSError):
            finalize_retirements(store, snapshot(), client, unittest.mock.Mock(side_effect=OSError("fsync")))
        fresh = finalize_retirements(disk, client.counters(), client, lambda value: None)
        apply_counters(disk, fresh, {}, {})
        self.assertEqual(disk["users"]["uid"]["upload"], 13)

    def test_epoch_history_is_cold_and_old_epoch_is_rejected(self):
        store = {"users": {}}
        for index in range(100):
            apply_counters(store, snapshot(instance="epoch-%d" % index), {"alias": "uid"}, {})
            self.assertEqual(store["runtimeCounters"]["retiredInstances"], [])
        with self.assertRaisesRegex(ValueError, "retired"):
            apply_counters(store, snapshot(instance="epoch-0"), {"alias": "uid"}, {})

    def test_v1_baseline_migrates_once_and_ack_validates_exact_response(self):
        store = {"users": {}}
        old = snapshot(); old.pop("counterVersion"); old["users"][0].pop("id")
        apply_counters(store, old, {"alias": "uid"}, {})
        apply_counters(store, snapshot(upload=20), {"alias": "uid"}, {})
        self.assertEqual(store["users"]["uid"]["upload"], 20)
        self.assertEqual(len(store["runtimeCounters"]["rows"]), 1)
        wrong = copy.deepcopy(snapshot()["users"]); wrong[0]["upload"] += 1
        with patch.object(RuntimeClient, "_request", return_value={"instanceId": "epoch", "retired": wrong}):
            with self.assertRaises(RuntimeUnavailable):
                RuntimeClient().acknowledge_counters("epoch", snapshot()["users"])

    def test_cold_usage_survives_delete_restore_and_reset_without_double_count(self):
        history.archive_usage({"old": {"upload": 100, "download": 200}})
        store = {"users": {}, "runtimeCounters": {"rows": {}}}
        traffic._archive_inactive_usage(store, set())
        self.assertEqual(history.archived_totals([]), [100, 200])
        store["users"].update(history.usage(["old"]))
        self.assertEqual(history.archived_totals(store["users"]), [0, 0])
        store["users"]["old"].update(upload=0, download=0)
        traffic._write_store(store)
        traffic._archive_inactive_usage(store, set())
        self.assertEqual(history.archived_totals([]), [0, 0])
        self.assertEqual(store["users"], {})


class HistoryRetentionTests(unittest.TestCase):
    setUp = fixtures.RuntimePublicationTests.setUp
    create = fixtures.RuntimePublicationTests.create
    writer = queue_fixtures.RuntimeQueueTests.writer
    mutation = queue_fixtures.RuntimeQueueTests.mutation

    def test_hot_tasks_bounded_and_archived_key_and_result_survive_restart(self):
        writer = self.writer(hot_history=4)
        first = None
        for index in range(18):
            task, _ = writer.submit(lambda data, registry, i=index: {"value": i},
                                    key="key-%d" % index, payload=index)
            if first is None: first = task
            self.assertEqual(writer.wait(task, 5), {"value": index})
        writer.archive_history()
        self.assertEqual(writer.snapshot()["hotTasks"], 4)
        self.assertEqual(self.fake.puts, 0, "no-op maintenance published full config")
        self.assertEqual(writer.db.execute("SELECT COUNT(*) FROM task_archive").fetchone()[0], 14)
        self.assertEqual(writer.wait(first), {"value": 0})
        writer.close()
        replacement = queue.RuntimeWriteQueue(self.root / "queue", hot_history=4)
        self.addCleanup(replacement.close)
        task, replayed = replacement.submit(lambda *_: self.fail("archived key replayed"), key="key-0", payload=0)
        self.assertTrue(replayed); self.assertEqual(task, first)
        self.assertEqual(replacement.wait(first), {"value": 0})
        from idempotency import IdempotencyConflict
        with self.assertRaises(IdempotencyConflict):
            replacement.submit(lambda *_: {}, key="key-0", payload="different")

    def test_alias_and_versions_archive_preserves_collision_and_stale_write_guards(self):
        self.create("old")
        aliases = publication.read_aliases()
        old_name = next(iter(aliases))
        manager.mutate_config(lambda data, registry: registry.setdefault("runtimeUserVersions", {}).update(old=7))
        manager.delete_user("old")
        self.assertNotIn(old_name, publication.read_aliases())
        self.assertEqual(history.owners([old_name]), {old_name: "old"})
        self.assertEqual(history.user_version("old", manager.read_registry()), 7)
        with self.assertRaises(manager.SingboxConfigError):
            history.bind_owners({old_name: "different"})
        self.assertEqual(history.owners([old_name]), {old_name: "old"})

    def test_terminal_receipt_removed_after_sqlite_commits(self):
        writer = self.writer(hot_history=1)
        task, _ = writer.submit(self.mutation("actual-change"), key="actual", payload=1)
        writer.wait(task, 5)
        # Wait for worker cleanup by taking the queue lock after archive sweep.
        writer.archive_history(); writer.cleanup_completed_receipts()
        self.assertEqual(list((writer.root / "receipts").glob("*.json")), [])
        self.assertEqual(writer.wait(task)["userId"], "actual-change")

    def test_more_than_50000_historical_keys_do_not_block_new_work(self):
        writer = self.writer(hot_history=4)
        first, _ = writer.submit(lambda *_: {"ok": True}, key="old", payload=0)
        writer.wait(first, 5)
        with writer.cv:
            row = tuple(writer.db.execute("SELECT * FROM tasks WHERE id=?", (first,)).fetchone())
            writer.db.executemany("INSERT INTO task_archive VALUES(?,?,?,?,?,?,?,?,?,?)", [
                ("old-%d" % i, "archive-%d" % i, *row[2:]) for i in range(50001)])
            writer.db.commit()
        task, replayed = writer.submit(lambda *_: {"ok": "new"}, key="new", payload=1)
        self.assertFalse(replayed)
        self.assertEqual(writer.wait(task, 5), {"ok": "new"})
        self.assertLessEqual(writer.snapshot()["hotTasks"], 4)
