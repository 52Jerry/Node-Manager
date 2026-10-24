"""Offline failure windows for the persistent node operation protocol."""
from __future__ import annotations

from dataclasses import replace
from contextlib import closing
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from operations import Observation, Operation, OperationConflict, OperationStore, OperationStoreError


def command(operation_id="op-1", version=1, generation=1, action="ALLOW", owner="customer:41"):
    return Operation(operation_id, "node:3", "EXTERNAL:3:9007199254740993", owner,
                     action, generation, version)


def proof(operation, payload, status="APPLIED"):
    return Observation(operation.operation_id, operation.request_hash(payload),
                       operation.generation, operation.desired_version, status)


def competing_worker(directory, ready, start, queue):
    store = OperationStore(directory)
    operation = command()
    payload = {"enabled": True}
    counter = Path(directory) / "effects.txt"
    ready.release()
    start.wait(10)

    def apply():
        with counter.open("a", encoding="utf-8") as handle:
            handle.write("applied\n")
            handle.flush()
            os.fsync(handle.fileno())
        time.sleep(0.04)

    receipt = store.execute(operation, payload, apply,
                            lambda: proof(operation, payload,
                                          "APPLIED" if counter.exists() else "NOT_APPLIED"))
    queue.put(receipt.as_dict())


def crash_after_remote_success(directory):
    store = OperationStore(directory)

    def apply():
        path = Path(directory) / "remote-effect.txt"
        with path.open("w", encoding="utf-8") as handle:
            handle.write("remote-applied")
            handle.flush()
            os.fsync(handle.fileno())
        os._exit(0)  # No finally block or local completion receipt.

    operation = command()
    store.execute(operation, {"enabled": True}, apply,
                  lambda: proof(operation, {"enabled": True}))


class OperationFailureWindowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.store = OperationStore(self.directory)
        self.operation = command()
        self.payload = {"enabled": True, "uuid": "sensitive-stable-uuid"}
        self.effects = []

    def tearDown(self):
        self.temporary.cleanup()

    def run_command(self, operation=None, payload=None):
        operation = operation or self.operation
        payload = payload if payload is not None else self.payload
        return self.store.execute(operation, payload,
                                  lambda: self.effects.append(operation.action),
                                  lambda: proof(operation, payload))

    def test_success_is_replayed_without_effect_and_payload_is_not_journaled(self):
        first = self.run_command()
        second = self.run_command()
        self.assertEqual(["ALLOW"], self.effects)
        self.assertEqual("APPLIED", first.status)
        self.assertTrue(second.replayed)
        with closing(sqlite3.connect(self.store.database)) as connection:
            rows = connection.execute("SELECT * FROM node_operation").fetchall()
        self.assertNotIn("sensitive-stable-uuid", json.dumps(rows))
        self.assertNotIn("sensitive-stable-uuid", json.dumps(first.as_dict()))

    def test_same_key_different_content_and_owner_are_rejected_without_effect(self):
        self.run_command()
        for operation, payload in [
            (self.operation, {"enabled": False}),
            (replace(self.operation, owner_ref="customer:42"), self.payload),
            (replace(self.operation, asset_key="EXTERNAL:4:9007199254740993"), self.payload),
        ]:
            with self.assertRaises(OperationConflict):
                self.run_command(operation, payload)
        self.assertEqual(["ALLOW"], self.effects)

    def test_equal_version_different_operation_cannot_reapply(self):
        self.run_command()
        receipt = self.run_command(command("other", action="DENY"))
        self.assertEqual("REJECTED", receipt.status)
        self.assertEqual("VERSION_CONFLICT", receipt.reason)
        self.assertEqual(["ALLOW"], self.effects)

    def test_delayed_enable_cannot_override_newer_revoke_even_after_restart(self):
        revoke = command("revoke-v2", version=2, action="DENY")
        self.run_command(revoke, {"enabled": False})
        self.store = OperationStore(self.directory)
        delayed = self.run_command()
        self.assertEqual("REJECTED", delayed.status)
        self.assertEqual("STALE_VERSION", delayed.reason)
        self.assertFalse(delayed.current)
        self.assertEqual(["DENY"], self.effects)

    def test_new_owner_generation_supersedes_all_old_owner_versions(self):
        old = command("old-v900", version=900)
        new = command("new-generation", generation=2, owner="customer:99")
        self.run_command(old)
        self.run_command(new)
        late = self.run_command(command("old-v901", version=901))
        self.assertEqual("REJECTED", late.status)
        self.assertEqual(["ALLOW", "ALLOW"], self.effects)

    def test_historical_success_keeps_receipt_but_is_no_longer_current(self):
        self.run_command()
        self.run_command(command("revoke", version=2, action="DENY"))
        replay = self.run_command()
        self.assertEqual("APPLIED", replay.status)
        self.assertFalse(replay.current)
        self.assertEqual(2, replay.accepted_version)
        self.assertEqual(["ALLOW", "DENY"], self.effects)

    def test_timeout_after_remote_success_is_unknown_then_readback_finishes_without_retry(self):
        def effect_then_timeout():
            self.effects.append("remote-applied")
            raise TimeoutError("sensitive-password-never-journal")

        result = self.store.execute(self.operation, self.payload, effect_then_timeout,
                                    lambda: self.fail("initial timeout must remain unknown"))
        self.assertEqual("UNKNOWN", result.status)
        self.store = OperationStore(self.directory)
        replay = self.store.execute(self.operation, self.payload,
                                    lambda: self.fail("must not repeat a successful remote effect"),
                                    lambda: proof(self.operation, self.payload))
        self.assertEqual("APPLIED", replay.status)
        self.assertEqual(["remote-applied"], self.effects)
        self.assertNotIn("sensitive-password", json.dumps(replay.as_dict()))

    def test_unknown_readback_never_repeats_an_uncertain_command(self):
        def fail():
            self.effects.append("uncertain")
            raise TimeoutError()

        self.store.execute(self.operation, self.payload, fail, lambda: proof(self.operation, self.payload))
        for _ in range(2):
            result = self.store.execute(self.operation, self.payload,
                                        lambda: self.fail("UNKNOWN is not permission to retry"),
                                        lambda: proof(self.operation, self.payload, "UNKNOWN"))
            self.assertEqual("UNKNOWN", result.status)
        self.assertEqual(["uncertain"], self.effects)

    def test_confirmed_absence_permits_same_exact_operation_retry(self):
        calls = []

        def fail_before_effect():
            raise TimeoutError()

        self.store.execute(self.operation, self.payload, fail_before_effect,
                            lambda: proof(self.operation, self.payload))

        def readback():
            calls.append("readback")
            return proof(self.operation, self.payload, "APPLIED" if self.effects else "NOT_APPLIED")

        def apply():
            calls.append("apply")
            self.effects.append("once")

        result = self.store.execute(self.operation, self.payload, apply, readback)
        self.assertEqual(["readback", "apply", "readback"], calls)
        self.assertEqual("APPLIED", result.status)
        self.assertEqual(["once"], self.effects)

    def test_readback_must_match_exact_operation_hash_and_version(self):
        bad = proof(command("unrelated", version=2), self.payload)
        result = self.store.execute(self.operation, self.payload,
                                    lambda: self.effects.append("once"), lambda: bad)
        self.assertEqual("UNKNOWN", result.status)
        self.assertEqual(["once"], self.effects)

    def test_new_revoke_supersedes_unknown_enable_and_retry_cannot_revive_it(self):
        self.store.execute(self.operation, self.payload,
                            lambda: (_ for _ in ()).throw(TimeoutError()),
                            lambda: proof(self.operation, self.payload))
        self.run_command(command("revoke", version=2, action="DENY"))
        late = self.run_command()
        self.assertEqual("REJECTED", late.status)
        self.assertEqual(["DENY"], self.effects)

    def test_reconcile_can_confirm_success_without_having_any_mutation_callback(self):
        self.store.execute(self.operation, self.payload,
                            lambda: (_ for _ in ()).throw(TimeoutError()),
                            lambda: proof(self.operation, self.payload))
        result = self.store.reconcile(self.operation, self.payload,
                                      lambda: proof(self.operation, self.payload))
        self.assertEqual("APPLIED", result.status)
        self.assertIsNone(self.store.reconcile(command("missing"), {},
                                              lambda: self.fail("missing task has no proof")))
        self.assertEqual([], self.effects)

    def test_explicit_reconcile_refreshes_current_runtime_proof_without_reapplying(self):
        self.run_command()
        result = self.store.reconcile(self.operation, self.payload,
                                      lambda: proof(self.operation, self.payload, "UNKNOWN"))
        self.assertEqual("UNKNOWN", result.status)
        self.assertEqual(["ALLOW"], self.effects)

    def test_callbacks_do_not_hold_a_database_transaction(self):
        other = command("other-asset")
        other = replace(other, asset_key="EXTERNAL:3:another")
        barrier = threading.Barrier(2)
        errors = []

        def worker(operation):
            try:
                self.store.execute(operation, {}, lambda: barrier.wait(3),
                                    lambda: proof(operation, {}))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(operation,))
                   for operation in (self.operation, other)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual("APPLIED", self.store.read(self.operation.operation_id).status)
        self.assertEqual("APPLIED", self.store.read(other.operation_id).status)

    def test_two_processes_execute_one_effect(self):
        context = multiprocessing.get_context("spawn")
        ready, start, queue = context.Semaphore(0), context.Event(), context.Queue()
        processes = [context.Process(target=competing_worker,
                                     args=(str(self.directory), ready, start, queue)) for _ in range(2)]
        try:
            for process in processes:
                process.start()
            for _ in processes:
                self.assertTrue(ready.acquire(timeout=10))
            start.set()
            results = [queue.get(timeout=10) for _ in processes]
            for process in processes:
                process.join(10)
                self.assertEqual(0, process.exitcode)
            self.assertEqual(["APPLIED", "APPLIED"], [result["status"] for result in results])
            self.assertEqual([False, True], sorted(result["replayed"] for result in results))
            self.assertEqual("applied\n", (self.directory / "effects.txt").read_text(encoding="utf-8"))
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                process.join(10)
            queue.close()
            queue.join_thread()

    def test_process_death_after_success_keeps_applying_fence_and_recovers_by_readback(self):
        context = multiprocessing.get_context("spawn")
        process = context.Process(target=crash_after_remote_success, args=(str(self.directory),))
        try:
            process.start()
            process.join(10)
            self.assertEqual(0, process.exitcode)
            store = OperationStore(self.directory)
            self.assertEqual("UNKNOWN", store.read("op-1").status)
            self.assertEqual("remote-applied", (self.directory / "remote-effect.txt").read_text())
            payload = {"enabled": True}
            receipt = store.execute(self.operation, payload,
                                     lambda: self.fail("crash recovery must not repeat effect"),
                                     lambda: proof(self.operation, payload))
            self.assertEqual("APPLIED", receipt.status)
        finally:
            if process.is_alive():
                process.terminate()
            process.join(10)

    def test_corrupt_journal_is_not_reset_to_empty(self):
        corrupt = self.directory / "corrupt"
        corrupt.mkdir()
        (corrupt / "operations.sqlite3").write_bytes(b"not-a-database")
        with self.assertRaises(OperationStoreError):
            OperationStore(corrupt)
        self.assertEqual(b"not-a-database", (corrupt / "operations.sqlite3").read_bytes())

    def test_invalid_versions_and_noncanonical_ids_are_rejected(self):
        for values in [{"generation": 0}, {"desired_version": True},
                       {"desired_version": 2**63}, {"asset_key": " asset"}]:
            with self.assertRaises(ValueError):
                replace(self.operation, **values)


if __name__ == "__main__":
    unittest.main()
