"""One bounded runtime writer; FIFO coalescing, durable receipts, no blind replay.

Only mutation closures run on the worker. Their callers keep post-commit work
(connection readback, traffic cleanup, HTTP response generation) on their thread.
Unknown publications pause admission until explicit runtime reconciliation.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from collections import deque
from concurrent.futures import Future, TimeoutError as FutureTimeout
from dataclasses import dataclass
from pathlib import Path

from idempotency import _encrypt_response, _decrypt_response, IdempotencyConflict
from singbox.errors import SingboxConfigError

submission_size = contextvars.ContextVar("runtime_submission_bytes", default=2048)

class QueueBusy(SingboxConfigError):
    pass


class TaskPending(SingboxConfigError):
    def __init__(self, task_id):
        self.task_id = task_id
        super().__init__("runtime task is still pending; query its status, do not resubmit")


class BatchRejected(Exception):
    def __init__(self, index, error):
        self.index, self.error = index, error


@dataclass
class Item:
    task_id: str
    callback: object
    context: contextvars.Context
    future: Future
    size: int
    units: int
    isolated: bool
    fingerprint: str
    keys: frozenset


class RuntimeWriteQueue:
    def __init__(self, root, *, capacity=4096, byte_capacity=16 << 20,
                 batch_size=128, merge_seconds=.025, hot_history=4096):
        from singbox.runtime_client import check_mode
        self.socket = check_mode()
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Fail closed on a second API worker. The kernel lease outlives requests.
        self.lease = (self.root / "writer.lock").open("a+b")
        self.lease.write(b"0"); self.lease.flush(); self.lease.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.lease.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lease.close()
            raise QueueBusy("another runtime writer owns this node; use one API worker") from None
        self.capacity, self.byte_capacity = capacity, byte_capacity
        self.hot_history=max(1,int(hot_history))
        self.batch_size, self.merge_seconds = batch_size, merge_seconds
        self.cv = threading.Condition(threading.RLock())
        self.pending, self.live = deque(), {}
        self.units = self.bytes = 0
        self.closed = self.paused = False
        self.db = sqlite3.connect(self.root / "tasks.sqlite3", check_same_thread=False)
        if os.name != "nt":
            os.chmod(self.root / "tasks.sqlite3", 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY, request_key TEXT UNIQUE, fingerprint TEXT NOT NULL,
            state TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
            batch TEXT, result TEXT, reason TEXT, units INTEGER NOT NULL)""")
        self.db.execute("CREATE TABLE IF NOT EXISTS task_archive AS SELECT * FROM tasks WHERE 0")
        self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS archived_task_id ON task_archive(id)")
        self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS archived_request_key ON task_archive(request_key)")
        self.db.execute("CREATE INDEX IF NOT EXISTS tasks_batch ON tasks(batch)")
        self.db.execute("PRAGMA journal_size_limit=8388608")
        self.db.commit()
        self.recover_receipts()
        self.thread = threading.Thread(target=self._run, name="singbox-runtime-writer", daemon=True)
        self.thread.start()

    def _row(self, task_id):
        self.db.row_factory = sqlite3.Row
        return (self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
                or self.db.execute("SELECT * FROM task_archive WHERE id=?",(task_id,)).fetchone())

    def archive_history(self):
        """Move terminal results, keys and fingerprints together; never forget a key."""
        with self.cv:
            count=self.db.execute("SELECT COUNT(*) FROM tasks WHERE state IN ('SUCCEEDED','FAILED','CANCELLED','NOT_APPLIED')").fetchone()[0]
            if count<=self.hot_history:return
            with self.db:
                self.db.execute("CREATE TEMP TABLE IF NOT EXISTS archive_ids(id TEXT PRIMARY KEY)")
                self.db.execute("DELETE FROM archive_ids")
                self.db.execute("INSERT INTO archive_ids SELECT id FROM tasks WHERE state IN ('SUCCEEDED','FAILED','CANCELLED','NOT_APPLIED') ORDER BY updated,id LIMIT ?",(count-self.hot_history,))
                self.db.execute("INSERT INTO task_archive SELECT * FROM tasks WHERE id IN (SELECT id FROM archive_ids)")
                self.db.execute("DELETE FROM tasks WHERE id IN (SELECT id FROM archive_ids)")

    def cleanup_receipt(self,batch):
        import runtime_publication as publication
        if not batch or publication.paths()[0].exists():return
        with self.cv:
            pending=self.db.execute("SELECT 1 FROM tasks WHERE batch=? AND state IN ('QUEUED','RUNNING','UNKNOWN') LIMIT 1",(batch,)).fetchone()
            if pending:return
            (self.root/'receipts'/(batch+'.json')).unlink(missing_ok=True)

    def cleanup_completed_receipts(self):
        directory=self.root/'receipts'
        if not directory.exists():return
        import itertools,re
        with os.scandir(directory) as entries:
            for entry in itertools.islice(entries,256):
                if entry.is_file(follow_symlinks=False) and re.fullmatch('[0-9a-f]{32}\\.json',entry.name):self.cleanup_receipt(entry.name[:-5])

    def _finish(self, item, state, *, result=None, error=None, reason=None):
        encrypted = _encrypt_response({"value": result}) if state == "SUCCEEDED" else None
        with self.cv:
            self.db.execute("UPDATE tasks SET state=?,updated=?,result=?,reason=? WHERE id=?",
                            (state, time.time(), encrypted, reason, item.task_id))
            self.db.commit()
            self.live.pop(item.task_id, None)
            self.units -= item.units; self.bytes -= item.size
            if not item.future.done():
                if state == "SUCCEEDED": item.future.set_result(result)
                else: item.future.set_exception(error or QueueBusy(reason or state))
            self.cv.notify_all()

    def recover_receipts(self):
        """Called only after the runtime WAL has been reconciled, or fail closed."""
        import runtime_publication as publication
        with self.cv:
            if publication.paths()[0].exists():
                self.paused = True
                return
            rows = self.db.execute("SELECT id,fingerprint,batch,state FROM tasks WHERE state IN ('QUEUED','RUNNING','UNKNOWN')").fetchall()
            receipts = {}
            for task_id, fingerprint, batch, state in rows:
                if task_id in self.live:
                    continue
                receipt = None
                if batch:
                    if batch not in receipts:
                        path = self.root / "receipts" / (batch + ".json")
                        receipts[batch] = json.loads(path.read_text()) if path.exists() else {}
                    receipt = receipts[batch].get(task_id)
                if receipt and receipt["fingerprint"] == fingerprint:
                    new_state, value, reason = "SUCCEEDED", receipt["result"], None
                else:
                    new_state, value = "CANCELLED" if state == "QUEUED" else "NOT_APPLIED", None
                    reason = "WRITER_RESTARTED_BEFORE_APPLY" if state == "QUEUED" else "RECONCILED_NOT_APPLIED"
                self.db.execute("UPDATE tasks SET state=?,updated=?,result=?,reason=? WHERE id=?",
                                (new_state, time.time(), value, reason, task_id))
            self.db.commit()
            self.archive_history()
            for _,_,batch,_ in rows:self.cleanup_receipt(batch)
            self.cleanup_completed_receipts()
            self.paused = False
            self.cv.notify_all()

    def submit(self, callback, *, key=None, payload=None, units=1, size=2048, isolated=False, keys=()):
        if units < 1 or size < 1: raise ValueError("positive queue cost required")
        fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        with self.cv:
            if key:
                row = (self.db.execute("SELECT id,fingerprint FROM tasks WHERE request_key=?", (key,)).fetchone()
                       or self.db.execute("SELECT id,fingerprint FROM task_archive WHERE request_key=?",(key,)).fetchone())
                if row:
                    if row[1] != fingerprint: raise IdempotencyConflict("runtime task key content conflict")
                    return row[0], True
            if self.closed or self.paused: raise QueueBusy("runtime writer unavailable; reconcile before new writes")
            if units > self.batch_size or self.units + units > self.capacity or self.bytes + size > self.byte_capacity:
                raise QueueBusy("runtime write queue is full; retry later with the same key")
            task_id = uuid.uuid4().hex
            now = time.time()
            self.db.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (task_id, key, fingerprint, "QUEUED", now, now, None, None, None, units))
            self.db.commit()
            item = Item(task_id, callback, contextvars.copy_context(), Future(), size, units, isolated, fingerprint, frozenset(keys))
            self.live[task_id] = item
            self.pending.append(item)
            self.units += units; self.bytes += size
            self.cv.notify_all()
            return task_id, False

    def wait(self, task_id, timeout=60):
        with self.cv:
            item = self.live.get(task_id)
            if item is None:
                row = self._row(task_id)
                if row and row["state"] == "SUCCEEDED":
                    result = _decrypt_response(row["result"])
                    if result is None: raise QueueBusy("task result could not be decrypted")
                    return result["value"]
                raise QueueBusy("runtime task is not successful; inspect task status")
        try:
            return item.future.result(timeout)
        except FutureTimeout:
            raise TaskPending(task_id) from None

    def status(self, task_id):
        with self.cv:
            row = self._row(task_id)
            if row is None: return None
            return {"taskId": row["id"], "state": row["state"], "createdAt": row["created"],
                    "updatedAt": row["updated"], "operationCount": row["units"], "reason": row["reason"],
                    "resultAvailable": row["state"] == "SUCCEEDED"}

    def snapshot(self):
        with self.cv:
            return {"queuedTasks": len(self.pending), "outstandingOperations": self.units,
                    "outstandingBytes": self.bytes, "capacity": self.capacity,
                    "byteCapacity": self.byte_capacity, "maxBatchOperations": self.batch_size,
                    "hotHistoryLimit":self.hot_history,
                    "hotTasks":self.db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],
                    "paused": self.paused, "closed": self.closed}

    def _apply(self, items):
        from singbox import manager
        import runtime_publication as publication
        from singbox.runtime_client import check_mode, RuntimeUnavailable
        try:
            if check_mode() != self.socket:
                raise RuntimeUnavailable("runtime socket changed")
        except RuntimeUnavailable:
            raise publication.RuntimeRecoveryRequired("runtime mode changed while tasks were queued; no restart fallback") from None
        batch = uuid.uuid4().hex
        with self.cv:
            self.db.executemany("UPDATE tasks SET state='RUNNING',batch=?,updated=? WHERE id=?",
                                [(batch, time.time(), item.task_id) for item in items])
            self.db.commit()
        results, proof = [], {}
        def apply(data, registry):
            baseline = manager._mutation_baseline.get()
            registry_baseline=manager._mutation_registry_baseline.get()
            for index, item in enumerate(items):
                def invoke():
                    # Context carries restart policy and related-file targets,
                    # but MUST NOT carry caller-side config lock ownership.
                    token = manager._mutation_workspace.set((data, registry))
                    baseline_token = manager._mutation_baseline.set(baseline)
                    lock_token = manager._config_lock_depth.set(1)
                    related = publication.related_targets.set(dict(publication.related_targets.get() or {}))
                    try:
                        value = item.callback(data, registry)
                        return value, dict(publication.related_targets.get() or {})
                    finally:
                        publication.related_targets.reset(related)
                        manager._mutation_workspace.reset(token)
                        manager._mutation_baseline.reset(baseline_token)
                        manager._config_lock_depth.reset(lock_token)
                try:
                    value, targets = item.context.run(invoke)
                except Exception as error:
                    raise BatchRejected(index, error) from error
                publication.related_targets.get().update(targets)
                results.append(value)
                proof[item.task_id] = {"fingerprint": item.fingerprint,
                                      "result": _encrypt_response({"value": value})}
            # This receipt is committed/rolled back with config and registry.
            if data!=baseline or registry!=registry_baseline or publication.related_targets.get():
                publication.stage_related(self.root / "receipts" / (batch + ".json"), proof)
        with publication.related_transaction():
            manager._mutate_config_direct(apply)
        return results

    def _process(self, items):
        import runtime_publication as publication
        try:
            results = self._apply(items)
        except BatchRejected as rejected:
            # Replay only the staged, uncommitted prefix. A bad request must
            # not roll back unrelated valid requests or reorder later deletes.
            if rejected.index: self._process(items[:rejected.index])
            self._finish(items[rejected.index], "FAILED", error=rejected.error, reason="MUTATION_REJECTED")
            if rejected.index + 1 < len(items):
                if self.paused:
                    for item in items[rejected.index + 1:]:
                        self._finish(item, "CANCELLED", reason="PRIOR_PUBLICATION_UNCERTAIN")
                else: self._process(items[rejected.index + 1:])
        except publication.RuntimeRecoveryRequired as error:
            with self.cv: self.paused = True
            for item in items: self._finish(item, "UNKNOWN", error=error, reason="RUNTIME_RECONCILIATION_REQUIRED")
        except Exception as error:
            for item in items: self._finish(item, "FAILED", error=error, reason="PUBLICATION_FAILED")
        else:
            for item, result in zip(items, results): self._finish(item, "SUCCEEDED", result=result)
        finally:
            self.archive_history()
            with self.cv:
                batches={self._row(item.task_id)['batch'] for item in items if self._row(item.task_id) is not None}
            for batch in batches:self.cleanup_receipt(batch)
            self.cleanup_completed_receipts()

    def _run(self):
        try:
            while True:
                with self.cv:
                    self.cv.wait_for(lambda: self.closed or (self.pending and not self.paused))
                    if self.closed: break
                    deadline = time.monotonic() + self.merge_seconds
                    while time.monotonic() < deadline and not self.closed:
                        self.cv.wait(deadline - time.monotonic())
                    if self.closed: break
                    items, units, size, keys = [], 0, 0, set()
                    while self.pending:
                        item = self.pending[0]
                        if items and (item.isolated or items[0].isolated or keys.intersection(item.keys) or units + item.units > self.batch_size or size + item.size > 1 << 20): break
                        items.append(self.pending.popleft()); units += item.units; size += item.size
                        keys.update(item.keys)
                self._process(items)
        except BaseException:
            # Persistence failures must not leave a dead worker accepting jobs.
            with self.cv:
                self.paused = self.closed = True
                for item in self.live.values():
                    if not item.future.done():
                        item.future.set_exception(QueueBusy("writer stopped; reconcile durable task receipts"))
            raise
        finally:
            with self.cv:
                self.closed = True
                while self.pending:
                    self._finish(self.pending.popleft(), "CANCELLED", reason="WRITER_SHUTDOWN_BEFORE_APPLY")
                self.db.close()
                self.lease.close()

    def close(self):
        with self.cv: self.closed = True; self.cv.notify_all()
        self.thread.join(30)
        # A running publication keeps the lease until its outcome is known.


_instance = None
_instance_lock = threading.Lock()


def current():
    return _instance


def start():
    global _instance
    from singbox import manager
    from singbox.runtime_client import enabled
    with _instance_lock:
        if _instance is None:
            if not enabled(): raise QueueBusy("single-process runtime mode is required")
            import runtime_publication
            with manager._config_lock():
                runtime_publication.initialize_locked()
                # r2 has preview/users but no configuration endpoint. Prove
                # the paired interface exists with a fenced, identical no-op.
                from singbox.runtime_client import RuntimeClient
                RuntimeClient().apply(manager.read_config(), runtime_publication.verify_current())
            root = Path(os.environ.get("NODE_MANAGER_RUNTIME_STATE_DIR", str(manager.REGISTRY_PATH.parent / "runtime"))) / "write-queue"
            _instance = RuntimeWriteQueue(root,hot_history=int(os.environ.get('NODE_MANAGER_RUNTIME_HOT_TASKS','4096')))
        return _instance


def stop():
    global _instance
    with _instance_lock:
        if _instance:
            _instance.close()
            if not _instance.thread.is_alive(): _instance = None
