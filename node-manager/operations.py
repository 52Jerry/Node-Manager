"""Persistent, versioned node operations. This module is inert until explicitly wired.

The control plane owns monotonically increasing (generation, desiredVersion).
All actions for one (node, asset) share a lock, including different owners. Each
writer and its readback must run synchronously under this lock AND the native
configuration/runtime locks. Legacy endpoints do not acquire this lock yet.

Only request hashes and redacted receipts are stored; payloads and callback
results (which may contain credentials) are never persisted. A crashed APPLYING
operation is uncertain and must be read back before the same operation retries.
Versions/receipts are durable tombstones: there is deliberately no TTL pruning.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Callable, Iterator


class OperationConflict(ValueError):
    """A stable operation/version was reused with different content."""


class OperationStoreError(RuntimeError):
    """The durable journal cannot safely be read; callers must fail closed."""


class OperationPreconditionFailed(ValueError):
    """A native adapter rejected a current business/identity guard BEFORE writes."""
    def __init__(self, reason: str):
        if reason not in {
            "BUSINESS_BLOCKED", "OWNER_IDENTITY_MISMATCH", "SOURCE_IDENTITY_MISMATCH",
            "OWNERSHIP_VERSION_MISMATCH", "UNSUPPORTED_POLICY",
        }:
            raise ValueError("unsupported precondition reason")
        self.reason = reason
        super().__init__(reason)


def _identifier(value: str, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(field + " must be a nonempty canonical string")
    if len(value) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(field + " is invalid")
    return value


def _canonical(value: Any) -> str:
    # Reject NaN and unsupported objects instead of silently changing identity.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


@dataclass(frozen=True)
class Operation:
    operation_id: str
    node_id: str
    asset_key: str
    owner_ref: str
    action: str
    generation: int
    desired_version: int

    def __post_init__(self) -> None:
        for field in ("operation_id", "node_id", "asset_key", "owner_ref", "action"):
            _identifier(getattr(self, field), field)
        for field in ("generation", "desired_version"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63 - 1:
                raise ValueError(field + " must be a positive signed 64-bit integer")

    @property
    def scope(self) -> str:
        return _canonical([self.node_id, self.asset_key])

    @property
    def version(self) -> tuple[int, int]:
        return self.generation, self.desired_version

    def request_hash(self, payload: Any) -> str:
        envelope = {
            "operationId": self.operation_id, "nodeId": self.node_id,
            "assetKey": self.asset_key, "ownerRef": self.owner_ref,
            "action": self.action, "generation": self.generation,
            "desiredVersion": self.desired_version, "payload": payload,
        }
        return hashlib.sha256(_canonical(envelope).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Observation:
    """An adapter's exact readback of the submitted operation.

    NOT_APPLIED is a positive assertion that retry is safe, not a missing row,
    timeout, partial read, or an unrelated owner. Those must be UNKNOWN.
    """
    operation_id: str
    request_hash: str
    generation: int
    desired_version: int
    status: str  # APPLIED / NOT_APPLIED / UNKNOWN


@dataclass(frozen=True)
class Receipt:
    operation_id: str
    node_id: str
    asset_key: str
    owner_ref: str
    action: str
    generation: int
    desired_version: int
    request_hash: str
    status: str
    reason: str | None
    current: bool
    accepted_generation: int
    accepted_version: int
    replayed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "operationId": self.operation_id, "nodeId": self.node_id,
            "assetKey": self.asset_key, "ownerRef": self.owner_ref,
            "action": self.action, "generation": self.generation,
            "desiredVersion": self.desired_version, "requestHash": self.request_hash,
            "status": self.status, "reason": self.reason, "current": self.current,
            "acceptedGeneration": self.accepted_generation,
            "acceptedVersion": self.accepted_version, "replayed": self.replayed,
        }


_thread_locks_guard = threading.Lock()
_thread_locks: dict[str, threading.RLock] = {}


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    key = str(path.resolve())
    with _thread_locks_guard:
        lock = _thread_locks.setdefault(key, threading.RLock())
    with lock:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt
                # Windows permits locking beyond EOF. Writing an initial byte
                # here would race a process that already locked an empty file.
                os.lseek(descriptor, 0, os.SEEK_SET)
                while True:
                    try:
                        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        # Windows locking reports EACCES/EDEADLK for contention.
                        if exc.errno not in (13, 36):
                            raise
                        time.sleep(0.01)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == "nt":
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


class OperationStore:
    def __init__(self, directory: Path | str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock_directory = self.directory / "locks"
        self.lock_directory.mkdir(exist_ok=True, mode=0o700)
        self.database = self.directory / "operations.sqlite3"
        # Serialize initialization between processes, too. Corruption is never
        # replaced with an empty store, which would lose the version fence.
        with _file_lock(self.lock_directory / "schema.lock"):
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1):
                    raise OperationStoreError("unsupported operation journal version")
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS node_operation (
                      operation_id TEXT PRIMARY KEY,
                      scope TEXT NOT NULL,
                      node_id TEXT NOT NULL,
                      asset_key TEXT NOT NULL,
                      owner_ref TEXT NOT NULL,
                      action TEXT NOT NULL,
                      generation INTEGER NOT NULL,
                      desired_version INTEGER NOT NULL,
                      request_hash TEXT NOT NULL,
                      status TEXT NOT NULL,
                      reason TEXT,
                      accepted_at REAL NOT NULL,
                      updated_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ix_node_operation_scope
                      ON node_operation(scope);
                    CREATE TABLE IF NOT EXISTS node_operation_fence (
                      scope TEXT PRIMARY KEY,
                      generation INTEGER NOT NULL,
                      desired_version INTEGER NOT NULL,
                      operation_id TEXT NOT NULL
                    );
                """)
                connection.execute("PRAGMA user_version=1")
        if os.name != "nt":
            descriptor = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.database, timeout=10, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=10000")
            for suffix in ("", "-wal", "-shm"):
                path = Path(str(self.database) + suffix)
                if path.exists():
                    os.chmod(path, 0o600)
            yield connection
        except sqlite3.DatabaseError as exc:
            raise OperationStoreError("operation journal unavailable; mutation refused") from exc
        finally:
            if connection is not None:
                connection.close()

    def _lock_path(self, operation: Operation) -> Path:
        digest = hashlib.sha256(operation.scope.encode("utf-8")).hexdigest()
        return self.lock_directory / (digest + ".lock")

    def read(self, operation_id: str) -> Receipt | None:
        """Read the exact persisted operation. Missing means UNKNOWN to a caller.

        APPLYING is returned as UNKNOWN: a GET cannot prove the live worker or
        its runtime outcome. read() never acquires a writer lock or mutates data.
        """
        _identifier(operation_id, "operation_id")
        with self._connect() as connection:
            row = connection.execute("""
                SELECT o.*, f.generation AS accepted_generation,
                  f.desired_version AS accepted_version,
                  f.operation_id AS current_operation
                FROM node_operation o JOIN node_operation_fence f ON f.scope=o.scope
                WHERE o.operation_id=?
            """, (operation_id,)).fetchone()
        return self._receipt(row) if row is not None else None

    @staticmethod
    def _receipt(row: sqlite3.Row, replayed: bool = False) -> Receipt:
        status = row["status"]
        return Receipt(
            operation_id=row["operation_id"], node_id=row["node_id"], asset_key=row["asset_key"],
            owner_ref=row["owner_ref"], action=row["action"], generation=row["generation"],
            desired_version=row["desired_version"], request_hash=row["request_hash"],
            status="UNKNOWN" if status == "APPLYING" else status,
            reason="INTERRUPTED_OR_IN_FLIGHT" if status == "APPLYING" else row["reason"],
            current=row["current_operation"] == row["operation_id"],
            accepted_generation=row["accepted_generation"], accepted_version=row["accepted_version"],
            replayed=replayed,
        )

    def _finish(self, operation: Operation, status: str, reason: str | None) -> None:
        # Caller retains the scope file lock throughout execution and finish.
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute("""
                    UPDATE node_operation SET status=?, reason=?, updated_at=?
                    WHERE operation_id=? AND EXISTS (
                      SELECT 1 FROM node_operation_fence f WHERE f.scope=?
                        AND f.operation_id=? AND f.generation=? AND f.desired_version=?)
                """, (status, reason, time.time(), operation.operation_id, operation.scope,
                      operation.operation_id, operation.generation, operation.desired_version))
                if cursor.rowcount != 1:
                    raise OperationStoreError("operation lost its version fence")
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _observe(operation: Operation, request_hash: str,
                 readback: Callable[[], Observation]) -> str:
        try:
            evidence = readback()
        except Exception:
            return "UNKNOWN"
        if not isinstance(evidence, Observation) or (
            evidence.operation_id != operation.operation_id
            or evidence.request_hash != request_hash
            or evidence.generation != operation.generation
            or evidence.desired_version != operation.desired_version
            or evidence.status not in ("APPLIED", "NOT_APPLIED", "UNKNOWN")
        ):
            return "UNKNOWN"
        return evidence.status

    def execute(self, operation: Operation, payload: Any,
                apply: Callable[[], Any], readback: Callable[[], Observation]) -> Receipt:
        """Run an exact command once, or reconcile the same uncertain command.

        Callers must authorize/register action types before entering here and
        use native config locks inside callbacks. There is no logging-success
        fallback. No SQLite transaction is held during either callback.
        """
        request_hash = operation.request_hash(payload)
        with _file_lock(self._lock_path(operation)):
            replayed = False
            terminal_replay = False
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    row = connection.execute("SELECT * FROM node_operation WHERE operation_id=?",
                                             (operation.operation_id,)).fetchone()
                    fence = connection.execute("SELECT * FROM node_operation_fence WHERE scope=?",
                                               (operation.scope,)).fetchone()
                    if row is not None:
                        if row["request_hash"] != request_hash:
                            raise OperationConflict("operationId already binds different content")
                        replayed = True
                        if row["status"] in ("APPLIED", "REJECTED"):
                            terminal_replay = True
                    previous = (fence["generation"], fence["desired_version"]) if fence else (0, 0)
                    stale = operation.version < previous
                    conflict = (operation.version == previous and fence is not None
                                and fence["operation_id"] != operation.operation_id)
                    now = time.time()
                    if row is None:
                        status = "REJECTED" if stale or conflict else "APPLYING"
                        reason = "STALE_VERSION" if stale else "VERSION_CONFLICT" if conflict else None
                        connection.execute("""
                            INSERT INTO node_operation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (operation.operation_id, operation.scope, operation.node_id,
                              operation.asset_key, operation.owner_ref, operation.action,
                              operation.generation, operation.desired_version, request_hash,
                              status, reason, now, now))
                    elif (stale or conflict) and not terminal_replay:
                        connection.execute("""
                            UPDATE node_operation SET status='REJECTED', reason='STALE_VERSION',
                              updated_at=? WHERE operation_id=?
                        """, (now, operation.operation_id))
                    if not stale and not conflict and not terminal_replay:
                        connection.execute("""
                            INSERT INTO node_operation_fence VALUES (?, ?, ?, ?)
                            ON CONFLICT(scope) DO UPDATE SET generation=excluded.generation,
                              desired_version=excluded.desired_version, operation_id=excluded.operation_id
                        """, (operation.scope, operation.generation, operation.desired_version,
                              operation.operation_id))
                    connection.execute("COMMIT")
                except BaseException:
                    connection.execute("ROLLBACK")
                    raise
            if terminal_replay:
                receipt = self.read(operation.operation_id)
                assert receipt is not None
                return replace(receipt, replayed=True)
            if stale or conflict:
                receipt = self.read(operation.operation_id)
                assert receipt is not None
                return replace(receipt, replayed=replayed)
            if replayed:
                observed = self._observe(operation, request_hash, readback)
                if observed == "APPLIED":
                    self._finish(operation, "APPLIED", None)
                elif observed != "NOT_APPLIED":
                    self._finish(operation, "UNKNOWN", "READBACK_REQUIRED")
                if observed != "NOT_APPLIED":
                    receipt = self.read(operation.operation_id)
                    assert receipt is not None
                    return replace(receipt, replayed=True)
                self._finish(operation, "APPLYING", None)
            try:
                apply()
            except OperationPreconditionFailed as exc:
                # The adapter may use this only before any side effect. It is
                # a visible business rejection, not a technical retry failure.
                self._finish(operation, "REJECTED", exc.reason)
            except Exception:
                # Deliberately do not store exception messages; they can carry
                # credentials. The same ID must be read back before any retry.
                self._finish(operation, "UNKNOWN", "EXECUTION_UNCERTAIN")
            else:
                observed = self._observe(operation, request_hash, readback)
                self._finish(operation, "APPLIED" if observed == "APPLIED" else "UNKNOWN",
                             None if observed == "APPLIED" else "READBACK_REQUIRED")
            receipt = self.read(operation.operation_id)
            assert receipt is not None
            return replace(receipt, replayed=replayed)

    def reconcile(self, operation: Operation, payload: Any,
                  readback: Callable[[], Observation]) -> Receipt | None:
        """Resolve an uncertain operation with no possible mutation callback.

        A transport GET may return the durable receipt through read(). To obtain
        fresh runtime proof, an authorized adapter should invoke this method
        using the original command (or its safely stored desired snapshot).
        A missing operation remains unknown and is never created by readback.
        """
        request_hash = operation.request_hash(payload)
        with _file_lock(self._lock_path(operation)):
            receipt = self.read(operation.operation_id)
            if receipt is None:
                return None
            if receipt.request_hash != request_hash:
                raise OperationConflict("operationId already binds different content")
            if receipt.status == "REJECTED" or not receipt.current:
                return receipt
            observed = self._observe(operation, request_hash, readback)
            self._finish(operation, "APPLIED" if observed == "APPLIED" else "UNKNOWN",
                         None if observed == "APPLIED" else
                         "NOT_APPLIED_CONFIRMED" if observed == "NOT_APPLIED" else "READBACK_REQUIRED")
            return self.read(operation.operation_id)
