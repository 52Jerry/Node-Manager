"""Wait for one accepted enforcement task instead of queueing stale copies.

No writer, worker, or persistent store is created at import time. This gate is
process-local and only retains one traffic-store scope and one task identifier;
the authoritative mutation receipt remains in the runtime writer.
"""
from __future__ import annotations

import importlib
import threading
from collections.abc import Callable


_WAITING_STATES = frozenset({"QUEUED", "RUNNING", "UNKNOWN"})
_TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED", "NOT_APPLIED"})


class PendingEnforcement:
    """Serialize submission and follow a timed-out task to a known terminal state.

    ``run`` is given the current round's callback. It never saves that callback
    or its desired-state payload. A future round after completion must supply
    a fresh callback computed from its own current policy and traffic sample.
    """

    def __init__(self, queue_provider: Callable[[], object] | None = None) -> None:
        self._queue_provider = queue_provider
        self._lock = threading.Lock()
        self._scope: str | None = None
        self._task_id: str | None = None
        self._inflight = False
        self._reason: str | None = None

    def _queue(self):
        return (self._queue_provider() if self._queue_provider is not None
                else importlib.import_module("runtime_write_queue"))

    @property
    def reason(self) -> str | None:
        with self._lock:
            return self._reason

    @property
    def pending_task_id(self) -> str | None:
        with self._lock:
            return self._task_id

    def _unavailable(self, reason: str) -> bool:
        with self._lock:
            self._reason = reason
        return False

    def _wait_for_receipt(self, task_id: str) -> bool:
        if not task_id:
            return self._unavailable("enforcement_task_id_invalid")
        try:
            writer = self._queue().current()
            if writer is None:
                return self._unavailable("enforcement_writer_unavailable")
            receipt = writer.status(task_id)
        except Exception:
            return self._unavailable("enforcement_task_query_failed")
        if receipt is None:
            return self._unavailable("enforcement_task_missing")
        state = receipt.get("state") if isinstance(receipt, dict) else None
        if (not isinstance(receipt, dict)
                or receipt.get("taskId", task_id) != task_id
                or not isinstance(state, str)
                or state not in _WAITING_STATES | _TERMINAL_STATES):
            return self._unavailable("enforcement_task_state_invalid")
        if state in _WAITING_STATES:
            return self._unavailable("enforcement_task_unknown" if state == "UNKNOWN"
                                     else "enforcement_task_pending")
        with self._lock:
            self._task_id = None
        return True

    def run(self, scope: str, callback: Callable[[], object]) -> bool:
        """Return false while work is pending/unprovable; never blindly resubmit.

        Querying the writer and executing a callback happen outside the small
        state lock. An in-flight marker makes concurrent callers return at once
        instead of waiting for a callback that may block on a runtime receipt.
        """
        if not isinstance(scope, str) or not scope:
            raise ValueError("a traffic-store scope is required")
        with self._lock:
            if self._inflight:
                self._reason = "enforcement_submission_inflight"
                return False
            if self._scope != scope:
                # A process normally owns one traffic store. Switching stores
                # (including isolated tests) must not inherit another scope's
                # receipt or accumulate a dictionary of old pending scopes.
                self._scope = scope
                self._task_id = None
                self._reason = None
            self._inflight = True
            task_id = self._task_id
        try:
            if task_id is not None and not self._wait_for_receipt(task_id):
                return False
            try:
                callback()
            except Exception as error:
                # Ordinary callback errors retain their original exception.
                # TaskPending is special: the mutation was already accepted,
                # so the next round must query its receipt, not enqueue again.
                try:
                    queue = self._queue()
                except Exception:
                    with self._lock:
                        self._reason = "enforcement_failed"
                    raise error
                if not isinstance(error, queue.TaskPending):
                    with self._lock:
                        self._reason = "enforcement_failed"
                    raise
                accepted_id = error.task_id
                valid_id = isinstance(accepted_id, str) and 0 < len(accepted_id) <= 128
                with self._lock:
                    # Empty is an unresolved marker. An invalid accepted id
                    # cannot safely turn into permission to submit again.
                    self._task_id = accepted_id if valid_id else ""
                    self._reason = ("enforcement_task_pending" if valid_id
                                    else "enforcement_task_id_invalid")
                return False
            with self._lock:
                self._reason = None
            return True
        finally:
            with self._lock:
                self._inflight = False
