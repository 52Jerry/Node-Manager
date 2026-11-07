"""An accepted enforcement timeout must not multiply queued desired-state copies."""
from __future__ import annotations

import gc
import importlib.util
import threading
import types
import weakref
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "node-manager/monitor/enforcement_wait.py"
spec = importlib.util.spec_from_file_location("_isolated_enforcement_wait", SOURCE)
enforcement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enforcement)


class TaskPending(Exception):
    def __init__(self, task_id):
        self.task_id = task_id
        super().__init__("accepted, still pending")


@pytest.fixture
def gate_and_queue():
    writer = types.SimpleNamespace(status=Mock(return_value={"taskId": "task-one", "state": "QUEUED"}))
    queue = types.SimpleNamespace(TaskPending=TaskPending, current=Mock(return_value=writer))
    gate = enforcement.PendingEnforcement(queue_provider=lambda: queue)
    return gate, queue, writer


def accepted(task_id="task-one"):
    raise TaskPending(task_id)


def test_independent_import_does_not_import_queue_or_create_threads():
    spec = importlib.util.spec_from_file_location("_fresh_enforcement_wait", SOURCE)
    module = importlib.util.module_from_spec(spec)
    with patch.object(threading, "Thread", side_effect=AssertionError("must not create threads")), \
         patch("importlib.import_module", side_effect=AssertionError("must not load runtime writer")):
        spec.loader.exec_module(module)
        instance = module.PendingEnforcement()
        assert instance.pending_task_id is None
        assert instance.reason is None


@pytest.mark.parametrize("state", ["QUEUED", "RUNNING", "UNKNOWN"])
def test_accepted_task_blocks_repeated_submissions_until_known_terminal(gate_and_queue, state):
    gate, _, writer = gate_and_queue
    first = Mock(side_effect=TaskPending("task-one"))
    assert gate.run("/state/traffic.json", first) is False
    writer.status.return_value = {"taskId": "task-one", "state": state}
    fresh = Mock()
    for _ in range(20):
        assert gate.run("/state/traffic.json", fresh) is False
    first.assert_called_once_with()
    fresh.assert_not_called()
    assert gate.pending_task_id == "task-one"
    assert writer.status.call_count == 20
    assert gate.reason == ("enforcement_task_unknown" if state == "UNKNOWN" else "enforcement_task_pending")


@pytest.mark.parametrize("state", ["SUCCEEDED", "FAILED", "CANCELLED", "NOT_APPLIED"])
def test_terminal_task_uses_current_round_callback(gate_and_queue, state):
    gate, _, writer = gate_and_queue
    assert gate.run("/state/traffic.json", accepted) is False
    obsolete = Mock()
    assert gate.run("/state/traffic.json", obsolete) is False
    writer.status.return_value = {"taskId": "task-one", "state": state}
    current = Mock()
    assert gate.run("/state/traffic.json", current) is True
    obsolete.assert_not_called()
    current.assert_called_once_with()
    assert gate.pending_task_id is None
    assert gate.reason is None


def test_gate_does_not_retain_old_desired_state_or_callback(gate_and_queue):
    gate, _, _ = gate_and_queue

    class Desired(dict):
        pass

    desired = Desired((str(i), {"trafficBlocked": False}) for i in range(1000))
    desired_ref = weakref.ref(desired)

    def make_callback(payload):
        def apply():
            assert len(payload) == 1000
            raise TaskPending("task-one")
        return apply

    callback = make_callback(desired)
    callback_ref = weakref.ref(callback)
    assert gate.run("/state/traffic.json", callback) is False
    del callback, desired
    gc.collect()
    assert desired_ref() is None
    assert callback_ref() is None
    assert gate.pending_task_id == "task-one"


@pytest.mark.parametrize("case,reason", [
    ("writer_missing", "enforcement_writer_unavailable"),
    ("task_missing", "enforcement_task_missing"),
    ("query_failed", "enforcement_task_query_failed"),
    ("invalid_state", "enforcement_task_state_invalid"),
    ("non_string_state", "enforcement_task_state_invalid"),
    ("wrong_id", "enforcement_task_state_invalid"),
])
def test_unprovable_receipt_fails_closed_without_resubmitting(gate_and_queue, case, reason):
    gate, queue, writer = gate_and_queue
    assert gate.run("/state/traffic.json", accepted) is False
    if case == "writer_missing":
        queue.current.return_value = None
    elif case == "task_missing":
        writer.status.return_value = None
    elif case == "query_failed":
        writer.status.side_effect = OSError("unavailable")
    elif case == "invalid_state":
        writer.status.return_value = {"state": "UNRECOGNIZED"}
    elif case == "non_string_state":
        writer.status.return_value = {"state": []}
    else:
        writer.status.return_value = {"taskId": "different-task", "state": "SUCCEEDED"}
    callback = Mock()
    for _ in range(3):
        assert gate.run("/state/traffic.json", callback) is False
    callback.assert_not_called()
    assert gate.pending_task_id == "task-one"
    assert gate.reason == reason


def test_status_query_provider_failure_keeps_original_pending_id(gate_and_queue):
    gate, _, _ = gate_and_queue
    assert gate.run("/state/traffic.json", accepted) is False
    gate._queue_provider = Mock(side_effect=OSError("writer module unavailable"))
    callback = Mock()
    assert gate.run("/state/traffic.json", callback) is False
    assert gate.reason == "enforcement_task_query_failed"
    assert gate.pending_task_id == "task-one"
    callback.assert_not_called()


def test_terminal_followup_can_record_a_new_accepted_task(gate_and_queue):
    gate, _, writer = gate_and_queue
    assert gate.run("/state/traffic.json", accepted) is False
    writer.status.return_value = {"taskId": "task-one", "state": "SUCCEEDED"}
    assert gate.run("/state/traffic.json", lambda: accepted("task-two")) is False
    assert gate.pending_task_id == "task-two"
    assert gate.reason == "enforcement_task_pending"


def test_unrelated_callback_exception_is_propagated_and_marker_is_released(gate_and_queue):
    gate, _, _ = gate_and_queue
    failure = ValueError("policy invalid")
    with pytest.raises(ValueError) as caught:
        gate.run("/state/traffic.json", Mock(side_effect=failure))
    assert caught.value is failure
    assert gate.pending_task_id is None
    assert gate.reason == "enforcement_failed"
    assert gate.run("/state/traffic.json", Mock()) is True


def test_concurrent_calls_do_not_wait_for_or_duplicate_slow_submission(gate_and_queue):
    gate, _, writer = gate_and_queue
    entered, release = threading.Event(), threading.Event()

    def slow_submission():
        entered.set()
        assert release.wait(2)
        raise TaskPending("task-one")

    with ThreadPoolExecutor(max_workers=8) as executor:
        first = executor.submit(gate.run, "/state/traffic.json", slow_submission)
        try:
            assert entered.wait(1)
            other = Mock()
            futures = [executor.submit(gate.run, "/state/traffic.json", other) for _ in range(16)]
            assert all(future.result(timeout=1) is False for future in futures)
            assert not release.is_set()
            other.assert_not_called()
            writer.status.assert_not_called()
        finally:
            release.set()
        assert first.result(timeout=1) is False
    assert gate.pending_task_id == "task-one"


def test_switching_store_scope_clears_old_receipt_without_retaining_history(gate_and_queue):
    gate, _, writer = gate_and_queue
    assert gate.run("/old/traffic.json", accepted) is False
    fresh = Mock()
    assert gate.run("/new/traffic.json", fresh) is True
    fresh.assert_called_once_with()
    writer.status.assert_not_called()
    assert gate.pending_task_id is None
    assert gate._scope == "/new/traffic.json"
    assert not any(isinstance(value, dict) for value in vars(gate).values())


@pytest.mark.parametrize("task_id", [None, "", "x" * 129])
def test_invalid_accepted_id_does_not_allow_another_submission(gate_and_queue, task_id):
    gate, _, writer = gate_and_queue
    assert gate.run("/state/traffic.json", lambda: accepted(task_id)) is False
    callback = Mock()
    assert gate.run("/state/traffic.json", callback) is False
    callback.assert_not_called()
    writer.status.assert_not_called()
    assert gate.reason == "enforcement_task_id_invalid"


def test_initial_synchronous_non_runtime_callback_does_not_load_writer():
    gate = enforcement.PendingEnforcement()
    callback = Mock()
    with patch.object(enforcement.importlib, "import_module", side_effect=AssertionError("must remain lazy")):
        assert gate.run("/shared/traffic.json", callback) is True
    callback.assert_called_once_with()
