"""Nonblocking collector intents converge using actual committed enforcement state."""
import copy
import json
import unittest
from unittest.mock import patch

import pytest

from test_next_stage import manager
import test_runtime_publication as fixtures
import runtime_publication as publication
import runtime_write_queue as queue
from monitor.enforcement_wait import PendingEnforcement


@pytest.fixture
def runtime(tmp_path, monkeypatch, request):
    fixture = unittest.TestCase()
    request.addfinalizer(fixture.doCleanups)
    fixtures.RuntimePublicationTests.setUp(fixture)
    monkeypatch.setattr(manager, "LOCK_PATH", fixture.root / "monitoring-config.lock")
    monkeypatch.setattr(queue, "_instance", None)
    manager._invalidate_monitoring_snapshot()
    monkeypatch.setattr(manager, "_enforcement_noop_cache", None)
    manager.create_user("alice", ["socks"], socks_username="alice-public", socks_password="synthetic")
    writer = queue.RuntimeWriteQueue(fixture.root / "monitoring-queue", merge_seconds=.001)
    request.addfinalizer(writer.close)
    request.addfinalizer(manager._invalidate_monitoring_snapshot)
    monkeypatch.setattr(queue, "_instance", writer)
    return fixture, writer, PendingEnforcement()


def callback(desired):
    def submit():
        token = queue.wait_timeout.set(0)
        try:
            return manager.sync_user_enforcements(desired)
        finally:
            queue.wait_timeout.reset(token)
    return submit


def task_count(writer):
    with writer.cv:
        return writer.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]


@pytest.mark.parametrize("desired", [{}, {"alice": {"trafficBlocked": False}},
                                      {"unknown-user": {"trafficBlocked": True}}])
def test_three_unchanged_rounds_do_not_enqueue_noop_tasks(runtime, desired):
    _, writer, gate = runtime
    for _ in range(3):
        assert gate.run("traffic-scope", callback(desired)) is True
        assert gate.pending_task_id is None
        assert task_count(writer) == 0


def test_real_block_and_unblock_complete_then_each_converges_for_three_rounds(runtime):
    fixture, writer, gate = runtime
    before_puts = fixture.fake.puts
    for expected_tasks, blocked in [(1, True), (2, False)]:
        desired = {"alice": {"trafficBlocked": blocked}}
        # Hold the writer's condition so acceptance deterministically precedes
        # completion; a zero-time wait must retain the accepted original task.
        with writer.cv:
            assert gate.run("traffic-scope", callback(desired)) is False
            original_task = gate.pending_task_id
            assert original_task
            assert task_count(writer) == expected_tasks
            for _ in range(3):
                assert gate.run("traffic-scope", callback(desired)) is False
                assert gate.pending_task_id == original_task
                assert task_count(writer) == expected_tasks
        writer.wait(original_task, timeout=10)
        assert writer.status(original_task)["state"] == "SUCCEEDED"
        for _ in range(3):
            assert gate.run("traffic-scope", callback(desired)) is True
            assert gate.pending_task_id is None
            assert task_count(writer) == expected_tasks
        metadata = manager.read_registry()["users"]["alice"]
        assert bool(metadata.get(manager.ENFORCEMENT_TRAFFIC_KEY)) is blocked
    assert fixture.fake.puts == before_puts + 2


def test_terminal_receipt_does_not_replace_current_round_changed_intent(runtime):
    _, writer, gate = runtime
    with writer.cv:
        assert gate.run("traffic-scope", callback({"alice": {"trafficBlocked": True}})) is False
        old_task = gate.pending_task_id
        assert gate.run("traffic-scope", callback({"alice": {"trafficBlocked": False}})) is False
        assert task_count(writer) == 1
    writer.wait(old_task, timeout=10)
    current = {"alice": {"trafficBlocked": False}}
    with writer.cv:
        assert gate.run("traffic-scope", callback(current)) is False
        new_task = gate.pending_task_id
        assert new_task != old_task
        assert task_count(writer) == 2
    writer.wait(new_task, timeout=10)
    for _ in range(3):
        assert gate.run("traffic-scope", callback(current)) is True
        assert task_count(writer) == 2
    assert not manager.read_registry()["users"]["alice"].get(manager.ENFORCEMENT_TRAFFIC_KEY)


def test_cached_satisfied_intent_cannot_bypass_unknown_publication(runtime):
    _, writer, _ = runtime
    desired = {"alice": {"trafficBlocked": False}}
    assert manager.sync_user_enforcements(desired) is False
    journal = publication.paths()[0]
    journal.write_text("unresolved", encoding="utf-8")
    with pytest.raises(publication.RuntimeRecoveryRequired):
        manager.sync_user_enforcements(desired)
    assert task_count(writer) == 0
    assert journal.read_text() == "unresolved"


def test_staged_change_and_capture_cannot_reuse_committed_noop(runtime):
    _, writer, _ = runtime
    desired = {"alice": {"trafficBlocked": False}}
    assert manager.sync_user_enforcements(desired) is False
    captured = manager.capture_mutation(lambda: manager.sync_user_enforcements(desired))
    assert callable(captured)
    data, registry = copy.deepcopy(manager.read_config()), copy.deepcopy(manager.read_registry())
    auth_users = ["alice-public", "node-manager:alice"]
    registry["users"]["alice"].update({manager.ENFORCEMENT_TRAFFIC_KEY: True,
                                       manager.ENFORCEMENT_AUTH_USERS_KEY: auth_users})
    data["route"]["rules"].insert(0, {"auth_user": auth_users, "action": "reject"})
    token = manager._mutation_workspace.set((data, registry))
    try:
        assert manager.sync_user_enforcements(desired) is True
        assert not registry["users"]["alice"].get(manager.ENFORCEMENT_TRAFFIC_KEY)
    finally:
        manager._mutation_workspace.reset(token)
    assert task_count(writer) == 0
    assert manager.sync_user_enforcements(desired) is False


def test_external_commit_after_snapshot_cannot_turn_changed_state_into_noop(runtime):
    _, writer, gate = runtime
    desired = {"alice": {"trafficBlocked": False}}
    original = manager.get_user_monitoring_snapshot
    changed = False
    def change_after_observation():
        nonlocal changed
        snapshot = original()
        if not changed:
            changed = True
            registry = manager.read_registry()
            registry["users"]["alice"].update({manager.ENFORCEMENT_TRAFFIC_KEY: True,
                manager.ENFORCEMENT_AUTH_USERS_KEY: ["alice-public", "node-manager:alice"]})
            replacement = manager.REGISTRY_PATH.with_suffix(".external")
            replacement.write_text(json.dumps(registry), encoding="utf-8")
            replacement.replace(manager.REGISTRY_PATH)
        return snapshot
    with writer.cv, patch.object(manager, "get_user_monitoring_snapshot", side_effect=change_after_observation):
        assert gate.run("traffic-scope", callback(desired)) is False
        task = gate.pending_task_id
        assert task_count(writer) == 1
    writer.wait(task, timeout=10)
    assert gate.run("traffic-scope", callback(desired)) is True
    assert not manager.read_registry()["users"]["alice"].get(manager.ENFORCEMENT_TRAFFIC_KEY)


def test_nonpersistent_sync_still_removes_earlier_persisted_source_rules(runtime):
    _, writer, gate = runtime
    assert manager.sync_user_enforcements({"alice": {
        "trafficBlocked": False, "blockedSourceIps": ["203.0.113.42"]}}, persist_source_blocks=True) is True
    assert manager.read_registry()["users"]["alice"].get(manager.ENFORCEMENT_SOURCE_CIDRS_KEY)
    desired = {"alice": {"trafficBlocked": False, "blockedSourceIps": []}}
    with writer.cv:
        assert gate.run("traffic-scope", callback(desired)) is False
        task = gate.pending_task_id
    writer.wait(task, timeout=10)
    expected_tasks = task_count(writer)
    for _ in range(3):
        assert gate.run("traffic-scope", callback(desired)) is True
        assert task_count(writer) == expected_tasks
    assert not manager.read_registry()["users"]["alice"].get(manager.ENFORCEMENT_SOURCE_CIDRS_KEY)
