"""Paired telemetry identities must remain coherent across publication boundaries."""
import copy
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from test_next_stage import manager, base_singbox_config
import runtime_publication as publication
import revision
from singbox.runtime_client import RuntimeClient
import test_runtime_publication as publication_fixtures


def replace_json(path, value, preserve_mtime=False):
    before = path.stat() if preserve_mtime else None
    temporary = path.with_suffix(".replacement")
    temporary.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
    if before is not None:
        os.utime(temporary, ns=(before.st_atime_ns, before.st_mtime_ns))
    temporary.replace(path)


@pytest.fixture
def files(tmp_path, monkeypatch):
    config = base_singbox_config()
    config["inbounds"][2]["users"] = [{"username": "alice-public", "password": "synthetic"}]
    registry = {"version": 2, "users": {"alice": {
        "socksUsername": "alice-public", "trafficLimitBytes": 100,
        "maxSourceIps": 2, "maxConnections": 3}}}
    config_path, registry_path = tmp_path / "config.json", tmp_path / "users.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    monkeypatch.setattr(manager, "CONFIG_PATH", config_path)
    monkeypatch.setattr(manager, "REGISTRY_PATH", registry_path)
    monkeypatch.setattr(manager, "LOCK_PATH", tmp_path / "config.lock")
    monkeypatch.setenv("NODE_MANAGER_RUNTIME_STATE_DIR", str(tmp_path / "runtime"))
    manager._invalidate_monitoring_snapshot()
    yield config, registry
    manager._invalidate_monitoring_snapshot()


def test_one_paired_decode_is_shared_by_repeated_readers(files):
    with patch.object(manager, "read_config", wraps=manager.read_config) as config_read, \
            patch.object(manager, "read_registry", wraps=manager.read_registry) as registry_read:
        first = manager.get_user_monitoring_snapshot()
        for _ in range(8):
            current = manager.get_user_monitoring_snapshot()
            assert current is first
            assert current.policies["alice"]["maxConnections"] == 3
            assert current.auth_map["alice-public"] == "alice"
    assert config_read.call_count == registry_read.call_count == 1


def test_projection_is_immutable_and_does_not_retain_input_dicts(files):
    config, registry = files
    snapshot = manager._make_monitoring_snapshot(config, registry, None)
    with pytest.raises(TypeError):
        snapshot.policies["alice"]["maxConnections"] = 999
    with pytest.raises(TypeError):
        snapshot.auth_map["alice-public"] = "someone-else"
    registry["users"]["alice"]["maxConnections"] = 999
    registry["users"]["alice"]["socksUsername"] = "uncommitted"
    assert snapshot.policies["alice"]["maxConnections"] == 3
    assert "uncommitted" not in snapshot.auth_map
    assert "password" not in repr(snapshot)


def test_warm_reader_does_not_wait_for_writer_or_decode_again(files):
    expected = manager.get_user_monitoring_snapshot()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with manager._config_lock(), \
                patch.object(manager, "_config_read_lock", side_effect=AssertionError("warm reader took config lock")), \
                patch.object(manager, "read_config", side_effect=AssertionError("warm reader decoded config")), \
                patch.object(manager, "read_registry", side_effect=AssertionError("warm reader decoded registry")):
            assert pool.submit(manager.get_user_monitoring_snapshot).result(timeout=2) is expected


def test_concurrent_cold_readers_decode_one_pair(files):
    barrier = threading.Barrier(6)
    def read():
        barrier.wait(timeout=5)
        return manager.get_user_monitoring_snapshot()
    with patch.object(manager, "read_config", wraps=manager.read_config) as config_read, \
            patch.object(manager, "read_registry", wraps=manager.read_registry) as registry_read:
        with ThreadPoolExecutor(max_workers=6) as pool:
            snapshots = list(pool.map(lambda _: read(), range(6)))
    assert all(snapshot is snapshots[0] for snapshot in snapshots)
    assert config_read.call_count == registry_read.call_count == 1


def test_same_size_and_mtime_atomic_registry_replacement_invalidates_pair(files):
    _, registry = files
    old = manager.get_user_monitoring_snapshot()
    registry["users"]["alice"]["maxConnections"] = 7
    registry["users"]["alice"]["socksUsername"] = "alice-change"
    replace_json(manager.REGISTRY_PATH, registry, preserve_mtime=True)
    with patch.object(manager, "_config_read_lock", wraps=manager._config_read_lock) as shared:
        new = manager.get_user_monitoring_snapshot()
    shared.assert_called_once()
    assert new is not old
    assert new.policies["alice"]["maxConnections"] == 7
    assert new.auth_map["alice-change"] == "alice"
    assert "alice-public" not in new.auth_map
    assert old.auth_map["alice-public"] == "alice"


def test_config_only_change_invalidates_auth_identity_projection(files):
    config, _ = files
    manager.get_user_monitoring_snapshot()
    config["inbounds"][1]["users"] = [{"name": "node-manager:bob", "uuid": "synthetic"}]
    replace_json(manager.CONFIG_PATH, config)
    snapshot = manager.get_user_monitoring_snapshot()
    assert snapshot.auth_map["node-manager:bob"] == "bob"


def test_summary_counts_preserve_registry_and_managed_list_semantics(files):
    config, registry = files
    registry["users"]["registry-only"] = {}
    config["inbounds"][0]["users"] = [{"name": "node-manager:bob", "uuid": "synthetic"}]
    config["inbounds"][1]["users"] = [{"name": "node-manager:bob", "uuid": "synthetic"}]
    config["inbounds"].append({"type": "vless", "tag": "unmanaged", "users": [
        {"name": "node-manager:outside", "uuid": "synthetic"}]})
    replace_json(manager.CONFIG_PATH, config)
    replace_json(manager.REGISTRY_PATH, registry)
    snapshot = manager.get_user_monitoring_snapshot()
    assert snapshot.registry_user_count == 2
    assert snapshot.discovered_user_count == 4
    assert snapshot.listed_user_count == 2
    assert snapshot.listed_user_count == len(manager.list_users())
    assert snapshot.socks_port == 5001


@pytest.mark.parametrize("port,expected", [(1080, 1080), ("1234", 1234), (0, None),
                                           (65536, None), (None, None), ("bad", None)])
def test_socks_port_projection_keeps_existing_validation(files, port, expected):
    config, _ = files
    config["inbounds"][2]["listen_port"] = port
    replace_json(manager.CONFIG_PATH, config)
    assert manager.get_user_monitoring_snapshot().socks_port == expected
    assert manager.get_socks_inbound_port() == expected


def test_external_pair_change_during_decode_is_retried_not_mislabelled(files):
    config, registry = files
    changed = copy.deepcopy(registry)
    changed["users"]["alice"].update(socksUsername="next-public", maxConnections=9)
    config["inbounds"][1]["users"] = [{"name": "node-manager:bob", "uuid": "synthetic"}]
    original_read = manager.read_registry
    replaced = False
    def replace_after_decode():
        nonlocal replaced
        value = original_read()
        if not replaced:
            replaced = True
            replace_json(manager.CONFIG_PATH, config)
            replace_json(manager.REGISTRY_PATH, changed)
        return value
    with patch.object(manager, "read_registry", side_effect=replace_after_decode) as read:
        snapshot = manager.get_user_monitoring_snapshot()
    assert read.call_count == 2
    assert snapshot.policies["alice"]["maxConnections"] == 9
    assert snapshot.auth_map["next-public"] == "alice"
    assert snapshot.auth_map["node-manager:bob"] == "bob"
    assert "alice-public" not in snapshot.auth_map


@pytest.mark.parametrize("changed", ["CONFIG_PATH", "REGISTRY_PATH"])
def test_invalid_changed_file_never_falls_back_to_old_identity(files, changed):
    manager.get_user_monitoring_snapshot()
    replace_json(getattr(manager, changed), "{broken")
    with pytest.raises((manager.SingboxConfigError, json.JSONDecodeError)):
        manager.get_user_monitoring_snapshot()
    assert manager._monitoring_snapshot is None


def test_pending_journal_never_serves_even_unchanged_cached_files(files):
    manager.get_user_monitoring_snapshot()
    journal = publication.paths()[0]
    journal.parent.mkdir()
    journal.write_text("unresolved", encoding="utf-8")
    with patch.object(publication, "recover_locked", side_effect=AssertionError("reader attempted recovery")):
        with pytest.raises(publication.RuntimeRecoveryRequired):
            manager.get_user_monitoring_snapshot()
    assert journal.read_text() == "unresolved"
    assert manager._monitoring_snapshot is None


def test_pending_revision_journal_cannot_reuse_cached_identity(files, tmp_path, monkeypatch):
    journal = tmp_path / "revision-transaction.json"
    monkeypatch.setattr(revision, "JOURNAL_PATH", journal)
    manager.get_user_monitoring_snapshot()
    journal.write_text("unresolved", encoding="utf-8")
    with pytest.raises(manager.SingboxConfigError, match="revision recovery required"):
        manager.get_user_monitoring_snapshot()
    assert manager._monitoring_snapshot is None
    assert journal.read_text() == "unresolved"


def test_staged_workspace_uses_current_data_without_publishing_it(files):
    committed = manager.get_user_monitoring_snapshot()
    data, registry = copy.deepcopy(files[0]), copy.deepcopy(files[1])
    registry["users"]["alice"].update(socksUsername="staged-public", maxConnections=99)
    token = manager._mutation_workspace.set((data, registry))
    try:
        staged = manager.get_user_monitoring_snapshot()
        assert staged.version is None
        assert staged.auth_map["staged-public"] == "alice"
        assert staged.policies["alice"]["maxConnections"] == 99
    finally:
        manager._mutation_workspace.reset(token)
    assert manager.get_user_monitoring_snapshot() is committed
    assert "staged-public" not in committed.auth_map


def test_reentrant_reader_never_primes_cache_from_staged_overrides(files):
    committed = manager.get_user_monitoring_snapshot()
    staged_registry = copy.deepcopy(files[1])
    staged_registry["users"]["alice"]["maxConnections"] = 99
    with manager._config_lock(), patch.object(manager, "read_registry", return_value=staged_registry):
        assert manager.get_user_monitoring_snapshot().policies["alice"]["maxConnections"] == 99
    assert manager.get_user_monitoring_snapshot() is committed


class TestPublicationMonitoringSnapshot:
    @pytest.fixture(autouse=True)
    def setup(self, request, monkeypatch):
        # Reuse the native runtime fault injector without inheriting its tests.
        import unittest
        fixture = unittest.TestCase()
        request.addfinalizer(fixture.doCleanups)
        publication_fixtures.RuntimePublicationTests.setUp(fixture)
        self.fixture = fixture
        monkeypatch.setattr(manager, "LOCK_PATH", fixture.root / "config.lock")
        manager._invalidate_monitoring_snapshot()
        request.addfinalizer(manager._invalidate_monitoring_snapshot)

    def create(self, user="alice"):
        return manager.create_user(user, ["socks"], socks_username=user + "-public", socks_password="synthetic")

    def test_writer_primes_old_committed_pair_before_native_preflight(self):
        self.create()
        manager._invalidate_monitoring_snapshot()
        original_preview = RuntimeClient().preview
        original_status = RuntimeClient().status
        observed = []
        def inspect_committed_pair():
            if observed:
                return
            with ThreadPoolExecutor(max_workers=1) as pool:
                snapshot = pool.submit(manager.get_user_monitoring_snapshot).result(timeout=2)
            observed.append(snapshot)
            assert snapshot.auth_map["alice-public"] == "alice"
            assert snapshot.policies["alice"]["maxConnections"] is None
        def during_preview(data):
            inspect_committed_pair()
            return original_preview(data)
        def during_status():
            inspect_committed_pair()
            return original_status()
        with patch.object(RuntimeClient, "preview", side_effect=during_preview), \
                patch.object(RuntimeClient, "status", side_effect=during_status):
            manager.mutate_config(lambda data, registry: registry["users"]["alice"].update(maxConnections=7))
        assert observed
        current = manager.get_user_monitoring_snapshot()
        assert current.policies["alice"]["maxConnections"] == 7
        assert all(snapshot.policies["alice"]["maxConnections"] is None for snapshot in observed)

    def test_confirmed_rejection_invalidates_and_reloads_restored_pair(self):
        self.create()
        old = manager.get_user_monitoring_snapshot()
        self.fixture.fake.mode = "reject"
        with pytest.raises(manager.SingboxConfigError, match="rejected"):
            self.create("bob")
        restored = manager.get_user_monitoring_snapshot()
        assert restored is not old
        assert restored.auth_map == old.auth_map
        assert "bob-public" not in restored.auth_map
        assert not publication.paths()[0].exists()

    def test_unknown_publication_blocks_reads_until_proven_recovery(self):
        self.create()
        manager.get_user_monitoring_snapshot()
        self.fixture.fake.mode = "disconnect_after"
        with pytest.raises(publication.RuntimeRecoveryRequired):
            self.create("bob")
        with pytest.raises(publication.RuntimeRecoveryRequired):
            manager.get_user_monitoring_snapshot()
        self.fixture.fake.offline = False
        self.fixture.fake.mode = "normal"
        assert publication.recover_locked() == "applied"
        recovered = manager.get_user_monitoring_snapshot()
        assert recovered.auth_map["bob-public"] == "bob"
        assert not publication.paths()[0].exists()

    def test_prepare_rejection_does_not_publish_desired_identity(self):
        self.create()
        committed = manager.get_user_monitoring_snapshot()
        self.fixture.fake.mode = "unsupported"
        with pytest.raises(manager.SingboxConfigError, match="unsupported"):
            self.create("bob")
        assert manager.get_user_monitoring_snapshot() is committed
        assert "bob-public" not in committed.auth_map
