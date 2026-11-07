import sys
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
from singbox import manager


def test_identical_enforcement_noop_skips_writer_until_files_or_decision_change(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    registry = tmp_path / "users.json"
    config.write_text('{"inbounds":[],"route":{"rules":[]}}')
    registry.write_text('{"users":{}}')
    monkeypatch.setattr(manager, "CONFIG_PATH", config)
    monkeypatch.setattr(manager, "REGISTRY_PATH", registry)
    monkeypatch.setattr(manager, "LOCK_PATH", tmp_path / "config.lock")
    monkeypatch.setenv("NODE_MANAGER_RUNTIME_STATE_DIR", str(tmp_path / "runtime"))
    import revision
    monkeypatch.setattr(revision, "JOURNAL_PATH", tmp_path / "revision-transaction.json")
    monkeypatch.setattr(manager, "_enforcement_noop_cache", None)
    monkeypatch.setattr(manager, "_monitoring_snapshot", None)
    writes = []

    def replace_json(path, value):
        replacement = path.with_suffix(".replacement")
        replacement.write_text(json.dumps(value), encoding="utf-8")
        replacement.replace(path)

    def fake_mutation(callback):
        # Model a writer transaction against the real fixture files. Losing
        # these mutations would make every round appear unconfigured again.
        data = json.loads(config.read_text(encoding="utf-8"))
        users = json.loads(registry.read_text(encoding="utf-8"))
        before = copy.deepcopy((data, users))
        changed = callback(data, users)
        writes.append(changed)
        if (data, users) != before:
            replace_json(config, data)
            replace_json(registry, users)
        return changed

    monkeypatch.setattr(manager, "mutate_config", fake_mutation)
    clear = {"u1": {"trafficBlocked": False, "blockedSourceIps": []}}
    blocked = {"u1": {"trafficBlocked": True, "blockedSourceIps": []}}
    # No configured identity exists: both desired states are provable no-ops.
    for desired in (clear, blocked, clear):
        assert manager.sync_user_enforcements(desired) is False
    assert writes == []

    data = {"inbounds": [{"type": "socks", "tag": manager.config.singbox.socks_tag,
                          "listen_port": 5080, "users": [{"username": "u1-public", "password": "synthetic"}]}],
            "route": {"rules": []}}
    users = {"users": {"u1": {"socksUsername": "u1-public"}}}
    replace_json(config, data)
    replace_json(registry, users)
    for _ in range(3):
        assert manager.sync_user_enforcements(clear) is False
    assert writes == []

    assert manager.sync_user_enforcements(blocked) is True
    for _ in range(3):
        assert manager.sync_user_enforcements(blocked) is False
    assert writes == [True]
    stored = json.loads(registry.read_text(encoding="utf-8"))
    assert stored["users"]["u1"][manager.ENFORCEMENT_TRAFFIC_KEY] is True

    # A new external version requires a new paired observation, but does not
    # justify rewriting an enforcement state that is still satisfied.
    old = manager.get_user_monitoring_snapshot()
    stored["revision"] = 1
    replace_json(registry, stored)
    assert manager.sync_user_enforcements(blocked) is False
    assert manager.get_user_monitoring_snapshot().version != old.version
    assert writes == [True]

    # Real credential changes invalidate the prior no-op. The mutator must
    # replace the old rule's auth names with the current configured identity.
    data = json.loads(config.read_text(encoding="utf-8"))
    data["inbounds"][0]["users"][0]["username"] = "u1-renamed"
    stored["users"]["u1"]["socksUsername"] = "u1-renamed"
    replace_json(config, data)
    replace_json(registry, stored)
    assert manager.sync_user_enforcements(blocked) is True
    current = json.loads(registry.read_text(encoding="utf-8"))["users"]["u1"]
    expected_auth = ["node-manager:u1", "u1-renamed"]
    assert current[manager.ENFORCEMENT_AUTH_USERS_KEY] == expected_auth
    assert json.loads(config.read_text(encoding="utf-8"))["route"]["rules"] == [
        {"auth_user": expected_auth, "action": "reject"}]
    assert manager.sync_user_enforcements(blocked) is False
    assert writes == [True, True]

    assert manager.sync_user_enforcements(clear) is True
    for _ in range(3):
        assert manager.sync_user_enforcements(clear) is False
    assert writes == [True, True, True]
    current = json.loads(registry.read_text(encoding="utf-8"))["users"]["u1"]
    assert manager.ENFORCEMENT_TRAFFIC_KEY not in current
    assert manager.ENFORCEMENT_AUTH_USERS_KEY not in current
    assert json.loads(config.read_text(encoding="utf-8"))["route"]["rules"] == []


def test_read_lock_rejects_nested_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr(manager, "LOCK_PATH", tmp_path / "config.lock")
    with manager._config_read_lock():
        with manager._config_read_lock():
            with __import__("pytest").raises(manager.SingboxConfigError):
                with manager._config_lock():
                    pass


def test_expiration_scheduler_skips_writer_when_no_user_needs_rule(tmp_path, monkeypatch):
    monkeypatch.setattr(manager, "LOCK_PATH", tmp_path / "config.lock")
    monkeypatch.setattr(manager, "EXPIRATION_ENABLED", True)
    now = datetime.now(timezone.utc)
    registry = {"users": {"future": {"expiresAt": (now + timedelta(days=1)).isoformat()}}}
    config = {"route": {"rules": []}}
    monkeypatch.setattr(manager, "read_registry", lambda: registry)
    monkeypatch.setattr(manager, "read_config", lambda: config)
    monkeypatch.setattr(manager, "mutate_config", lambda _: (_ for _ in ()).throw(AssertionError("writer called")))
    assert manager.process_user_expirations(now) == 0

    names = ["expired"]
    registry["users"]["expired"] = {
        "expiresAt": (now - timedelta(minutes=1)).isoformat(),
        manager.EXPIRATION_BLOCKED_KEY: True,
        manager.EXPIRATION_AUTH_USERS_KEY: names,
    }
    config["route"]["rules"].append({"auth_user": names, "action": "reject"})
    monkeypatch.setattr(manager, "_user_auth_names", lambda _registry, _user_id: names)
    monkeypatch.setattr(manager, "_connections_to_close_for_expired_users", lambda *_: set())
    assert manager.process_user_expirations(now) == 0


def test_inventory_serializes_large_result_once_without_response_conversion(monkeypatch):
    import main
    import user_cleanup
    from fastapi import Response
    result = {"items": [{"userId": "中文用户", "protocols": ["vless"]}], "total": 1}
    monkeypatch.setattr(main, "get_users", lambda **_: result)
    response = user_cleanup.inventory(Response())
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private"
    assert __import__("json").loads(response.body) == result
