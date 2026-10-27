import sys
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
    monkeypatch.setattr(manager, "_enforcement_noop_cache", None)
    writes = []

    def fake_mutation(callback):
        writes.append(True)
        return callback({"inbounds": [], "route": {"rules": []}}, {"users": {}})

    monkeypatch.setattr(manager, "mutate_config", fake_mutation)
    clear = {"u1": {"trafficBlocked": False, "blockedSourceIps": []}}
    assert manager.sync_user_enforcements(clear) is False
    assert manager.sync_user_enforcements(clear) is False
    assert len(writes) == 1

    blocked = {"u1": {"trafficBlocked": True, "blockedSourceIps": []}}
    assert manager.sync_user_enforcements(blocked) is False
    assert len(writes) == 2
    registry.write_text('{"users":{},"revision":1}')
    assert manager.sync_user_enforcements(blocked) is False
    assert len(writes) == 3


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
