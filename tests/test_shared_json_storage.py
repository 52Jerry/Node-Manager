"""Canonical JSON durability, migration, and concurrent account transactions."""
from dataclasses import replace
import base64
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import time
from unittest.mock import patch
from urllib.parse import urlsplit

from fastapi.testclient import TestClient
import httpx
import pytest

from shared_manager.agent import Agent
from shared_manager.app import COOKIE, create_app
from shared_manager.json_database import migrate_sqlite_to_json
from shared_manager.settings import Settings
from shared_manager.store import ProfileConflict, Store


PASSWORD = " x "


def settings_for(path):
    return Settings(secret="json-storage-secret-" * 3, agent_token="json-storage-agent-" * 3,
                    origin="http://localhost:8090", database=Path(path))


def quote(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def snapshot(store):
    """Read every typed value and rowid without depending on JSON's encoding."""
    with store.connection() as db:
        names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {name: {
            "columns": tuple(row[1] for row in db.execute("PRAGMA table_info(" + quote(name) + ")")),
            "rows": tuple(tuple(row) for row in db.execute("SELECT rowid,* FROM " + quote(name) + " ORDER BY rowid")),
        } for name in names}


def encrypted(store, value, aad):
    nonce = os.urandom(12)
    return nonce + store.cipher.encrypt(nonce, value.encode(), aad.encode())


def seed_complete_state(settings):
    # Application startup installs subscriptions and import-history tables in
    # addition to the Store's account/profile schema. No network calls occur.
    app = create_app(settings, agent=object())
    store = app.state.store
    owner = store.register("管理员🌐@example", PASSWORD)
    assert store.set_admin(owner["username"])
    session = store.create_session(owner["id"])
    default = store.allocation(owner["id"], create=True)
    store.mark_profile_ready(owner["id"], default["id"])
    store.update_profile_policy(owner["id"], default["id"], 17 * 1024**3)
    applied = {"mode": "socks5", "server": "8.8.8.8", "resolvedServer": "8.8.8.8", "port": 1080,
               "username": "住宅账户", "password": "private-residential-password"}
    operation = store.prepare_profile_upstream(owner["id"], default["id"], applied)
    store.apply_profile_upstream(owner["id"], default["id"], operation["operation_id"])
    pending = {**applied, "password": "new-private-residential-password"}
    store.prepare_profile_upstream(owner["id"], default["id"], pending)
    extra = store.create_profile(owner["id"], "保留连接", "durable-create-key")
    removed = store.create_profile(owner["id"], "已删除连接", "deleted-create-key")
    store.begin_delete_profile(owner["id"], removed["id"])
    store.delete_profile(owner["id"], removed["id"])
    store.throttle("json-test", owner["id"], 10, 900)
    token = "private-subscription-token-exactly-preserved"
    import_key = "canonical-import-key"
    plan = json.dumps([{"line": 1, "name": "住宅批次", "payload": applied}], ensure_ascii=False)
    with store.connection() as db:
        db.execute("INSERT INTO subscriptions VALUES (?, ?, ?)",
                   (owner["id"], hashlib.sha256(token.encode()).hexdigest(),
                    encrypted(store, token, "subscription:" + owner["id"])))
        db.execute("INSERT INTO profile_imports VALUES (?, ?, ?, ?)",
                   (owner["id"], import_key, "content-fingerprint", encrypted(store, plan, "profile-import:" + owner["id"] + ":" + import_key)))
        db.execute("INSERT INTO profile_import_key_aliases VALUES (?, ?, ?, ?)",
                   (owner["id"], "alias-import-key", "content-fingerprint", import_key))
        db.execute("CREATE TABLE storage_values (id TEXT PRIMARY KEY, binary_value BLOB, text_value TEXT, integer_value INTEGER, real_value REAL, null_value TEXT)")
        db.execute("INSERT INTO storage_values VALUES (?, ?, ?, ?, ?, ?)",
                   ("typed", bytes(range(256)), "正文\n{\"$blob\":\"literal text\"}", 9007199254740991, 3.25, None))
    return store, {"owner": owner, "session": session, "default": default, "extra": extra,
                   "removed": removed, "upstream": {"applied": applied, "pending": pending}, "subscription": token}


def assert_functional_state(store, state):
    owner = state["owner"]
    actual = store.authenticate(owner["username"], PASSWORD)
    assert actual["id"] == owner["id"]
    assert actual["password_hash"] == owner["password_hash"]
    assert actual["is_admin"] == 1
    assert store.session_user(state["session"])["id"] == owner["id"]
    default = store.allocation(owner["id"])
    assert default["id"] == state["default"]["id"]
    assert default["request"] == state["default"]["request"]
    assert default["ready"] == 1
    assert default["traffic_limit_bytes"] == 17 * 1024**3
    upstream = store.get_profile_upstream(owner["id"], default["id"])
    assert upstream["applied"] == state["upstream"]["applied"]
    assert upstream["pending"] == state["upstream"]["pending"]
    assert store.create_profile(owner["id"], "保留连接", "durable-create-key")["id"] == state["extra"]["id"]
    assert store.get_profile(owner["id"], state["removed"]["id"]) is None
    with pytest.raises(ProfileConflict):
        store.create_profile(owner["id"], "已删除连接", "deleted-create-key")
    with store.connection() as db:
        value = db.execute("SELECT encrypted_token FROM subscriptions WHERE user_id=?", (owner["id"],)).fetchone()[0]
        assert isinstance(value, bytes)
        assert store.cipher.decrypt(value[:12], value[12:], ("subscription:" + owner["id"]).encode()).decode() == state["subscription"]


def test_json_is_canonical_and_reopening_preserves_all_accounts_and_encrypted_state(tmp_path):
    settings = settings_for(tmp_path / "accounts.json")
    store, state = seed_complete_state(settings)
    expected = snapshot(store)
    data = json.loads(settings.database.read_text(encoding="utf-8"))
    assert data["format"] == "shared-node-manager-json"
    assert data["version"] == 1
    assert set(data["tables"]) == set(expected)
    raw = settings.database.read_text(encoding="utf-8")
    assert "private-residential-password" not in raw
    assert state["subscription"] not in raw
    assert state["session"] not in raw
    assert state["default"]["request"]["socksPassword"] not in raw
    reopened = Store(settings)
    assert snapshot(reopened) == expected
    assert_functional_state(reopened, state)
    assert not [p for p in tmp_path.iterdir() if p.name.endswith((".sqlite3", ".db", "-wal", "-shm"))]
    if os.name == "posix":
        assert settings.database.stat().st_mode & 0o077 == 0


def test_reads_and_unchanged_transactions_do_not_rewrite_json(tmp_path):
    settings = settings_for(tmp_path / "accounts.json")
    store = Store(settings)
    user = store.register("ordinary", PASSWORD)
    before = settings.database.read_bytes()
    with patch("shared_manager.json_database.os.replace", side_effect=AssertionError("read attempted persistence")):
        assert store.authenticate("ordinary", PASSWORD)["id"] == user["id"]
        assert store.admin_users()["summary"]["registeredUsers"] == 1
        with store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 1
    assert settings.database.read_bytes() == before


def test_connection_exception_rolls_back_and_releases_storage_lock(tmp_path):
    settings = settings_for(tmp_path / "accounts.json")
    store = Store(settings)
    owner = store.register("owner", PASSWORD)
    before = settings.database.read_bytes()
    with pytest.raises(RuntimeError, match="synthetic transaction abort"):
        with store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE users SET username='discarded' WHERE id=?", (owner["id"],))
            raise RuntimeError("synthetic transaction abort")
    assert settings.database.read_bytes() == before
    assert store.authenticate("owner", PASSWORD)["id"] == owner["id"]
    profile = store.create_profile(owner["id"], "锁已释放", "after-rollback")
    assert Store(settings).get_profile(owner["id"], profile["id"])["name"] == "锁已释放"


def test_atomic_replace_failure_keeps_old_json_and_does_not_report_uncommitted_user(tmp_path):
    settings = settings_for(tmp_path / "accounts.json")
    store = Store(settings)
    store.register("existing", PASSWORD)
    before = settings.database.read_bytes()
    with patch("shared_manager.json_database.os.replace", side_effect=OSError("synthetic replacement failure")):
        with pytest.raises(OSError, match="synthetic replacement failure"):
            store.register("uncommitted", PASSWORD)
    assert settings.database.read_bytes() == before
    assert json.loads(before)["format"] == "shared-node-manager-json"
    assert store.authenticate("uncommitted", PASSWORD) is None
    assert store.authenticate("existing", PASSWORD) is not None
    assert store.register("uncommitted", PASSWORD)["username"] == "uncommitted"


def test_commit_stages_complete_json_beside_target_before_atomic_replace(tmp_path):
    settings = settings_for(tmp_path / "accounts.json")
    store = Store(settings)
    before = settings.database.read_bytes()
    actual_replace = os.replace
    observed = []

    def inspect_replace(source, target, *args, **kwargs):
        assert Path(source).parent == settings.database.parent
        assert Path(target) == settings.database
        assert settings.database.read_bytes() == before
        staged = json.loads(Path(source).read_text(encoding="utf-8"))
        assert staged["format"] == "shared-node-manager-json"
        assert len(staged["tables"]["users"]["rows"]) == 1
        observed.append(True)
        return actual_replace(source, target, *args, **kwargs)

    with patch("shared_manager.json_database.os.replace", side_effect=inspect_replace):
        store.register("committed", PASSWORD)
    assert observed == [True]
    assert Store(settings).authenticate("committed", PASSWORD) is not None


@pytest.mark.parametrize("corruption", ["truncated", "wrong-format", "wrong-version", "missing-table", "invalid-blob"])
def test_corrupt_json_fails_closed_and_is_never_overwritten(tmp_path, corruption):
    settings = settings_for(tmp_path / "accounts.json")
    store = Store(settings)
    owner = store.register("owner", PASSWORD)
    store.create_profile(owner["id"], "持久凭据", "secret-profile")
    data = json.loads(settings.database.read_text(encoding="utf-8"))
    if corruption == "truncated":
        broken = b'{"format":"shared-node-manager-json",'
    else:
        if corruption == "wrong-format":
            data["format"] = "not-the-account-store"
        elif corruption == "wrong-version":
            data["version"] = 999
        elif corruption == "missing-table":
            del data["tables"]["users"]
        elif corruption == "invalid-blob":
            table = data["tables"]["profiles"]
            table["rows"][0]["values"][table["columns"].index("payload")] = {"$blob": "invalid/base64!"}
        broken = json.dumps(data, ensure_ascii=False).encode("utf-8")
    settings.database.write_bytes(broken)
    with pytest.raises(ValueError):
        Store(settings)
    assert settings.database.read_bytes() == broken


def test_wrong_secret_cannot_modify_or_replace_json_state(tmp_path):
    settings = settings_for(tmp_path / "accounts.json")
    store = Store(settings)
    store.register("owner", PASSWORD)
    before = settings.database.read_bytes()
    with pytest.raises(ValueError, match="SHARED_SECRET"):
        Store(replace(settings, secret="wrong-json-secret-" * 3))
    assert settings.database.read_bytes() == before
    assert Store(settings).authenticate("owner", PASSWORD) is not None


def test_sqlite_migration_preserves_every_typed_row_rowid_and_encrypted_payload(tmp_path):
    legacy_settings = settings_for(tmp_path / "accounts.sqlite3")
    legacy, state = seed_complete_state(legacy_settings)
    # Gaps in rowids must survive: legacy/default selection and same-second
    # profile ordering cannot change when the canonical file changes format.
    with legacy.connection() as db:
        db.execute("UPDATE profiles SET rowid=rowid+100 WHERE id=?", (state["extra"]["id"],))
    before = snapshot(legacy)
    legacy_bytes = legacy_settings.database.read_bytes()
    target = tmp_path / "accounts.json"
    result = migrate_sqlite_to_json(legacy_settings.database, target)
    assert isinstance(result, dict)
    assert legacy_settings.database.read_bytes() == legacy_bytes
    migrated = Store(replace(legacy_settings, database=target))
    assert snapshot(migrated) == before
    assert_functional_state(migrated, state)
    assert snapshot(legacy) == before
    assert state["subscription"] not in json.dumps(result)
    assert state["session"] not in json.dumps(result)


def test_json_after_migration_is_independent_of_legacy_sqlite_file(tmp_path):
    legacy_settings = settings_for(tmp_path / "legacy.sqlite3")
    legacy = Store(legacy_settings)
    owner = legacy.register("original", PASSWORD)
    target = tmp_path / "accounts.json"
    migrate_sqlite_to_json(legacy_settings.database, target)
    current = Store(replace(legacy_settings, database=target))
    with legacy.connection() as db:
        db.execute("UPDATE users SET username='legacy-only' WHERE id=?", (owner["id"],))
    assert current.authenticate("original", PASSWORD)["id"] == owner["id"]
    assert current.authenticate("legacy-only", PASSWORD) is None
    current.register("json-only", PASSWORD)
    assert legacy.authenticate("json-only", PASSWORD) is None


def test_migration_refuses_existing_target_without_altering_either_source_or_target(tmp_path):
    settings = settings_for(tmp_path / "legacy.sqlite3")
    Store(settings).register("preserve", PASSWORD)
    source_bytes = settings.database.read_bytes()
    target = tmp_path / "accounts.json"
    target.write_text("existing canonical file must survive", encoding="utf-8")
    before = target.read_bytes()
    with pytest.raises((ValueError, FileExistsError)):
        migrate_sqlite_to_json(settings.database, target)
    assert target.read_bytes() == before
    assert settings.database.read_bytes() == source_bytes


@pytest.mark.parametrize("declaration", [
    "CREATE VIEW unsupported_view AS SELECT username FROM users",
    "CREATE TRIGGER unsupported_trigger AFTER INSERT ON users BEGIN SELECT 1; END",
])
def test_migration_rejects_unsupported_schema_instead_of_dropping_it(tmp_path, declaration):
    settings = settings_for(tmp_path / "legacy.sqlite3")
    store = Store(settings)
    store.register("preserve", PASSWORD)
    with store.connection() as db:
        db.execute(declaration)
    before = settings.database.read_bytes()
    target = tmp_path / "accounts.json"
    with pytest.raises(ValueError):
        migrate_sqlite_to_json(settings.database, target)
    assert not target.exists()
    assert settings.database.read_bytes() == before


def test_json_backed_public_profile_import_and_subscription_api_survives_restart(tmp_path):
    # Use the existing wire-level fake node: the real portal/Agent/provisioning
    # paths run, while every node request remains inside MockTransport.
    from test_shared_profiles_api import ProfileNode

    settings = replace(settings_for(tmp_path / "accounts.json"), registration_enabled=True,
                       agent_token="agent-token-" * 3)
    node = ProfileNode()
    agent = Agent(settings, transport=httpx.MockTransport(node))
    first_app = create_app(settings, agent)
    try:
        with TestClient(first_app, base_url=settings.origin, headers={"Origin": settings.origin}) as client:
            registered = client.post("/api/auth/register", json={"username": "接口用户@测试", "password": "密"})
            assert registered.status_code == 201, registered.text
            headers = {"X-CSRF-Token": registered.json()["csrfToken"]}
            created = client.post("/api/me/profiles", json={"name": "JSON 独立连接", "idempotencyKey": "json-api-direct"}, headers=headers)
            assert created.status_code == 201, created.text
            direct_id = created.json()["id"]
            imported_text = "8.8.8.8:1080:residential:json-private-residential-password"
            imported = client.post("/api/me/profiles/import", json={"text": imported_text, "idempotencyKey": "json-api-import"}, headers=headers)
            assert imported.status_code == 200, imported.text
            assert imported.json()["createdCount"] == 1
            assert imported.json()["failedCount"] == 0
            ids = {item["id"] for item in client.get("/api/me/profiles").json()["items"]}
            assert len(ids) == 2
            subscription = client.post("/api/me/subscription", json={"rotate": False}, headers=headers)
            assert subscription.status_code == 200, subscription.text
            url = subscription.json()["url"]
            subscribed = client.get(urlsplit(url).path)
            assert subscribed.status_code == 200
            assert len(base64.b64decode(subscribed.text).decode().splitlines()) == 6
            cookie = client.cookies.get(COOKIE)
            first_app.state.store.set_admin("接口用户@测试")
            assert client.get("/api/admin/users").json()["summary"]["readyConnections"] == 2

        second_app = create_app(settings, agent)
        with TestClient(second_app, base_url=settings.origin, headers={"Origin": settings.origin}) as client:
            client.cookies.set(COOKIE, cookie)
            assert client.get("/api/me").json()["user"]["isAdmin"] is True
            assert {item["id"] for item in client.get("/api/me/profiles").json()["items"]} == ids
            assert client.get("/api/me/subscription").json()["url"] == url
            assert client.get(urlsplit(url).path).text == subscribed.text
            replay = client.post("/api/me/profiles", json={"name": "JSON 独立连接", "idempotencyKey": "json-api-direct"}, headers=headers)
            assert replay.status_code == 201, replay.text
            assert replay.json()["id"] == direct_id
            duplicate_import = client.post("/api/me/profiles/import", json={"text": imported_text, "idempotencyKey": "json-api-import-new-key"}, headers=headers)
            assert duplicate_import.status_code == 200, duplicate_import.text
            assert len(client.get("/api/me/profiles").json()["items"]) == 2
            assert len(node.creates) == 2
        assert "json-private-residential-password" not in settings.database.read_text(encoding="utf-8")
        assert urlsplit(url).path.split("/")[-1] not in settings.database.read_text(encoding="utf-8")
    finally:
        agent.close()


def _writer_process(path, owner, number, start, events):
    """Spawn-safe process entrypoint: separate interpreters have no shared lock."""
    try:
        store = Store(settings_for(path))
        events.put(("ready", number))
        if not start.wait(20):
            raise TimeoutError("writer start was not released")
        ids = []
        for index in range(4):
            profile = store.create_profile(owner, f"worker-{number}-{index}", f"worker-{number}-key-{index}")
            ids.append(profile["id"])
            with store.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                count = int(db.execute("SELECT value FROM metadata WHERE key='concurrency-counter'").fetchone()[0])
                db.execute("UPDATE metadata SET value=? WHERE key='concurrency-counter'", (str(count + 1),))
        events.put(("done", number, ids))
    except Exception as exc:
        events.put(("error", number, type(exc).__name__, str(exc)))


def test_separate_process_writers_and_readers_do_not_lose_json_transactions(tmp_path):
    settings = settings_for(tmp_path / "accounts.json")
    store = Store(settings)
    owner = store.register("owner", PASSWORD)
    with store.connection() as db:
        db.execute("INSERT INTO metadata VALUES ('concurrency-counter', '0')")
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    events = context.Queue()
    processes = [context.Process(target=_writer_process, args=(str(settings.database), owner["id"], number, start, events))
                 for number in range(3)]
    try:
        for process in processes:
            process.start()
        ready = [events.get(timeout=25) for _ in processes]
        assert all(event[0] == "ready" for event in ready), ready
        start.set()
        # Reads also use the adapter, so this exercises its lock while avoiding
        # Windows' unrelated deny-delete sharing rules for arbitrary raw opens.
        deadline = time.monotonic() + 25
        while any(process.is_alive() for process in processes) and time.monotonic() < deadline:
            report = store.admin_users()
            assert 0 <= report["summary"]["totalConnections"] <= 12
            time.sleep(0.005)
        for process in processes:
            process.join(timeout=3)
            assert process.exitcode == 0
        completed = [events.get(timeout=5) for _ in processes]
        assert all(event[0] == "done" for event in completed), completed
        expected_ids = {identity for event in completed for identity in event[2]}
        actual = Store(settings)
        assert len(expected_ids) == 12
        assert {profile["id"] for profile in actual.list_profiles(owner["id"])} == expected_ids
        with actual.connection() as db:
            assert db.execute("SELECT value FROM metadata WHERE key='concurrency-counter'").fetchone()[0] == "12"
        assert json.loads(settings.database.read_text(encoding="utf-8"))["format"] == "shared-node-manager-json"
    finally:
        start.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
            if process.pid is not None:
                process.join(timeout=5)
        events.close()
