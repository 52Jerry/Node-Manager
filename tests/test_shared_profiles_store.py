from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hmac
import json
import secrets
from unittest.mock import patch

import pytest

from shared_manager.settings import Settings
from shared_manager.store import (CapacityError, PendingUpstream, ProfileConflict,
                                  ProfileDeleting, ProfileNotFound, Store)


@pytest.fixture
def setup_store(tmp_path):
    settings = Settings(secret="profile-store-secret-" * 3, agent_token="agent-token-" * 3,
                        origin="http://localhost:8090", database=tmp_path / "profiles.sqlite3")
    store = Store(settings)
    alice = store.register("alice", "example-password-123")
    bob = store.register("bob", "example-password-456")
    return settings, store, alice["id"], bob["id"]


def test_multiple_profiles_have_independent_credentials_and_ownership(setup_store):
    _, store, alice, bob = setup_store
    first = store.create_profile(alice, "住宅 A", "first")
    second = store.create_profile(alice, "住宅 B", "second")
    assert len(store.list_profiles(alice)) == 2
    assert store.list_profiles(bob) == []
    assert first["node_user_id"] != second["node_user_id"]
    assert first["request"]["uuid"] != second["request"]["uuid"]
    assert first["request"]["socksUsername"] != second["request"]["socksUsername"]
    assert first["request"]["socksPassword"] != second["request"]["socksPassword"]
    assert store.get_profile(bob, first["id"]) is None
    with pytest.raises(ProfileNotFound):
        store.rename_profile(bob, first["id"], "别人的连接")
    with pytest.raises(ProfileNotFound):
        store.prepare_profile_upstream(bob, first["id"], {"mode": "direct"})


def test_concurrent_retries_fix_one_profile_identity(setup_store):
    _, store, alice, _ = setup_store
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda _: store.create_profile(alice, "同一请求", "durable-key"), range(12)))
    assert len({row["id"] for row in rows}) == 1
    assert len({row["request"]["uuid"] for row in rows}) == 1
    assert len(store.list_profiles(alice)) == 1
    with pytest.raises(ProfileConflict):
        store.create_profile(alice, "请求内容改变", "durable-key")


def test_different_keys_and_account_scoping(setup_store):
    _, store, alice, bob = setup_store
    a = store.create_profile(alice, "连接", "same-key")
    b = store.create_profile(bob, "连接", "same-key")
    c = store.create_profile(alice, "连接", "other-key")
    assert len({a["id"], b["id"], c["id"]}) == 3


def test_same_second_creation_preserves_default_profile(setup_store):
    _, store, alice, _ = setup_store
    with patch("shared_manager.store.time.time", return_value=1700000000):
        first = store.create_profile(alice, "第一个")
        for i in range(6):
            store.create_profile(alice, "后续 " + str(i))
    assert store.allocation(alice)["id"] == first["id"]
    assert store.list_profiles(alice)[0]["id"] == first["id"]


def test_profile_limit_is_atomic_under_concurrency(setup_store):
    _, store, alice, _ = setup_store
    for i in range(99):
        store.create_profile(alice, str(i), "key-" + str(i))
    def add(i):
        try:
            return store.create_profile(alice, "最后 " + str(i), "race-" + str(i))
        except CapacityError:
            return None
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(add, range(6)))
    assert len([row for row in results if row]) == 1
    assert len(store.list_profiles(alice)) == 100
    # Replaying an admitted key remains valid even at full capacity.
    assert store.create_profile(alice, "0", "key-0")["id"]


def test_rename_retains_credentials_and_create_identity(setup_store):
    _, store, alice, _ = setup_store
    original = store.create_profile(alice, "原名", "original")
    renamed = store.rename_profile(alice, original["id"], " 新名字 ")
    assert renamed["name"] == "新名字"
    assert renamed["request"] == original["request"]
    assert store.create_profile(alice, "原名", "original")["name"] == "新名字"
    for invalid in ["", "  ", "x" * 65, "test\nline"]:
        with pytest.raises(ValueError):
            store.create_profile(alice, invalid)


def test_upstream_mutations_are_isolated_and_encrypted(setup_store):
    _, store, alice, _ = setup_store
    first = store.create_profile(alice, "代理 A")
    second = store.create_profile(alice, "代理 B")
    desired = {"mode": "socks5", "server": "proxy.example.com", "resolvedServer": "203.0.113.9",
               "port": 1080, "username": "own-user", "password": "private-upstream-secret"}
    pending = store.prepare_profile_upstream(alice, first["id"], desired)
    assert store.prepare_profile_upstream(alice, first["id"], {**desired, "resolvedServer": "203.0.113.10"}) == pending
    with pytest.raises(PendingUpstream):
        store.prepare_profile_upstream(alice, first["id"], {"mode": "direct"})
    assert store.get_profile_upstream(alice, second["id"])["applied"] == {"mode": "direct"}
    other = store.prepare_profile_upstream(alice, second["id"], {"mode": "direct"})
    store.apply_profile_upstream(alice, second["id"], other["operation_id"])
    store.apply_profile_upstream(alice, first["id"], pending["operation_id"])
    assert store.get_profile_upstream(alice, first["id"])["applied"] == desired
    with store.connection() as db:
        raw = db.execute("SELECT applied FROM profile_upstreams WHERE profile_id=?", (first["id"],)).fetchone()[0]
        assert b"private-upstream-secret" not in raw
        profile_cipher = db.execute("SELECT payload FROM profiles WHERE id=?", (first["id"],)).fetchone()[0]
        assert first["request"]["socksPassword"].encode() not in profile_cipher


def test_delete_freezes_mutations_and_preserves_replay_tombstone(setup_store):
    settings, store, alice, _ = setup_store
    profile = store.create_profile(alice, "要删除的连接", "delete-this")
    with pytest.raises(ProfileConflict):
        store.delete_profile(alice, profile["id"])
    frozen = store.begin_delete_profile(alice, profile["id"])
    assert frozen["deleting"]
    assert store.list_profiles(alice) == []
    assert len(store.list_profiles(alice, include_deleting=True)) == 1
    assert store.get_profile(alice, profile["id"])["deleting"]
    assert not store.mark_profile_ready(alice, profile["id"])
    with pytest.raises(ProfileDeleting):
        store.rename_profile(alice, profile["id"], "不能重命名")
    with pytest.raises(ProfileDeleting):
        store.prepare_profile_upstream(alice, profile["id"], {"mode": "direct"})
    store.delete_profile(alice, profile["id"])
    with pytest.raises(ProfileConflict):
        store.create_profile(alice, "要删除的连接", "delete-this")
    restarted = Store(settings)
    assert restarted.list_profiles(alice) == []
    with pytest.raises(ProfileConflict):
        restarted.create_profile(alice, "要删除的连接", "delete-this")


def test_pending_upstream_blocks_delete_until_settled(setup_store):
    _, store, alice, _ = setup_store
    profile = store.create_profile(alice, "还在变更")
    operation = store.prepare_profile_upstream(alice, profile["id"], {"mode": "direct"})
    with pytest.raises(PendingUpstream):
        store.begin_delete_profile(alice, profile["id"])
    assert not store.get_profile(alice, profile["id"])["deleting"]
    store.reject_profile_upstream(alice, profile["id"], operation["operation_id"])
    assert store.begin_delete_profile(alice, profile["id"])["deleting"]


def test_legacy_upgrade_preserves_identity_pending_upstream_and_sessions(setup_store):
    settings, store, alice, _ = setup_store
    legacy = store.allocation(alice, create=True)
    store.mark_ready(alice)
    token = store.create_session(alice)
    desired = {"mode": "socks5", "server": "proxy.example.com", "resolvedServer": "203.0.113.9",
               "port": 1080, "username": "old-user", "password": "old-private-secret"}
    operation = store.prepare_upstream(alice, desired)
    with store.connection() as db:
        db.execute("CREATE TABLE subscriptions (user_id TEXT PRIMARY KEY REFERENCES users(id), token_hash TEXT, encrypted_token BLOB)")
        nonce = secrets.token_bytes(12)
        subscription_cipher = nonce + store.cipher.encrypt(nonce, b"existing-subscription-token", ("subscription:" + alice).encode())
        db.execute("INSERT INTO subscriptions VALUES (?, ?, ?)", (alice, "existing-token-hash", subscription_cipher))
        cipher = db.execute("SELECT payload FROM allocations WHERE user_id=?", (alice,)).fetchone()[0]
        for table in ["profile_upstreams", "profile_create_requests", "profile_tombstones", "profiles"]:
            db.execute("DROP TABLE " + table)
        db.execute("DELETE FROM metadata WHERE key='profiles_migration_v1'")
    migrated = Store(settings)
    profile = migrated.list_profiles(alice)[0]
    assert profile["id"] == alice
    assert profile["ready"]
    assert profile["node_user_id"] == legacy["node_user_id"]
    assert profile["request"] == legacy["request"]
    assert migrated.session_user(token)["id"] == alice
    assert migrated.prepare_profile_upstream(alice, alice, desired)["operation_id"] == operation["operation_id"]
    with migrated.connection() as db:
        assert db.execute("SELECT payload FROM profiles WHERE id=?", (alice,)).fetchone()[0] == cipher
        subscription = db.execute("SELECT encrypted_token FROM subscriptions WHERE user_id=?", (alice,)).fetchone()[0]
        assert subscription == subscription_cipher
        assert migrated.cipher.decrypt(subscription[:12], subscription[12:], ("subscription:" + alice).encode()) == b"existing-subscription-token"
    assert len(Store(settings).list_profiles(alice)) == 1


def test_deleted_legacy_default_never_reuses_node_identity_or_remigrates(setup_store):
    settings, store, alice, _ = setup_store
    original = store.allocation(alice, create=True)
    store.begin_delete_profile(alice, original["id"])
    store.delete_profile(alice, original["id"])
    restarted = Store(settings)
    assert restarted.allocation(alice) is None
    replacement = restarted.allocation(alice, create=True)
    assert replacement["node_user_id"] != original["node_user_id"]
    assert replacement["idempotency_key"] != original["idempotency_key"]


def test_disabled_owner_cannot_create_and_foreign_delete_is_rejected(setup_store):
    _, store, alice, bob = setup_store
    profile = store.create_profile(alice, "私有连接")
    with pytest.raises(ProfileNotFound):
        store.begin_delete_profile(bob, profile["id"])
    with store.connection() as db:
        db.execute("UPDATE users SET enabled=0 WHERE id=?", (alice,))
    with pytest.raises(ProfileNotFound):
        store.create_profile(alice, "不能创建")


def test_initial_residential_route_is_part_of_first_create_payload(setup_store):
    settings, store, alice, _ = setup_store
    desired = {"mode": "socks5", "server": "proxy.example.com", "resolvedServer": "93.184.216.34",
               "port": 1080, "username": "provider-user", "password": "provider-private-secret"}
    profile = store.create_profile(alice, "首笔原子绑定", "atomic-create", initial_proxy=desired)
    assert profile["request"]["proxy"] == {"type": "socks5", "server": "93.184.216.34", "port": 1080,
                                            "username": "provider-user", "password": "provider-private-secret"}
    assert not profile["ready"]
    upstream = store.get_profile_upstream(alice, profile["id"])
    assert upstream["pending"] == desired
    assert upstream["pending_id"]
    # Restart/retry cannot omit the residential request or silently repin DNS.
    restarted = Store(settings)
    same = restarted.create_profile(alice, "首笔原子绑定", "atomic-create",
                                    initial_proxy={**desired, "resolvedServer": "1.1.1.1"})
    assert same["id"] == profile["id"]
    assert same["request"] == profile["request"]
    assert restarted.prepare_profile_upstream(alice, profile["id"], desired)["operation_id"] == upstream["pending_id"]
    with store.connection() as db:
        raw = db.execute("SELECT payload FROM profiles WHERE id=?", (profile["id"],)).fetchone()[0]
        assert b"provider-private-secret" not in raw
    with pytest.raises(ProfileConflict):
        store.create_profile(alice, "首笔原子绑定", "atomic-create")
    with pytest.raises(ProfileConflict):
        store.create_profile(alice, "首笔原子绑定", "atomic-create", initial_proxy={**desired, "password": "changed"})


def test_invalid_initial_route_never_admits_a_default_direct_profile(setup_store):
    _, store, alice, _ = setup_store
    for invalid in [{"mode": "direct"},
                    {"mode": "socks5", "server": "local", "resolvedServer": "127.0.0.1", "port": 1080, "username": "", "password": ""}]:
        with pytest.raises(ValueError):
            store.create_profile(alice, "不应创建", initial_proxy=invalid)
    assert store.list_profiles(alice) == []


def test_unconfirmed_atomic_initial_route_can_be_frozen_for_create_reconciliation(setup_store):
    _, store, alice, _ = setup_store
    desired = {"mode": "socks5", "server": "proxy.example.com", "resolvedServer": "93.184.216.34",
               "port": 1080, "username": "provider-user", "password": "provider-private-secret"}
    profile = store.create_profile(alice, "初始绑定未成功", "initial-rejected", initial_proxy=desired)
    assert not profile["ready"]
    assert store.begin_delete_profile(alice, profile["id"])["deleting"]
    # A created profile's later pending mutation keeps the stronger guard.
    other = store.create_profile(alice, "已经生成")
    store.mark_profile_ready(alice, other["id"])
    store.prepare_profile_upstream(alice, other["id"], desired)
    with pytest.raises(PendingUpstream):
        store.begin_delete_profile(alice, other["id"])


def test_default_and_explicit_quota_are_fixed_in_creation_identity(setup_store):
    settings, store, alice, _ = setup_store
    default = store.create_profile(alice, "默认额度", "default-quota")
    assert default["request"]["trafficLimitBytes"] == settings.traffic_limit_bytes
    chosen = store.create_profile(alice, "自定义额度", "chosen-quota", traffic_limit_bytes=64 * 1024**3)
    assert chosen["request"]["trafficLimitBytes"] == chosen["traffic_limit_bytes"] == 64 * 1024**3
    assert store.create_profile(alice, "自定义额度", "chosen-quota", traffic_limit_bytes=64 * 1024**3)["id"] == chosen["id"]
    with pytest.raises(ProfileConflict):
        store.create_profile(alice, "自定义额度", "chosen-quota", traffic_limit_bytes=65 * 1024**3)
    # Retrying the same omitted default after an operator default change retains
    # the first admitted request; only a fresh identity uses the new default.
    restarted = Store(replace(settings, traffic_limit_bytes=600 * 1024**3))
    assert restarted.create_profile(alice, "默认额度", "default-quota")["request"] == default["request"]
    with pytest.raises(ProfileConflict):
        restarted.create_profile(alice, "默认额度", "default-quota", traffic_limit_bytes=600 * 1024**3)
    assert restarted.create_profile(alice, "新默认额度")["traffic_limit_bytes"] == 600 * 1024**3


def test_policy_override_never_mutates_create_payload_or_key(setup_store):
    settings, store, alice, _ = setup_store
    profile = store.create_profile(alice, "独立策略", "immutable-policy", traffic_limit_bytes=10 * 1024**3)
    with store.connection() as db:
        original_cipher = db.execute("SELECT payload FROM profiles WHERE id=?", (profile["id"],)).fetchone()[0]
    with pytest.raises(ProfileConflict):
        store.update_profile_policy(alice, profile["id"], 300 * 1024**3)
    store.mark_profile_ready(alice, profile["id"])
    updated = store.update_profile_policy(alice, profile["id"], 300 * 1024**3)
    assert updated["traffic_limit_bytes"] == 300 * 1024**3
    assert updated["request"] == profile["request"]
    assert updated["idempotency_key"] == profile["idempotency_key"]
    with store.connection() as db:
        assert db.execute("SELECT payload FROM profiles WHERE id=?", (profile["id"],)).fetchone()[0] == original_cipher
    restarted = Store(settings)
    replay = restarted.create_profile(alice, "独立策略", "immutable-policy", traffic_limit_bytes=10 * 1024**3)
    assert replay["id"] == profile["id"] and replay["traffic_limit_bytes"] == 300 * 1024**3
    assert restarted.get_profile_policy(alice, profile["id"]) == {"trafficLimitBytes": 300 * 1024**3}
    with pytest.raises(ProfileConflict):
        restarted.create_profile(alice, "独立策略", "immutable-policy", traffic_limit_bytes=300 * 1024**3)


def test_quota_updates_are_owned_frozen_and_js_safe(setup_store):
    _, store, alice, bob = setup_store
    profile = store.create_profile(alice, "边界策略")
    store.mark_profile_ready(alice, profile["id"])
    with pytest.raises(ProfileNotFound):
        store.update_profile_policy(bob, profile["id"], 30)
    for value in [0, -1, True, "12", 1.5, 9007199254740992]:
        with pytest.raises(ValueError):
            store.create_profile(alice, "无效额度", traffic_limit_bytes=value)
        with pytest.raises(ValueError):
            store.set_profile_traffic_limit(alice, profile["id"], value)
    assert store.update_profile_policy(alice, profile["id"], 9007199254740991)["traffic_limit_bytes"] == 9007199254740991
    store.begin_delete_profile(alice, profile["id"])
    with pytest.raises(ProfileDeleting):
        store.update_profile_policy(alice, profile["id"], 300)


def test_quota_schema_upgrade_preserves_old_ten_gib_and_v1_replay(setup_store):
    settings, store, alice, _ = setup_store
    profile = store.create_profile(alice, "旧版十 GiB", "v1-key", traffic_limit_bytes=10 * 1024**3)
    # Materialize the actual previous profiles schema with no policy override
    # or quota-fingerprint version. Do not touch users, sessions or secret keys.
    with store.connection() as db:
        record = dict(db.execute("SELECT * FROM profiles WHERE id=?", (profile["id"],)).fetchone())
        key_hash = db.execute("SELECT key_hash FROM profile_create_requests WHERE owner_id=?", (alice,)).fetchone()[0]
        for table in ["profile_upstreams", "profile_create_requests", "profile_tombstones", "profiles"]:
            db.execute("DROP TABLE " + table)
        db.execute("""CREATE TABLE profiles (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
            name TEXT NOT NULL, created_at INTEGER NOT NULL, node_user_id TEXT NOT NULL UNIQUE, payload BLOB NOT NULL,
            ready INTEGER NOT NULL DEFAULT 0, deleting INTEGER NOT NULL DEFAULT 0)""")
        db.execute("INSERT INTO profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   tuple(record[k] for k in ["id", "owner_id", "name", "created_at", "node_user_id", "payload", "ready", "deleting"]))
        db.execute("""CREATE TABLE profile_create_requests (owner_id TEXT NOT NULL REFERENCES users(id),
            key_hash TEXT NOT NULL, fingerprint TEXT NOT NULL, profile_id TEXT NOT NULL, PRIMARY KEY(owner_id,key_hash))""")
        old_fingerprint = hmac.new(store.key, json.dumps({"name": "旧版十 GiB"}, sort_keys=True).encode(), "sha256").hexdigest()
        db.execute("INSERT INTO profile_create_requests VALUES (?, ?, ?, ?)", (alice, key_hash, old_fingerprint, profile["id"]))
    upgraded = Store(replace(settings, traffic_limit_bytes=300 * 1024**3))
    old = upgraded.get_profile(alice, profile["id"])
    assert old["traffic_limit_bytes"] == 10 * 1024**3
    assert old["request"] == profile["request"]
    assert upgraded.create_profile(alice, "旧版十 GiB", "v1-key")["id"] == profile["id"]
    assert upgraded.create_profile(alice, "旧版十 GiB", "v1-key", traffic_limit_bytes=10 * 1024**3)["id"] == profile["id"]
    with pytest.raises(ProfileConflict):
        upgraded.create_profile(alice, "旧版十 GiB", "v1-key", traffic_limit_bytes=300 * 1024**3)
