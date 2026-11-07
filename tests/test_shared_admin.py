"""Administrator visibility, durable authorization, and safe aggregate reporting."""
from datetime import datetime
from unittest.mock import patch

from fastapi.testclient import TestClient
import httpx
import pytest

from shared_manager.agent import Agent
from shared_manager.app import COOKIE, create_app
from shared_manager.settings import Settings
from shared_manager.store import Store


ORIGIN = "http://localhost:8090"
PASSWORD = "test-only-admin-password-123"
SUMMARY_KEYS = {"registeredUsers", "enabledUsers", "totalConnections", "readyConnections",
                "pendingConnections", "deletingConnections"}
USER_KEYS = {"username", "createdAt", "enabled", "isAdmin", "totalConnections",
             "readyConnections", "pendingConnections", "deletingConnections"}


@pytest.fixture
def admin_app(tmp_path):
    settings = Settings(secret="admin-test-secret-" * 3, agent_token="admin-agent-token-" * 3,
                        origin=ORIGIN, database=tmp_path / "accounts.json")
    node_calls = []

    def no_node(request):
        node_calls.append(request.url.path)
        raise AssertionError("Administrator reporting must not contact the node")

    agent = Agent(settings, transport=httpx.MockTransport(no_node))
    app = create_app(settings, agent)
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        yield settings, app.state.store, client, node_calls
    agent.close()
    assert node_calls == []


def authenticate(client, store, user):
    token = store.create_session(user["id"])
    client.cookies.set(COOKIE, token)
    return token


def administrator(client, store):
    user = store.register("111", PASSWORD)
    assert store.set_admin("111") is True
    authenticate(client, store, user)
    return user


def test_admin_api_requires_a_live_administrator_session(admin_app):
    _, store, client, _ = admin_app
    assert client.get("/api/admin/users").status_code == 401
    user = store.register("regular", PASSWORD)
    authenticate(client, store, user)
    assert client.get("/api/me").json()["user"]["isAdmin"] is False
    for params, headers in [({}, {}), ({"isAdmin": "true", "role": "admin"}, {}),
                            ({}, {"X-Admin": "true", "X-User-Role": "admin"})]:
        response = client.get("/api/admin/users", params=params, headers=headers)
        assert response.status_code == 403
        assert "regular" not in response.text


def test_registration_cannot_assign_administrator_privileges(admin_app):
    _, store, client, _ = admin_app
    for extra in [{"isAdmin": True}, {"is_admin": True}, {"role": "admin"}]:
        response = client.post("/api/auth/register", json={"username": "forged", "password": PASSWORD, **extra})
        assert response.status_code == 422
    response = client.post("/api/auth/register", json={"username": "111", "password": PASSWORD})
    assert response.status_code == 201
    assert response.json()["user"]["isAdmin"] is False
    assert client.get("/api/admin/users").status_code == 403
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 1


def test_role_grant_and_revocation_apply_to_existing_cookie(admin_app):
    _, store, client, _ = admin_app
    user = store.register("Original.Name", PASSWORD)
    token = authenticate(client, store, user)
    assert client.get("/api/admin/users").status_code == 403
    assert store.set_admin("ORIGINAL.NAME") is True
    assert client.cookies.get(COOKIE) == token
    assert client.get("/api/me").json()["user"]["isAdmin"] is True
    assert client.get("/api/admin/users").status_code == 200
    assert store.set_admin("original.name", enabled=False) is True
    assert client.get("/api/me").json()["user"]["isAdmin"] is False
    assert client.get("/api/admin/users").status_code == 403
    assert client.cookies.get(COOKIE) == token


def test_login_returns_the_persisted_role(admin_app):
    _, store, client, _ = admin_app
    store.register("operator", PASSWORD)
    assert store.set_admin("operator") is True
    response = client.post("/api/auth/login", json={"username": "OPERATOR", "password": PASSWORD})
    assert response.status_code == 200
    assert response.json()["user"]["isAdmin"] is True
    with store.connection() as db:
        db.execute("UPDATE users SET enabled=0 WHERE username='operator'")
    assert client.get("/api/admin/users").status_code == 401
    assert client.post("/api/auth/login", json={"username": "operator", "password": PASSWORD}).status_code == 401


def test_report_counts_each_profile_once_and_includes_empty_disabled_users(admin_app):
    _, store, client, _ = admin_app
    administrator(client, store)
    alice = store.register("alice_1", PASSWORD)
    bob = store.register("bob", PASSWORD)
    store.register("empty", PASSWORD)
    for index in range(4):
        profile = store.create_profile(alice["id"], "private-profile-" + str(index))
        if index < 3:
            store.mark_profile_ready(alice["id"], profile["id"])
        if index == 2:
            store.begin_delete_profile(alice["id"], profile["id"])
    store.create_profile(bob["id"], "disabled-pending")
    with store.connection() as db:
        db.execute("UPDATE users SET enabled=0 WHERE id=?", (bob["id"],))
    # Reports need counts only; using credential decryption would be unnecessary
    # and make the administrative endpoint depend on sensitive payload contents.
    with patch.object(store, "_profile_dict", side_effect=AssertionError("Unexpected credential decryption")):
        response = client.get("/api/admin/users")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["summary"] == {"registeredUsers": 4, "enabledUsers": 3, "totalConnections": 5,
                               "readyConnections": 2, "pendingConnections": 2, "deletingConnections": 1}
    assert data["total"] == 4
    rows = {row["username"]: row for row in data["items"]}
    assert {key: rows["alice_1"][key] for key in ("totalConnections", "readyConnections", "pendingConnections", "deletingConnections")} == {
        "totalConnections": 4, "readyConnections": 2, "pendingConnections": 1, "deletingConnections": 1}
    assert rows["111"]["isAdmin"] is True
    assert rows["empty"]["totalConnections"] == 0
    assert rows["bob"]["enabled"] is False
    assert rows["bob"]["pendingConnections"] == 1
    assert rows["alice_1"]["enabled"] is True
    for row in data["items"]:
        assert datetime.fromisoformat(row["createdAt"].replace("Z", "+00:00")).utcoffset() is not None


def test_report_is_allowlisted_and_does_not_expose_credentials_or_node_details(admin_app):
    settings, store, client, _ = admin_app
    user = administrator(client, store)
    profile = store.create_profile(user["id"], "private-profile-title")
    proxy = {"mode": "socks5", "server": "secret-upstream.example", "resolvedServer": "8.8.8.8",
             "port": 1080, "username": "private-upstream-user", "password": "private-upstream-password"}
    operation = store.prepare_profile_upstream(user["id"], profile["id"], proxy)
    store.apply_profile_upstream(user["id"], profile["id"], operation["operation_id"])
    response = client.get("/api/admin/users")
    assert response.status_code == 200
    data = response.json()
    assert set(data) == {"summary", "items", "total", "page", "pageSize", "totalPages"}
    assert set(data["summary"]) == SUMMARY_KEYS
    assert all(set(row) == USER_KEYS for row in data["items"])
    for secret in [PASSWORD, settings.secret, settings.agent_token, profile["node_user_id"],
                   profile["request"]["uuid"], profile["request"]["socksPassword"],
                   proxy["server"], proxy["username"], proxy["password"], "private-profile-title"]:
        assert secret not in response.text
    for forbidden in ["password_hash", "csrfToken", "payload", "node_user_id", "socksUsername", "encrypted_token"]:
        assert forbidden not in response.text


def test_search_is_a_case_insensitive_literal_substring_and_preserves_global_summary(admin_app):
    _, store, client, _ = admin_app
    administrator(client, store)
    store.register("Alice_One", PASSWORD)
    store.register("aliceTwo", PASSWORD)
    store.register("unrelated", PASSWORD)
    baseline = client.get("/api/admin/users").json()["summary"]
    for search, expected in [("ALICE", {"alice_one", "alicetwo"}), ("_", {"alice_one"}),
                             ("%", set()), ("alice%", set()), ("%' OR 1=1 --", set()),
                             ("\\", set()), ("not-present", set())]:
        response = client.get("/api/admin/users", params={"search": search})
        assert response.status_code == 200, response.text
        data = response.json()
        assert {row["username"] for row in data["items"]} == expected
        assert data["total"] == len(expected)
        assert data["summary"] == baseline


def test_pagination_is_bounded_and_stable_with_identical_registration_times(admin_app):
    _, store, client, _ = admin_app
    administrator(client, store)
    for name in ["user_a", "user_b", "user_c", "user_d"]:
        store.register(name, PASSWORD)
    with store.connection() as db:
        db.execute("UPDATE users SET created_at=1700000000")
    first = client.get("/api/admin/users", params={"page": 1, "pageSize": 2}).json()
    second = client.get("/api/admin/users", params={"page": 2, "pageSize": 2}).json()
    third = client.get("/api/admin/users", params={"page": 3, "pageSize": 2}).json()
    assert first["total"] == second["total"] == third["total"] == 5
    assert first["page"] == 1 and first["pageSize"] == 2 and first["totalPages"] == 3
    assert [len(page["items"]) for page in [first, second, third]] == [2, 2, 1]
    names = [row["username"] for page in [first, second, third] for row in page["items"]]
    assert len(set(names)) == 5
    assert client.get("/api/admin/users", params={"page": 1, "pageSize": 2}).json() == first
    assert client.get("/api/admin/users", params={"page": 1000, "pageSize": 2}).json()["items"] == []


@pytest.mark.parametrize("params", [{"page": 0}, {"page": -1}, {"page": "no"}, {"page": 1000001},
                                        {"pageSize": 0}, {"pageSize": 101}, {"pageSize": "no"},
                                        {"search": "x" * 65}])
def test_administrator_query_limits_are_validated(admin_app, params):
    _, store, client, _ = admin_app
    administrator(client, store)
    assert client.get("/api/admin/users", params=params).status_code == 422


def test_unknown_role_target_never_creates_an_account_and_empty_report_is_well_formed(admin_app):
    _, store, _, _ = admin_app
    assert store.set_admin("does-not-exist") is False
    assert store.set_admin("does-not-exist", enabled=False) is False
    data = store.admin_users()
    assert data["summary"] == dict.fromkeys(SUMMARY_KEYS, 0)
    assert data["items"] == [] and data["total"] == 0 and data["page"] == 1 and data["pageSize"] == 20
    assert data["totalPages"] == 1


def test_legacy_database_upgrade_preserves_credentials_sessions_and_profile_payloads(tmp_path):
    settings = Settings(secret="legacy-admin-secret-" * 3, agent_token="legacy-agent-token-" * 2,
                        origin=ORIGIN, database=tmp_path / "legacy.sqlite3")
    store = Store(settings)
    user = store.register("existing", PASSWORD)
    profile = store.create_profile(user["id"], "现有连接")
    store.mark_profile_ready(user["id"], profile["id"])
    token = store.create_session(user["id"])
    with store.connection() as db:
        original_user = tuple(db.execute("SELECT id,username,password_hash,created_at,enabled FROM users").fetchone())
        original_profile = tuple(db.execute("SELECT * FROM profiles").fetchone())
        original_session = tuple(db.execute("SELECT * FROM sessions").fetchone())
        assert "is_admin" in {row[1] for row in db.execute("PRAGMA table_info(users)")}
        db.execute("ALTER TABLE users DROP COLUMN is_admin")
    migrated = Store(settings)
    with migrated.connection() as db:
        assert tuple(db.execute("SELECT id,username,password_hash,created_at,enabled FROM users").fetchone()) == original_user
        assert tuple(db.execute("SELECT * FROM profiles").fetchone()) == original_profile
        assert tuple(db.execute("SELECT * FROM sessions").fetchone()) == original_session
        assert db.execute("SELECT is_admin FROM users").fetchone()[0] == 0
    assert migrated.authenticate("EXISTING", PASSWORD)["id"] == user["id"]
    assert migrated.session_user(token)["id"] == user["id"]
    assert migrated.session_user(token)["is_admin"] == 0
    assert migrated.get_profile(user["id"], profile["id"])["request"] == profile["request"]
    assert migrated.set_admin("EXISTING") is True
    assert Store(settings).session_user(token)["is_admin"] == 1
