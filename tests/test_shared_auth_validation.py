"""Authentication accepts arbitrary nonempty account/password strings safely."""
from dataclasses import replace
import json

from fastapi.testclient import TestClient
import httpx
import pytest

from shared_manager.agent import Agent
from shared_manager.app import create_app
from shared_manager.settings import Settings


ORIGIN = "http://localhost:8090"
PASSWORD = "private-response-secret-123"
USERNAME_DETAIL = "请输入账号。"
PASSWORD_DETAIL = "请输入密码。"
BODY_DETAIL = "登录或注册信息格式无效，请检查输入。"


@pytest.fixture
def auth_app(tmp_path):
    settings = Settings(secret="auth-validation-secret-" * 3,
                        agent_token="auth-validation-agent-" * 3,
                        origin=ORIGIN, database=tmp_path / "accounts.json")
    calls = []

    def no_node(request):
        calls.append(request.url.path)
        raise AssertionError("Authentication must not contact a node")

    agent = Agent(settings, transport=httpx.MockTransport(no_node))
    app = create_app(settings, agent)
    assert_json_account_file(app.state.store)
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        yield client, app.state.store
    assert_json_account_file(app.state.store)
    agent.close()
    assert calls == []


def assert_json_account_file(store):
    path = store.settings.database
    assert path.suffix == ".json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    assert "users" in document["tables"]
    assert not path.read_bytes().startswith(b"SQLite format 3")
    assert not list(path.parent.glob("*.sqlite3"))
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()


def assert_no_accounts_or_sessions(store):
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM profiles").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM rate_limits").fetchone()[0] == 0


@pytest.mark.parametrize("endpoint", ["register", "login"])
@pytest.mark.parametrize("username", [
    "", "   ", "\t\n", None, 123, [], {},
])
def test_invalid_account_gets_specific_chinese_guidance(auth_app, endpoint, username):
    client, store = auth_app
    response = client.post("/api/auth/" + endpoint,
                           json={"username": username, "password": PASSWORD})
    assert response.status_code == 422
    assert response.json() == {"detail": USERNAME_DETAIL, "field": "username"}
    assert PASSWORD not in response.text
    if isinstance(username, str) and username:
        assert username not in response.text
    assert_no_accounts_or_sessions(store)


@pytest.mark.parametrize("endpoint", ["register", "login"])
@pytest.mark.parametrize("password", ["", None, 123, [], {}])
def test_invalid_password_gets_specific_guidance_without_echo(auth_app, endpoint, password):
    client, store = auth_app
    response = client.post("/api/auth/" + endpoint,
                           json={"username": "private_user", "password": password})
    assert response.status_code == 422
    assert response.json() == {"detail": PASSWORD_DETAIL, "field": "password"}
    assert "private_user" not in response.text
    if isinstance(password, str) and password:
        assert password not in response.text
    assert_no_accounts_or_sessions(store)


@pytest.mark.parametrize("endpoint", ["register", "login"])
def test_invalid_account_has_priority_when_both_fields_are_invalid(auth_app, endpoint):
    client, store = auth_app
    response = client.post("/api/auth/" + endpoint,
                           json={"username": "", "password": ""})
    assert response.status_code == 422
    assert response.json() == {"detail": USERNAME_DETAIL, "field": "username"}
    assert_no_accounts_or_sessions(store)


@pytest.mark.parametrize("endpoint", ["register", "login"])
@pytest.mark.parametrize("extra", [{"isAdmin": True}, {"role": "admin"}, {"private_extra": PASSWORD}])
def test_extra_auth_fields_are_rejected_without_privilege_or_input_echo(auth_app, endpoint, extra):
    client, store = auth_app
    response = client.post("/api/auth/" + endpoint,
                           json={"username": "private_user", "password": PASSWORD, **extra})
    assert response.status_code == 422
    assert response.json() == {"detail": BODY_DETAIL}
    assert PASSWORD not in response.text and "private_user" not in response.text
    assert_no_accounts_or_sessions(store)


@pytest.mark.parametrize("endpoint", ["register", "login"])
def test_non_object_auth_body_is_rejected_safely(auth_app, endpoint):
    client, store = auth_app
    response = client.post("/api/auth/" + endpoint, json=["private_user", PASSWORD])
    assert response.status_code == 422
    assert response.json() == {"detail": BODY_DETAIL}
    assert PASSWORD not in response.text and "private_user" not in response.text
    assert_no_accounts_or_sessions(store)


@pytest.mark.parametrize("endpoint", ["register", "login"])
def test_malformed_json_does_not_echo_private_body(auth_app, endpoint):
    client, store = auth_app
    response = client.post("/api/auth/" + endpoint,
                           content='{"username":"private_user","password":"' + PASSWORD,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert response.json() == {"detail": BODY_DETAIL}
    assert PASSWORD not in response.text and "private_user" not in response.text
    assert_no_accounts_or_sessions(store)


@pytest.mark.parametrize("username", [
    "111", "a.b_c-d", "A" + "b" * 31, "a", "ab", "a" * 256,
    "中文用户", "email@example.com", "user name", ".user", "_user", "-user",
    "user/name", "user+name", "Émile",
])
def test_arbitrary_nonempty_accounts_can_register_and_login(auth_app, username):
    client, store = auth_app
    registered = client.post("/api/auth/register", json={"username": username, "password": PASSWORD})
    assert registered.status_code == 201
    assert registered.json()["user"]["username"] == username.lower()
    assert registered.json()["user"]["isAdmin"] is False
    logged_in = client.post("/api/auth/login", json={"username": username.upper(), "password": PASSWORD})
    assert logged_in.status_code == 200
    assert logged_in.json()["user"]["username"] == username.lower()
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 1


def test_username_boundary_spaces_are_trimmed_without_changing_password(auth_app):
    client, store = auth_app
    password = "  private-login-password  "
    registered = client.post("/api/auth/register", json={"username": "  Mixed.Name_1-2  ", "password": password})
    assert registered.status_code == 201
    assert registered.json()["user"]["username"] == "mixed.name_1-2"
    logged_in = client.post("/api/auth/login", json={"username": " \tMIXED.NAME_1-2\t ", "password": password})
    assert logged_in.status_code == 200
    assert logged_in.json()["user"]["username"] == "mixed.name_1-2"
    trimmed_password = client.post("/api/auth/login", json={"username": "mixed.name_1-2", "password": password.strip()})
    assert trimmed_password.status_code == 401
    assert password not in trimmed_password.text and password.strip() not in trimmed_password.text
    assert store.authenticate("mixed.name_1-2", password) is not None
    assert store.authenticate("mixed.name_1-2", password.strip()) is None


@pytest.mark.parametrize("password", ["p", " ", "123", "p" * 129, "p" * 512, "🔐"])
def test_arbitrary_nonempty_passwords_can_register_and_login(auth_app, password):
    client, _ = auth_app
    registered = client.post("/api/auth/register", json={"username": "password_boundary", "password": password})
    assert registered.status_code == 201
    logged_in = client.post("/api/auth/login", json={"username": "password_boundary", "password": password})
    assert logged_in.status_code == 200


def test_registration_disabled_still_rejects_short_unicode_credentials_on_json(auth_app):
    _, store = auth_app
    settings = replace(store.settings, registration_enabled=False)

    def no_node(_request):
        raise AssertionError("Disabled registration must not contact a node")

    agent = Agent(settings, transport=httpx.MockTransport(no_node))
    with TestClient(create_app(settings, agent), base_url=ORIGIN,
                    headers={"Origin": ORIGIN}) as client:
        assert client.get("/api/site").json()["registrationEnabled"] is False
        response = client.post("/api/auth/register", json={"username": "中", "password": "1"})
        assert response.status_code == 403
    agent.close()
    assert_no_accounts_or_sessions(store)
    assert_json_account_file(store)

