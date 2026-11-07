import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import time
from unittest.mock import patch

from fastapi.testclient import TestClient
import httpx
import pytest

from shared_manager.agent import Agent, AgentError
from shared_manager.app import create_app
from shared_manager.settings import Settings
from shared_manager.store import Store


ORIGIN = "http://localhost:8090"


class MockNode:
    def __init__(self):
        self.users = {}
        self.creates = []
        self.drop_create_reply = False
        self.unavailable = False
        self.suspend = False
        self.proxies = {}
        self.routes = []
        self.drop_route_reply = False

    def __call__(self, request):
        assert request.headers["Authorization"] == "Bearer " + "agent-token-" * 3
        if self.unavailable:
            raise httpx.ConnectError("private failure with secrets", request=request)
        if self.suspend:
            return httpx.Response(409, json={"detail": "private-secret"})
        if request.method == "POST" and request.url.path == "/api/user/bind-proxy":
            payload = json.loads(request.content)
            self.routes.append((dict(request.headers), payload))
            self.proxies[payload["userId"]] = {"userId": payload["userId"], "proxyBound": True, **payload["proxy"]}
            if self.drop_route_reply:
                self.drop_route_reply = False
                raise httpx.ReadTimeout("route response lost", request=request)
            return httpx.Response(200, json={"success": True, "userId": payload["userId"]})
        if request.method == "POST" and request.url.path.endswith("/direct"):
            identity = request.url.path.split("/")[3]
            self.routes.append((dict(request.headers), {"mode": "direct", "userId": identity}))
            self.proxies[identity] = {"userId": identity, "proxyBound": False}
            return httpx.Response(200, json={"success": True, "userId": identity})
        if request.method == "POST":
            payload = json.loads(request.content)
            self.creates.append((dict(request.headers), payload))
            identity = payload["userId"]
            socks = {"host": "150.242.80.15", "port": 35001, "username": payload["socksUsername"], "password": payload["socksPassword"]}
            self.users[identity] = {"success": True, "userId": identity, "uuid": payload["uuid"],
                "vless": "vless://" + payload["uuid"] + "@150.242.80.15:32168",
                "vmess": "vmess://" + base64.b64encode(json.dumps({"id": payload["uuid"]}).encode()).decode(),
                "protocolsAll": {"socksAcceleration": "socks://" + base64.b64encode((socks["username"] + ":" + socks["password"]).encode()).decode() + "@150.242.80.15:35001"},
                "socks": socks, "expiresAt": payload["expiresAt"]}
            if self.drop_create_reply:
                self.drop_create_reply = False
                raise httpx.ReadTimeout("response lost", request=request)
            return httpx.Response(200, json=self.users[identity])
        identity = request.url.path.split("/")[3]
        if request.url.path.endswith("/proxy"):
            return httpx.Response(200, json=self.proxies.get(identity, {"userId": identity, "proxyBound": False}))
        if request.url.path.endswith("/traffic"):
            return httpx.Response(200, json={"userId": identity, "upload": 12, "download": 30, "total": 42,
                "available": True, "onlineConnections": [{"private": "must-not-be-exposed"}], "activeSourceIps": ["private-ip"]})
        return httpx.Response(200, json=self.users[identity]) if identity in self.users else httpx.Response(404)


@pytest.fixture
def setup(tmp_path):
    settings = Settings(secret="portal-secret-" * 4, agent_token="agent-token-" * 3, origin=ORIGIN, database=tmp_path / "accounts.json")
    node = MockNode()
    agent = Agent(settings, transport=httpx.MockTransport(node))
    app = create_app(settings, agent=agent)
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        yield settings, node, app, client
    agent.close()


def register(client, name="alice"):
    result = client.post("/api/auth/register", json={"username": name, "password": "example-password-123"})
    assert result.status_code == 201, result.text
    return result.json()


def generate(client, session):
    return client.post("/api/me/connections", json={}, headers={"X-CSRF-Token": session["csrfToken"]})


def test_register_login_generate_and_logout(setup):
    settings, node, app, client = setup
    session = register(client)
    assert session["connectionState"] == "EMPTY"
    assert not node.creates
    result = generate(client, session)
    assert result.status_code == 200
    data = result.json()
    assert [x["protocol"] for x in data["links"]] == ["vless", "vmess", "socks"]
    assert data["socks"]["password"] != "example-password-123"
    assert node.creates[0][1]["requireReadiness"] is True
    assert "proxy" not in node.creates[0][1]
    assert client.get("/api/me/connections").json() == data
    assert generate(client, session).json() == data
    assert len(node.creates) == 1
    old_token = client.cookies.get("shared_session")
    assert client.post("/api/auth/logout", json={}, headers={"X-CSRF-Token": session["csrfToken"]}).status_code == 200
    assert app.state.store.session_user(old_token) is None
    assert client.get("/api/me/connections").status_code == 401
    result = client.post("/api/auth/login", json={"username": "ALICE", "password": "example-password-123"})
    assert result.status_code == 200
    assert result.json()["connectionState"] == "READY"


def test_legacy_missing_user_409_is_distinguished_from_suspended(setup):
    settings, node, app, client = setup
    original = node.__call__
    def legacy(request):
        result = original(request)
        if result.status_code == 404:
            return httpx.Response(409, json={"detail": "user not found: " + request.url.path.split("/")[3]})
        return result
    # Swap only the HTTP transport; the portal still calls the real Agent logic.
    app_agent = Agent(settings, transport=httpx.MockTransport(legacy))
    with TestClient(create_app(settings, app_agent), base_url=ORIGIN, headers={"Origin": ORIGIN}) as browser:
        session = register(browser)
        assert generate(browser, session).status_code == 200
        assert len(node.creates) == 1
        node.suspend = True
        assert generate(browser, session).status_code == 409
        assert len(node.creates) == 1
    app_agent.close()


def test_user_isolation_and_no_agent_admin_routes(setup):
    _, node, app, client = setup
    alice = register(client)
    first = generate(client, alice).json()
    bob = register(client, "bob")
    assert client.get("/api/me/connections").status_code == 404
    second = generate(client, bob).json()
    assert first["links"] != second["links"]
    assert first["socks"]["username"] != second["socks"]["username"]
    alice_id = node.creates[0][1]["userId"]
    assert client.get("/api/me/connections", params={"userId": alice_id}).json() == second
    for path in ["/api/users", "/api/agent/info", "/api/user/" + alice_id + "/connections"]:
        assert client.get(path).status_code == 404
    assert "agent-token" not in client.get("/api/site").text


def test_body_origin_csrf_and_password_validation(setup):
    _, _, _, client = setup
    assert client.post("/api/auth/register", json={"username": "alice", "password": "example-password-123"}, headers={"Origin": "https://evil.example"}).status_code == 403
    invalid = client.post("/api/auth/register", json={"username": "", "password": "secret"})
    assert invalid.status_code == 422
    assert "secret" not in invalid.text
    assert client.post("/api/auth/register", content=b"x" * 17000, headers={"Content-Type": "application/json"}).status_code == 413
    session = register(client)
    assert client.post("/api/me/connections", json={}).status_code == 403
    assert client.post("/api/auth/logout", json={}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert generate(client, session).status_code == 200


def test_lost_create_response_recovers_without_duplicate(setup):
    settings, node, app, client = setup
    session = register(client)
    node.drop_create_reply = True
    assert generate(client, session).status_code == 503
    restarted = Store(settings)
    allocation = restarted.allocation(app.state.store.session_user(client.cookies.get("shared_session"))["id"])
    assert not allocation["ready"]
    assert generate(client, session).status_code == 200
    assert len(node.creates) == 1


def test_cannot_recreate_removed_or_suspended_user(setup):
    _, node, _, client = setup
    session = register(client)
    assert generate(client, session).status_code == 200
    node.suspend = True
    response = generate(client, session)
    assert response.status_code == 409
    assert "private-secret" not in response.text
    node.suspend = False
    node.users.clear()
    assert generate(client, session).status_code == 409
    assert len(node.creates) == 1


def test_foreign_identity_is_never_returned(setup):
    _, node, _, client = setup
    session = register(client)
    assert generate(client, session).status_code == 200
    value = next(iter(node.users.values()))
    value["uuid"] = "another-users-uuid"
    assert client.get("/api/me/connections").status_code == 409


def test_private_storage_and_atomic_allocation(setup):
    settings, node, app, client = setup
    register(client)
    user = app.state.store.session_user(client.cookies.get("shared_session"))
    with ThreadPoolExecutor(max_workers=8) as pool:
        allocations = list(pool.map(lambda _: app.state.store.allocation(user["id"], create=True), range(8)))
    assert len({a["node_user_id"] for a in allocations}) == 1
    assert len({a["request"]["uuid"] for a in allocations}) == 1
    with app.state.store.connection() as db:
        row = db.execute("SELECT * FROM users").fetchone()
        cipher = db.execute("SELECT payload FROM allocations").fetchone()[0]
        assert "example-password-123" not in row["password_hash"]
        assert allocations[0]["request"]["socksPassword"].encode() not in cipher
        assert client.cookies.get("shared_session") != db.execute("SELECT token_hash FROM sessions").fetchone()[0]
    with pytest.raises(ValueError, match="不匹配"):
        Store(replace(settings, secret="different-secret-" * 4))


def test_cookie_and_cache_headers(setup):
    settings, node, app, client = setup
    response = client.post("/api/auth/register", json={"username": "alice", "password": "example-password-123"})
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]
    assert "no-store" in response.headers["cache-control"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]
    secure = replace(settings, origin="https://shared.example.com", database=settings.database.parent / "secure.sqlite3")
    with TestClient(create_app(secure, Agent(secure, transport=httpx.MockTransport(node))), base_url=secure.origin, headers={"Origin": secure.origin}) as browser:
        register(browser)
        assert browser.cookies.get("shared_session")
        assert next(iter(browser.cookies.jar)).secure


def test_disabled_expired_session_and_capacity(setup):
    settings, node, app, client = setup
    session = register(client)
    user = app.state.store.session_user(client.cookies.get("shared_session"))
    with app.state.store.connection() as db:
        db.execute("UPDATE sessions SET expires_at=0")
    assert client.get("/api/me").status_code == 401
    with app.state.store.connection() as db:
        db.execute("UPDATE users SET enabled=0 WHERE id=?", (user["id"],))
    assert client.post("/api/auth/login", json={"username": "alice", "password": "example-password-123"}).status_code == 401
    small = replace(settings, max_accounts=1)
    other_app = create_app(small, Agent(small, transport=httpx.MockTransport(node)))
    with TestClient(other_app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as browser:
        assert browser.post("/api/auth/register", json={"username": "bob", "password": "example-password-123"}).status_code == 409


def test_login_rate_limit_before_password_work(setup):
    _, _, app, client = setup
    register(client)
    for _ in range(10):
        assert client.post("/api/auth/login", json={"username": "alice", "password": "incorrect-password"}).status_code == 401
    with patch.object(app.state.store, "authenticate", side_effect=AssertionError("must throttle first")):
        assert client.post("/api/auth/login", json={"username": "alice", "password": "incorrect-password"}).status_code == 429


def test_registration_switch_and_https_required(setup):
    settings, node, _, _ = setup
    with pytest.raises(ValueError, match="HTTPS"):
        replace(settings, origin="http://shared.example.com")
    closed = replace(settings, registration_enabled=False)
    with TestClient(create_app(closed, Agent(closed, transport=httpx.MockTransport(node))), base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        assert client.get("/api/site").json()["registrationEnabled"] is False
        assert client.post("/api/auth/register", json={"username": "bob", "password": "example-password-123"}).status_code == 403


def test_static_page_and_openapi(setup):
    _, _, app, client = setup
    assert client.get("/").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    schema = app.openapi()
    assert {"/api/me/upstream", "/api/me/traffic", "/api/me/connections"} <= set(schema["paths"])
    for path, methods in schema["paths"].items():
        if path.startswith("/subscription/"):
            continue
        for operation in methods.values():
            response = operation["responses"].get("200") or operation["responses"].get("201")
            assert response["content"]["application/json"]["schema"]


def test_upstream_default_bind_and_restore_direct(setup):
    _, node, app, client = setup
    session = register(client)
    assert client.get("/api/me/upstream").json() == {"mode": "direct", "state": "APPLIED", "server": None,
        "port": None, "username": None, "passwordConfigured": False}
    headers = {"X-CSRF-Token": session["csrfToken"]}
    upstream = {"server": "8.8.8.8", "port": 1080, "username": "supplier-account", "password": "supplier-secret"}
    assert client.put("/api/me/upstream", json=upstream, headers=headers).status_code == 409
    original = generate(client, session).json()
    response = client.put("/api/me/upstream", json=upstream, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["mode"] == "socks5"
    assert "supplier-secret" not in response.text
    assert response.json()["passwordConfigured"] is True
    assert node.routes[0][1]["syncSocksCredentials"] is False
    assert client.get("/api/me/connections").json() == original
    user = app.state.store.session_user(client.cookies.get("shared_session"))
    with app.state.store.connection() as db:
        encrypted = db.execute("SELECT applied FROM upstreams WHERE user_id=?", (user["id"],)).fetchone()[0]
        assert b"supplier-secret" not in encrypted
    assert client.request("DELETE", "/api/me/upstream", json={}, headers=headers).status_code == 200
    assert client.get("/api/me/upstream").json()["mode"] == "direct"
    assert node.routes[-1][1]["mode"] == "direct"


def test_upstream_lost_reply_persists_and_readback_settles(setup):
    settings, node, app, client = setup
    session = register(client)
    generate(client, session)
    headers = {"X-CSRF-Token": session["csrfToken"]}
    upstream = {"server": "upstream.example.com", "port": 1080, "username": "supplier", "password": "supplier-secret"}
    answer = [(2, 1, 6, "", ("8.8.4.4", 1080))]
    node.drop_route_reply = True
    with patch("shared_manager.agent.socket.getaddrinfo", return_value=answer):
        assert client.put("/api/me/upstream", json=upstream, headers=headers).status_code == 503
    store = Store(settings)
    user = store.session_user(client.cookies.get("shared_session"))
    pending = store.upstream(user["id"])
    assert pending["pending"]["resolvedServer"] == "8.8.4.4"
    assert pending["pending_id"]
    # Exact retry must keep the saved IP even when DNS would now fail.
    with patch("shared_manager.agent.socket.getaddrinfo", side_effect=AssertionError("retry must not resolve")):
        response = client.put("/api/me/upstream", json=upstream, headers=headers)
    assert response.status_code == 200, response.text
    assert len(node.routes) == 1
    assert store.upstream(user["id"])["pending"] is None


def test_upstream_pending_rejects_conflicting_mutation(setup):
    _, node, app, client = setup
    session = register(client)
    generate(client, session)
    headers = {"X-CSRF-Token": session["csrfToken"]}
    node.unavailable = True
    upstream = {"server": "8.8.8.8", "port": 1080, "username": "", "password": ""}
    assert client.put("/api/me/upstream", json=upstream, headers=headers).status_code == 503
    assert client.put("/api/me/upstream", json={**upstream, "port": 1090}, headers=headers).status_code == 409
    assert client.request("DELETE", "/api/me/upstream", json={}, headers=headers).status_code == 409
    node.unavailable = False
    assert client.put("/api/me/upstream", json=upstream, headers=headers).status_code == 200


@pytest.mark.parametrize("server", ["127.0.0.1", "10.44.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1", "http://example.com", "8.8.8.8/path", "8.8.8.8%eth0"])
def test_upstream_rejects_internal_and_invalid_hosts(setup, server):
    _, node, app, client = setup
    session = register(client)
    generate(client, session)
    result = client.put("/api/me/upstream", json={"server": server, "port": 1080}, headers={"X-CSRF-Token": session["csrfToken"]})
    assert result.status_code == 422, result.text
    assert not node.routes


def test_upstream_dns_with_any_private_address_is_rejected(setup):
    _, node, _, client = setup
    session = register(client)
    generate(client, session)
    answer = [(2, 1, 6, "", ("8.8.8.8", 1080)), (2, 1, 6, "", ("10.44.0.1", 1080))]
    with patch("shared_manager.agent.socket.getaddrinfo", return_value=answer):
        response = client.put("/api/me/upstream", json={"server": "rebinding.example", "port": 1080}, headers={"X-CSRF-Token": session["csrfToken"]})
    assert response.status_code == 422
    assert not node.routes


def test_upstream_and_traffic_are_self_only(setup):
    _, node, _, client = setup
    alice = register(client)
    generate(client, alice)
    payload = {"server": "8.8.8.8", "port": 1080, "username": "alice-upstream", "password": "secret"}
    assert client.put("/api/me/upstream", json=payload, headers={"X-CSRF-Token": alice["csrfToken"]}).status_code == 200
    traffic = client.get("/api/me/traffic").json()
    assert traffic["total"] == 42
    assert traffic["onlineConnectionCount"] == 1
    assert "private" not in json.dumps(traffic)
    bob = register(client, "bob")
    assert client.get("/api/me/upstream").json()["mode"] == "direct"
    assert client.get("/api/me/traffic").json()["available"] is False
    assert client.put("/api/me/upstream", json=payload, headers={"X-CSRF-Token": bob["csrfToken"]}).status_code == 409


def test_upstream_denied_node_public_addresses(setup):
    settings, _, _, _ = setup
    with patch.dict("os.environ", {"SHARED_UPSTREAM_DENY_HOSTS": "150.242.80.15,168.93.208.118"}):
        agent = Agent(settings, transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    try:
        for host in ["150.242.80.15", "168.93.208.118", "::ffff:150.242.80.15", "::ffff:168.93.208.118"]:
            with pytest.raises(AgentError) as error:
                agent.public_upstream(host, 1080, "", "")
            assert error.value.status == 422
    finally:
        agent.close()
