import base64
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time

from fastapi.testclient import TestClient
import httpx
import pytest

from shared_manager.agent import Agent
from shared_manager.app import create_app
from shared_manager.settings import Settings
from test_shared_manager import MockNode, ORIGIN, register


class ProfileNode(MockNode):
    def __init__(self):
        super().__init__()
        self.reject_creates = False
        self.ignore_initial_proxy = False
        self.slow_create_started = None
        self.slow_create_release = None
        self.reject_servers = set()
        self.drop_delete_reply = False
        self.ignore_policy_changes = False
        self.policy_calls = []

    def __call__(self, request):
        if request.method == "PATCH" and request.url.path.endswith("/policy"):
            self.policy_calls.append(json.loads(request.content))
            identity = request.url.path.split("/")[3]
            if not self.ignore_policy_changes:
                self.users[identity]["trafficLimitBytes"] = json.loads(request.content)["trafficLimitBytes"]
            return httpx.Response(200, json={"success": True})
        if request.method == "GET" and request.url.path.endswith("/traffic"):
            identity = request.url.path.split("/")[3]
            return httpx.Response(200, json={"userId": identity, "upload": 12, "download": 30, "total": 42,
                "available": True, "trafficLimitBytes": self.users.get(identity, {}).get("trafficLimitBytes"),
                "activeSourceIps": [], "onlineConnections": []})
        if request.method == "DELETE" and request.url.path.startswith("/api/user/delete/"):
            identity = request.url.path.rsplit("/", 1)[-1]
            self.users.pop(identity, None)
            self.proxies.pop(identity, None)
            if self.drop_delete_reply:
                self.drop_delete_reply = False
                raise httpx.ReadTimeout("delete reply lost", request=request)
            return httpx.Response(200, json={"success": True})
        if request.method == "POST" and request.url.path == "/api/user/create":
            payload = json.loads(request.content)
            if self.reject_creates or (payload.get("proxy") or {}).get("server") in self.reject_servers:
                return httpx.Response(409, json={"detail": "duplicate proxy"})
            if self.slow_create_started:
                self.slow_create_started.set()
                assert self.slow_create_release.wait(5)
            lost_reply, self.drop_create_reply = self.drop_create_reply, False
            result = super().__call__(request)
            self.users[payload["userId"]]["trafficLimitBytes"] = payload["trafficLimitBytes"]
            if payload.get("proxy") and not self.ignore_initial_proxy:
                self.proxies[payload["userId"]] = {"userId": payload["userId"], "proxyBound": True, **payload["proxy"]}
                self.users[payload["userId"]]["proxyBound"] = True
            if lost_reply:
                raise httpx.ReadTimeout("atomic proxy create reply lost", request=request)
            return result
        return super().__call__(request)


@pytest.fixture
def profile_setup(tmp_path):
    settings = Settings(secret="profile-secret-" * 4, agent_token="agent-token-" * 3, origin=ORIGIN,
                        database=tmp_path / "accounts.json")
    node = ProfileNode()
    agent = Agent(settings, transport=httpx.MockTransport(node))
    app = create_app(settings, agent)
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        session = register(client)
        headers = {"X-CSRF-Token": session["csrfToken"]}
        yield settings, node, app, client, headers
    agent.close()


def create(client, headers, name="工作连接", key="create-one"):
    result = client.post("/api/me/profiles", json={"name": name, "idempotencyKey": key}, headers=headers)
    assert result.status_code == 201, result.text
    return result.json()


def test_multiple_profiles_have_distinct_credentials_and_upstreams(profile_setup):
    _, node, _, client, headers = profile_setup
    first = create(client, headers)
    second = create(client, headers, "备用连接", "create-two")
    assert first["id"] != second["id"]
    assert len(client.get("/api/me/profiles").json()["items"]) == 2
    one = client.get(f'/api/me/profiles/{first["id"]}/connections').json()
    two = client.get(f'/api/me/profiles/{second["id"]}/connections').json()
    assert one["socks"]["password"] != two["socks"]["password"]
    assert len(node.creates) == 2
    response = client.put(f'/api/me/profiles/{first["id"]}/upstream',
        json={"server": "8.8.8.8", "port": 1080, "username": "residential", "password": "private-password"}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["mode"] == "socks5"
    assert "private-password" not in response.text
    assert client.get(f'/api/me/profiles/{second["id"]}/upstream').json()["mode"] == "direct"
    assert client.request("DELETE", f'/api/me/profiles/{first["id"]}/upstream', json={}, headers=headers).status_code == 200


def test_cross_account_profile_access_is_not_found(profile_setup):
    _, node, _, client, headers = profile_setup
    profile = create(client, headers)
    bob = register(client, "bob")
    other_headers = {"X-CSRF-Token": bob["csrfToken"]}
    assert client.get("/api/me/profiles").json()["items"] == []
    root = f'/api/me/profiles/{profile["id"]}'
    for path in [root + "/connections", root + "/upstream", root + "/traffic"]:
        assert client.get(path).status_code == 404
    assert client.patch(root, json={"name": "stolen"}, headers=other_headers).status_code == 404
    assert client.request("DELETE", root, json={}, headers=other_headers).status_code == 404
    assert len(node.users) == 1


def test_rename_rewrites_only_own_display_labels(profile_setup):
    _, _, _, client, headers = profile_setup
    profile = create(client, headers)
    prefix = f'/api/me/profiles/{profile["id"]}'
    original = client.get(prefix + "/connections").json()
    assert client.patch(prefix, json={"name": "我的住宅"}, headers=headers).status_code == 200
    renamed = client.get(prefix + "/connections").json()
    assert original["socks"] == renamed["socks"]
    assert "我的住宅" in json.loads(base64.b64decode(renamed["links"][1]["uri"][8:]))["ps"]
    assert "node-manager" not in json.dumps(renamed)


def test_profile_delete_revokes_only_target_and_creation_replay(profile_setup):
    _, node, _, client, headers = profile_setup
    one = create(client, headers)
    two = create(client, headers, "保留", "keep")
    assert client.request("DELETE", f'/api/me/profiles/{one["id"]}', json={}, headers=headers).status_code == 200
    assert len(node.users) == 1
    assert [p["id"] for p in client.get("/api/me/profiles").json()["items"]] == [two["id"]]
    assert client.get(f'/api/me/profiles/{one["id"]}/connections').status_code == 404
    replay = client.post("/api/me/profiles", json={"name": "工作连接", "idempotencyKey": "create-one"}, headers=headers)
    assert replay.status_code == 409
    assert len(node.creates) == 2


def test_import_preview_and_idempotent_atomic_proxy_creation(profile_setup):
    _, node, _, client, headers = profile_setup
    text = "8.8.8.8:1080:first:password-one\nsocks5://second:password-two@1.1.1.1:1080#备用"
    preview = client.post("/api/me/profiles/import/preview", json={"text": text}, headers=headers)
    assert preview.status_code == 200
    assert preview.json()["validCount"] == 2
    assert "password-one" not in preview.text and "password-two" not in preview.text
    body = {"text": text, "idempotencyKey": "batch-one"}
    response = client.post("/api/me/profiles/import", json=body, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["createdCount"] == 2
    assert response.json()["failedCount"] == 0
    assert all(c[1].get("proxy") for c in node.creates)
    assert len(node.routes) == 0  # proxy committed as part of create, never direct first
    ids = [item["profileId"] for item in response.json()["items"]]
    replay = client.post("/api/me/profiles/import", json=body, headers=headers)
    assert [item["profileId"] for item in replay.json()["items"]] == ids
    assert len(node.creates) == 2
    new_key_replay = client.post("/api/me/profiles/import", json={**body, "idempotencyKey": "after-reload"}, headers=headers)
    assert [item["profileId"] for item in new_key_replay.json()["items"]] == ids
    assert len(node.creates) == 2
    alias_changed = client.post("/api/me/profiles/import", json={"idempotencyKey": "after-reload", "text": "9.9.9.9:1080:u:p"}, headers=headers)
    assert alias_changed.status_code == 409
    assert len(node.creates) == 2
    changed = client.post("/api/me/profiles/import", json={**body, "text": text + "\n9.9.9.9:1080:u:p"}, headers=headers)
    assert changed.status_code == 409
    assert len(node.creates) == 2


@pytest.mark.parametrize("text", ["invalid-password-string", "8.8.8.8:1080:u:p\n8.8.8.8:1080:u:p", "127.0.0.1:1080:u:p"])
def test_import_invalid_rows_do_not_create_any_profiles(profile_setup, text):
    _, node, _, client, headers = profile_setup
    response = client.post("/api/me/profiles/import", json={"text": text, "idempotencyKey": "bad"}, headers=headers)
    assert response.status_code == 422
    assert not node.creates
    assert client.get("/api/me/profiles").json()["items"] == []


def test_unconfirmed_residential_import_never_releases_direct_links(profile_setup):
    _, node, _, client, headers = profile_setup
    node.ignore_initial_proxy = True
    response = client.post("/api/me/profiles/import", json={"text": "8.8.8.8:1080:u:private-password", "idempotencyKey": "unconfirmed"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["items"][0]["state"] == "PENDING"
    profile = client.get("/api/me/profiles").json()["items"][0]
    assert profile["state"] == "PENDING"
    assert client.get(f'/api/me/profiles/{profile["id"]}/connections').status_code == 503
    assert client.get("/api/me/connections").status_code == 503
    assert client.post("/api/me/subscription", json={}, headers=headers).status_code == 409


def test_rejected_import_can_be_deleted_without_orphan(profile_setup):
    _, node, _, client, headers = profile_setup
    node.reject_creates = True
    response = client.post("/api/me/profiles/import", json={"text": "8.8.8.8:1080:u:p", "idempotencyKey": "rejected"}, headers=headers)
    profile_id = response.json()["items"][0]["profileId"]
    assert response.json()["failedCount"] == 1
    assert client.request("DELETE", f'/api/me/profiles/{profile_id}', json={}, headers=headers).status_code == 200
    assert not node.users
    assert client.get("/api/me/profiles").json()["items"] == []


def test_delete_serializes_with_inflight_generation(profile_setup):
    _, node, app, client, headers = profile_setup
    user = app.state.store.session_user(client.cookies.get("shared_session"))
    profile = app.state.store.create_profile(user["id"], "race", "race-key")
    node.slow_create_started = threading.Event()
    node.slow_create_release = threading.Event()
    with ThreadPoolExecutor(max_workers=2) as pool:
        generating = pool.submit(client.post, f'/api/me/profiles/{profile["id"]}/connections', json={}, headers=headers)
        assert node.slow_create_started.wait(3)
        deleting = pool.submit(client.request, "DELETE", f'/api/me/profiles/{profile["id"]}', json={}, headers=headers)
        time.sleep(.1)
        assert not deleting.done()
        node.slow_create_release.set()
        assert generating.result().status_code == 200
        assert deleting.result().status_code == 200
    assert not node.users
    assert app.state.store.list_profiles(user["id"]) == []


def test_public_site_does_not_expose_topology(profile_setup):
    _, _, _, client, _ = profile_setup
    response = client.get("/api/site")
    assert response.json()["nodeName"] == "共享节点"
    assert not any(term in response.text for term in ["深圳", "香港", "深港", "10.44."])


def test_atomic_import_lost_reply_retries_same_identity(profile_setup):
    _, node, _, client, headers = profile_setup
    node.drop_create_reply = True
    body = {"text": "8.8.8.8:1080:u:p", "idempotencyKey": "lost-atomic-reply"}
    first = client.post("/api/me/profiles/import", json=body, headers=headers)
    assert first.json()["items"][0]["state"] == "PENDING"
    profile_id = first.json()["items"][0]["profileId"]
    assert client.get("/api/me/profiles").json()["items"][0]["state"] == "PENDING"
    replay = client.post("/api/me/profiles/import", json=body, headers=headers)
    assert replay.json()["items"][0]["state"] == "READY"
    assert replay.json()["items"][0]["profileId"] == profile_id
    assert len(node.creates) == 1


def test_import_partial_results_retry_without_duplicate_profiles(profile_setup):
    _, node, _, client, headers = profile_setup
    node.reject_servers = {"1.1.1.1"}
    body = {"text": "8.8.8.8:1080:a:one\n1.1.1.1:1080:b:two", "idempotencyKey": "partial"}
    first = client.post("/api/me/profiles/import", json=body, headers=headers).json()
    assert first["createdCount"] == 1 and first["failedCount"] == 1
    assert [row["state"] for row in first["items"]] == ["READY", "FAILED"]
    assert len(client.get("/api/me/profiles").json()["items"]) == 2
    node.reject_servers.clear()
    replay = client.post("/api/me/profiles/import", json=body, headers=headers).json()
    assert replay["createdCount"] == 2
    assert [r["profileId"] for r in first["items"]] == [r["profileId"] for r in replay["items"]]
    assert len(node.creates) == 2


def test_large_batch_has_only_scoped_body_budget(profile_setup):
    _, _, _, client, headers = profile_setup
    text = "\n".join(f'8.8.8.8:1080:user{i:02d}{"a" * 220}:{"b" * 240}' for i in range(40))
    assert len(text) > 16384
    result = client.post("/api/me/profiles/import/preview", json={"text": text}, headers=headers)
    assert result.status_code == 200 and result.json()["validCount"] == 40
    response = client.post("/api/auth/login", json={"username": "alice", "password": "b" * 20000})
    assert response.status_code == 413


def test_deletion_timeout_remains_visible_and_retryable(profile_setup):
    _, node, _, client, headers = profile_setup
    profile = create(client, headers)
    node.drop_delete_reply = True
    path = f'/api/me/profiles/{profile["id"]}'
    assert client.request("DELETE", path, json={}, headers=headers).status_code == 503
    assert client.get("/api/me/profiles").json()["items"][0]["state"] == "DELETING"
    assert client.get(path + "/connections").status_code == 409
    assert client.request("DELETE", path, json={}, headers=headers).status_code == 200
    assert not node.users and not client.get("/api/me/profiles").json()["items"]


def test_pending_delete_wins_over_new_generation_without_late_orphan(profile_setup):
    _, node, app, client, headers = profile_setup
    user = app.state.store.session_user(client.cookies.get("shared_session"))
    profile = app.state.store.create_profile(user["id"], "pending", "delete-wins")
    path = f'/api/me/profiles/{profile["id"]}'
    node.slow_create_started = threading.Event()
    node.slow_create_release = threading.Event()
    with ThreadPoolExecutor(max_workers=2) as pool:
        deleting = pool.submit(client.request, "DELETE", path, json={}, headers=headers)
        assert node.slow_create_started.wait(3)
        generating = pool.submit(client.post, path + "/connections", json={}, headers=headers)
        time.sleep(.1)
        assert not generating.done()
        node.slow_create_release.set()
        assert deleting.result().status_code == 200
        assert generating.result().status_code == 404
    assert not node.users


def test_default_and_custom_creation_quotas_and_key_conflicts(profile_setup):
    settings, node, _, client, headers = profile_setup
    standard = create(client, headers)
    assert standard["trafficLimitBytes"] == settings.traffic_limit_bytes
    custom_body = {"name": "定制额度", "idempotencyKey": "quota-create", "trafficLimitBytes": 123 * 1024**3}
    custom = client.post("/api/me/profiles", json=custom_body, headers=headers)
    assert custom.status_code == 201
    assert custom.json()["trafficLimitBytes"] == 123 * 1024**3
    assert node.creates[-1][1]["trafficLimitBytes"] == 123 * 1024**3
    replay = client.post("/api/me/profiles", json=custom_body, headers=headers)
    assert replay.json()["id"] == custom.json()["id"]
    conflict = client.post("/api/me/profiles", json={**custom_body, "trafficLimitBytes": 456 * 1024**3}, headers=headers)
    assert conflict.status_code == 409
    assert len(node.creates) == 2


def test_edit_quota_preserves_usage_credentials_and_other_profiles(profile_setup):
    _, node, app, client, headers = profile_setup
    first = create(client, headers)
    second = create(client, headers, "其他连接", "other-quota")
    path = f'/api/me/profiles/{first["id"]}'
    original = client.get(path + "/connections").json()
    before = client.get(path + "/traffic").json()
    new_limit = 500 * 1024**3
    changed = client.patch(path + "/policy", json={"trafficLimitBytes": new_limit}, headers=headers)
    assert changed.status_code == 200, changed.text
    assert changed.json()["trafficLimitBytes"] == new_limit
    assert client.get(path + "/connections").json() == original
    after = client.get(path + "/traffic").json()
    assert after["trafficLimitBytes"] == new_limit
    assert after["total"] == before["total"] == 42
    assert client.get(f'/api/me/profiles/{second["id"]}/traffic').json()["trafficLimitBytes"] == second["trafficLimitBytes"]
    user = app.state.store.session_user(client.cookies.get("shared_session"))
    stored = app.state.store.get_profile(user["id"], first["id"])
    assert stored["request"]["trafficLimitBytes"] == first["trafficLimitBytes"]
    assert stored["traffic_limit_bytes"] == new_limit
    assert client.get("/api/me/traffic").json()["trafficLimitBytes"] == new_limit
    # The original creation request is still replayable after quota editing.
    assert client.post("/api/me/profiles", json={"name": "工作连接", "idempotencyKey": "create-one"}, headers=headers).json()["id"] == first["id"]


def test_policy_edit_requires_owner_csrf_and_positive_integer(profile_setup):
    _, node, _, client, headers = profile_setup
    profile = create(client, headers)
    path = f'/api/me/profiles/{profile["id"]}/policy'
    assert client.patch(path, json={"trafficLimitBytes": 100}).status_code == 403
    for value in [0, -1, True, 1.5, 9007199254740992]:
        assert client.patch(path, json={"trafficLimitBytes": value}, headers=headers).status_code == 422
    assert not node.policy_calls
    bob = register(client, "bob")
    assert client.patch(path, json={"trafficLimitBytes": 100}, headers={"X-CSRF-Token": bob["csrfToken"]}).status_code == 404


def test_unconfirmed_policy_edit_keeps_local_override_unchanged(profile_setup):
    _, node, _, client, headers = profile_setup
    profile = create(client, headers)
    node.ignore_policy_changes = True
    response = client.patch(f'/api/me/profiles/{profile["id"]}/policy', json={"trafficLimitBytes": 999}, headers=headers)
    assert response.status_code == 503
    actual = client.get("/api/me/profiles").json()["items"][0]
    assert actual["trafficLimitBytes"] == profile["trafficLimitBytes"]


def test_quota_safe_integer_maximum_and_invalid_creation_never_calls_node(profile_setup):
    _, node, _, client, headers = profile_setup
    invalid = client.post("/api/me/profiles", json={"name": "bad", "idempotencyKey": "unsafe", "trafficLimitBytes": 9007199254740992}, headers=headers)
    assert invalid.status_code == 422 and not node.creates
    profile = create(client, headers)
    response = client.patch(f'/api/me/profiles/{profile["id"]}/policy', json={"trafficLimitBytes": 9007199254740991}, headers=headers)
    assert response.status_code == 200 and response.json()["trafficLimitBytes"] == 9007199254740991
