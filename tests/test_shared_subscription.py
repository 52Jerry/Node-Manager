import base64

from test_shared_manager import setup, register, generate


def test_subscription_requires_owned_generated_connections(setup):
    _, _, _, client = setup
    alice = register(client)
    assert client.get("/api/me/subscription").status_code == 404
    assert client.post("/api/me/subscription", json={}, headers={"X-CSRF-Token": alice["csrfToken"]}).status_code == 409
    assert generate(client, alice).status_code == 200
    assert client.post("/api/me/subscription", json={}).status_code == 403
    result = client.post("/api/me/subscription", json={}, headers={"X-CSRF-Token": alice["csrfToken"]})
    assert result.status_code == 200
    url = result.json()["url"]
    assert client.get("/api/me/subscription").json()["url"] == url
    assert client.post("/api/me/subscription", json={}, headers={"X-CSRF-Token": alice["csrfToken"]}).json()["url"] == url
    response = client.get(url)
    assert response.status_code == 200
    lines = base64.b64decode(response.text).decode().splitlines()
    assert len(lines) == 3
    assert [line.split(":")[0] for line in lines] == ["vless", "vmess", "socks"]
    assert "no-store" in response.headers["cache-control"]
    bob = register(client, "bob")
    assert client.get("/api/me/subscription").status_code == 404
    assert client.get("/subscription/not-a-token").status_code == 404


def test_subscription_rotation_and_account_restrictions(setup):
    _, node, app, client = setup
    alice = register(client)
    generate(client, alice)
    headers = {"X-CSRF-Token": alice["csrfToken"]}
    first = client.post("/api/me/subscription", json={}, headers=headers).json()["url"]
    second = client.post("/api/me/subscription", json={"rotate": True}, headers=headers).json()["url"]
    assert first != second
    assert client.get(first).status_code == 404
    assert client.get(second).status_code == 200
    node.suspend = True
    assert client.get(second).status_code == 403
    node.suspend = False
    user = app.state.store.session_user(client.cookies.get("shared_session"))
    with app.state.store.connection() as db:
        db.execute("UPDATE users SET enabled=0 WHERE id=?", (user["id"],))
    assert client.get(second).status_code == 404
