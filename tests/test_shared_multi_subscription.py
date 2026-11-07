import base64
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from shared_manager.agent import Agent, AgentError
from test_shared_manager import setup, register, generate
import httpx


def create_second(settings, node, app, client):
    store = app.state.store
    user = store.session_user(client.cookies.get("shared_session"))
    profile = store.create_profile(user["id"], "住宅 B", "create-second")
    agent = Agent(settings, transport=httpx.MockTransport(node))
    result = agent.connections(profile, create=True)
    agent.close()
    store.mark_profile_ready(user["id"], profile["id"])
    return user, profile, result


def test_account_subscription_collects_profiles_and_tracks_renames_deletion(setup):
    settings, node, app, client = setup
    session = register(client)
    assert generate(client, session).status_code == 200
    user, second, _ = create_second(settings, node, app, client)
    headers = {"X-CSRF-Token": session["csrfToken"]}
    url = client.post("/api/me/subscription", json={}, headers=headers).json()["url"]
    values = base64.b64decode(client.get(url).text).decode().splitlines()
    assert len(values) == 6
    assert len({urlsplit(value).netloc for value in values if value.startswith("vless://")}) == 2
    assert unquote(urlsplit(values[3]).fragment) == "住宅 B · VLESS"
    app.state.store.rename_profile(user["id"], second["id"], "住宅 C")
    renamed = base64.b64decode(client.get(url).text).decode().splitlines()
    assert unquote(urlsplit(renamed[3]).fragment) == "住宅 C · VLESS"
    assert urlsplit(values[3]).netloc == urlsplit(renamed[3]).netloc
    app.state.store.begin_delete_profile(user["id"], second["id"])
    remaining = base64.b64decode(client.get(url).text).decode().splitlines()
    assert len(remaining) == 3
    register(client, "bob")
    assert client.get("/api/me/subscription").status_code == 404


def test_expired_connection_does_not_hide_active_connection(setup):
    settings, node, app, client = setup
    session = register(client)
    assert generate(client, session).status_code == 200
    user, second, result = create_second(settings, node, app, client)
    headers = {"X-CSRF-Token": session["csrfToken"]}
    url = client.post("/api/me/subscription", json={}, headers=headers).json()["url"]
    profiles = app.state.store.list_profiles(user["id"])
    profiles[0]["request"]["expiresAt"] = "2000-01-01T00:00:00+00:00"
    with patch.object(app.state.store, "list_profiles", return_value=profiles), patch.object(Agent, "connections", side_effect=[AgentError(409, "连接已到期"), result]):
        response = client.get(url)
    assert response.status_code == 200
    assert len(base64.b64decode(response.text).decode().splitlines()) == 3


def test_duplicate_names_have_distinct_subscription_labels(setup):
    settings, node, app, client = setup
    session = register(client)
    generate(client, session)
    user, second, _ = create_second(settings, node, app, client)
    app.state.store.rename_profile(user["id"], second["id"], "默认连接")
    url = client.post("/api/me/subscription", json={}, headers={"X-CSRF-Token": session["csrfToken"]}).json()["url"]
    links = base64.b64decode(client.get(url).text).decode().splitlines()
    aliases = [unquote(urlsplit(uri).fragment) for uri in links if uri.startswith("vless://")]
    assert len(set(aliases)) == 2
    assert all(user["id"] not in alias and second["id"] not in alias for alias in aliases)
