"""Registration attempt policy is independent from durable account capacity."""
from dataclasses import replace
import json

from fastapi.testclient import TestClient
import httpx
import pytest

from shared_manager.agent import Agent
from shared_manager.app import create_app
from shared_manager.settings import Settings


ORIGIN = "http://localhost:8090"


@pytest.fixture
def policy_app(tmp_path):
    settings = Settings(secret="registration-policy-secret-" * 3,
                        agent_token="registration-policy-agent-" * 3, origin=ORIGIN,
                        database=tmp_path / "accounts.json", max_accounts=500,
                        registration_daily_attempts=500)

    def no_node(_request):
        raise AssertionError("Registration policy must not contact a node")

    agent = Agent(settings, transport=httpx.MockTransport(no_node))
    app = create_app(settings, agent)
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        yield settings, app.state.store, client, agent
    agent.close()
    assert json.loads(settings.database.read_text(encoding="utf-8"))["format"] == "shared-node-manager-json"


def seed_global_attempts(store, count):
    # Let the real limiter choose the durable bucket identity and expiry.
    store.throttle("register-global", "all", store.settings.registration_daily_attempts, 86400)
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM rate_limits").fetchone()[0] == 1
        assert db.execute("UPDATE rate_limits SET count=?", (count,)).rowcount == 1


def test_existing_100_attempt_bucket_no_longer_blocks_configured_500(policy_app):
    _, store, client, _ = policy_app
    seed_global_attempts(store, 100)
    response = client.post("/api/auth/register", json={"username": "新用户", "password": "1"})
    assert response.status_code == 201, response.text
    assert response.json()["user"]["username"] == "新用户"
    assert response.json()["user"]["isAdmin"] is False
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 1
        assert sorted(row[0] for row in db.execute("SELECT count FROM rate_limits")) == [1, 101]


def test_configured_500_attempt_limit_still_rejects_the_next_request(policy_app):
    _, store, client, _ = policy_app
    seed_global_attempts(store, 500)
    response = client.post("/api/auth/register", json={"username": "新用户", "password": "1"})
    assert response.status_code == 429
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
        assert sorted(row[0] for row in db.execute("SELECT count FROM rate_limits")) == [1, 500]


def test_account_capacity_remains_independent_from_daily_attempt_allowance(policy_app):
    settings, _, _, agent = policy_app
    limited = replace(settings, max_accounts=1)
    app = create_app(limited, agent)
    store = app.state.store
    store.register("existing", "1")
    seed_global_attempts(store, 100)
    with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
        response = client.post("/api/auth/register", json={"username": "another", "password": "1"})
    assert response.status_code == 409
    assert response.json()["detail"] == "当前节点注册名额已满"
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 1
        assert db.execute("SELECT username FROM users").fetchone()[0] == "existing"


def test_per_source_limit_is_not_relaxed_with_global_daily_allowance(policy_app):
    _, store, client, _ = policy_app
    # The ASGI TestClient uses this source name for every request.
    store.throttle("register-source", "testclient", 5, 900)
    with store.connection() as db:
        assert db.execute("UPDATE rate_limits SET count=5").rowcount == 1
    response = client.post("/api/auth/register", json={"username": "new", "password": "1"})
    assert response.status_code == 429
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM rate_limits").fetchone()[0] == 1


@pytest.mark.parametrize("attempts", [0, -1])
def test_daily_attempt_allowance_must_be_positive(policy_app, attempts):
    settings, _, _, _ = policy_app
    with pytest.raises(ValueError, match="registration_daily_attempts"):
        replace(settings, registration_daily_attempts=attempts)


def test_daily_attempt_allowance_reads_environment_and_keeps_compatibility_default(monkeypatch):
    monkeypatch.setenv("SHARED_SECRET", "registration-policy-secret-" * 3)
    monkeypatch.setenv("SHARED_AGENT_TOKEN", "registration-policy-agent-" * 3)
    monkeypatch.setenv("SHARED_ORIGIN", ORIGIN)
    monkeypatch.setenv("SHARED_MAX_ACCOUNTS", "500")
    monkeypatch.delenv("SHARED_REGISTRATION_DAILY_ATTEMPTS", raising=False)
    assert Settings.from_env().registration_daily_attempts == 100
    monkeypatch.setenv("SHARED_REGISTRATION_DAILY_ATTEMPTS", "500")
    configured = Settings.from_env()
    assert configured.registration_daily_attempts == 500
    assert configured.max_accounts == 500
