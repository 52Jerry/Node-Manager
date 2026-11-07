"""Restoring a shared user's default egress must preserve other identities."""
import copy
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

import idempotency
import main
from singbox import manager
import user_direct


UUID = "11111111-1111-4111-8111-111111111111"


def fixture_state():
    tag = manager.USER_OUTBOUND_PREFIX + "shared-alice"
    other = manager.USER_OUTBOUND_PREFIX + "shared-bob"
    data = {"inbounds": [
        {"tag": manager.config.singbox.vless_tag, "users": [{"name": "node-manager:shared-alice", "uuid": UUID}]},
        {"tag": manager.config.singbox.vmess_tag, "users": [{"name": "node-manager:shared-alice", "uuid": UUID}]},
        {"tag": manager.config.singbox.socks_tag, "users": [{"username": "alice-inbound", "password": "inbound-secret"}]}],
        "outbounds": [{"type": "socks", "tag": tag, "server": "8.8.8.8", "server_port": 1080, "password": "upstream-secret"},
                      {"type": "socks", "tag": other, "server": "8.8.4.4", "server_port": 1080}],
        "route": {"rules": [{"auth_user": ["bob"], "outbound": other}, {"auth_user": ["node-manager:shared-alice", "alice-inbound"], "outbound": tag}]}}
    registry = {"users": {"shared-alice": {"socksUsername": "alice-inbound", "sourceIp": "8.8.8.8", "sourceAddress": "8.8.8.8",
        "sourcePort": 1080, "countryCode": "US", "expiresAt": "2030-01-01T00:00:00Z", "accessEnabled": False},
        "shared-bob": {"socksUsername": "bob-inbound"}}}
    return data, registry


def test_restore_direct_owns_only_one_outbound_and_preserves_credentials():
    data, registry = fixture_state()
    old_inbounds = copy.deepcopy(data["inbounds"])
    other_outbound = copy.deepcopy(data["outbounds"][1])
    def mutation(callback):
        return callback(data, registry)
    with patch.object(manager, "mutate_config", side_effect=mutation), patch.object(manager, "_audit"):
        result = user_direct.restore_direct("shared-alice", UUID, "alice-inbound")
    assert result["success"]
    assert data["inbounds"] == old_inbounds
    assert other_outbound in data["outbounds"]
    assert {"type": "direct", "tag": manager.USER_OUTBOUND_PREFIX + "shared-alice"} in data["outbounds"]
    own_rules = [r for r in data["route"]["rules"] if r.get("outbound") == manager.USER_OUTBOUND_PREFIX + "shared-alice"]
    assert len(own_rules) == 1
    assert set(own_rules[0]["auth_user"]) == {"node-manager:shared-alice", "alice-inbound"}
    assert "sourceAddress" not in registry["users"]["shared-alice"]
    assert registry["users"]["shared-alice"]["accessEnabled"] is False
    assert registry["users"]["shared-alice"]["expiresAt"] == "2030-01-01T00:00:00Z"


@pytest.mark.parametrize("expected_uuid,expected_socks", [("22222222-2222-4222-8222-222222222222", "alice-inbound"), (UUID, "wrong-user")])
def test_restore_direct_rejects_changed_identity_before_mutating(expected_uuid, expected_socks):
    data, registry = fixture_state()
    before = copy.deepcopy((data, registry))
    with patch.object(manager, "mutate_config", side_effect=lambda cb: cb(data, registry)):
        with pytest.raises(manager.SingboxConfigError, match="identity changed"):
            user_direct.restore_direct("shared-alice", expected_uuid, expected_socks)
    assert (data, registry) == before


def test_direct_endpoint_auth_idempotency_and_request_identity(tmp_path):
    result = {"success": True, "userId": "shared-alice", "message": "restored direct route"}
    payload = {"expectedUuid": UUID, "expectedSocksUsername": "alice-inbound"}
    headers = {"Authorization": "Bearer " + main.config.security.token, "Idempotency-Key": "shared-direct-test"}
    client = TestClient(main.app)
    persisted = {"version": 1, "entries": {}}
    def write_store(data):
        persisted.clear()
        persisted.update(copy.deepcopy(data))
    with patch.object(idempotency, "_read_store", side_effect=lambda: copy.deepcopy(persisted)), patch.object(idempotency, "_write_store", side_effect=write_store), patch.object(user_direct, "restore_direct", return_value=result) as restore:
        assert client.post("/api/user/shared-alice/direct", json=payload).status_code in {401, 403}
        assert client.post("/api/user/shared-alice/direct", json=payload, headers={"Authorization": headers["Authorization"]}).status_code == 422
        response = client.post("/api/user/shared-alice/direct", json=payload, headers=headers)
        assert response.status_code == 200, response.text
        assert response.headers["Idempotency-Replayed"] == "false"
        assert client.post("/api/user/shared-alice/direct", json=payload, headers=headers).headers["Idempotency-Replayed"] == "true"
        restore.assert_called_once_with("shared-alice", UUID, "alice-inbound")
        changed = {**payload, "expectedSocksUsername": "wrong-user"}
        assert client.post("/api/user/shared-alice/direct", json=changed, headers=headers).status_code == 409
