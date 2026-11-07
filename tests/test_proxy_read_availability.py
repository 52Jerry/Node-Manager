"""Proxy detail reads share current snapshots without retaining old credentials."""
import json
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from test_connection_read_availability import user
from test_next_stage import main, manager
from singbox.connection_snapshot import ConnectionSnapshotCache


@pytest.fixture
def proxy_user(user):
    manager.bind_proxy('cached-user', {
        'server': '203.0.113.70', 'port': 1080,
        'username': 'upstream-account', 'password': 'upstream-old-secret',
    })
    assert manager.get_user_proxy('cached-user')['password'] == 'upstream-old-secret'
    return user


def replace_json(path, value):
    replacement = path.with_suffix('.replacement')
    replacement.write_text(value if isinstance(value, str) else json.dumps(value), encoding='utf8')
    replacement.replace(path)


def forbid_writer_lock():
    raise AssertionError('a proxy detail read must not acquire an exclusive config lock')


def test_unchanged_proxy_read_remains_available_while_writer_holds_lock(proxy_user, monkeypatch):
    with ThreadPoolExecutor(max_workers=1) as pool:
        with manager._config_lock():
            future = pool.submit(manager.get_user_proxy, 'cached-user')
            assert future.result(timeout=1)['password'] == 'upstream-old-secret'
    monkeypatch.setattr(manager, '_config_lock', forbid_writer_lock)
    with patch.object(manager, '_config_read_lock', side_effect=AssertionError('cached read must not wait for writer')):
        assert manager.get_user_proxy('cached-user')['server'] == '203.0.113.70'


def test_cold_proxy_read_uses_shared_lock_and_preserves_result(proxy_user, monkeypatch):
    monkeypatch.setattr(manager, '_connection_snapshot_cache', ConnectionSnapshotCache())
    monkeypatch.setattr(manager, '_config_lock', forbid_writer_lock)
    with patch.object(manager, '_config_read_lock', wraps=manager._config_read_lock) as shared:
        result = manager.get_user_proxy('cached-user')
    shared.assert_called_once()
    assert result['userId'] == 'cached-user'
    assert result['proxyBound'] is True
    assert result['password'] == 'upstream-old-secret'


def test_changed_config_reloads_new_password_under_shared_lock(proxy_user, monkeypatch):
    value = manager.read_config()
    next(row for row in value['outbounds'] if row['tag'] == 'node-manager-out:cached-user')['password'] = 'upstream-new-secret'
    replace_json(manager.CONFIG_PATH, value)
    monkeypatch.setattr(manager, '_config_lock', forbid_writer_lock)
    with patch.object(manager, '_config_read_lock', wraps=manager._config_read_lock) as shared:
        assert manager.get_user_proxy('cached-user')['password'] == 'upstream-new-secret'
    shared.assert_called_once()


@pytest.mark.parametrize('changed', ['config', 'registry'])
def test_invalid_changed_file_never_returns_old_proxy_password(proxy_user, changed):
    path = manager.CONFIG_PATH if changed == 'config' else manager.REGISTRY_PATH
    replace_json(path, 'invalid-json')
    with pytest.raises((manager.SingboxConfigError, json.JSONDecodeError)):
        manager.get_user_proxy('cached-user')


def test_removed_config_cannot_reuse_previous_credentials(proxy_user):
    manager.CONFIG_PATH.unlink()
    with pytest.raises((manager.SingboxConfigError, FileNotFoundError)):
        manager.get_user_proxy('cached-user')


def test_changed_suspension_is_enforced_after_cache_hit(proxy_user):
    value = manager.read_registry()
    value['users']['cached-user']['accessEnabled'] = False
    replace_json(manager.REGISTRY_PATH, value)
    response = TestClient(main.app).get('/api/user/cached-user/proxy', headers={'Authorization': 'Bearer test-token'})
    assert response.status_code == 409
    assert 'upstream-old-secret' not in response.text


def test_proxy_keeps_existing_expiration_semantics(proxy_user):
    value = manager.read_registry()
    value['users']['cached-user']['expiresAt'] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    replace_json(manager.REGISTRY_PATH, value)
    # Proxy inspection historically checks configured ownership and suspension;
    # connection delivery separately enforces the expiry date.
    assert manager.get_user_proxy('cached-user')['password'] == 'upstream-old-secret'
    with pytest.raises(manager.SingboxConfigError, match='expired'):
        manager.get_user_connection('cached-user')


def test_proxy_api_contract_and_wrong_identity_remain_distinct(proxy_user):
    client = TestClient(main.app)
    headers = {'Authorization': 'Bearer test-token'}
    response = client.get('/api/user/cached-user/proxy', headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert {key: body[key] for key in ('userId','proxyBound','server','port','username','password')} == {
        'userId':'cached-user','proxyBound':True,'server':'203.0.113.70','port':1080,
        'username':'upstream-account','password':'upstream-old-secret',
    }
    assert response.headers['cache-control'] == 'no-store'
    wrong = client.get('/api/user/other-user/proxy', headers=headers)
    assert wrong.status_code == 409
    assert 'upstream-old-secret' not in wrong.text
    assert client.get('/api/user/cached-user/proxy', headers={'Authorization':'Bearer wrong-token'}).status_code == 401


def test_direct_and_socks5_outbounds_keep_existing_contract(proxy_user):
    value = manager.read_config()
    outbound = next(row for row in value['outbounds'] if row['tag'] == 'node-manager-out:cached-user')
    outbound['type'] = 'socks5'
    replace_json(manager.CONFIG_PATH, value)
    assert manager.get_user_proxy('cached-user')['proxyBound'] is True
    outbound['type'] = 'direct'
    replace_json(manager.CONFIG_PATH, value)
    result = manager.get_user_proxy('cached-user')
    assert result['proxyBound'] is False
    assert all(result[field] is None for field in ('server','port','username','password'))
    assert result['protocolInfo'] == {}


def test_staged_proxy_and_new_user_reads_never_publish_uncommitted_cache(proxy_user):
    data, registry = copy.deepcopy(manager.read_config()), copy.deepcopy(manager.read_registry())
    token = manager._mutation_workspace.set((data, registry))
    try:
        manager.bind_proxy('cached-user', {
            'server':'203.0.113.71','port':1081,'username':'staged-account','password':'staged-secret',
        })
        manager.create_user('staged-user', ['socks'], proxy={
            'server':'203.0.113.72','port':1082,'username':'new-account','password':'new-secret',
        })
        assert manager.get_user_proxy('cached-user')['password'] == 'staged-secret'
        assert manager.get_user_proxy('staged-user')['password'] == 'new-secret'
        assert manager.get_user_connection('staged-user')['success']
    finally:
        manager._mutation_workspace.reset(token)
    # A rollback leaves the old committed snapshot intact and hides the new user.
    assert manager.get_user_proxy('cached-user')['password'] == 'upstream-old-secret'
    with pytest.raises(manager.SingboxConfigError, match='user not found'):
        manager.get_user_proxy('staged-user')
    replace_json(manager.CONFIG_PATH, data)
    replace_json(manager.REGISTRY_PATH, registry)
    assert manager.get_user_proxy('cached-user')['password'] == 'staged-secret'
    assert manager.get_user_proxy('staged-user')['password'] == 'new-secret'


def test_outer_write_transaction_honors_fresh_read_overrides(proxy_user):
    data, registry = copy.deepcopy(manager.read_config()), copy.deepcopy(manager.read_registry())
    outbound = next(row for row in data['outbounds'] if row['tag'] == 'node-manager-out:cached-user')
    with manager._config_lock(), patch.object(manager, 'read_config', return_value=data), \
            patch.object(manager, 'read_registry', return_value=registry):
        outbound['password'] = 'first-staged-secret'
        assert manager.get_user_proxy('cached-user')['password'] == 'first-staged-secret'
        outbound['password'] = 'second-staged-secret'
        assert manager.get_user_proxy('cached-user')['password'] == 'second-staged-secret'
    assert manager.get_user_proxy('cached-user')['password'] == 'upstream-old-secret'
