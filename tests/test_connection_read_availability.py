import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_next_stage import base_singbox_config, manager
from singbox.connection_snapshot import ConnectionSnapshotCache


@pytest.fixture
def user(tmp_path, monkeypatch):
    config_path, registry_path = tmp_path / 'config.json', tmp_path / 'users.json'
    config_path.write_text(json.dumps(base_singbox_config()), encoding='utf8')
    monkeypatch.setattr(manager, 'CONFIG_PATH', config_path)
    monkeypatch.setattr(manager, 'REGISTRY_PATH', registry_path)
    monkeypatch.setattr(manager, 'LOCK_PATH', tmp_path / 'config.lock')
    monkeypatch.setattr(manager, '_connection_snapshot_cache', ConnectionSnapshotCache())
    monkeypatch.setattr(manager, '_write_and_reload', lambda data: config_path.write_text(json.dumps(data), encoding='utf8'))
    manager.create_user('cached-user', ['vless', 'socks'], socks_username='cached-login', socks_password='test-password')
    assert manager.get_user_connection('cached-user')['success']
    return registry_path


def test_unchanged_connection_read_remains_available_while_writer_holds_lock(user):
    with ThreadPoolExecutor(max_workers=1) as pool:
        with manager._config_lock():
            future = pool.submit(manager.get_user_connection, 'cached-user')
            try:
                assert future.result(timeout=1)['success']
            finally:
                # The context releases the writer before the pool waits on shutdown.
                pass


@pytest.mark.parametrize('change', ['suspended', 'expired', 'invalid'])
def test_changed_registry_never_returns_previously_authorized_credentials(user, change):
    registry = json.loads(user.read_text(encoding='utf8'))
    if change == 'suspended':
        registry['users']['cached-user']['accessEnabled'] = False
    elif change == 'expired':
        registry['users']['cached-user']['expiresAt'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    replacement = user.with_suffix('.replacement')
    replacement.write_text('invalid-json' if change == 'invalid' else json.dumps(registry), encoding='utf8')
    replacement.replace(user)
    with pytest.raises(manager.SingboxConfigError):
        manager.get_user_connection('cached-user')
