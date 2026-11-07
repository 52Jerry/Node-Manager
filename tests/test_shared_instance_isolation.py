"""A shared instance must not send lifecycle commands to the existing core."""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import call, patch

import pytest
import requests

import config as config_module
import provisioning_readiness
from singbox import manager


def completed(command, code=0, output=""):
    return subprocess.CompletedProcess(command, code, output, "")


def test_default_service_keeps_existing_deployments_compatible():
    assert config_module.SingboxConfig().service == "sing-box"


def test_health_probe_uses_selected_instance_service():
    with patch.object(manager.config.singbox, "service", "sing-box-shared"), \
            patch.object(manager, "_run", return_value=completed([], output="active\n")) as run:
        assert manager.is_singbox_running()
    run.assert_called_once_with(["systemctl", "is-active", "sing-box-shared"])


@pytest.mark.parametrize("restart", [False, True])
def test_reload_and_emergency_restart_never_target_original_core(restart):
    invoked = []

    def run(command):
        invoked.append(command)
        if command[1] == "reload":
            return completed(command, code=1)
        return completed(command, output="active\n")

    with patch.object(manager.config.singbox, "service", "sing-box-shared"), \
            patch("singbox.runtime_client.enabled", return_value=False), \
            patch.dict(os.environ, {}, clear=False), \
            patch.object(manager, "_run", side_effect=run):
        os.environ.pop("NODE_MANAGER_VLESS_PUBLICATION_SPEC", None)
        assert manager.reload_singbox(restart_if_reload_fails=restart) is restart
    expected = [["systemctl", "reload", "sing-box-shared"]]
    if restart:
        expected += [["systemctl", "restart", "sing-box-shared"], ["systemctl", "is-active", "sing-box-shared"]]
    assert invoked == expected


def test_ordinary_mutation_guard_refuses_restart_even_for_custom_service():
    with patch.object(manager.config.singbox, "service", "sing-box-shared"), \
            patch("singbox.runtime_client.enabled", return_value=False), \
            patch.dict(os.environ, {}, clear=False), \
            patch.object(manager, "_run", return_value=completed([], code=1)) as run:
        os.environ.pop("NODE_MANAGER_VLESS_PUBLICATION_SPEC", None)
        with manager.without_restart():
            assert manager.reload_singbox(restart_if_reload_fails=True) is False
    run.assert_called_once_with(["systemctl", "reload", "sing-box-shared"])


def test_readiness_rechecks_only_the_selected_service_pid():
    data = {"inbounds": [{"type": "socks", "tag": "socks", "listen_port": 9999, "listen": "10.44.0.1"}]}
    watched = {}
    with ExitStack() as stack:
        stack.enter_context(patch.object(provisioning_readiness.config.singbox, "service", "sing-box-shared"))
        stack.enter_context(patch.dict(os.environ, {}, clear=False))
        os.environ.pop("NODE_MANAGER_VLESS_PUBLICATION_SPEC", None)
        pid = stack.enter_context(patch.object(provisioning_readiness, "_pid", return_value=42))
        stack.enter_context(patch.object(provisioning_readiness, "_identity", return_value=123))
        stack.enter_context(patch.object(provisioning_readiness, "_listeners", return_value=[
            {"network": "tcp", "address": "10.44.0.1", "port": 9999, "inode": 99}]))
        stack.enter_context(patch.object(provisioning_readiness, "_owned_sockets", return_value={99: "descriptor"}))
        stack.enter_context(patch.object(provisioning_readiness, "_verify_descriptors"))
        assert provisioning_readiness.evaluate(data, ["socks"], watched)["state"] == "READY"
    assert pid.call_args_list == [call("sing-box-shared"), call("sing-box-shared")]


def test_custom_service_is_loaded_without_changing_global_configuration(tmp_path):
    path = tmp_path / "node.yaml"
    path.write_text("node:\n  host: 192.0.2.10\nsingbox:\n  service: sing-box-shared.service\n", encoding="utf-8")
    previous = config_module.config.singbox.service
    with patch.dict(os.environ, {"NODE_MANAGER_CONFIG": str(path)}), \
            patch.object(requests, "get", side_effect=requests.RequestException("offline")), \
            patch.object(socket.socket, "connect", side_effect=OSError("offline")):
        loaded = config_module.load_config()
    assert loaded.singbox.service == "sing-box-shared.service"
    assert config_module.config.singbox.service == previous


@pytest.mark.parametrize("service", ["", "--all", "../sing-box", "sing-box other", "sing-box\nnode-manager", "sing-box;reboot"])
def test_invalid_service_names_are_rejected(tmp_path, service):
    path = tmp_path / "node.yaml"
    import yaml
    path.write_text(yaml.safe_dump({"node": {"host": "192.0.2.10"}, "singbox": {"service": service}}), encoding="utf-8")
    with patch.dict(os.environ, {"NODE_MANAGER_CONFIG": str(path)}), \
            patch.object(requests, "get", side_effect=requests.RequestException("offline")), \
            patch.object(socket.socket, "connect", side_effect=OSError("offline")), \
            pytest.raises(ValueError, match="singbox.service"):
        config_module.load_config()


def test_separate_process_uses_scoped_lock_config_and_registry(tmp_path):
    """Exercise import-time paths and a registry write without touching host state."""
    import yaml
    original = tmp_path / "original"
    shared = tmp_path / "shared"
    original.mkdir()
    shared.mkdir()
    original_registry = original / "users.json"
    sentinel = {"version": 2, "users": {"existing-customer": {"status": "active"}}, "expiredUsers": {}}
    original_registry.write_text(json.dumps(sentinel), encoding="utf-8")
    config_path = shared / "node.yaml"
    config_path.write_text(yaml.safe_dump({"node": {"host": "192.0.2.10"}, "security": {"token": "synthetic-token"},
                                         "singbox": {"service": "sing-box-shared", "config": str(shared / "sing-box.json")}}), encoding="utf-8")
    source = r'''
import json, requests, socket
from unittest.mock import patch
with patch.object(requests, "get", side_effect=requests.RequestException("offline")), patch.object(socket.socket, "connect", side_effect=OSError("offline")):
    import config
    from singbox import manager
    import idempotency
    import monitor.traffic as traffic
    import revision
class FakeFcntl:
    LOCK_EX = 1
    LOCK_SH = 2
    def __init__(self): self.calls = []
    def flock(self, descriptor, kind): self.calls.append(kind)
fcntl = FakeFcntl()
manager.fcntl = fcntl
with manager._config_lock():
    manager._write_registry({"version": 2, "users": {"new-shared-user": {}}, "expiredUsers": {}})
with manager._config_read_lock():
    registry = manager.read_registry()
print(json.dumps({"service": config.config.singbox.service, "config": str(manager.CONFIG_PATH),
                  "lock": str(manager.LOCK_PATH), "registry": str(manager.REGISTRY_PATH),
                  "idempotency": str(idempotency.STORE_PATH), "traffic": str(traffic.TRAFFIC_PATH),
                  "revisions": str(revision.REVISIONS_DIR), "lockKinds": fcntl.calls, "users": list(registry["users"])}))
'''
    environment = {key: value for key, value in os.environ.items() if not key.startswith("NODE_MANAGER_")}
    environment.update({"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "node-manager"),
                        "NODE_MANAGER_CONFIG": str(config_path), "NODE_MANAGER_CONFIG_LOCK": str(shared / "config.lock"),
                        "NODE_MANAGER_USER_REGISTRY": str(shared / "users.json"),
                        "NODE_MANAGER_TRAFFIC_STORE": str(shared / "traffic.json"),
                        "NODE_MANAGER_IDEMPOTENCY_STORE": str(shared / "idempotency.json"),
                        "NODE_MANAGER_REVISIONS_DIR": str(shared / "revisions")})
    result = subprocess.run([sys.executable, "-c", source], env=environment, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=25)
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["service"] == "sing-box-shared"
    for key in ["config", "lock", "registry", "idempotency", "traffic", "revisions"]:
        assert Path(observed[key]).is_relative_to(shared)
    assert observed["lockKinds"] == [1, 2]
    assert observed["users"] == ["new-shared-user"]
    assert (shared / "config.lock").exists()
    assert json.loads(original_registry.read_text(encoding="utf-8")) == sentinel
