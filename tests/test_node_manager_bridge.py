import ast, importlib.util, json, logging, os, subprocess, sys, types
from pathlib import Path
from unittest import mock
import pytest

ROOT = Path(__file__).resolve().parents[2] / "Node Manager/node-manager"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def client(monkeypatch):
    import singbox.runtime_client as runtime_client
    monkeypatch.setattr(runtime_client, "enabled", lambda: False)
    fake = types.ModuleType("config")
    fake.config = types.SimpleNamespace(
        singbox=types.SimpleNamespace(api_port=9090, api_secret="fixture")
    )
    monkeypatch.setitem(sys.modules, "config", fake)
    spec = importlib.util.spec_from_file_location(
        "singbox.isolated_singbox_api", ROOT / "singbox/api.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SingboxAPI()


def test_default_api_still_calls_original_endpoint(client, monkeypatch):
    monkeypatch.delenv("NODE_MANAGER_VLESS_PUBLICATION_SPEC", raising=False)
    with mock.patch(
        "requests.get",
        return_value=types.SimpleNamespace(
            status_code=200, json=lambda: {"connections": []}
        ),
    ) as get:
        assert client.get_connections() == {"connections": []}
        assert get.call_args.args[0] == "http://127.0.0.1:9090/connections"


def publication(monkeypatch):
    module = types.ModuleType("vless_publication")
    module.configured_spec = lambda: {"enabled": True}
    module.snapshot = mock.Mock(
        return_value={
            "uploadTotal": 40,
            "downloadTotal": 50,
            "connections": [{"id": "rr:g:x"}],
        }
    )
    module.proxies = mock.Mock(return_value={"proxies": {}})
    module.close = mock.Mock(return_value=True)
    module.__file__ = "/opt/test/vless_publication.py"
    monkeypatch.setenv("NODE_MANAGER_VLESS_PUBLICATION_SPEC", "/etc/test.json")
    monkeypatch.setitem(sys.modules, "vless_publication", module)
    return module


def test_merged_snapshot_is_used_when_enabled(client, monkeypatch):
    module = publication(monkeypatch)
    with mock.patch("requests.get") as direct:
        assert client.get_connections() == module.snapshot.return_value
        direct.assert_not_called()


def test_missing_old_instance_never_falls_back_to_partial_billing(client, monkeypatch):
    module = publication(monkeypatch)
    module.snapshot.side_effect = RuntimeError("missing drainer")
    with mock.patch("requests.get") as direct:
        assert client.get_connections() is None
        direct.assert_not_called()


def test_close_uses_generation_identity(client, monkeypatch):
    module = publication(monkeypatch)
    with mock.patch("requests.delete") as direct:
        assert client.close_connection("rr:g:old")
        module.close.assert_called_once_with("rr:g:old")
        direct.assert_not_called()


def test_active_vless_unavailable_is_reported(client, monkeypatch):
    module = publication(monkeypatch)
    module.proxies.side_effect = RuntimeError("not ready")
    assert client.is_available() is False


def reload_function(monkeypatch):
    tree = ast.parse((ROOT / "singbox/manager.py").read_text(encoding="utf-8"))
    fn = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "reload_singbox"
    )
    scope = {
        "__package__": "singbox",
        "os": os,
        "json": json,
        "Path": Path,
        "subprocess": subprocess,
        "logger": logging.getLogger("test"),
        "_restart_allowed": types.SimpleNamespace(get=lambda: False),
        "is_singbox_running": lambda: True,
    }
    exec(
        compile(
            ast.Module(body=[fn], type_ignores=[]), "<real_reload_function>", "exec"
        ),
        scope,
    )
    return scope


def test_default_reload_behaviour_unchanged(monkeypatch):
    monkeypatch.delenv("NODE_MANAGER_VLESS_PUBLICATION_SPEC", raising=False)
    scope = reload_function(monkeypatch)
    scope["_run"] = mock.Mock(
        return_value=types.SimpleNamespace(returncode=0, stderr="")
    )
    assert scope["reload_singbox"]()
    scope["_run"].assert_called_once_with(["systemctl", "reload", "sing-box"])


def test_managed_reload_uses_coordinator_receipt(monkeypatch):
    publication(monkeypatch)
    scope = reload_function(monkeypatch)
    scope["_run"] = mock.Mock(
        return_value=types.SimpleNamespace(returncode=0, stdout='{"ok":true}')
    )
    assert scope["reload_singbox"]()
    cmd = scope["_run"].call_args.args[0]
    assert cmd[-1] == "apply" and "vless_publication.py" in cmd[1]
    assert "systemctl" not in cmd


def test_failed_vless_publication_never_falls_back_to_hup(monkeypatch):
    publication(monkeypatch)
    scope = reload_function(monkeypatch)
    scope["_run"] = mock.Mock(
        return_value=types.SimpleNamespace(returncode=1, stdout='{"ok":false}')
    )
    assert not scope["reload_singbox"]()
    assert scope["_run"].call_count == 1


def test_corrupt_feature_spec_does_not_trigger_legacy_hup(monkeypatch):
    module = publication(monkeypatch)
    module.configured_spec = lambda: (_ for _ in ()).throw(ValueError("bad spec"))
    scope = reload_function(monkeypatch)
    scope["_run"] = mock.Mock()
    assert not scope["reload_singbox"]()
    scope["_run"].assert_not_called()
