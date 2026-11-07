"""Core liveness uses the small authenticated version endpoint."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests


API_PATH = Path(__file__).resolve().parents[1] / "node-manager/singbox/api.py"


@pytest.fixture
def api_client():
    config_module = types.ModuleType("config")
    config_module.config = types.SimpleNamespace(
        singbox=types.SimpleNamespace(api_port=9090, api_secret="liveness-test")
    )
    with patch.dict(sys.modules, {"config": config_module}):
        spec = importlib.util.spec_from_file_location("singbox._isolated_liveness_api", API_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module, module.SingboxAPI()


def test_liveness_uses_authenticated_version_without_loading_outbounds(api_client):
    module, client = api_client
    response = Mock(status_code=200)
    response.json.side_effect = AssertionError("liveness must not decode an outbound snapshot")
    with patch.object(client, "_vless_publication", return_value=None), \
            patch.object(module.requests, "get", return_value=response) as get:
        assert client.is_available() is True
    get.assert_called_once_with(
        "http://127.0.0.1:9090/version",
        headers={"Authorization": "Bearer liveness-test"},
        timeout=2,
    )
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [204, 401, 403, 404, 500])
def test_non_200_including_authentication_failure_is_unavailable(api_client, status):
    module, client = api_client
    with patch.object(client, "_vless_publication", return_value=None), \
            patch.object(module.requests, "get", return_value=types.SimpleNamespace(status_code=status)):
        assert client.is_available() is False


@pytest.mark.parametrize("error", [requests.Timeout(), requests.ConnectionError(), RuntimeError()])
def test_request_timeout_or_other_exception_is_unavailable(api_client, error):
    module, client = api_client
    with patch.object(client, "_vless_publication", return_value=None), \
            patch.object(module.requests, "get", side_effect=error):
        assert client.is_available() is False


def test_keyboard_interrupt_is_not_swallowed(api_client):
    module, client = api_client
    with patch.object(client, "_vless_publication", return_value=None), \
            patch.object(module.requests, "get", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            client.is_available()


@pytest.mark.parametrize("proxies,available", [({"proxies": {}}, True), (None, False)])
def test_generation_publication_keeps_aggregate_proxies_check(api_client, proxies, available):
    module, client = api_client
    publication = types.SimpleNamespace(proxies=Mock(return_value=proxies))
    with patch.object(client, "_vless_publication", return_value=publication), \
            patch.object(module.requests, "get") as get:
        assert client.is_available() is available
    publication.proxies.assert_called_once_with()
    get.assert_not_called()


def test_generation_failure_does_not_fall_back_to_version(api_client):
    module, client = api_client
    publication = types.SimpleNamespace(proxies=Mock(side_effect=RuntimeError("missing generation")))
    with patch.object(client, "_vless_publication", return_value=publication), \
            patch.object(module.requests, "get") as get:
        assert client.is_available() is False
    get.assert_not_called()


def test_runtime_mode_validation_failure_does_not_fall_back_to_http(api_client):
    module, client = api_client
    with patch.object(client, "_vless_publication", side_effect=RuntimeError("runtime mode invalid")), \
            patch.object(module.requests, "get") as get:
        assert client.is_available() is False
    get.assert_not_called()
