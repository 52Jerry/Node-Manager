"""Load a synthetic node configuration before test module collection.

Runtime modules retain the config object imported at module load time. Loading
the fixture only in test_next_stage made the full suite depend on import order.
"""
from __future__ import annotations

import os
import tempfile
import sys
import socket
from pathlib import Path
from unittest.mock import patch
import requests

_previous = os.environ.get("NODE_MANAGER_CONFIG")
_directory = tempfile.TemporaryDirectory(prefix="node-manager-tests-")
_path = Path(_directory.name) / "config.yaml"
_path.write_text("""node:
  id: test-node
  name: Test Node
  host: 192.0.2.10
server:
  port: 8088
security:
  token: test-token
singbox:
  config: unused.json
  api_port: 9090
  vless_tag: vless-reality
  vmess_tag: vmess
  socks_tag: socks
""", encoding="utf-8")
os.environ["NODE_MANAGER_CONFIG"] = str(_path)
sys.path.insert(0, str(Path(__file__).parent / "node-manager"))
# Embedded offline tests must not initialize the shared configuration using
# their deliberately absent fixture before normal authenticated API tests run.
with patch.object(requests, "get", side_effect=requests.RequestException("offline tests")), \
        patch.object(socket.socket, "connect", side_effect=OSError("offline tests")):
    import config as _config_module


def pytest_unconfigure(config):
    if _previous is None:
        os.environ.pop("NODE_MANAGER_CONFIG", None)
    else:
        os.environ["NODE_MANAGER_CONFIG"] = _previous
    _directory.cleanup()
