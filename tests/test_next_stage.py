import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "node-manager"
sys.path.insert(0, str(APP_ROOT))

BOOTSTRAP_DIR = tempfile.TemporaryDirectory()
BOOTSTRAP_ROOT = Path(BOOTSTRAP_DIR.name)
BOOTSTRAP_CONFIG = BOOTSTRAP_ROOT / "config.yaml"
BOOTSTRAP_CONFIG.write_text(
    """
node:
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
""".strip()
    + "\n",
    encoding="utf-8",
)
os.environ["NODE_MANAGER_CONFIG"] = str(BOOTSTRAP_CONFIG)

import config as config_module

importlib.reload(config_module)
import singbox.manager as manager
import main
from models.request import CreateUserRequest


def base_singbox_config():
    return {
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-reality",
                "listen_port": 20168,
                "users": [],
                "tls": {
                    "server_name": "www.cloudflare.com",
                    "reality": {
                        "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                        "short_id": ["0123456789abcdef"],
                    },
                },
            },
            {"type": "vmess", "tag": "vmess", "listen_port": 20169, "users": []},
            {"type": "socks", "tag": "socks", "listen_port": 5001, "users": []},
        ],
        "outbounds": [],
        "route": {"rules": []},
    }


class ManagerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.config_path = root / "sing-box.json"
        self.registry_path = root / "users.json"
        self.config_path.write_text(
            json.dumps(base_singbox_config(), indent=2) + "\n", encoding="utf-8"
        )
        self.config_patch = patch.object(manager, "CONFIG_PATH", self.config_path)
        self.registry_patch = patch.object(manager, "REGISTRY_PATH", self.registry_path)
        self.write_patch = patch.object(manager, "_write_and_reload", self._write_config)
        self.config_patch.start()
        self.registry_patch.start()
        self.write_patch.start()

    def tearDown(self):
        self.write_patch.stop()
        self.registry_patch.stop()
        self.config_patch.stop()
        self.temp_dir.cleanup()

    def _write_config(self, data):
        self.config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def test_custom_socks_credentials_follow_bind_list_and_delete(self):
        created = manager.create_user(
            "customer-1",
            ["vless", "vmess", "socks"],
            socks_username="residential-user",
            socks_password="residential-password",
        )
        self.assertEqual(created["socks"]["username"], "residential-user")
        self.assertEqual(created["socks"]["password"], "residential-password")

        manager.bind_proxy(
            "customer-1",
            {
                "type": "socks5",
                "server": "203.0.113.20",
                "port": 1080,
                "username": "residential-user",
                "password": "residential-password",
            },
        )
        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(
            data["route"]["rules"][0]["auth_user"],
            ["node-manager:customer-1", "residential-user"],
        )

        users = manager.list_users()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["userId"], "customer-1")
        self.assertEqual(users[0]["protocols"], ["vless", "vmess", "socks"])
        self.assertEqual(users[0]["socksUsername"], "residential-user")
        self.assertTrue(users[0]["proxyBound"])
        self.assertEqual(users[0]["proxyServer"], "203.0.113.20:1080")

        manager.delete_user("customer-1")
        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(sum(len(item["users"]) for item in data["inbounds"]), 0)
        self.assertEqual(data["outbounds"], [])
        self.assertEqual(data["route"]["rules"], [])
        self.assertEqual(manager.list_users(), [])

    def test_password_is_generated_when_omitted(self):
        created = manager.create_user(
            "customer-2", ["socks"], socks_username="residential-user-2"
        )
        self.assertEqual(created["socks"]["username"], "residential-user-2")
        self.assertGreaterEqual(len(created["socks"]["password"]), 20)

    def test_create_can_atomically_bind_proxy_and_reuse_credentials(self):
        created = manager.create_user(
            "customer-proxy",
            ["vless", "socks"],
            proxy={
                "type": "socks5",
                "server": "203.0.113.30",
                "port": 2080,
                "username": "upstream-user",
                "password": "upstream-password",
            },
        )
        self.assertTrue(created["proxyBound"])
        self.assertEqual(created["socks"]["username"], "upstream-user")
        self.assertEqual(created["socks"]["password"], "upstream-password")

        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(data["outbounds"][0]["server"], "203.0.113.30")
        self.assertEqual(data["outbounds"][0]["server_port"], 2080)
        self.assertEqual(
            data["route"]["rules"][0]["auth_user"],
            ["node-manager:customer-proxy", "upstream-user"],
        )
        self.assertTrue(manager.list_users()[0]["proxyBound"])

    def test_duplicate_socks_username_is_rejected(self):
        manager.create_user("customer-3", ["socks"], socks_username="shared-user")
        with self.assertRaisesRegex(manager.SingboxConfigError, "SOCKS username already exists"):
            manager.create_user("customer-4", ["socks"], socks_username="shared-user")

    def test_socks_username_cannot_match_another_protocol_auth_name(self):
        manager.create_user("customer-7", ["vless"])
        with self.assertRaisesRegex(manager.SingboxConfigError, "SOCKS username already exists"):
            manager.create_user(
                "customer-8", ["socks"], socks_username="node-manager:customer-7"
            )

    def test_registry_is_restored_when_config_update_fails(self):
        self.write_patch.stop()
        with patch.object(
            manager, "_write_and_reload", side_effect=manager.SingboxConfigError("failed")
        ):
            with self.assertRaises(manager.SingboxConfigError):
                manager.create_user("customer-5", ["socks"])
        self.write_patch.start()
        self.assertFalse(self.registry_path.exists())

    def test_credentials_require_socks_protocol(self):
        with self.assertRaises(ValueError):
            CreateUserRequest(
                userId="customer-6",
                protocols=["vless"],
                socksUsername="not-applicable",
            )


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.config_path = root / "sing-box.json"
        self.registry_path = root / "users.json"
        self.config_path.write_text(
            json.dumps(base_singbox_config(), indent=2) + "\n", encoding="utf-8"
        )
        self.config_patch = patch.object(manager, "CONFIG_PATH", self.config_path)
        self.registry_patch = patch.object(manager, "REGISTRY_PATH", self.registry_path)
        self.write_patch = patch.object(manager, "_write_and_reload", self._write_config)
        self.config_patch.start()
        self.registry_patch.start()
        self.write_patch.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.write_patch.stop()
        self.registry_patch.stop()
        self.config_patch.stop()
        self.temp_dir.cleanup()

    def _write_config(self, data):
        self.config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def test_create_user_and_list_endpoints(self):
        headers = {"Authorization": "Bearer test-token"}
        response = self.client.post(
            "/api/user/create",
            headers=headers,
            json={
                "userId": "api-user",
                "protocols": ["socks"],
                "socksUsername": "api-socks-user",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["socks"]["username"], "api-socks-user")

        response = self.client.get("/api/users?page=1&pageSize=10", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["total"], 1)
        self.assertEqual(response.json()["items"][0]["userId"], "api-user")
        self.assertNotIn("password", response.text.lower())

    def test_create_user_endpoint_can_bind_proxy(self):
        headers = {"Authorization": "Bearer test-token"}
        response = self.client.post(
            "/api/user/create",
            headers=headers,
            json={
                "userId": "api-proxy-user",
                "protocols": ["socks"],
                "proxy": {
                    "type": "socks5",
                    "server": "203.0.113.40",
                    "port": 1080,
                    "username": "proxy-user",
                    "password": "proxy-password",
                },
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["proxyBound"])
        self.assertEqual(body["socks"]["username"], "proxy-user")

        response = self.client.get("/api/users", headers=headers)
        self.assertTrue(response.json()["items"][0]["proxyBound"])

    def test_node_list_endpoint(self):
        headers = {"Authorization": "Bearer test-token"}
        with (
            patch.object(
                main,
                "get_node_status",
                return_value={
                    "node": "test-node",
                    "singbox": "running",
                    "cpu": 1.5,
                    "memory": 2.5,
                    "connections": 3,
                },
            ),
            patch.object(main, "_singbox_version", return_value="1.13.14"),
            patch.object(main, "is_api_available", return_value=True),
        ):
            response = self.client.get("/api/nodes", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["nodeId"], "test-node")
        self.assertEqual(body["items"][0]["managerVersion"], "1.2.0")
        self.assertEqual(body["items"][0]["singboxVersion"], "1.13.14")


if __name__ == "__main__":
    unittest.main()
