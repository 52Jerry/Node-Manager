import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote
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
import idempotency
import main
import monitor.status as status_monitor
import monitor.traffic as traffic
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
        self.idempotency_path = root / "idempotency.json"
        self.traffic_path = root / "traffic.json"
        self.config_path.write_text(
            json.dumps(base_singbox_config(), indent=2) + "\n", encoding="utf-8"
        )
        self.config_patch = patch.object(manager, "CONFIG_PATH", self.config_path)
        self.registry_patch = patch.object(manager, "REGISTRY_PATH", self.registry_path)
        self.write_patch = patch.object(manager, "_write_and_reload", self._write_config)
        self.idempotency_patch = patch.object(
            idempotency, "STORE_PATH", self.idempotency_path
        )
        self.traffic_patch = patch.object(traffic, "TRAFFIC_PATH", self.traffic_path)
        self.config_patch.start()
        self.registry_patch.start()
        self.write_patch.start()
        self.idempotency_patch.start()
        self.traffic_patch.start()

    def tearDown(self):
        self.traffic_patch.stop()
        self.idempotency_patch.stop()
        self.write_patch.stop()
        self.registry_patch.stop()
        self.config_patch.stop()
        self.temp_dir.cleanup()

    def _write_config(self, data):
        self.config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def test_explicit_credential_edit_updates_inbound_outbound_links_and_enforcement(self):
        created = manager.create_user(
            "edit-user", ["vless", "vmess", "socks"],
            socks_username="old-account", socks_password="old-password",
        )
        manager.sync_user_enforcements({"edit-user": {"trafficBlocked": True, "blockedSourceIps": []}})
        manager.bind_proxy("edit-user", {
            "server": "203.0.113.20", "port": 1080,
            "username": "new-account", "password": "new-password",
        }, sync_socks_credentials=True)
        data = manager.read_config()
        socks = next(item for item in data["inbounds"] if item["tag"] == "socks")
        self.assertEqual(socks["users"], [{"username": "new-account", "password": "new-password"}])
        outbound = next(item for item in data["outbounds"] if item["type"] == "socks")
        self.assertEqual(outbound["username"], "new-account")
        self.assertEqual(outbound["password"], "new-password")
        for rule in data["route"]["rules"]:
            if "auth_user" in rule:
                self.assertNotIn("old-account", rule["auth_user"])
                self.assertIn("new-account", rule["auth_user"])
        connections = manager.get_user_connection("edit-user")
        self.assertEqual(connections["uuid"], created["uuid"])
        self.assertEqual(connections["socks"]["password"], "new-password")
        self.assertEqual(manager.get_user_proxy("edit-user")["username"], "new-account")
        self.assertEqual(connections["protocolInfo"]["password"], "new-password")
        self.assertEqual(manager.read_registry()["users"]["edit-user"]["expiresAt"], created["expiresAt"])
        manager.sync_user_enforcements({"edit-user": {"trafficBlocked": False, "blockedSourceIps": []}})
        self.assertFalse(any(rule.get("action") == "reject" for rule in manager.read_config()["route"]["rules"]))

    def test_credential_edit_preserves_source_ip_and_expiration_blocks(self):
        manager.create_user("edit-user", ["socks"], socks_username="old-account", socks_password="old")
        manager.sync_user_enforcements({"edit-user": {"blockedSourceIps": ["198.51.100.3"]}})
        now = datetime.now(timezone.utc)
        registry = manager.read_registry()
        registry["users"]["edit-user"]["expiresAt"] = (now - timedelta(hours=1)).isoformat()
        self.registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
        with patch.object(manager.singbox_api, "get_connections", return_value={"connections": []}):
            manager.process_user_expirations(now)
        manager.bind_proxy("edit-user", {
            "server": "203.0.113.20", "port": 1080, "username": "new-account", "password": "new",
        }, sync_socks_credentials=True)
        rules = manager.read_config()["route"]["rules"]
        self.assertEqual([rule["action"] for rule in rules[:3]], ["reject", "reject", "route"])
        self.assertTrue(all("new-account" in rule["auth_user"] for rule in rules))
        manager.sync_user_enforcements({"edit-user": {"blockedSourceIps": []}})
        self.assertEqual(sum(rule["action"] == "reject" for rule in manager.read_config()["route"]["rules"]), 1)
        manager.update_user_expiration("edit-user", datetime.now(timezone.utc) + timedelta(days=1))
        self.assertFalse(any(rule["action"] == "reject" for rule in manager.read_config()["route"]["rules"]))

    def test_credential_edit_rejects_duplicate_username_without_mutation(self):
        manager.create_user("edit-user", ["socks"], socks_username="first", socks_password="old")
        manager.create_user("other-user", ["socks"], socks_username="taken", socks_password="other")
        before = self.config_path.read_bytes(), self.registry_path.read_bytes()
        with self.assertRaises(manager.SingboxConfigError):
            manager.bind_proxy("edit-user", {
                "server": "203.0.113.20", "port": 1080, "username": "taken", "password": "new",
            }, sync_socks_credentials=True)
        self.assertEqual(before, (self.config_path.read_bytes(), self.registry_path.read_bytes()))

    def test_credential_edit_reload_failure_restores_registry(self):
        manager.create_user("edit-user", ["socks"], socks_username="old-account", socks_password="old")
        before = self.config_path.read_bytes(), self.registry_path.read_bytes()
        with patch.object(manager, "_write_and_reload", side_effect=RuntimeError("reload failed")):
            with self.assertRaises(RuntimeError):
                manager.bind_proxy("edit-user", {
                    "server": "203.0.113.20", "port": 1080, "username": "new-account", "password": "new",
                }, sync_socks_credentials=True)
        self.assertEqual(before, (self.config_path.read_bytes(), self.registry_path.read_bytes()))

    def test_credential_rotation_updates_all_protocol_credentials_atomically(self):
        config_data = manager.read_config()
        config_data["inbounds"].append({
            "type": "trojan",
            "tag": "trojan",
            "listen_port": 20170,
            "tls": json.loads(json.dumps(config_data["inbounds"][0]["tls"])),
            "users": [],
        })
        self._write_config(config_data)
        created = manager.create_user(
            "rotate-user",
            ["vless", "vmess", "trojan", "socks"],
            socks_username="old-account",
            socks_password="old-password",
        )
        rotated_uuid = "22222222-2222-4222-8222-222222222222"

        manager.bind_proxy(
            "rotate-user",
            {
                "server": "203.0.113.20",
                "port": 1080,
                "username": "new-account",
                "password": "new-password",
            },
            sync_socks_credentials=True,
            new_uuid=rotated_uuid,
        )

        data = manager.read_config()
        inbounds = {item["tag"]: item for item in data["inbounds"]}
        self.assertEqual(
            next(user for user in inbounds["vless-reality"]["users"]
                 if user["name"] == "node-manager:rotate-user")["uuid"],
            rotated_uuid,
        )
        self.assertEqual(
            next(user for user in inbounds["vmess"]["users"]
                 if user["name"] == "node-manager:rotate-user")["uuid"],
            rotated_uuid,
        )
        self.assertEqual(
            next(user for user in inbounds["trojan"]["users"]
                 if user["name"] == "node-manager:rotate-user")["password"],
            rotated_uuid,
        )
        self.assertEqual(
            next(user for user in inbounds["socks"]["users"]
                 if user["username"] == "new-account")["password"],
            "new-password",
        )
        connection = manager.get_user_connection("rotate-user")
        self.assertEqual(connection["uuid"], rotated_uuid)
        self.assertNotEqual(connection["vless"], created["vless"])
        self.assertNotEqual(connection["vmess"], created["vmess"])

    def test_proxy_rebind_without_explicit_edit_preserves_socks_credentials(self):
        manager.create_user("edit-user", ["socks"], socks_username="local-user", socks_password="local-password")
        manager.bind_proxy("edit-user", {
            "server": "203.0.113.20", "port": 1080, "username": "upstream-user", "password": "upstream-password",
        })
        self.assertEqual(manager.get_user_connection("edit-user")["socks"]["password"], "local-password")

    def test_custom_socks_credentials_follow_bind_list_and_delete(self):
        created = manager.create_user(
            "customer-1",
            ["vless", "vmess", "socks"],
            socks_username="residential-user",
            socks_password="residential-password",
        )
        self.assertEqual(created["socks"]["username"], "residential-user")
        self.assertEqual(created["socks"]["password"], "residential-password")
        self.assertEqual(
            set(created["protocolsAll"]),
            {"vless", "socksAcceleration", "vmess"},
        )

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
        vless_user = next(
            user
            for user in next(item for item in data["inbounds"] if item["tag"] == "vless-reality")["users"]
            if user["name"] == "node-manager:customer-1"
        )
        vmess_user = next(
            user
            for user in next(item for item in data["inbounds"] if item["tag"] == "vmess")["users"]
            if user["name"] == "node-manager:customer-1"
        )
        socks_user = next(
            user
            for user in next(item for item in data["inbounds"] if item["tag"] == "socks")["users"]
            if user["username"] == "residential-user"
        )
        self.assertEqual(vless_user["uuid"], created["uuid"])
        self.assertEqual(vmess_user["uuid"], created["uuid"])
        self.assertEqual(socks_user["password"], "residential-password")
        outbound = next(
            item for item in data["outbounds"] if item["tag"] == "node-manager-out:customer-1"
        )
        self.assertEqual(outbound["server"], "203.0.113.20")
        self.assertEqual(outbound["server_port"], 1080)
        self.assertEqual(data["route"]["rules"][0]["outbound"], outbound["tag"])

        users = manager.list_users()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["userId"], "customer-1")
        self.assertEqual(users[0]["protocols"], ["vless", "vmess", "socks"])
        self.assertEqual(users[0]["socksUsername"], "residential-user")
        self.assertTrue(users[0]["proxyBound"])
        self.assertEqual(users[0]["proxyServer"], "203.0.113.20:1080")

        connection = manager.get_user_connection("customer-1")
        self.assertEqual(connection["protocols"], ["vless", "vmess", "socks"])
        self.assertEqual(connection["uuid"], created["uuid"])
        self.assertEqual(connection["vless"], created["vless"])
        self.assertEqual(connection["vmess"], created["vmess"])
        self.assertEqual(connection["socks"], created["socks"])
        self.assertEqual(
            set(connection["protocolsAll"]),
            {"vless", "socksAcceleration", "vmess"},
        )
        self.assertTrue(connection["proxyBound"])
        self.assertNotIn("socks5", connection["protocolsAll"])
        self.assertNotIn("bitbrowser", connection["protocolsAll"])
        self.assertNotIn("upstream-user", str(connection))
        self.assertNotIn("upstream-password", str(connection))

        manager.delete_user("customer-1")
        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(sum(len(item["users"]) for item in data["inbounds"]), 0)
        self.assertEqual(data["outbounds"], [])
        self.assertEqual(data["route"]["rules"], [])
        self.assertEqual(manager.list_users(), [])

    def test_protocol_links_follow_actual_singbox_inbound_ports(self):
        data = base_singbox_config()
        data["inbounds"][0]["listen_port"] = 21068
        data["inbounds"][1]["listen_port"] = 21069
        data["inbounds"][2]["listen_port"] = 5101
        self._write_config(data)

        created = manager.create_user(
            "custom-ports",
            ["vless", "vmess", "socks"],
            socks_username="custom-ports-user",
            socks_password="custom-ports-password",
        )

        # VLESS/VMess/SOCKS 加速协议使用配置的 acceleration_domain，
        # 但端口必须跟随实际 sing-box inbound，而不是硬编码默认值。
        self.assertIn("@192.0.2.10:21068?", created["protocolsAll"]["vless"])
        self.assertEqual(created["socks"]["port"], 5101)
        self.assertIn("@192.0.2.10:5101#", created["protocolsAll"]["socksAcceleration"])
        vmess_payload = created["protocolsAll"]["vmess"].split("//", 1)[1]
        vmess_config = json.loads(__import__("base64").b64decode(vmess_payload))
        self.assertEqual(vmess_config["port"], "21069")

    def test_residential_links_separate_exit_ip_upstream_and_node_endpoint(self):
        """住宅出口只用于展示；原始 SOCKS 连接上游；加速协议连接本节点。"""
        with patch.object(manager.config.node, "host", "203.0.113.20"), patch.object(
            manager.config.node, "acceleration_domain", "203.0.113.20"
        ):
            created = manager.create_user(
                "residential-user",
                ["vless", "vmess", "socks"],
                socks_username="residential-user",
                socks_password="local-node-password",
                proxy={
                    "type": "socks5",
                    "server": "203.0.113.30",
                    "port": 5001,
                    "username": "upstream-user",
                    "password": "upstream-password",
                    "sourceIp": "203.0.113.10",
                    "sourceAddress": "203.0.113.30",
                    "sourcePort": 5001,
                    "countryCode": "us",
                },
            )

        links = created["protocolsAll"]
        raw_auth = __import__("base64").b64encode(
            b"upstream-user:upstream-password"
        ).decode("ascii")
        self.assertIn(f"socks://{raw_auth}@203.0.113.30:5001", links["socks5"])
        self.assertEqual(links["bitbrowser"], "203.0.113.30:5001:upstream-user:upstream-password")
        self.assertIn("@203.0.113.20:20168?", links["vless"])
        self.assertIn("@203.0.113.20:5001#", links["socksAcceleration"])
        self.assertEqual(
            unquote(links["vless"].rsplit("#", 1)[1]), "[US] 203.0.113.10"
        )
        self.assertEqual(
            unquote(links["socksAcceleration"].rsplit("#", 1)[1]),
            "[US] 203.0.113.10",
        )
        vmess_payload = links["vmess"].split("//", 1)[1]
        vmess_config = json.loads(__import__("base64").b64decode(vmess_payload))
        self.assertEqual(vmess_config["add"], "203.0.113.20")
        self.assertEqual(vmess_config["ps"], "[US] 203.0.113.10")
        self.assertEqual(created["protocolInfo"]["countryCode"], "US")
        self.assertEqual(created["protocolInfo"]["ip"], "203.0.113.10")
        for key in ("vless", "socksAcceleration", "vmess"):
            self.assertNotIn("upstream-user", links[key])
            self.assertNotIn("upstream-password", links[key])

        refreshed = manager.get_user_connection("residential-user")
        self.assertEqual(refreshed["protocolInfo"]["countryCode"], "US")
        self.assertEqual(
            unquote(refreshed["protocolsAll"]["vless"].rsplit("#", 1)[1]),
            "[US] 203.0.113.10",
        )

    def test_proxy_metadata_backfill_repairs_legacy_alias_without_changing_route(self):
        manager.create_user(
            "legacy-country",
            ["vless", "vmess", "socks"],
            proxy={
                "type": "socks5",
                "server": "proxy.example.test",
                "port": 1080,
                "username": "upstream-user",
                "password": "upstream-password",
                "sourceIp": "207.152.99.183",
            },
        )
        before_config = json.loads(self.config_path.read_text(encoding="utf-8"))
        before = manager.get_user_connection("legacy-country")
        self.assertEqual(
            unquote(before["protocolsAll"]["vless"].rsplit("#", 1)[1]),
            "[XX] 207.152.99.183",
        )

        manager.update_proxy_metadata(
            "legacy-country",
            {
                "sourceIp": "207.152.99.183",
                "countryCode": "us",
                "countryName": "美国",
            },
        )

        after_config = json.loads(self.config_path.read_text(encoding="utf-8"))
        after = manager.get_user_connection("legacy-country")
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertEqual(after_config, before_config)
        self.assertEqual(registry["users"]["legacy-country"]["countryCode"], "US")
        self.assertEqual(after["protocolInfo"]["countryCode"], "US")
        self.assertEqual(
            unquote(after["protocolsAll"]["vless"].rsplit("#", 1)[1]),
            "[US] 207.152.99.183",
        )
        vmess_payload = after["protocolsAll"]["vmess"].split("//", 1)[1]
        vmess_config = json.loads(__import__("base64").b64decode(vmess_payload))
        self.assertEqual(vmess_config["ps"], "[US] 207.152.99.183")

    def test_structured_protocol_info_uses_configured_domain_and_uuid(self):
        with patch.object(manager.config.node, "acceleration_domain", "proxy.example.test"):
            created = manager.create_user("structured-domain", ["vless", "vmess", "socks"])

        info = created["protocolInfo"]
        self.assertEqual(info["id"], created["uuid"])
        self.assertEqual(info["accelerationDomain"], "proxy.example.test")
        self.assertEqual(info["vlessPort"], 20168)
        self.assertEqual(info["vmessPort"], 20169)
        self.assertEqual(info["accelerationPortSocks"], 5001)
        self.assertNotIn("rawProtocol", info)
        self.assertIn("@proxy.example.test:20168?", created["vless"])
        self.assertEqual(created["vmess"], created["protocolsAll"]["vmess"])
        self.assertEqual(created["socks"]["host"], "proxy.example.test")

    def test_structured_protocol_info_supports_ipv6_acceleration_endpoint(self):
        with patch.object(manager.config.node, "acceleration_domain", "2001:db8::10"):
            created = manager.create_user("structured-ipv6", ["vless", "vmess", "socks"])

        info = created["protocolInfo"]
        self.assertEqual(info["accelerationDomain"], "2001:db8::10")
        self.assertIn("@[2001:db8::10]:20168?", created["vless"])
        self.assertEqual(created["socks"]["host"], "2001:db8::10")
        vmess_payload = created["vmess"].split("//", 1)[1]
        vmess_config = json.loads(__import__("base64").b64decode(vmess_payload))
        self.assertEqual(vmess_config["add"], "2001:db8::10")

    def test_password_is_generated_when_omitted(self):
        created = manager.create_user(
            "customer-2", ["socks"], socks_username="residential-user-2"
        )
        self.assertEqual(created["socks"]["username"], "residential-user-2")
        self.assertGreaterEqual(len(created["socks"]["password"]), 20)

        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        outbound = next(
            item
            for item in data["outbounds"]
            if item["tag"] == "node-manager-out:customer-2"
        )
        self.assertEqual(outbound["type"], "direct")
        self.assertFalse(manager.list_users()[0]["proxyBound"])

        connection = manager.get_user_connection("customer-2")
        self.assertEqual(connection["protocols"], ["socks"])
        self.assertEqual(connection["socks"]["username"], "residential-user-2")
        self.assertEqual(connection["socks"]["password"], created["socks"]["password"])

    def test_connection_details_support_legacy_socks_user_without_registry(self):
        data = base_singbox_config()
        legacy_name = "node-manager:legacy-user"
        data["inbounds"][0]["users"].append(
            {
                "name": legacy_name,
                "uuid": "11111111-1111-4111-8111-111111111111",
                "flow": "xtls-rprx-vision",
            }
        )
        data["inbounds"][1]["users"].append(
            {
                "name": legacy_name,
                "uuid": "11111111-1111-4111-8111-111111111111",
            }
        )
        data["inbounds"][2]["users"].append(
            {"username": legacy_name, "password": "legacy-password"}
        )
        self._write_config(data)

        connection = manager.get_user_connection("legacy-user")

        self.assertEqual(connection["protocols"], ["vless", "vmess", "socks"])
        self.assertEqual(connection["socks"]["username"], "legacy-user")
        self.assertEqual(connection["socks"]["password"], "legacy-password")

    def test_legacy_socks_username_migration_updates_route_and_registry(self):
        data = base_singbox_config()
        legacy_name = "node-manager:migrate-user"
        data["inbounds"][0]["users"].append(
            {
                "name": legacy_name,
                "uuid": "22222222-2222-4222-8222-222222222222",
                "flow": "xtls-rprx-vision",
            }
        )
        data["inbounds"][1]["users"].append(
            {"name": legacy_name, "uuid": "22222222-2222-4222-8222-222222222222"}
        )
        data["inbounds"][2]["users"].append(
            {"username": legacy_name, "password": "keep-this-password"}
        )
        data["route"]["rules"].append(
            {
                "auth_user": [legacy_name],
                "action": "route",
                "outbound": "node-manager-out:migrate-user",
            }
        )
        self._write_config(data)

        self.assertEqual(manager.migrate_legacy_socks_usernames(), 1)
        migrated = json.loads(self.config_path.read_text(encoding="utf-8"))
        socks_users = next(item for item in migrated["inbounds"] if item["tag"] == "socks")["users"]
        self.assertEqual(socks_users, [{"username": "migrate-user", "password": "keep-this-password"}])
        self.assertEqual(migrated["route"]["rules"][-1]["auth_user"], ["migrate-user"])
        self.assertEqual(manager.list_users()[0]["socksUsername"], "migrate-user")

    def test_expiration_migration_discovers_users_missing_from_registry(self):
        data = base_singbox_config()
        legacy_name = "node-manager:config-only-user"
        data["inbounds"][0]["users"].append({
            "name": legacy_name,
            "uuid": "33333333-3333-4333-8333-333333333333",
            "flow": "xtls-rprx-vision",
        })
        data["inbounds"][1]["users"].append({
            "name": legacy_name,
            "uuid": "33333333-3333-4333-8333-333333333333",
        })
        data["inbounds"][2]["users"].append({
            "username": "config-only-user",
            "password": "config-only-password",
        })
        data["inbounds"][2]["users"].append({
            "username": "manual-socks-user",
            "password": "manual-socks-password",
        })
        self._write_config(data)

        self.assertEqual(manager.migrate_user_expirations(), 1)
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        metadata = registry["users"]["config-only-user"]
        self.assertNotIn("manual-socks-user", registry["users"])
        created_at = datetime.fromisoformat(metadata["createdAt"])
        expires_at = datetime.fromisoformat(metadata["expiresAt"])
        self.assertEqual(expires_at - created_at, timedelta(days=30))
        self.assertEqual(
            manager.list_users()[0]["expirationStatus"],
            "ACTIVE",
        )
        self.assertEqual(
            manager.get_user_connection("config-only-user")["socks"]["username"],
            "config-only-user",
        )
        migrated = json.loads(self.config_path.read_text(encoding="utf-8"))
        socks_users = next(item for item in migrated["inbounds"] if item["tag"] == "socks")["users"]
        self.assertIn({"username": "manual-socks-user", "password": "manual-socks-password"}, socks_users)

    def test_create_can_atomically_bind_proxy_without_reusing_upstream_credentials(self):
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
        self.assertNotEqual(created["socks"]["username"], "upstream-user")
        self.assertNotEqual(created["socks"]["password"], "upstream-password")
        self.assertEqual(
            set(created["protocolsAll"]),
            {"socks5", "bitbrowser", "vless", "socksAcceleration"},
        )
        # Raw SOCKS5 and BitBrowser intentionally use the upstream
        # residential credentials.  Only acceleration protocols must keep
        # those credentials out of public links.
        raw_auth = created["protocolsAll"]["socks5"].split("socks://", 1)[1].split("@", 1)[0]
        self.assertEqual(
            __import__("base64").b64decode(raw_auth).decode("utf-8"),
            "upstream-user:upstream-password",
        )
        self.assertIn("upstream-user", created["protocolsAll"]["bitbrowser"])
        self.assertIn("upstream-password", created["protocolsAll"]["bitbrowser"])
        for key in ("vless", "socksAcceleration"):
            self.assertNotIn("upstream-user", created["protocolsAll"][key])
            self.assertNotIn("upstream-password", created["protocolsAll"][key])

        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(data["outbounds"][0]["server"], "203.0.113.30")
        self.assertEqual(data["outbounds"][0]["server_port"], 2080)
        self.assertEqual(
            set(data["route"]["rules"][0]["auth_user"]),
            {"customer-proxy", "node-manager:customer-proxy"},
        )
        self.assertTrue(manager.list_users()[0]["proxyBound"])

    def test_direct_user_returns_only_three_acceleration_links(self):
        created = manager.create_user(
            "direct-user",
            ["vless", "vmess", "socks"],
        )
        self.assertEqual(
            set(created["protocolsAll"]),
            {"vless", "socksAcceleration", "vmess"},
        )
        self.assertNotIn("socks5", created["protocolsAll"])
        self.assertNotIn("bitbrowser", created["protocolsAll"])
        for link in created["protocolsAll"].values():
            self.assertTrue(link)

    def test_proxy_credentials_are_used_only_by_outbound(self):
        created = manager.create_user(
            "proxy-isolated",
            ["vless", "vmess", "socks"],
            proxy={
                "type": "socks5",
                "server": "203.0.113.30",
                "port": 2080,
                "username": "upstream-user",
                "password": "upstream-password",
            },
        )
        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        outbound = next(item for item in data["outbounds"] if item["tag"] == "node-manager-out:proxy-isolated")
        self.assertEqual(outbound["username"], "upstream-user")
        self.assertEqual(outbound["password"], "upstream-password")
        self.assertNotEqual(created["socks"]["username"], outbound["username"])
        self.assertNotEqual(created["socks"]["password"], outbound["password"])

    def test_create_rejects_proxy_loop_to_local_socks_without_leaving_user(self):
        with self.assertRaisesRegex(manager.SingboxConfigError, "proxy loop"):
            manager.create_user(
                "loop-user",
                ["vless", "vmess", "socks"],
                proxy={
                    "type": "socks5",
                    "server": "192.0.2.10",
                    "port": 5001,
                    "username": "loop-user",
                    "password": "loop-password",
                },
            )

        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(sum(len(item["users"]) for item in data["inbounds"]), 0)
        self.assertEqual(data["outbounds"], [])
        self.assertEqual(data["route"]["rules"], [])
        self.assertEqual(manager.list_users(), [])

    def test_bind_rejects_domain_resolving_to_local_socks_and_preserves_direct_route(self):
        manager.create_user("loop-bind-user", ["socks"])

        with (
            patch.object(
                manager,
                "_resolve_host_addresses",
                side_effect=lambda host: (
                    {"192.0.2.10"} if host in {"local-proxy.example", "192.0.2.10"} else set()
                ),
            ),
            self.assertRaisesRegex(manager.SingboxConfigError, "proxy loop"),
        ):
            manager.bind_proxy(
                "loop-bind-user",
                {
                    "type": "socks5",
                    "server": "local-proxy.example",
                    "port": 5001,
                    "username": "upstream-user",
                    "password": "upstream-password",
                },
            )

        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        outbound = next(
            item
            for item in data["outbounds"]
            if item["tag"] == "node-manager-out:loop-bind-user"
        )
        self.assertEqual(outbound["type"], "direct")
        self.assertFalse(manager.list_users()[0]["proxyBound"])

    def test_local_address_on_a_different_port_is_allowed(self):
        created = manager.create_user(
            "different-port-user",
            ["socks"],
            proxy={
                "type": "socks5",
                "server": "192.0.2.10",
                "port": 6000,
                "username": "upstream-user",
                "password": "upstream-password",
            },
        )

        self.assertTrue(created["proxyBound"])
        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        outbound = next(
            item
            for item in data["outbounds"]
            if item["tag"] == "node-manager-out:different-port-user"
        )
        self.assertEqual(outbound["server_port"], 6000)

    def test_duplicate_socks_username_is_rejected(self):
        manager.create_user("customer-3", ["socks"], socks_username="shared-user")
        with self.assertRaisesRegex(manager.SingboxConfigError, "SOCKS username already exists"):
            manager.create_user("customer-4", ["socks"], socks_username="shared-user")

    def test_batch_residential_endpoints_with_shared_upstream_account_route_independently(self):
        endpoints = [("200.36.30.206", 36214), ("91.149.231.14", 50101), ("169.40.131.205", 50101)]
        for index, (server, port) in enumerate(endpoints):
            user_id = f"res-{index:032x}"
            proxy = {
                "type": "socks5", "server": server, "port": port, "sourceIp": server,
                "username": "shared-upstream", "password": "test-upstream-password",
            }
            created = manager.create_user(user_id, ["vless", "vmess", "socks"], proxy=proxy)
            self.assertTrue(created["success"])
            self.assertEqual(created["socks"]["username"], user_id)
            self.assertEqual(created["protocolInfo"]["rawUsername"], proxy["username"])
            self.assertEqual(created["protocolInfo"]["rawPassword"], proxy["password"])
            self.assertEqual(created["protocolInfo"]["sourceIp"], server)
            self.assertEqual(manager.get_user_proxy(user_id)["server"], server)

        data = manager.read_config()
        self.assertEqual(len(manager.list_users()), 3)
        socks = next(item for item in data["inbounds"] if item["tag"] == "socks")
        self.assertEqual(len({user["username"] for user in socks["users"]}), 3)
        for index, (server, port) in enumerate(endpoints):
            user_id = f"res-{index:032x}"
            outbound_tag = f"node-manager-out:{user_id}"
            outbound = next(item for item in data["outbounds"] if item["tag"] == outbound_tag)
            self.assertEqual((outbound["server"], outbound["server_port"]), (server, port))
            self.assertEqual(outbound["username"], "shared-upstream")
            self.assertEqual(outbound["password"], "test-upstream-password")
            rule = next(item for item in data["route"]["rules"] if item.get("outbound") == outbound_tag)
            self.assertEqual(set(rule["auth_user"]), {user_id, f"node-manager:{user_id}"})

    def test_duplicate_upstream_socks_identity_is_rejected(self):
        proxy = {
            "type": "socks5",
            "server": "2001:0db8:0:0:0:0:0:1",
            "port": 1080,
            "username": "residential-user",
            "password": "residential-password",
        }
        manager.create_user("duplicate-source-1", ["socks"], proxy=proxy)

        with self.assertRaisesRegex(manager.SingboxConfigError, "当前已有这条住宅IP的连接了"):
            manager.create_user("duplicate-source-1", ["socks"], proxy=proxy)

        with self.assertRaisesRegex(manager.SingboxConfigError, "当前已有这条住宅IP的连接了"):
            manager.create_user(
                "duplicate-source-2",
                ["socks"],
                proxy={**proxy, "server": "2001:db8::1"},
            )

        self.assertEqual(
            [item["userId"] for item in manager.list_users()],
            ["duplicate-source-1"],
        )

    def test_upstream_socks_identity_can_be_rebound_for_same_user(self):
        proxy = {
            "type": "socks5",
            "server": "203.0.113.50",
            "port": 1080,
            "username": "residential-user",
            "password": "residential-password",
        }
        manager.create_user("rebind-source-user", ["socks"], proxy=proxy)

        rebound = manager.bind_proxy("rebind-source-user", proxy)

        self.assertTrue(rebound["success"])
        self.assertEqual(manager.list_users()[0]["proxyServer"], "203.0.113.50:1080")

    def test_upstream_socks_identity_changes_with_port_or_credentials(self):
        manager.create_user(
            "identity-change-user",
            ["socks"],
            proxy={
                "type": "socks5",
                "server": "203.0.113.60",
                "port": 1080,
                "username": "residential-user",
                "password": "residential-password",
            },
        )

        manager.bind_proxy(
            "identity-change-user",
            {
                "type": "socks5",
                "server": "203.0.113.60",
                "port": 1081,
                "username": "residential-user",
                "password": "residential-password",
            },
        )
        manager.bind_proxy(
            "identity-change-user",
            {
                "type": "socks5",
                "server": "203.0.113.60",
                "port": 1081,
                "username": "residential-user",
                "password": "next-password",
            },
        )

        self.assertEqual(manager.list_users()[0]["proxyServer"], "203.0.113.60:1081")

    def test_multiple_upstream_socks_validation_is_atomic(self):
        manager.create_user(
            "batch-conflict-owner",
            ["socks"],
            proxy={
                "type": "socks5",
                "server": "203.0.113.70",
                "port": 1080,
                "username": "owner",
                "password": "owner-password",
            },
        )
        manager.create_user("batch-conflict-user", ["socks"])
        original = self.config_path.read_text(encoding="utf-8")

        with self.assertRaisesRegex(manager.SingboxConfigError, "当前已有这条住宅IP的连接了"):
            manager.bind_multiple_proxies(
                "batch-conflict-user",
                [
                    {
                        "server": "203.0.113.71",
                        "port": 1080,
                        "username": "new-user",
                        "password": "new-password",
                    },
                    {
                        "server": "203.0.113.70",
                        "port": 1080,
                        "username": "owner",
                        "password": "owner-password",
                    },
                ],
            )

        self.assertEqual(self.config_path.read_text(encoding="utf-8"), original)

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

    def test_user_policy_is_saved_and_can_be_updated(self):
        manager.create_user(
            "limited-user",
            ["socks"],
            traffic_limit_bytes=1024,
            max_source_ips=2,
        )
        self.assertEqual(
            manager.get_user_policy("limited-user"),
            {"trafficLimitBytes": 1024, "maxSourceIps": 2},
        )

        updated = manager.update_user_policy(
            "limited-user", {"trafficLimitBytes": 0, "maxSourceIps": 1}
        )
        self.assertIsNone(updated["trafficLimitBytes"])
        self.assertEqual(updated["maxSourceIps"], 1)

    def test_user_expiration_blocks_then_can_be_restored_within_24_hours(self):
        manager.create_user("expiring-user", ["socks"])
        now = datetime.now(timezone.utc).replace(microsecond=0)
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        registry["users"]["expiring-user"]["expiresAt"] = (now - timedelta(hours=1)).isoformat()
        self.registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")

        snapshot = {
            "connections": [
                {
                    "id": "expired-connection",
                    "chains": ["node-manager-out:expiring-user"],
                }
            ]
        }
        with (
            patch.object(manager.singbox_api, "get_connections", return_value=snapshot),
            patch.object(manager.singbox_api, "close_connection", return_value=True) as close,
        ):
            self.assertEqual(manager.process_user_expirations(now), 1)
        close.assert_called_once_with("expired-connection")
        blocked = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(blocked["route"]["rules"][0]["action"], "reject")
        with self.assertRaisesRegex(manager.SingboxConfigError, "connection expired"):
            manager.get_user_connection("expiring-user")

        restored = manager.restore_user(
            "expiring-user", now + timedelta(days=30)
        )
        self.assertEqual(restored["expirationStatus"], "ACTIVE")
        self.assertEqual(manager.get_user_connection("expiring-user")["success"], True)
        current = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertFalse(any(rule.get("action") == "reject" for rule in current["route"]["rules"]))

    def test_expired_connection_matching_indexes_identities_once(self):
        registry = {"users": {
            "expired-one": {"socksUsername": "custom-one"},
            "expired-two": {"socksUsername": "custom-two"},
            "active-user": {"socksUsername": "active-account"},
        }}
        snapshot = {"connections": [
            {"id": "by-chain", "chains": ["node-manager-out:expired-one"]},
            {"id": "by-custom", "metadata": {"inboundUser": "custom-two"}},
            {"id": "by-alias", "auth_user": "node-manager:expired-one"},
            {"id": "by-id", "user": "expired-two"},
            {"id": "active", "chains": ["node-manager-out:active-user"],
             "metadata": {"user": "active-account"}},
            {"id": "unrelated", "metadata": None},
            {"metadata": {"user": "custom-one"}},
            None,
        ]}
        with (
            patch.object(manager.singbox_api, "get_connections", return_value=snapshot),
            patch.object(manager, "_user_auth_names", wraps=manager._user_auth_names) as identities,
        ):
            result = manager._connections_to_close_for_expired_users(
                registry, {"expired-one", "expired-two"}
            )
        self.assertEqual(result, {"by-chain", "by-custom", "by-alias", "by-id"})
        self.assertEqual(identities.call_count, 2)

    def test_no_expired_users_does_not_read_live_connections(self):
        with patch.object(manager.singbox_api, "get_connections") as connections:
            self.assertEqual(manager._connections_to_close_for_expired_users({}, set()), set())
        connections.assert_not_called()

    def test_user_expiration_is_archived_after_restore_window(self):
        manager.create_user("archive-user", ["socks"])
        now = datetime.now(timezone.utc).replace(microsecond=0)
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        registry["users"]["archive-user"]["expiresAt"] = (now - timedelta(hours=24)).isoformat()
        self.registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")

        self.assertEqual(manager.process_user_expirations(now), 1)
        current = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertFalse(any(
            user.get("username") == "archive-user"
            for inbound in current["inbounds"]
            for user in inbound["users"]
        ))
        self.assertFalse(any(item.get("tag") == "node-manager-out:archive-user" for item in current["outbounds"]))
        self.assertFalse(any(rule.get("outbound") == "node-manager-out:archive-user" for rule in current["route"]["rules"]))
        archived = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertNotIn("archive-user", archived["users"])
        self.assertEqual(archived["expiredUsers"]["archive-user"]["status"], "ARCHIVED")

        self.assertEqual(manager.ensure_user_outbounds(), 0)
        after_compensation = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertFalse(any(
            item.get("tag") == "node-manager-out:archive-user"
            for item in after_compensation["outbounds"]
        ))
        self.assertFalse(any(
            rule.get("outbound") == "node-manager-out:archive-user"
            for rule in after_compensation["route"]["rules"]
        ))

    def test_expiration_and_enforcement_reject_rules_keep_their_owners(self):
        manager.create_user("overlap-user", ["socks"])
        now = datetime.now(timezone.utc).replace(microsecond=0)
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        registry["users"]["overlap-user"]["expiresAt"] = (now - timedelta(hours=1)).isoformat()
        self.registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")

        manager.process_user_expirations(now)
        manager.sync_user_enforcements(
            {"overlap-user": {"trafficBlocked": True, "blockedSourceIps": []}}
        )
        rules = json.loads(self.config_path.read_text(encoding="utf-8"))["route"]["rules"]
        self.assertEqual([rule.get("action") for rule in rules[:2]], ["reject", "reject"])

        manager.bind_proxy("overlap-user", {"server": "203.0.113.40", "port": 1080})
        rules = json.loads(self.config_path.read_text(encoding="utf-8"))["route"]["rules"]
        self.assertEqual([rule.get("action") for rule in rules[:3]], ["reject", "reject", "route"])

        manager.sync_user_enforcements(
            {"overlap-user": {"trafficBlocked": False, "blockedSourceIps": []}}
        )
        rules = json.loads(self.config_path.read_text(encoding="utf-8"))["route"]["rules"]
        self.assertEqual(sum(rule.get("action") == "reject" for rule in rules), 1)

        manager.update_user_expiration("overlap-user", now + timedelta(days=30))
        rules = json.loads(self.config_path.read_text(encoding="utf-8"))["route"]["rules"]
        self.assertFalse(any(rule.get("action") == "reject" for rule in rules))

    def test_user_enforcement_rules_are_persistent_idempotent_and_removable(self):
        manager.create_user(
            "limited-user",
            ["socks"],
            socks_username="limited-login",
        )

        manager.sync_user_enforcements(
            {"limited-user": {"trafficBlocked": True, "blockedSourceIps": []}}
        )
        blocked = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(
            blocked["route"]["rules"][0],
            {
                "auth_user": ["limited-login", "node-manager:limited-user"],
                "action": "reject",
            },
        )
        self.assertEqual(blocked["route"]["rules"][1]["action"], "route")

        with patch.object(manager, "_write_and_reload") as reload_config:
            manager.sync_user_enforcements(
                {"limited-user": {"trafficBlocked": True, "blockedSourceIps": []}}
            )
        reload_config.assert_not_called()

        manager.sync_user_enforcements(
            {"limited-user": {"trafficBlocked": False, "blockedSourceIps": []}}
        )
        unblocked = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertFalse(
            any(rule.get("action") == "reject" for rule in unblocked["route"]["rules"])
        )

    def test_multiple_enforcement_rules_are_idempotent_across_input_order(self):
        manager.create_user("limited-a", ["socks"])
        manager.create_user("limited-b", ["socks"])
        desired = {"trafficBlocked": True, "blockedSourceIps": []}
        manager.sync_user_enforcements(
            {"limited-a": desired, "limited-b": desired}
        )

        with patch.object(manager, "_write_and_reload") as reload_config:
            manager.sync_user_enforcements(
                {"limited-b": desired, "limited-a": desired}
            )

        reload_config.assert_not_called()

    def test_source_ip_enforcement_survives_proxy_rebinding_and_user_deletion(self):
        manager.create_user("device-user", ["socks"])
        manager.sync_user_enforcements(
            {
                "device-user": {
                    "trafficBlocked": False,
                    "blockedSourceIps": ["198.51.100.20", "2001:db8::20"],
                }
            }
        )
        manager.bind_proxy(
            "device-user",
            {"server": "203.0.113.20", "port": 1080},
        )

        rebound = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(rebound["route"]["rules"][0]["action"], "reject")
        self.assertEqual(
            rebound["route"]["rules"][0]["source_ip_cidr"],
            ["198.51.100.20/32", "2001:db8::20/128"],
        )
        self.assertEqual(rebound["route"]["rules"][1]["action"], "route")

        manager.delete_user("device-user")
        deleted = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertFalse(
            any(rule.get("action") == "reject" for rule in deleted["route"]["rules"])
        )

    def test_user_auth_map_includes_protocol_and_custom_socks_names(self):
        manager.create_user(
            "mapped-user", ["vless", "socks"], socks_username="mapped-login"
        )
        auth_map = manager.get_user_auth_map()
        self.assertEqual(auth_map["node-manager:mapped-user"], "mapped-user")
        self.assertEqual(auth_map["mapped-login"], "mapped-user")


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.config_path = root / "sing-box.json"
        self.registry_path = root / "users.json"
        self.idempotency_path = root / "idempotency.json"
        self.traffic_path = root / "traffic.json"
        self.config_path.write_text(
            json.dumps(base_singbox_config(), indent=2) + "\n", encoding="utf-8"
        )
        self.config_patch = patch.object(manager, "CONFIG_PATH", self.config_path)
        self.registry_patch = patch.object(manager, "REGISTRY_PATH", self.registry_path)
        self.write_patch = patch.object(manager, "_write_and_reload", self._write_config)
        self.idempotency_patch = patch.object(
            idempotency, "STORE_PATH", self.idempotency_path
        )
        self.traffic_path_patch = patch.object(traffic, "TRAFFIC_PATH", self.traffic_path)
        self.connections_patch = patch.object(
            traffic.singbox_api, "get_connections", return_value={"connections": []}
        )
        self.config_patch.start()
        self.registry_patch.start()
        self.write_patch.start()
        self.idempotency_patch.start()
        self.traffic_path_patch.start()
        self.connections_patch.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.connections_patch.stop()
        self.traffic_path_patch.stop()
        self.idempotency_patch.stop()
        self.write_patch.stop()
        self.registry_patch.stop()
        self.config_patch.stop()
        self.temp_dir.cleanup()

    def _write_config(self, data):
        self.config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def test_bind_proxy_endpoint_syncs_credentials_and_accepts_later_edits(self):
        headers = {"Authorization": "Bearer test-token"}
        manager.create_user("credential-api", ["vless", "socks"],
                            socks_username="old-account", socks_password="old-password")
        original_uuid = manager.get_user_connection("credential-api")["uuid"]
        for username, password in [("new-account", "new-password"), ("next-account", "next-password")]:
            response = self.client.post("/api/user/bind-proxy", headers=headers, json={
                "userId": "credential-api",
                "syncSocksCredentials": True,
                "proxy": {"server": "203.0.113.20", "port": 1080,
                          "username": username, "password": password},
            })
            self.assertEqual(response.status_code, 200, response.text)
            connection = self.client.get("/api/user/credential-api/connections", headers=headers).json()
            self.assertEqual(connection["socks"]["username"], username)
            self.assertEqual(connection["socks"]["password"], password)
            self.assertEqual(connection["uuid"], original_uuid)
            self.assertEqual(manager.get_user_proxy("credential-api")["password"], password)

    def test_bind_proxy_endpoint_rotates_protocol_uuid(self):
        headers = {"Authorization": "Bearer test-token"}
        manager.create_user("credential-rotate-api", ["vless", "vmess", "socks"],
                            socks_username="old-account", socks_password="old-password")
        rotated_uuid = "33333333-3333-4333-8333-333333333333"
        response = self.client.post("/api/user/bind-proxy", headers=headers, json={
            "userId": "credential-rotate-api",
            "syncSocksCredentials": True,
            "uuid": rotated_uuid,
            "proxy": {
                "server": "203.0.113.20",
                "port": 1080,
                "username": "new-account",
                "password": "new-password",
            },
        })
        self.assertEqual(response.status_code, 200, response.text)
        connection = self.client.get(
            "/api/user/credential-rotate-api/connections", headers=headers
        ).json()
        self.assertEqual(connection["uuid"], rotated_uuid)
        self.assertEqual(connection["socks"]["username"], "new-account")
        self.assertEqual(connection["socks"]["password"], "new-password")

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
        self.assertEqual(
            set(response.json()["protocolsAll"]),
            {"socksAcceleration"},
        )

        response = self.client.get("/api/users?page=1&pageSize=10", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["total"], 1)
        self.assertEqual(response.json()["items"][0]["userId"], "api-user")
        self.assertNotIn("password", response.text.lower())

        response = self.client.get(
            "/api/user/api-user/connections", headers=headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.json()["socks"]["username"], "api-socks-user")
        self.assertTrue(response.json()["socks"]["password"])

        # response_model 必须保留五协议字段，且连接详情仍然禁止缓存。
        connections = self.client.get(
            "/api/user/api-user/connections", headers=headers
        )
        self.assertEqual(connections.status_code, 200, connections.text)
        self.assertEqual(
            set(connections.json()["protocolsAll"]),
            {"socksAcceleration"},
        )

    def test_list_users_supports_node_side_user_id_sorting(self):
        headers = {"Authorization": "Bearer test-token"}
        for user_id in ("sort-z", "sort-a"):
            response = self.client.post(
                "/api/user/create",
                headers=headers,
                json={"userId": user_id, "protocols": ["socks"]},
            )
            self.assertEqual(response.status_code, 200, response.text)

        response = self.client.get(
            "/api/users?page=1&pageSize=2&sort=userIdAsc", headers=headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            [item["userId"] for item in response.json()["items"]],
            ["sort-a", "sort-z"],
        )

        response = self.client.get(
            "/api/users?page=1&pageSize=2&sort=userIdDesc", headers=headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            [item["userId"] for item in response.json()["items"]],
            ["sort-z", "sort-a"],
        )

    def test_renewal_retries_do_not_reset_new_traffic_or_shorten_expiration(self):
        headers = {"Authorization": "Bearer test-token"}
        manager.create_user("renew-api-user", ["socks"])
        expiry = datetime.now(timezone.utc) + timedelta(days=60)
        payload = {"expiresAt": expiry.isoformat(), "resetTraffic": True}

        first = self.client.post("/api/user/renew-api-user/renew", headers=headers, json=payload)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(first.json()["trafficReset"])

        store = json.loads(self.traffic_path.read_text(encoding="utf-8"))
        store["users"]["renew-api-user"]["download"] = 1234
        self.traffic_path.write_text(json.dumps(store), encoding="utf-8")

        retry = self.client.post("/api/user/renew-api-user/renew", headers=headers, json=payload)
        self.assertEqual(retry.status_code, 200, retry.text)
        self.assertFalse(retry.json()["trafficReset"])
        store = json.loads(self.traffic_path.read_text(encoding="utf-8"))
        self.assertEqual(store["users"]["renew-api-user"]["download"], 1234)

        stale_payload = {"expiresAt": (expiry - timedelta(days=1)).isoformat()}
        stale = self.client.post("/api/user/renew-api-user/renew", headers=headers, json=stale_payload)
        self.assertEqual(stale.status_code, 409, stale.text)

        payload["expiresAt"] = (expiry + timedelta(days=30)).isoformat()
        next_renewal = self.client.post("/api/user/renew-api-user/renew", headers=headers, json=payload)
        self.assertEqual(next_renewal.status_code, 200, next_renewal.text)
        self.assertTrue(next_renewal.json()["trafficReset"])
        store = json.loads(self.traffic_path.read_text(encoding="utf-8"))
        self.assertEqual(store["users"]["renew-api-user"]["download"], 0)

    def test_user_list_exposes_proxy_metadata_and_batch_deletes(self):
        headers = {"Authorization": "Bearer test-token"}
        for user_id, source_ip, port, country_name, city_name in (
            ("ip-search-a", "207.152.99.183", 1080, "美国", "洛杉矶"),
            ("ip-search-b", "198.51.100.20", 1081, "美国", "纽约"),
        ):
            response = self.client.post(
                "/api/user/create",
                headers=headers,
                json={
                    "userId": user_id,
                    "protocols": ["vless", "vmess", "socks"],
                    "proxy": {
                        "server": "proxy.example.test",
                        "port": port,
                        "sourceIp": source_ip,
                        "countryCode": "US",
                        "countryName": country_name,
                        "cityName": city_name,
                    },
                },
            )
            self.assertEqual(response.status_code, 200, response.text)

        response = self.client.get(
            "/api/users?page=1&pageSize=1&keyword=207.152.99.183",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["total"], 1)
        item = response.json()["items"][0]
        self.assertEqual(item["userId"], "ip-search-a")
        self.assertEqual(item["sourceIp"], "207.152.99.183")
        self.assertEqual(item["countryCode"], "US")
        self.assertEqual(item["countryName"], "美国")
        self.assertEqual(item["cityName"], "洛杉矶")
        self.assertTrue(item["expiresAt"])

        response = self.client.get(
            "/api/users?page=1&pageSize=20&keyword=洛杉矶",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            [user["userId"] for user in response.json()["items"]],
            ["ip-search-a"],
        )

        deleted = self.client.post(
            "/api/users/batch-delete",
            headers=headers,
            json={"userIds": ["ip-search-a", "ip-search-b", "missing-user"]},
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        body = deleted.json()
        self.assertFalse(body["success"])
        self.assertEqual(set(body["deleted"]), {"ip-search-a", "ip-search-b"})
        self.assertEqual(body["failed"][0]["userId"], "missing-user")

        remaining = self.client.get("/api/users", headers=headers)
        self.assertEqual(remaining.status_code, 200, remaining.text)
        self.assertEqual(remaining.json()["total"], 0)

    def test_create_and_update_user_policy_endpoints(self):
        headers = {"Authorization": "Bearer test-token"}
        response = self.client.post(
            "/api/user/create",
            headers=headers,
            json={
                "userId": "policy-user",
                "protocols": ["socks"],
                "trafficLimitBytes": 4096,
                "maxSourceIps": 2,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)

        users = self.client.get("/api/users", headers=headers)
        self.assertEqual(users.status_code, 200, users.text)
        item = users.json()["items"][0]
        self.assertEqual(item["trafficLimitBytes"], 4096)
        self.assertEqual(item["maxSourceIps"], 2)

        updated = self.client.patch(
            "/api/user/policy-user/policy",
            headers=headers,
            json={"trafficLimitBytes": 0, "maxSourceIps": 1},
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertIsNone(updated.json()["trafficLimitBytes"])
        self.assertEqual(updated.json()["maxSourceIps"], 1)

    def test_traffic_endpoint_serializes_current_policy_and_online_sessions(self):
        headers = {"Authorization": "Bearer test-token"}
        manager.create_user("live-api", ["socks"],
                            traffic_limit_bytes=200 * 1024 ** 3, max_source_ips=5)
        snapshot = {"connections": [{
            "id": "live-session", "chains": ["node-manager-out:live-api"],
            "upload": 10, "download": 20, "start": "2026-10-03T00:00:00Z",
            "metadata": {"sourceIP": "198.51.100.10", "sourcePort": "12000",
                         "network": "tcp", "type": "SOCKS"},
        }]}
        with patch.object(traffic.singbox_api, "get_connections", return_value=snapshot):
            response = self.client.get("/api/user/live-api/traffic", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["available"])
        self.assertEqual(body["trafficLimitBytes"], 200 * 1024 ** 3)
        self.assertEqual(body["maxSourceIps"], 5)
        self.assertEqual(body["sourceIpActiveWindowSeconds"], traffic.DEVICE_ACTIVE_WINDOW_SECONDS)
        self.assertEqual(body["onlineConnections"], [{
            "id": "live-session", "sourceIp": "198.51.100.10", "sourcePort": 12000,
            "network": "tcp", "protocol": "SOCKS", "startedAt": "2026-10-03T00:00:00Z",
            "upload": 10, "download": 20,
        }])
        with patch.object(traffic.singbox_api, "get_connections", return_value=None):
            response = self.client.get("/api/user/live-api/traffic", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["available"])
        self.assertIsNone(response.json()["onlineConnections"])
        self.assertEqual(response.json()["trafficLimitBytes"], 200 * 1024 ** 3)

    def test_delete_user_clears_traffic_before_recreating_same_id(self):
        headers = {"Authorization": "Bearer test-token"}
        payload = {
            "userId": "recreated-user",
            "protocols": ["socks"],
            "trafficLimitBytes": 100,
        }
        created = self.client.post("/api/user/create", headers=headers, json=payload)
        self.assertEqual(created.status_code, 200, created.text)

        self.traffic_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "users": {
                        "recreated-user": {
                            "upload": 75,
                            "download": 50,
                            "status": "traffic_limited",
                        }
                    },
                    "connections": {
                        "old-connection": {
                            "userId": "recreated-user",
                            "upload": 75,
                            "download": 50,
                        }
                    },
                    "collectedAt": "2026-08-17T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )

        deleted = self.client.delete(
            "/api/user/delete/recreated-user", headers=headers
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertEqual(
            traffic.get_user_traffic("recreated-user", refresh=False)["total"], 0
        )

        recreated = self.client.post("/api/user/create", headers=headers, json=payload)
        self.assertEqual(recreated.status_code, 200, recreated.text)
        current = self.client.get(
            "/api/user/recreated-user/traffic", headers=headers
        )
        self.assertEqual(current.status_code, 200, current.text)
        self.assertEqual(current.json()["total"], 0)
        self.assertEqual(current.json()["status"], "active")

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
        self.assertNotEqual(body["socks"]["username"], "proxy-user")
        self.assertNotEqual(body["socks"]["password"], "proxy-password")
        self.assertEqual(
            set(body["protocolsAll"]),
            {"socks5", "bitbrowser", "socksAcceleration"},
        )

        response = self.client.get("/api/users", headers=headers)
        self.assertTrue(response.json()["items"][0]["proxyBound"])

    def test_proxy_metadata_endpoint_persists_country_for_existing_user(self):
        headers = {"Authorization": "Bearer test-token"}
        created = self.client.post(
            "/api/user/create",
            headers=headers,
            json={
                "userId": "metadata-user",
                "protocols": ["vless", "vmess", "socks"],
                "proxy": {
                    "server": "proxy.example.test",
                    "port": 1080,
                    "sourceIp": "207.152.99.183",
                },
            },
        )
        self.assertEqual(created.status_code, 200, created.text)

        updated = self.client.patch(
            "/api/user/metadata-user/proxy-metadata",
            headers=headers,
            json={
                "sourceIp": "207.152.99.183",
                "countryCode": "US",
                "countryName": "美国",
            },
        )
        self.assertEqual(updated.status_code, 200, updated.text)

        connection = self.client.get(
            "/api/user/metadata-user/connections", headers=headers
        )
        self.assertEqual(connection.status_code, 200, connection.text)
        self.assertEqual(connection.json()["protocolInfo"]["countryCode"], "US")
        self.assertEqual(
            unquote(connection.json()["protocolsAll"]["vless"].rsplit("#", 1)[1]),
            "[US] 207.152.99.183",
        )

    def test_create_user_is_idempotent(self):
        headers = {
            "Authorization": "Bearer test-token",
            "Idempotency-Key": "spring-order-1001",
        }
        payload = {"userId": "idempotent-user", "protocols": ["socks"]}
        first = self.client.post("/api/user/create", headers=headers, json=payload)
        second = self.client.post("/api/user/create", headers=headers, json=payload)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(first.headers["Idempotency-Replayed"], "false")
        self.assertEqual(second.headers["Idempotency-Replayed"], "true")
        self.assertEqual(len(manager.list_users()), 1)
        stored = self.idempotency_path.read_text(encoding="utf-8")
        self.assertNotIn(first.json()["socks"]["password"], stored)
        self.assertIn("responseEncrypted", stored)

        conflict = self.client.post(
            "/api/user/create",
            headers=headers,
            json={"userId": "different-user", "protocols": ["socks"]},
        )
        self.assertEqual(conflict.status_code, 409, conflict.text)

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
                    "systemConnections": 8,
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
        self.assertEqual(body["items"][0]["managerVersion"], "1.4.13")
        self.assertEqual(body["items"][0]["singboxVersion"], "1.13.14")
        self.assertEqual(body["items"][0]["connections"], 3)
        self.assertEqual(body["items"][0]["systemConnections"], 8)

    def test_agent_contract_and_heartbeat(self):
        headers = {"Authorization": "Bearer test-token"}
        info = self.client.get("/api/agent/info", headers=headers)
        self.assertEqual(info.status_code, 200, info.text)
        self.assertEqual(info.json()["apiVersion"], "v1")
        self.assertIn("request.idempotency", info.json()["capabilities"])
        self.assertIn(
            "offline-detection", info.json()["controlPlaneResponsibilities"]
        )

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
                    "systemConnections": 8,
                },
            ),
            patch.object(main, "_singbox_version", return_value="1.13.14"),
            patch.object(main, "is_api_available", return_value=True),
            patch.object(
                main,
                "get_traffic_totals",
                return_value={
                    "upload": 10,
                    "download": 20,
                    "total": 30,
                    "available": True,
                    "source": "clash-api-sampled",
                    "collectedAt": "2026-07-22T00:00:00Z",
                },
            ),
        ):
            heartbeat = self.client.get("/api/agent/heartbeat", headers=headers)
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        self.assertEqual(heartbeat.json()["status"], "online")
        self.assertEqual(heartbeat.json()["connections"], 3)
        self.assertEqual(heartbeat.json()["systemConnections"], 8)
        self.assertEqual(heartbeat.json()["socksPort"], 5001)
        self.assertEqual(heartbeat.json()["traffic"]["total"], 30)


class StatusTestCase(unittest.TestCase):
    def test_linux_connection_count_uses_kernel_tables(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for name, rows in (("tcp", 2), ("tcp6", 1), ("udp", 3), ("unix", 4)):
                (root / name).write_text("header\n" + "socket\n" * rows + "\n", encoding="ascii")
            with (patch.object(status_monitor.sys, "platform", "linux"),
                  patch.object(status_monitor, "Path", return_value=root),
                  patch.object(status_monitor.psutil, "net_connections") as connections):
                self.assertEqual(status_monitor.get_system_connections(), 10)
                connections.assert_not_called()

    def test_linux_connection_count_falls_back_if_tables_unavailable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with (patch.object(status_monitor.sys, "platform", "linux"),
                  patch.object(status_monitor, "Path", return_value=Path(temp_dir)),
                  patch.object(status_monitor.psutil, "net_connections", return_value=[1, 2]) as connections):
                self.assertEqual(status_monitor.get_system_connections(), 2)
                connections.assert_called_once_with()

    def test_non_linux_connection_count_keeps_psutil(self):
        with (patch.object(status_monitor.sys, "platform", "win32"),
              patch.object(status_monitor.psutil, "net_connections", return_value=[1])):
            self.assertEqual(status_monitor.get_system_connections(), 1)

    def test_connection_count_returns_zero_when_fallback_fails(self):
        with (patch.object(status_monitor.sys, "platform", "win32"),
              patch.object(status_monitor.psutil, "net_connections", side_effect=OSError)):
            self.assertEqual(status_monitor.get_system_connections(), 0)

    def test_proxy_connections_are_counted_from_clash_api(self):
        with patch.object(
            status_monitor.singbox_api,
            "get_connections",
            return_value={"connections": [{"id": "a"}, {"id": "b"}]},
        ):
            self.assertEqual(status_monitor.get_proxy_connections(), 2)


class TrafficTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.traffic_path = Path(self.temp_dir.name) / "traffic.json"
        self.path_patch = patch.object(traffic, "TRAFFIC_PATH", self.traffic_path)
        self.policy_patch = patch.object(traffic, "get_user_policies", return_value={})
        self.auth_map_patch = patch.object(traffic, "get_user_auth_map", return_value={})
        self.enforcement_patch = patch.object(
            traffic, "sync_user_enforcements", return_value=True
        )
        self.path_patch.start()
        self.policy_patch.start()
        self.auth_map = self.auth_map_patch.start()
        self.enforcement = self.enforcement_patch.start()

    def tearDown(self):
        self.enforcement_patch.stop()
        self.auth_map_patch.stop()
        self.policy_patch.stop()
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_online_sessions_are_current_and_separate_from_recent_source_ips(self):
        snapshot = {"connections": [
            {"id": "session-a", "upload": 10, "download": 20,
             "chains": ["node-manager-out:live-user"], "start": "2026-10-03T00:00:00Z",
             "metadata": {"sourceIP": "198.51.100.10", "sourcePort": "12000",
                          "network": "tcp", "type": "VLESS"}},
            {"id": "session-b", "upload": 5, "download": 6,
             "chains": ["node-manager-out:live-user"],
             "metadata": {"sourceIP": "198.51.100.10", "sourcePort": 12001}},
            {"id": "other-session", "chains": ["node-manager-out:other-user"]},
        ]}
        with patch.object(traffic.singbox_api, "get_connections", side_effect=[snapshot, {"connections": []}]):
            first = traffic.get_user_traffic("live-user")
            self.assertEqual(len(first["onlineConnections"]), 2)
            self.assertEqual(first["onlineConnections"][0]["sourcePort"], "12000")
            self.assertEqual(first["onlineConnections"][0]["protocol"], "VLESS")
            self.assertEqual(first["activeSourceIps"], ["198.51.100.10"])
            second = traffic.get_user_traffic("live-user")
            self.assertEqual(second["onlineConnections"], [])
            self.assertEqual(second["activeSourceIps"], ["198.51.100.10"])
            self.assertEqual(second["total"], 41)

    def test_unavailable_telemetry_returns_current_policy_not_stale_limits(self):
        self.traffic_path.write_text(json.dumps({
            "users": {"live-user": {"trafficLimitBytes": 100, "maxSourceIps": 2,
                                     "upload": 100, "status": "traffic_limited"}},
            "connections": {"old": {"userId": "live-user"}},
            "collectedAt": "2026-10-03T00:00:00Z",
        }), encoding="utf-8")
        with (patch.object(traffic.singbox_api, "get_connections", return_value=None),
              patch.object(traffic, "get_user_policies", return_value={
                  "live-user": {"trafficLimitBytes": 200 * 1024 ** 3, "maxSourceIps": 5}
              })):
            result = traffic.get_user_traffic("live-user")
            self.assertFalse(result["available"])
            self.assertIsNone(result["onlineConnections"])
            self.assertEqual(result["trafficLimitBytes"], 200 * 1024 ** 3)
            self.assertEqual(result["maxSourceIps"], 5)
            self.assertEqual(result["status"], "active")
        result = traffic.get_user_traffic("live-user", refresh=False, policy={
            "trafficLimitBytes": None, "maxSourceIps": None
        })
        self.assertIsNone(result["trafficLimitBytes"])
        self.assertIsNone(result["maxSourceIps"])

    def test_sampled_connection_traffic_is_accumulated(self):
        snapshots = [
            {
                "connections": [
                    {
                        "id": "connection-1",
                        "upload": 100,
                        "download": 200,
                        "chains": ["node-manager-out:traffic-user"],
                    }
                ]
            },
            {
                "connections": [
                    {
                        "id": "connection-1",
                        "upload": 150,
                        "download": 260,
                        "chains": ["node-manager-out:traffic-user"],
                    }
                ]
            },
            {"connections": []},
        ]
        with patch.object(traffic.singbox_api, "get_connections", side_effect=snapshots):
            self.assertTrue(traffic.collect_traffic())
            self.assertTrue(traffic.collect_traffic())
            self.assertTrue(traffic.collect_traffic())

        result = traffic.get_user_traffic("traffic-user", refresh=False)
        self.assertEqual(result["upload"], 150)
        self.assertEqual(result["download"], 260)
        self.assertEqual(result["total"], 410)
        self.assertTrue(result["available"])

        traffic.delete_user_traffic("traffic-user")
        deleted = traffic.get_user_traffic("traffic-user", refresh=False)
        self.assertEqual(deleted["total"], 0)

    def test_user_traffic_can_reuse_one_store_snapshot(self):
        self.traffic_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "users": {
                        "snapshot-a": {"upload": 10, "download": 20},
                        "snapshot-b": {"upload": 30, "download": 40},
                    },
                    "connections": {},
                    "collectedAt": "2026-09-06T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )

        with patch.object(traffic, "_read_store", wraps=traffic._read_store) as read_store:
            snapshot = traffic.get_traffic_store_snapshot()
            first = traffic.get_user_traffic("snapshot-a", refresh=False, store=snapshot)
            second = traffic.get_user_traffic("snapshot-b", refresh=False, store=snapshot)

        self.assertEqual(first["total"], 30)
        self.assertEqual(second["total"], 70)
        read_store.assert_called_once_with()

    def test_delete_traffic_uses_the_collection_transaction_lock(self):
        self.traffic_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "users": {"deleted-user": {"upload": 10, "download": 20}},
                    "connections": {
                        "deleted-connection": {"userId": "deleted-user"}
                    },
                    "collectedAt": "2026-09-04T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )

        with patch.object(traffic, "collection_lock") as collection_lock:
            traffic.delete_user_traffic("deleted-user")

        collection_lock.__enter__.assert_called_once_with()
        deleted = traffic.get_user_traffic("deleted-user", refresh=False)
        self.assertEqual(deleted["total"], 0)
        stored = json.loads(self.traffic_path.read_text(encoding="utf-8"))
        self.assertNotIn("deleted-connection", stored["connections"])

    def test_traffic_quota_closes_user_connections(self):
        snapshot = {
            "connections": [
                {
                    "id": "quota-connection",
                    "upload": 400,
                    "download": 700,
                    "chains": ["node-manager-out:quota-user"],
                    "metadata": {"sourceIP": "198.51.100.10"},
                }
            ]
        }
        with (
            patch.object(traffic.singbox_api, "get_connections", return_value=snapshot),
            patch.object(
                traffic,
                "get_user_policies",
                return_value={
                    "quota-user": {"trafficLimitBytes": 1000, "maxSourceIps": None}
                },
            ),
            patch.object(traffic.singbox_api, "close_connection", return_value=True) as close,
        ):
            self.assertTrue(traffic.collect_traffic())

        close.assert_called_once_with("quota-connection")
        self.enforcement.assert_called_once_with(
            {"quota-user": {"trafficBlocked": True, "blockedSourceIps": []}}
        )
        result = traffic.get_user_traffic("quota-user", refresh=False)
        self.assertEqual(result["status"], "traffic_limited")
        self.assertEqual(result["trafficLimitBytes"], 1000)
        self.assertEqual(result["onlineConnections"], [])

    def test_raising_traffic_quota_clears_the_persistent_block(self):
        snapshot = {
            "connections": [
                {
                    "id": "quota-recovery-connection",
                    "upload": 400,
                    "download": 700,
                    "chains": ["node-manager-out:quota-recovery-user"],
                    "metadata": {"sourceIP": "198.51.100.12"},
                }
            ]
        }
        with (
            patch.object(
                traffic.singbox_api,
                "get_connections",
                side_effect=[snapshot, snapshot],
            ),
            patch.object(
                traffic,
                "get_user_policies",
                side_effect=[
                    {
                        "quota-recovery-user": {
                            "trafficLimitBytes": 1000,
                            "maxSourceIps": None,
                        }
                    },
                    {
                        "quota-recovery-user": {
                            "trafficLimitBytes": 2000,
                            "maxSourceIps": None,
                        }
                    },
                ],
            ),
            patch.object(traffic.singbox_api, "close_connection", return_value=True),
        ):
            self.assertTrue(traffic.collect_traffic())
            self.assertTrue(traffic.collect_traffic())

        self.assertEqual(
            self.enforcement.call_args_list[0].args[0],
            {
                "quota-recovery-user": {
                    "trafficBlocked": True,
                    "blockedSourceIps": [],
                }
            },
        )
        self.assertEqual(
            self.enforcement.call_args_list[1].args[0],
            {
                "quota-recovery-user": {
                    "trafficBlocked": False,
                    "blockedSourceIps": [],
                }
            },
        )
        result = traffic.get_user_traffic("quota-recovery-user", refresh=False)
        self.assertEqual(result["status"], "active")

    def test_source_ip_limit_closes_only_excess_ip_connections(self):
        snapshot = {
            "connections": [
                {
                    "id": "first-device",
                    "upload": 10,
                    "download": 20,
                    "chains": ["node-manager-out:device-user"],
                    "metadata": {"sourceIP": "198.51.100.10"},
                },
                {
                    "id": "second-device",
                    "upload": 30,
                    "download": 40,
                    "chains": ["node-manager-out:device-user"],
                    "metadata": {"sourceIP": "198.51.100.11"},
                },
            ]
        }
        with (
            patch.object(traffic.singbox_api, "get_connections", return_value=snapshot),
            patch.object(
                traffic,
                "get_user_policies",
                return_value={
                    "device-user": {"trafficLimitBytes": None, "maxSourceIps": 1}
                },
            ),
            patch.object(traffic.singbox_api, "close_connection", return_value=True) as close,
        ):
            self.assertTrue(traffic.collect_traffic())

        close.assert_called_once_with("second-device")
        result = traffic.get_user_traffic("device-user", refresh=False)
        self.assertEqual(result["activeSourceIps"], ["198.51.100.10"])
        self.assertEqual([item["id"] for item in result["onlineConnections"]], ["first-device"])
        self.assertEqual(result["status"], "device_limited")
        self.enforcement.assert_called_once_with(
            {
                "device-user": {
                    "trafficBlocked": False,
                    "blockedSourceIps": ["198.51.100.11"],
                }
            }
        )

    def test_custom_auth_metadata_is_attributed_to_the_registered_user(self):
        self.auth_map.return_value = {"customer-login": "metadata-user"}
        snapshot = {
            "connections": [
                {
                    "id": "metadata-connection",
                    "upload": 25,
                    "download": 75,
                    "metadata": {
                        "inboundUser": "customer-login",
                        "sourceIP": "198.51.100.30",
                    },
                }
            ]
        }
        with (
            patch.object(traffic.singbox_api, "get_connections", return_value=snapshot),
            patch.object(traffic, "get_user_policies", return_value={}),
        ):
            self.assertTrue(traffic.collect_traffic())

        result = traffic.get_user_traffic("metadata-user", refresh=False)
        self.assertEqual(result["total"], 100)
        self.assertEqual(result["activeSourceIps"], ["198.51.100.30"])

    def test_recent_device_remains_online_until_activity_window_expires(self):
        policies = {"window-user": {"trafficLimitBytes": None, "maxSourceIps": 2}}
        first = {
            "connections": [
                {
                    "id": "window-connection",
                    "upload": 0,
                    "download": 0,
                    "chains": ["node-manager-out:window-user"],
                    "metadata": {"sourceIP": "198.51.100.40"},
                }
            ]
        }
        with (
            patch.object(
                traffic.singbox_api,
                "get_connections",
                side_effect=[first, {"connections": []}, {"connections": []}],
            ),
            patch.object(traffic, "get_user_policies", return_value=policies),
            patch.object(traffic.time, "time", side_effect=[1000, 1059, 1061]),
            patch.object(traffic, "DEVICE_ACTIVE_WINDOW_SECONDS", 60),
        ):
            self.assertTrue(traffic.collect_traffic())
            self.assertTrue(traffic.collect_traffic())
            recent = traffic.get_user_traffic("window-user", refresh=False)
            self.assertEqual(recent["activeSourceIps"], ["198.51.100.40"])
            self.assertTrue(traffic.collect_traffic())

        expired = traffic.get_user_traffic("window-user", refresh=False)
        self.assertEqual(expired["activeSourceIps"], [])

    def test_rejected_device_stays_blocked_while_allowed_device_is_online(self):
        policies = {"sticky-user": {"trafficLimitBytes": None, "maxSourceIps": 1}}
        both_devices = {
            "connections": [
                {
                    "id": "allowed-device",
                    "upload": 0,
                    "download": 0,
                    "chains": ["node-manager-out:sticky-user"],
                    "metadata": {"sourceIP": "198.51.100.50"},
                },
                {
                    "id": "rejected-device",
                    "upload": 0,
                    "download": 0,
                    "chains": ["node-manager-out:sticky-user"],
                    "metadata": {"sourceIP": "198.51.100.51"},
                },
            ]
        }
        allowed_only = {
            "connections": [
                {
                    "id": "allowed-device",
                    "upload": 0,
                    "download": 0,
                    "chains": ["node-manager-out:sticky-user"],
                    "metadata": {"sourceIP": "198.51.100.50"},
                }
            ]
        }
        with (
            patch.object(
                traffic.singbox_api,
                "get_connections",
                side_effect=[both_devices, allowed_only],
            ),
            patch.object(traffic, "get_user_policies", return_value=policies),
            patch.object(traffic.time, "time", side_effect=[1000, 1061]),
            patch.object(traffic.singbox_api, "close_connection", return_value=True),
        ):
            self.assertTrue(traffic.collect_traffic())
            self.assertTrue(traffic.collect_traffic())

        result = traffic.get_user_traffic("sticky-user", refresh=False)
        self.assertEqual(result["activeSourceIps"], ["198.51.100.50"])
        self.assertEqual(result["status"], "device_limited")
        self.assertEqual(
            self.enforcement.call_args_list[-1].args[0]["sticky-user"]["blockedSourceIps"],
            ["198.51.100.51"],
        )

    def test_device_slot_and_rejected_ip_are_released_after_activity_window(self):
        policies = {"release-user": {"trafficLimitBytes": None, "maxSourceIps": 1}}
        both_devices = {
            "connections": [
                {
                    "id": "release-allowed",
                    "upload": 0,
                    "download": 0,
                    "chains": ["node-manager-out:release-user"],
                    "metadata": {"sourceIP": "198.51.100.60"},
                },
                {
                    "id": "release-rejected",
                    "upload": 0,
                    "download": 0,
                    "chains": ["node-manager-out:release-user"],
                    "metadata": {"sourceIP": "198.51.100.61"},
                },
            ]
        }
        with (
            patch.object(
                traffic.singbox_api,
                "get_connections",
                side_effect=[both_devices, {"connections": []}],
            ),
            patch.object(traffic, "get_user_policies", return_value=policies),
            patch.object(traffic.time, "time", side_effect=[1000, 1061]),
            patch.object(traffic.singbox_api, "close_connection", return_value=True),
        ):
            self.assertTrue(traffic.collect_traffic())
            self.assertTrue(traffic.collect_traffic())

        result = traffic.get_user_traffic("release-user", refresh=False)
        self.assertEqual(result["activeSourceIps"], [])
        self.assertEqual(result["status"], "active")
        self.assertEqual(
            self.enforcement.call_args_list[-1].args[0],
            {
                "release-user": {
                    "trafficBlocked": False,
                    "blockedSourceIps": [],
                }
            },
        )


class SingboxWriteReloadTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self.temp_dir.name) / "sing-box.json"
        self.config_path.write_text(
            json.dumps(base_singbox_config(), indent=2) + "\n", encoding="utf-8"
        )
        self.path_patch = patch.object(manager, "CONFIG_PATH", self.config_path)
        self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_identical_config_skips_validation_write_and_reload(self):
        current = json.loads(self.config_path.read_text(encoding="utf-8"))
        with (
            patch.object(manager, "check_config") as check_config,
            patch.object(manager, "reload_singbox") as reload_singbox,
        ):
            manager._write_and_reload(current)

        check_config.assert_not_called()
        reload_singbox.assert_not_called()
        self.assertEqual(
            json.loads(self.config_path.read_text(encoding="utf-8")), current
        )


class MonitoringConfigTest(unittest.TestCase):
    def test_sampling_interval_accepts_supported_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                "node:\n  host: 192.0.2.10\nmonitoring:\n  traffic_sample_interval_seconds: 0.5\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"NODE_MANAGER_CONFIG": str(config_path)}):
                loaded = config_module.load_config()
            self.assertEqual(loaded.monitoring.traffic_sample_interval_seconds, 0.5)

            config_path.write_text(
                "node:\n  host: 192.0.2.10\nmonitoring:\n  traffic_sample_interval_seconds: 300\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"NODE_MANAGER_CONFIG": str(config_path)}):
                loaded = config_module.load_config()
            self.assertEqual(loaded.monitoring.traffic_sample_interval_seconds, 300)

    def test_sampling_interval_rejects_values_outside_supported_range(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            for value in (0.49, 300.01):
                config_path.write_text(
                    f"node:\n  host: 192.0.2.10\nmonitoring:\n  traffic_sample_interval_seconds: {value}\n",
                    encoding="utf-8",
                )
                with self.subTest(value=value), patch.dict(
                    os.environ, {"NODE_MANAGER_CONFIG": str(config_path)}
                ):
                    with self.assertRaisesRegex(ValueError, "between 0.5 and 300"):
                        config_module.load_config()

    def test_device_active_window_accepts_supported_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            for value in (1, 3600):
                config_path.write_text(
                    f"node:\n  host: 192.0.2.10\nmonitoring:\n  device_active_window_seconds: {value}\n",
                    encoding="utf-8",
                )
                with self.subTest(value=value), patch.dict(
                    os.environ, {"NODE_MANAGER_CONFIG": str(config_path)}
                ):
                    loaded = config_module.load_config()
                self.assertEqual(loaded.monitoring.device_active_window_seconds, value)

    def test_device_active_window_rejects_values_outside_supported_range(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            for value in (0.99, 3600.01):
                config_path.write_text(
                    f"node:\n  host: 192.0.2.10\nmonitoring:\n  device_active_window_seconds: {value}\n",
                    encoding="utf-8",
                )
                with self.subTest(value=value), patch.dict(
                    os.environ, {"NODE_MANAGER_CONFIG": str(config_path)}
                ):
                    with self.assertRaisesRegex(ValueError, "between 1 and 3600"):
                        config_module.load_config()


class NodeIdentityTest(unittest.TestCase):
    def test_default_node_id_is_stable_and_distinguishes_same_hostname(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            machine_id_path = Path(temp_dir) / "machine-id"
            machine_id_path.write_text("machine-a\n", encoding="utf-8")
            with patch.object(config_module, "MACHINE_ID_PATH", machine_id_path), patch.object(
                config_module.socket, "gethostname", return_value="vultr"
            ):
                first = config_module.default_node_id()
                second = config_module.default_node_id()
            self.assertEqual(first, second)
            self.assertEqual(first, "vultr-" + __import__("hashlib").sha256(b"machine-a").hexdigest()[:12])

            machine_id_path.write_text("machine-b\n", encoding="utf-8")
            with patch.object(config_module, "MACHINE_ID_PATH", machine_id_path), patch.object(
                config_module.socket, "gethostname", return_value="vultr"
            ):
                other = config_module.default_node_id()
            self.assertNotEqual(first, other)

    def test_default_node_id_falls_back_to_hostname_without_machine_id(self):
        with patch.object(config_module, "MACHINE_ID_PATH", Path("Z:/missing-machine-id")), patch.object(
            config_module.socket, "gethostname", return_value="test-node"
        ):
            self.assertEqual(config_module.default_node_id(), "test-node")


class InstallerContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = (PROJECT_ROOT / "install.sh").read_text(encoding="utf-8")

    def test_page_install_token_uses_dedicated_header(self):
        self.assertIn(
            'usage: bash install.sh [CONTROL_PLANE_URL] [ONE_TIME_INSTALL_TOKEN]',
            self.installer,
        )
        self.assertIn('CONTROL_PLANE_INSTALL_TOKEN="$2"', self.installer)
        self.assertIn(
            "printf 'X-Install-Token: %s\\n' \"$install_token\" > \"$header_file\"",
            self.installer,
        )
        self.assertIn(
            "printf 'X-Registration-Token: %s\\n' \"$registration_token\" > \"$header_file\"",
            self.installer,
        )

    def test_installer_is_valid_bash_syntax(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is not available")
        result = subprocess.run(
            [bash, "-n", str(PROJECT_ROOT / "install.sh")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_registration_credentials_are_not_written_to_info_file(self):
        info_file_section = self.installer.split('INFO_FILE="/root/node-manager-info.txt"', 1)[1]
        self.assertNotIn("CONTROL_PLANE_INSTALL_TOKEN", info_file_section)
        self.assertNotIn("CONTROL_PLANE_REGISTRATION_TOKEN", info_file_section)
        self.assertIn('chmod 0600 "$response_file" "$request_file" "$header_file"', self.installer)
        self.assertIn('CONTROL_PLANE_INSTALL_TOKEN=""', self.installer)
        self.assertIn('CONTROL_PLANE_REGISTRATION_TOKEN=""', self.installer)

    def test_one_time_registration_transport_error_has_actionable_diagnostic(self):
        self.assertIn('curl_exit_code=$?', self.installer)
        self.assertIn(
            'if [ "$curl_exit_code" -ne 0 ] && [ -n "$install_token" ]; then',
            self.installer,
        )
        self.assertIn('provider cloud firewall/security group for TCP 8088', self.installer)
        self.assertIn('generate a new one-time install command', self.installer)

    def test_business_error_response_is_not_reported_as_registered(self):
        # 平台业务失败（例如 NODE_NOT_REGISTERED）同样返回 HTTP 200，
        # 安装脚本必须校验响应体的 code 和节点 ID 才能判定成功。
        self.assertIn("(.code // empty)", self.installer)
        self.assertIn("(.data.id // .id // empty)", self.installer)
        self.assertIn('response_code="$(jq -r', self.installer)
        self.assertIn('response_node_id="$(jq -r', self.installer)
        self.assertIn(
            'if [ "$response_code" = "200" ] && [ -n "$response_node_id" ]; then',
            self.installer,
        )
        self.assertIn('CONTROL_PLANE_REGISTRATION_STATUS="rejected-${response_code:-invalid-response}"',
                      self.installer)
        self.assertIn(
            'fail "control-plane registration failed after retries ($CONTROL_PLANE_REGISTRATION_STATUS): ${CONTROL_PLANE_RESPONSE:-no message}"',
            self.installer,
        )

    def test_page_install_command_carries_one_time_code_in_install_token(self):
        # 节点侧只拿到短时一次性安装码，长期注册凭证不下发到节点。
        page_section = self.installer.split("register_with_control_plane()", 1)[0]
        self.assertIn("CONTROL_PLANE_INSTALL_TOKEN=\"${CONTROL_PLANE_INSTALL_TOKEN:-}\"", page_section)

    def test_fresh_install_does_not_exit_when_sing_box_is_missing(self):
        self.assertIn(
            'if command -v sing-box >/dev/null 2>&1; then',
            self.installer,
        )
        self.assertIn(
            'INSTALLED_SINGBOX_VERSION="$(sing-box version 2>/dev/null | awk',
            self.installer,
        )
        self.assertNotIn(
            'INSTALLED_SINGBOX_VERSION="$(sing-box version 2>/dev/null | awk \'NR == 1 {print $3}\')"',
            self.installer,
        )

    def test_sing_box_uses_retrying_github_release_install(self):
        self.assertIn(
            'https://github.com/SagerNet/sing-box/releases/download/v${version}/${package_name}',
            self.installer,
        )
        self.assertIn('--retry-all-errors', self.installer)
        self.assertIn('apt_get install -y "$package_path"', self.installer)
        self.assertNotIn('https://sing-box.app/install.sh | sh', self.installer)

    def test_apt_operations_wait_for_the_dpkg_lock(self):
        self.assertIn('APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-300}"', self.installer)
        self.assertIn('apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_TIMEOUT_SECONDS" "$@"', self.installer)
        self.assertIn('apt_get update -y', self.installer)
        self.assertIn(
            'apt_get install -y ca-certificates curl jq openssl python3 python3-pip python3-venv ufw',
            self.installer,
        )

    def test_force_update_switch_can_refresh_same_application_version(self):
        self.assertIn('FORCE_NODE_MANAGER_UPDATE="${NODE_MANAGER_FORCE_UPDATE:-0}"', self.installer)
        self.assertIn('NODE_MANAGER_FORCE_UPDATE must be 0 or 1', self.installer)
        self.assertIn('Node Manager force update requested; installing application $APP_VERSION', self.installer)

    def test_packaged_default_config_is_replaced_but_user_config_is_preserved(self):
        self.assertIn('is_packaged_default_singbox_config()', self.installer)
        self.assertIn("dpkg-query -W -f='${Conffiles}\\n' sing-box", self.installer)
        self.assertIn('md5sum "$SINGBOX_CONFIG"', self.installer)
        self.assertIn(
            'if [ -f "$SINGBOX_CONFIG" ] && ! is_packaged_default_singbox_config; then',
            self.installer,
        )
        self.assertIn(
            'replacing the sing-box package default config with the Node Manager config',
            self.installer,
        )

    def test_fresh_install_generates_unique_node_id_from_machine_id(self):
        self.assertIn('default_node_id() {', self.installer)
        self.assertIn('sha256sum', self.installer)
        self.assertIn('NODE_ID="${NODE_MANAGER_NODE_ID:-${EXISTING_NODE_ID:-$(default_node_id)}}"', self.installer)


if __name__ == "__main__":
    unittest.main()
