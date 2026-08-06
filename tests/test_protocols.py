import base64
import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "node-manager"
sys.path.insert(0, str(APP_ROOT))

from pydantic import ValidationError

from protocols import ProtocolData, generate_all, socks5_original, bitbrowser, vless, socks_acceleration, vmess
from residential import (
    ResidentialConfigError,
    validate_config,
    validate_ip,
    validate_port,
    validate_credential,
    validate_batch,
)
from models.request import ResidentialSocksRequest, _UUID_PATTERN


def sample_data(**overrides):
    base = dict(
        ip="149.52.53.230",
        port=5001,
        username="a1b2c3d4e5f6a7b8",
        password="888888",
        country_code="US",
        country_name="United States",
        city_name="Los Angeles",
        uuid="9b6deb80-4b32-4496-9a5e-1a2b3c4d5e6f",
        acceleration_domain="proxy.tkip.xin",
        vless_pbk="abc123",
        vless_sid="0123456789abcdef",
        vless_sni="www.microsoft.com",
    )
    base.update(overrides)
    return ProtocolData(**base)


class ProtocolGenerationTest(unittest.TestCase):
    def test_socks5_original_format(self):
        link = socks5_original(sample_data())
        self.assertTrue(link.startswith("socks://a1b2c3d4e5f6a7b8:888888@149.52.53.230:5001#"))
        self.assertIn("#US-149.52.53.230", link)

    def test_bitbrowser_format(self):
        link = bitbrowser(sample_data())
        self.assertEqual(link, "149.52.53.230:5001:a1b2c3d4e5f6a7b8:888888")

    def test_vless_format(self):
        link = vless(sample_data())
        self.assertTrue(link.startswith("vless://9b6deb80-4b32-4496-9a5e-1a2b3c4d5e6f@proxy.tkip.xin:20168?"))
        self.assertIn("security=reality", link)
        self.assertIn("sni=www.microsoft.com", link)
        self.assertIn("pbk=abc123", link)
        self.assertIn("sid=0123456789abcdef", link)

    def test_socks_acceleration_uses_base64_credentials(self):
        link = socks_acceleration(sample_data())
        self.assertTrue(link.startswith("socks://"))
        self.assertIn("@proxy.tkip.xin:5001#", link)
        # 凭据应为 Base64 编码
        self.assertNotIn(":888888@proxy.tkip.xin", link)
        self.assertIn(base64.b64encode(b"888888").decode(), link)

    def test_vmess_format(self):
        link = vmess(sample_data())
        self.assertTrue(link.startswith("vmess://"))
        payload = link[len("vmess://"):]
        config = json.loads(base64.b64decode(payload))
        self.assertEqual(config["add"], "proxy.tkip.xin")
        self.assertEqual(config["port"], "20169")
        self.assertEqual(config["id"], "9b6deb80-4b32-4496-9a5e-1a2b3c4d5e6f")

    def test_generate_all_returns_five_protocols(self):
        links = generate_all(sample_data())
        self.assertEqual(set(links.keys()), {
            "socks5", "bitbrowser", "vless", "socksAcceleration", "vmess"
        })
        for value in links.values():
            self.assertTrue(value)


class ResidentialValidationTest(unittest.TestCase):
    def test_valid_config(self):
        cfg = validate_config("198.51.100.10", 1080, "user", "pass")
        self.assertEqual(cfg.ip, "198.51.100.10")
        self.assertEqual(cfg.port, 1080)

    def test_invalid_ip(self):
        with self.assertRaises(ResidentialConfigError):
            validate_ip("999.1.1.1")
        with self.assertRaises(ResidentialConfigError):
            validate_ip("not-an-ip")

    def test_invalid_port(self):
        with self.assertRaises(ResidentialConfigError):
            validate_port(0)
        with self.assertRaises(ResidentialConfigError):
            validate_port(65536)

    def test_invalid_credential(self):
        with self.assertRaises(ResidentialConfigError):
            validate_credential("")
        with self.assertRaises(ResidentialConfigError):
            validate_credential("has space")
        with self.assertRaises(ResidentialConfigError):
            validate_credential("has\tcontrol")

    def test_batch_validation(self):
        rows = [
            "198.51.100.10 1080 user1 pass1",
            "198.51.100.11 1081 user2 pass2",
        ]
        configs = validate_batch(rows)
        self.assertEqual(len(configs), 2)


class ResidentialRequestModelTest(unittest.TestCase):
    def test_valid_uuid_accepted(self):
        req = ResidentialSocksRequest(
            ip="198.51.100.10",
            port=1080,
            username="user",
            password="pass",
            uuid="9b6deb80-4b32-4496-9a5e-1a2b3c4d5e6f",
        )
        self.assertEqual(req.uuid, "9b6deb80-4b32-4496-9a5e-1a2b3c4d5e6f")

    def test_invalid_uuid_rejected(self):
        with self.assertRaises(ValidationError):
            ResidentialSocksRequest(
                ip="198.51.100.10",
                port=1080,
                username="user",
                password="pass",
                uuid="not-a-uuid",
            )

    def test_empty_uuid_allowed(self):
        req = ResidentialSocksRequest(
            ip="198.51.100.10", port=1080, username="user", password="pass"
        )
        self.assertEqual(req.uuid, "")

    def test_empty_uuid_is_replaced_by_api_with_one_uuid_for_vless_and_vmess(self):
        # The request model intentionally permits omission.  The API layer must
        # replace it before protocol generation so links never contain uuid="".
        from unittest.mock import patch
        from main import generate_residential_protocols

        request = ResidentialSocksRequest(
            ip="198.51.100.10", port=1080, username="user", password="pass"
        )
        with patch("main.config.node.acceleration_domain", "proxy.example.test"):
            result = generate_residential_protocols(request, response=type("R", (), {"headers": {}})(), _token="test")

        links = result["protocolsAll"]
        vless_uuid = links["vless"].split("//", 1)[1].split("@", 1)[0]
        vmess_payload = links["vmess"].split("//", 1)[1]
        vmess_config = json.loads(base64.b64decode(vmess_payload))
        self.assertRegex(vless_uuid, _UUID_PATTERN)
        self.assertEqual(vmess_config["id"], vless_uuid)


if __name__ == "__main__":
    unittest.main()
