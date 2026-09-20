import base64
import json
import sys
import unittest
from unittest.mock import patch
from pathlib import Path
from urllib.parse import unquote

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "node-manager"
sys.path.insert(0, str(APP_ROOT))

from pydantic import ValidationError

from protocols import (
    ProtocolData,
    generate_all,
    protocol_info,
    socks5_original,
    bitbrowser,
    vless,
    socks_acceleration,
    vmess,
    trojan,
)
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
        encoded = base64.b64encode(b"a1b2c3d4e5f6a7b8:888888").decode("ascii")
        self.assertTrue(link.startswith(f"socks://{encoded}@149.52.53.230:5001#"))
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
        self.assertEqual(unquote(link.rsplit("#", 1)[1]), "[US] 149.52.53.230")

    def test_socks_acceleration_uses_v2ray_compatible_base64_credentials(self):
        link = socks_acceleration(sample_data())
        self.assertTrue(link.startswith("socks://"))
        self.assertIn("@proxy.tkip.xin:5001#", link)
        encoded = link.split("socks://", 1)[1].split("@", 1)[0]
        self.assertEqual(
            base64.b64decode(encoded).decode("utf-8"),
            "a1b2c3d4e5f6a7b8:888888",
        )
        self.assertEqual(unquote(link.rsplit("#", 1)[1]), "[US] 149.52.53.230")

    def test_original_and_acceleration_socks_encode_complete_credentials(self):
        data = sample_data(username="user@name", password="p:a+ss/word=")
        expected = base64.b64encode(b"user@name:p:a+ss/word=").decode("ascii")
        for link in (socks5_original(data), socks_acceleration(data)):
            encoded = link.split("socks://", 1)[1].split("@", 1)[0]
            self.assertEqual(base64.b64decode(encoded).decode("utf-8"), "user@name:p:a+ss/word=")
            self.assertIn(f"socks://{expected}@", link)

    def test_vmess_format(self):
        link = vmess(sample_data())
        self.assertTrue(link.startswith("vmess://"))
        payload = link[len("vmess://"):]
        config = json.loads(base64.b64decode(payload))
        self.assertEqual(config["add"], "proxy.tkip.xin")
        self.assertEqual(config["port"], "20169")
        self.assertEqual(config["id"], "9b6deb80-4b32-4496-9a5e-1a2b3c4d5e6f")
        self.assertEqual(config["ps"], "[US] 149.52.53.230")

    def test_acceleration_alias_normalizes_lowercase_country_code(self):
        data = sample_data(country_code="us")
        self.assertEqual(unquote(vless(data).rsplit("#", 1)[1]), "[US] 149.52.53.230")
        self.assertEqual(
            unquote(socks_acceleration(data).rsplit("#", 1)[1]),
            "[US] 149.52.53.230",
        )
        vmess_config = json.loads(base64.b64decode(vmess(data).split("//", 1)[1]))
        self.assertEqual(vmess_config["ps"], "[US] 149.52.53.230")
        self.assertEqual(protocol_info(data)["countryCode"], "US")

    def test_protocol_info_contains_documented_fields_and_can_use_ipv6_endpoint(self):
        data = sample_data(acceleration_domain="2001:db8::10")
        result = protocol_info(data, protocol_id=data.uuid, include_original=False)

        required = {
            "id", "ip", "port", "username", "password", "countryCode",
            "countryName", "cityName", "status", "expireTime", "remark",
            "accelerationDomain", "uuid", "accelerationPortSocks",
            "vlessPort", "vlessEncryption", "vlessSecurity", "vlessSni",
            "vlessFp", "vlessPbk", "vlessSid", "vlessSpx", "vlessType",
            "vlessHeaderType", "vlessFlow", "vmessPort", "vmessV", "vmessAid",
            "vmessScy", "vmessNet", "vmessType", "vmessHost", "vmessPath",
            "vmessTls", "vmessSni", "vmessAlpn", "vmessFp",
        }
        self.assertTrue(required.issubset(result))
        self.assertEqual(result["id"], data.uuid)
        self.assertNotIn("rawProtocol", result)
        self.assertNotIn("rawPort", result)
        self.assertIn("@[2001:db8::10]:20168?", vless(data))
        self.assertIn("@[2001:db8::10]:5001#", socks_acceleration(data))

    def test_protocol_info_can_include_original_fields_only_for_residential_mode(self):
        result = protocol_info(sample_data(), protocol_id="allocation-1", include_original=True)
        self.assertEqual(result["id"], "allocation-1")
        self.assertEqual(result["rawProtocol"], "socks5")
        self.assertEqual(result["rawPort"], 5001)

    def test_trojan_format(self):
        link = trojan(sample_data(trojan_pbk="abc123", trojan_sid="0123456789abcdef"))
        self.assertTrue(link.startswith("trojan://9b6deb80-4b32-4496-9a5e-1a2b3c4d5e6f@proxy.tkip.xin:20170?"))
        self.assertIn("security=reality", link)
        self.assertIn("sni=www.microsoft.com", link)
        self.assertIn("pbk=abc123", link)
        self.assertIn("sid=0123456789abcdef", link)
        self.assertEqual(unquote(link.rsplit("#", 1)[1]), "[US] 149.52.53.230")

    def test_trojan_uses_uuid_when_no_explicit_password(self):
        link = trojan(sample_data(trojan_pbk="abc123", trojan_sid="0123456789abcdef"))
        self.assertIn("trojan://9b6deb80-4b32-4496-9a5e-1a2b3c4d5e6f@", link)

    def test_trojan_uses_explicit_password_when_provided(self):
        link = trojan(sample_data(trojan_password="trojan-secret", trojan_pbk="abc123", trojan_sid="0123456789abcdef"))
        self.assertTrue(link.startswith("trojan://trojan-secret@"))

    def test_generate_all_returns_six_protocols(self):
        links = generate_all(sample_data())
        self.assertEqual(set(links.keys()), {
            "socks5", "bitbrowser", "vless", "socksAcceleration", "vmess", "trojan"
        })
        for value in links.values():
            self.assertTrue(value)


class ResidentialValidationTest(unittest.TestCase):
    def test_valid_config(self):
        with patch("residential.socket.create_connection") as mock_connect:
            mock_connect.return_value.__enter__.return_value = None
            cfg = validate_config("198.51.100.10", 1080, "", "")
        self.assertEqual(cfg.ip, "198.51.100.10")
        self.assertEqual(cfg.port, 1080)
        self.assertEqual(cfg.username, "")
        self.assertEqual(cfg.password, "")

    def test_unreachable_port_rejected(self):
        with patch("residential.socket.create_connection") as mock_connect:
            mock_connect.side_effect = OSError("connection refused")
            with self.assertRaises(ResidentialConfigError):
                validate_config("198.51.100.10", 1080, "user", "pass")

    def test_batch_validation(self):
        rows = [
            "198.51.100.10 1080 user1 pass1",
            "198.51.100.11 1081 user2 pass2",
        ]
        with patch("residential.socket.create_connection") as mock_connect:
            mock_connect.return_value.__enter__.return_value = None
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
        from main import generate_residential_protocols

        request = ResidentialSocksRequest(
            ip="198.51.100.10", port=1080, username="user", password="pass"
        )
        with patch("main.config.node.acceleration_domain", "proxy.example.test"):
            with patch("residential.socket.create_connection") as mock_connect:
                mock_connect.return_value.__enter__.return_value = None
                result = generate_residential_protocols(
                    request,
                    response=type("R", (), {"headers": {}})(),
                    _token="test",
                )

        links = result["protocolsAll"]
        vless_uuid = links["vless"].split("//", 1)[1].split("@", 1)[0]
        vmess_payload = links["vmess"].split("//", 1)[1]
        vmess_config = json.loads(base64.b64decode(vmess_payload))
        self.assertRegex(vless_uuid, _UUID_PATTERN)
        self.assertEqual(vmess_config["id"], vless_uuid)


if __name__ == "__main__":
    unittest.main()
