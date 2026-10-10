import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
from trusted_source import networks, resolve


class TrustedSourceTest(unittest.TestCase):
    def test_direct_spoof_ignored(self):
        self.assertEqual(resolve("198.51.100.9", ["127.0.0.1"], []), "198.51.100.9")

    def test_walk_from_trusted_end(self):
        trust = networks("127.0.0.1/32,10.2.0.0/24")
        self.assertEqual(resolve("127.0.0.1", ["192.0.2.8, 198.51.100.7, 10.2.0.1"], trust),
                         "198.51.100.7")

    def test_ipv6_and_mapped(self):
        self.assertEqual(resolve("::1", ["2001:db8::8"], networks("::1/128")), "2001:db8::8")
        self.assertEqual(resolve("::ffff:192.0.2.9", ["10.0.0.1"], []), "192.0.2.9")

    def test_malformed_chain_rejected(self):
        for headers in [["unknown"], ["192.0.2.1,"], ["192.0.2.1", "192.0.2.2"],
                        ["1" * 2049], [",".join(["192.0.2.1"] * 17)], ["fe80::1%eth0"],
                        ["192.0.2.1:123"], ["192.0.2.1, bad"]]:
            with self.subTest(headers=headers):
                self.assertIsNone(resolve("127.0.0.1", headers, networks("127.0.0.1/32")))

    def test_missing_peer_and_header(self):
        self.assertIsNone(resolve(None, ["127.0.0.1"], []))
        self.assertEqual(resolve("127.0.0.1", [], networks("127.0.0.1/32")), "127.0.0.1")

    def test_all_network_trust_forbidden(self):
        for cidr in ["0.0.0.0/0", "::/0", "not-a-cidr"]:
            with self.assertRaises(ValueError):
                networks(cidr)

    def test_auth_keeps_token_and_source_controls(self):
        import auth
        from fastapi import HTTPException
        from fastapi.security import HTTPAuthorizationCredentials
        from starlette.requests import Request
        request = Request({"type": "http", "client": ("198.51.100.9", 443),
                           "headers": [(b"x-forwarded-for", b"127.0.0.1")]})
        with patch.object(auth.config.security, "token", "local-test-token"), \
             patch.object(auth.config.security, "allowed_cidrs", "127.0.0.1/32"), \
             patch.object(auth.config.security, "trusted_proxy_cidrs", ""):
            with self.assertRaises(HTTPException) as error:
                auth.verify_token(request, HTTPAuthorizationCredentials(scheme="Bearer", credentials="wrong"))
            self.assertEqual(error.exception.status_code, 401)
            with self.assertRaises(HTTPException) as error:
                auth.verify_token(request, HTTPAuthorizationCredentials(scheme="Bearer", credentials="local-test-token"))
            self.assertEqual(error.exception.status_code, 403)
