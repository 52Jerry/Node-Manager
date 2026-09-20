"""B2/B3/B4/B5: revision 管理单元测试。

覆盖：
  - B2: HMAC-SHA256 签名校验（verify_signature）
  - B2: canonical JSON 序列化确定性（键顺序无关）
  - B2: SHA-256 哈希稳定性
  - B5: 用户集合缩减保护（_discover_user_ids 对比逻辑）
"""
import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "node-manager"
sys.path.insert(0, str(APP_ROOT))

from revision import (
    _canonical_json,
    _sha256,
    _sign,
    verify_signature,
)


class SignatureVerificationTest(unittest.TestCase):
    """B2: HMAC-SHA256 签名校验。"""

    def test_valid_signature_accepted(self):
        payload = {"config": {"node": "alpha"}, "registry": {"users": {}}}
        signature = _sign(payload)
        self.assertTrue(verify_signature(payload, signature))

    def test_tampered_payload_rejected(self):
        payload = {"config": {"node": "alpha"}, "registry": {"users": {}}}
        signature = _sign(payload)
        tampered = {"config": {"node": "beta"}, "registry": {"users": {}}}
        self.assertFalse(verify_signature(tampered, signature))

    def test_tampered_signature_rejected(self):
        payload = {"config": {"node": "alpha"}}
        signature = _sign(payload)
        # 翻转最后一个字符破坏签名
        bad_signature = signature[:-1] + ("0" if signature[-1] != "0" else "1")
        self.assertFalse(verify_signature(payload, bad_signature))

    def test_empty_signature_rejected(self):
        payload = {"config": {}}
        self.assertFalse(verify_signature(payload, ""))
        self.assertFalse(verify_signature(payload, None))

    def test_different_payload_order_still_valid(self):
        # canonical_json 使用 sort_keys，键顺序不影响签名
        payload_a = {"a": 1, "b": 2}
        payload_b = {"b": 2, "a": 1}
        self.assertEqual(_sign(payload_a), _sign(payload_b))
        self.assertTrue(verify_signature(payload_b, _sign(payload_a)))

    def test_combined_payload_signature_covers_registry(self):
        # 签名覆盖 config + registry 组合载荷，防止单独篡改 registry
        config = {"inbounds": []}
        registry = {"users": {"user-1": {}}}
        combined = {"config": config, "registry": registry}
        signature = _sign(combined)
        self.assertTrue(verify_signature(combined, signature))
        # 篡改 registry 后签名失效
        tampered_registry = {"config": config, "registry": {"users": {"user-2": {}}}}
        self.assertFalse(verify_signature(tampered_registry, signature))


class CanonicalJsonTest(unittest.TestCase):
    """B2: canonical JSON 序列化确定性。"""

    def test_key_order_independent(self):
        a = _canonical_json({"z": 1, "a": 2, "m": 3})
        b = _canonical_json({"a": 2, "m": 3, "z": 1})
        self.assertEqual(a, b)

    def test_compact_separators(self):
        result = _canonical_json({"k": "v"})
        self.assertEqual(result, '{"k":"v"}')

    def test_unicode_preserved(self):
        result = _canonical_json({"name": "测试"})
        self.assertIn("测试", result)

    def test_nested_order_independent(self):
        a = _canonical_json({"outer": {"z": 1, "a": 2}})
        b = _canonical_json({"outer": {"a": 2, "z": 1}})
        self.assertEqual(a, b)


class Sha256Test(unittest.TestCase):
    """B2: SHA-256 哈希稳定性。"""

    def test_stable_hash(self):
        text = '{"node":"alpha"}'
        self.assertEqual(_sha256(text), _sha256(text))

    def test_different_input_different_hash(self):
        self.assertNotEqual(_sha256("alpha"), _sha256("beta"))

    def test_returns_hex_digest(self):
        result = _sha256("test")
        self.assertEqual(len(result), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in result))


class UserShrinkProtectionTest(unittest.TestCase):
    """B5: 用户集合缩减保护逻辑。

    使用 singbox.manager._discover_user_ids 验证对比逻辑，
    确保误删除用户时能被检测到。
    """

    def _discover(self, config, registry):
        from singbox.manager import _discover_user_ids
        return _discover_user_ids(config, registry)

    def test_empty_config_and_registry_yields_empty_set(self):
        self.assertEqual(self._discover({}, {}), set())

    def test_registry_users_discovered(self):
        registry = {"users": {"user-1": {}, "user-2": {}}}
        self.assertEqual(self._discover({}, registry), {"user-1", "user-2"})

    def test_inbound_auth_users_discovered(self):
        config = {
            "inbounds": [
                {"users": [{"name": "node-manager:user-3"}]},
                {"users": [{"username": "node-manager:user-4"}]},
            ]
        }
        result = self._discover(config, {})
        self.assertIn("user-3", result)
        self.assertIn("user-4", result)

    def test_shrink_detection(self):
        """B5: desired 删除用户时，差集非空，应触发保护。"""
        current_registry = {"users": {"user-1": {}, "user-2": {}, "user-3": {}}}
        desired_registry = {"users": {"user-1": {}, "user-2": {}}}
        current_users = self._discover({}, current_registry)
        desired_users = self._discover({}, desired_registry)
        removed = current_users - desired_users
        self.assertEqual(removed, {"user-3"})

    def test_no_shrink_when_user_added(self):
        """B5: desired 新增用户不触发保护（差集为空）。"""
        current_registry = {"users": {"user-1": {}}}
        desired_registry = {"users": {"user-1": {}, "user-2": {}}}
        current_users = self._discover({}, current_registry)
        desired_users = self._discover({}, desired_registry)
        removed = current_users - desired_users
        self.assertEqual(removed, set())


if __name__ == "__main__":
    unittest.main()
