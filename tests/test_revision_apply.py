"""B2/B3/B4 发布链路端到端单元测试（打桩 sing-box 二进制与文件路径）。

覆盖 apply_desired_revision / rollback_to_last_known_good 的完整分支：
  - 错误签名 → 拒绝并归档 rejected/
  - 校验通过 → 临时文件 → 原子替换 → reload → 写入 state/current 快照
  - 相同 revision+hash 重复推送 → 幂等 replay，不再次写盘
  - sing-box check 失败 → 拒绝，原配置保持不变
  - reload 失败 → 自动回滚原配置并置 status=rolled-back
  - 用户集合缩减 → 默认拒绝；allow_user_deletion=True 时放行
  - 显式 rollback → 恢复 last_good.json 到生效路径

全部测试在临时目录内运行，不接触 /var/lib 与真实 sing-box。
"""
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "node-manager"
sys.path.insert(0, str(APP_ROOT))

import config as config_module  # noqa: E402
import singbox.manager as manager  # noqa: E402

if "NODE_MANAGER_CONFIG" not in os.environ:
    _bootstrap_dir = tempfile.TemporaryDirectory()
    _bootstrap = Path(_bootstrap_dir.name) / "config.yaml"
    _bootstrap.write_text(
        "node:\n  id: test-node\n  host: 192.0.2.10\n"
        "server:\n  port: 8088\n"
        "security:\n  token: test-token\n"
        "singbox:\n  config: unused.json\n",
        encoding="utf-8",
    )
    os.environ["NODE_MANAGER_CONFIG"] = str(_bootstrap)
    importlib.reload(config_module)

import revision as revision_module  # noqa: E402
from revision import (  # noqa: E402
    SingboxConfigError,
    _sign,
    apply_desired_revision,
    rollback_to_last_known_good,
)


def _combined(config, registry):
    return {"config": config, "registry": registry}


class RevisionApplyTestBase(unittest.TestCase):
    """共用夹具：临时 revisions 目录 + 打桩的配置路径/校验/reload/registry。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.revisions_dir = root / "revisions"
        self.config_path = root / "sing-box" / "config.json"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path = root / "users.json"

        old_env = os.environ.get("NODE_MANAGER_REVISIONS_DIR")
        os.environ["NODE_MANAGER_REVISIONS_DIR"] = str(self.revisions_dir)
        importlib.reload(revision_module)
        if old_env is None:
            os.environ.pop("NODE_MANAGER_REVISIONS_DIR", None)
        else:
            os.environ["NODE_MANAGER_REVISIONS_DIR"] = old_env

        self.patches = [
            patch.object(revision_module, "CONFIG_PATH", self.config_path),
            patch.object(revision_module, "check_config", return_value=(True, "")),
            patch.object(revision_module, "reload_singbox", return_value=True),
            patch.object(revision_module, "read_config", return_value={}),
            patch.object(manager, "REGISTRY_PATH", self.registry_path),
            patch.object(manager, "_write_registry", side_effect=self._write_registry_stub),
            patch.object(manager, "read_registry", side_effect=self._read_registry_stub),
        ]
        self.check_config = self.patches[1].start()
        self.reload_singbox = self.patches[2].start()
        self.read_config = self.patches[3].start()
        self.write_registry = self.patches[5].start()
        self.read_registry = self.patches[6].start()
        self.patches[0].start()
        self.patches[4].start()

    def tearDown(self):
        for patcher in self.patches:
            patcher.stop()
        self._tmp.cleanup()

    def _write_registry_stub(self, registry):
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path.write_text(json.dumps(registry), encoding="utf-8")

    def _read_registry_stub(self):
        if not self.registry_path.exists():
            return {"version": 1, "users": {}}
        try:
            data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": 1, "users": {}}
        if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
            return {"version": 1, "users": {}}
        return data

    def apply(self, config, registry=None, revision_id="rev-1", **kwargs):
        registry = {} if registry is None else registry
        signature = _sign(_combined(config, registry))
        return apply_desired_revision(
            config, registry, signature, revision_id, **kwargs
        )

    def rejected_reasons(self):
        rejected = revision_module.REJECTED_DIR
        if not rejected.exists():
            return []
        reasons = []
        for path in sorted(rejected.glob("rejected-*.json")):
            try:
                reasons.append(json.loads(path.read_text(encoding="utf-8"))["reason"])
            except (OSError, json.JSONDecodeError, KeyError):
                reasons.append("<unreadable>")
        return reasons

    def state(self):
        return revision_module._read_state()


class SignatureGateTest(RevisionApplyTestBase):
    def test_bad_signature_rejected_and_archived(self):
        with self.assertRaises(SingboxConfigError) as ctx:
            apply_desired_revision({"inbounds": []}, {}, "deadbeef", "rev-bad")
        self.assertIn("signature", str(ctx.exception).lower())
        self.assertIn("signature-mismatch", self.rejected_reasons())
        self.assertFalse(self.config_path.exists(), "拒绝时不得写入生效配置")

    def test_missing_revision_id_rejected(self):
        with self.assertRaises(SingboxConfigError):
            apply_desired_revision({"inbounds": []}, {}, "anything", "")

    def test_tampered_registry_invalidates_signature(self):
        config = {"inbounds": []}
        signature = _sign(_combined(config, {"users": {}}))
        with self.assertRaises(SingboxConfigError):
            apply_desired_revision(
                config, {"users": {"evil": {}}}, signature, "rev-tamper"
            )


class ApplySuccessTest(RevisionApplyTestBase):
    def test_apply_persists_config_state_and_snapshot(self):
        desired = {"inbounds": [{"tag": "vless", "listen_port": 20168}]}
        result = self.apply(desired, revision_id="rev-a")
        self.assertTrue(result["success"])
        self.assertFalse(result["replayed"])
        self.assertEqual(
            json.loads(self.config_path.read_text(encoding="utf-8")), desired
        )
        self.assertEqual(self.state()["currentRevisionId"], "rev-a")
        self.assertEqual(self.state()["status"], "applied")
        current = json.loads(
            revision_module.CURRENT_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(current, desired)
        self.assertEqual(self.write_registry.call_count, 1)

    def test_check_failure_keeps_original_config(self):
        original = {"inbounds": [{"tag": "orig", "listen_port": 20168}]}
        self.config_path.write_text(json.dumps(original), encoding="utf-8")
        self.check_config.return_value = (False, "invalid inbound type")
        with self.assertRaises(SingboxConfigError) as ctx:
            self.apply({"inbounds": [{"tag": "new"}]}, revision_id="rev-x")
        self.assertIn("invalid inbound type", str(ctx.exception))
        self.assertEqual(
            json.loads(self.config_path.read_text(encoding="utf-8")), original
        )
        self.assertTrue(
            any("check-failed" in reason for reason in self.rejected_reasons())
        )

    def test_replay_same_revision_is_idempotent(self):
        desired = {"inbounds": [{"tag": "vless"}]}
        first = self.apply(desired, revision_id="rev-same")
        self.assertFalse(first["replayed"])
        second = self.apply(desired, revision_id="rev-same")
        self.assertTrue(second["replayed"])
        self.assertEqual(self.check_config.call_count, 1)
        self.assertEqual(self.reload_singbox.call_count, 1)

    def test_same_revision_id_with_different_payload_is_not_replay(self):
        self.apply({"inbounds": [{"tag": "v1"}]}, revision_id="rev-dup")
        second = self.apply({"inbounds": [{"tag": "v2"}]}, revision_id="rev-dup")
        self.assertFalse(second["replayed"])
        self.assertEqual(self.reload_singbox.call_count, 2)

    def test_reload_failure_rolls_back_previous_config(self):
        original = {"inbounds": [{"tag": "orig", "listen_port": 20168}]}
        self.config_path.write_text(json.dumps(original), encoding="utf-8")
        self.reload_singbox.return_value = False
        with self.assertRaises(SingboxConfigError) as ctx:
            self.apply({"inbounds": [{"tag": "broken"}]}, revision_id="rev-fail")
        self.assertIn("reload failed", str(ctx.exception))
        self.assertEqual(
            json.loads(self.config_path.read_text(encoding="utf-8")),
            original,
            "reload 失败后必须恢复上一份可用配置",
        )
        self.assertEqual(self.state()["status"], "rolled-back")
        self.assertIn("reload-failed", self.rejected_reasons())

    def test_reload_failure_without_previous_config_still_signals(self):
        self.reload_singbox.return_value = False
        with self.assertRaises(SingboxConfigError):
            self.apply({"inbounds": [{"tag": "broken"}]}, revision_id="rev-f1")
        self.assertEqual(self.state()["status"], "rolled-back")

    def test_second_apply_promotes_last_good(self):
        first = {"inbounds": [{"tag": "one", "listen_port": 1}]}
        second = {"inbounds": [{"tag": "two", "listen_port": 2}]}
        self.apply(first, revision_id="rev-1")
        result = self.apply(second, revision_id="rev-2")
        self.assertFalse(result["replayed"])
        last_good = json.loads(
            revision_module.LAST_GOOD_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(last_good, first)
        self.assertEqual(result["lastGoodRevisionId"], "rev-1")
        self.assertEqual(result["currentRevisionId"], "rev-2")

    def test_config_file_permissions_preserved(self):
        original = {"inbounds": [{"tag": "orig"}]}
        self.config_path.write_text(json.dumps(original), encoding="utf-8")
        os.chmod(self.config_path, 0o640)
        self.apply({"inbounds": [{"tag": "new"}]}, revision_id="rev-perm")
        if os.name != "nt":
            self.assertEqual(self.config_path.stat().st_mode & 0o777, 0o640)


class UserShrinkGateTest(RevisionApplyTestBase):
    def setUp(self):
        super().setUp()
        self.read_config.return_value = {"inbounds": []}
        self.registry_path.write_text(
            json.dumps({"version": 1, "users": {"user-1": {}, "user-2": {}}}),
            encoding="utf-8",
        )

    def test_removing_user_blocked_by_default(self):
        with self.assertRaises(SingboxConfigError) as ctx:
            self.apply(
                {"inbounds": []},
                registry={"users": {"user-1": {}}},
                revision_id="rev-shrink",
            )
        self.assertIn("remove", str(ctx.exception).lower())
        self.assertTrue(
            any("user-shrink" in reason for reason in self.rejected_reasons())
        )

    def test_removing_user_allowed_with_explicit_flag(self):
        result = self.apply(
            {"inbounds": []},
            registry={"users": {"user-1": {}}},
            revision_id="rev-shrink-ok",
            allow_user_deletion=True,
        )
        self.assertTrue(result["success"])

    def test_adding_user_not_blocked(self):
        result = self.apply(
            {"inbounds": []},
            registry={"users": {"user-1": {}, "user-2": {}, "user-3": {}}},
            revision_id="rev-grow",
        )
        self.assertTrue(result["success"])


class ExplicitRollbackTest(RevisionApplyTestBase):
    def test_rollback_restores_last_good_config(self):
        first = {"inbounds": [{"tag": "one", "listen_port": 1}]}
        second = {"inbounds": [{"tag": "two", "listen_port": 2}]}
        self.apply(first, revision_id="rev-1")
        self.apply(second, revision_id="rev-2")
        result = rollback_to_last_known_good()
        self.assertTrue(result["success"])
        self.assertEqual(
            json.loads(self.config_path.read_text(encoding="utf-8")), first
        )
        self.assertEqual(result["status"], "rolled-back")

    def test_rollback_without_last_good_raises(self):
        with self.assertRaises(SingboxConfigError):
            rollback_to_last_known_good()

    def test_rollback_reload_failure_restores_original(self):
        first = {"inbounds": [{"tag": "one", "listen_port": 1}]}
        second = {"inbounds": [{"tag": "two", "listen_port": 2}]}
        self.apply(first, revision_id="rev-1")
        self.apply(second, revision_id="rev-2")
        self.reload_singbox.return_value = False
        with self.assertRaises(SingboxConfigError) as ctx:
            rollback_to_last_known_good()
        self.assertIn("rollback", str(ctx.exception).lower())
        self.assertEqual(
            json.loads(self.config_path.read_text(encoding="utf-8")),
            second,
            "回滚失败时应恢复回滚前的配置",
        )


class PortConflictGateTest(RevisionApplyTestBase):
    """B2: 端口冲突预检。

    sing-box check 不检测重复 listen_port（真机实测 rc=0），
    因此 apply 前显式拒绝：重复端点 / 通配与具体地址重叠 / 占用 node-manager API 端口。
    """

    def test_duplicate_listen_port_rejected(self):
        config = {"inbounds": [
            {"type": "vless", "tag": "a", "listen": "0.0.0.0", "listen_port": 20168},
            {"type": "vmess", "tag": "b", "listen": "0.0.0.0", "listen_port": 20168},
        ]}
        with self.assertRaises(SingboxConfigError) as ctx:
            self.apply(config, revision_id="rev-port-dup")
        self.assertIn("port conflict", str(ctx.exception).lower())
        self.assertTrue(
            any(r.startswith("port-conflict:") for r in self.rejected_reasons()),
            self.rejected_reasons(),
        )
        self.assertFalse(self.config_path.exists(), "拒绝时不得覆盖生效配置")

    def test_wildcard_overlaps_specific_address(self):
        config = {"inbounds": [
            {"type": "vless", "tag": "wild", "listen_port": 20169},
            {"type": "vless", "tag": "specific", "listen": "127.0.0.1", "listen_port": 20169},
        ]}
        with self.assertRaises(SingboxConfigError):
            self.apply(config, revision_id="rev-port-wild")

    def test_manager_api_port_conflict_rejected(self):
        manager_port = int(getattr(config_module.config.server, "port", 0) or 0)
        self.assertTrue(manager_port, "测试需要已配置 server.port")
        config = {"inbounds": [
            {"type": "vless", "tag": "api", "listen": "0.0.0.0", "listen_port": manager_port},
        ]}
        with self.assertRaises(SingboxConfigError) as ctx:
            self.apply(config, revision_id="rev-port-api")
        self.assertIn("node-manager API port", str(ctx.exception))

    def test_tcp_udp_split_on_same_port_allowed(self):
        config = {"inbounds": [
            {"type": "vless", "tag": "tcp-only", "listen_port": 20170, "network": "tcp"},
            {"type": "vless", "tag": "udp-only", "listen_port": 20170, "network": "udp"},
        ]}
        result = self.apply(config, revision_id="rev-port-split")
        self.assertTrue(result["success"])

    def test_same_port_on_distinct_addresses_allowed(self):
        config = {"inbounds": [
            {"type": "vless", "tag": "lo", "listen": "127.0.0.1", "listen_port": 20173},
            {"type": "vless", "tag": "pub", "listen": "192.0.2.10", "listen_port": 20173},
        ]}
        result = self.apply(config, revision_id="rev-port-addr")
        self.assertTrue(result["success"])

    def test_distinct_ports_allowed(self):
        config = {"inbounds": [
            {"type": "vless", "tag": "a", "listen": "0.0.0.0", "listen_port": 20171},
            {"type": "vless", "tag": "b", "listen": "0.0.0.0", "listen_port": 20172},
        ]}
        result = self.apply(config, revision_id="rev-port-ok")
        self.assertTrue(result["success"])


class NodeTargetGateTest(RevisionApplyTestBase):
    """B2: 节点目标校验。revision 显式声明目标节点时必须等于本机 node.id。"""

    def local_node_id(self):
        return str(getattr(config_module.config.node, "id", "") or "").strip()

    def test_foreign_node_target_rejected(self):
        local = self.local_node_id()
        self.assertTrue(local, "测试需要已配置 node.id")
        config = {"nodeId": local + "-other", "inbounds": []}
        with self.assertRaises(SingboxConfigError) as ctx:
            self.apply(config, revision_id="rev-target-bad")
        self.assertIn("target", str(ctx.exception).lower())
        self.assertTrue(
            any(r.startswith("node-target-mismatch:") for r in self.rejected_reasons()),
            self.rejected_reasons(),
        )

    def test_registry_node_target_rejected(self):
        local = self.local_node_id()
        registry = {"target_node_id": local + "-other", "users": {}}
        with self.assertRaises(SingboxConfigError):
            self.apply({"inbounds": []}, registry=registry, revision_id="rev-target-reg")

    def test_matching_node_target_applied(self):
        config = {"nodeId": self.local_node_id(), "inbounds": []}
        result = self.apply(config, revision_id="rev-target-ok")
        self.assertTrue(result["success"])

    def test_undeclared_node_target_applied(self):
        result = self.apply({"inbounds": []}, revision_id="rev-target-none")
        self.assertTrue(result["success"])


class RegistryPayloadGateTest(RevisionApplyTestBase):
    """B2: desired registry 结构校验（防止非法 registry 落盘后污染节点）。"""

    def test_invalid_users_type_rejected(self):
        with self.assertRaises(SingboxConfigError) as ctx:
            self.apply({"inbounds": []}, registry={"users": []}, revision_id="rev-reg-bad")
        self.assertIn("registry", str(ctx.exception).lower())
        self.assertTrue(
            any(r.startswith("registry-invalid:") for r in self.rejected_reasons()),
            self.rejected_reasons(),
        )
        self.assertFalse(self.config_path.exists(), "拒绝时不得写盘")

    def test_unknown_key_without_users_rejected(self):
        with self.assertRaises(SingboxConfigError):
            self.apply({"inbounds": []}, registry={"foo": 1}, revision_id="rev-reg-key")

    def test_non_dict_registry_rejected(self):
        with self.assertRaises(SingboxConfigError):
            self.apply({"inbounds": []}, registry=["nope"], revision_id="rev-reg-type")

    def test_empty_registry_normalized_and_not_poisoning(self):
        first = self.apply({"inbounds": []}, registry={}, revision_id="rev-reg-empty-1")
        self.assertTrue(first["success"])
        stored = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertEqual(stored, {"version": 1, "users": {}})
        # 回归：非法 registry 落盘会让后续 apply 全部失败；归一化后不得复发
        second = self.apply({"inbounds": []}, registry={}, revision_id="rev-reg-empty-2")
        self.assertTrue(second["success"])

    def test_version_only_registry_normalized(self):
        self.apply({"inbounds": []}, registry={"version": 7}, revision_id="rev-reg-ver")
        stored = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertEqual(stored, {"version": 7, "users": {}})

    def test_valid_registry_kept_verbatim(self):
        registry = {"version": 1, "users": {"user-1": {"trafficLimitBytes": 1024}}}
        self.apply({"inbounds": []}, registry=registry, revision_id="rev-reg-ok")
        stored = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.assertEqual(stored, registry)


class RejectedArchiveTest(RevisionApplyTestBase):
    """B4: 拒绝归档逐条留存（同一秒内多次拒绝不得互相覆盖，保留 MAX_REJECTED 条）。"""

    def conflict_config(self, port=20201):
        return {"inbounds": [
            {"type": "vless", "tag": "a", "listen": "0.0.0.0", "listen_port": port},
            {"type": "vless", "tag": "b", "listen": "0.0.0.0", "listen_port": port},
        ]}

    def test_two_rejections_same_second_both_archived(self):
        config = self.conflict_config()
        for index in (1, 2):
            with self.assertRaises(SingboxConfigError):
                self.apply(config, revision_id=f"rev-arch-{index}")
        reasons = self.rejected_reasons()
        self.assertEqual(len(reasons), 2, reasons)
        self.assertTrue(all(r.startswith("port-conflict:") for r in reasons), reasons)

    def test_archive_retention_capped(self):
        config = self.conflict_config(port=20202)
        for index in range(revision_module.MAX_REJECTED + 3):
            with self.assertRaises(SingboxConfigError):
                self.apply(config, revision_id=f"rev-cap-{index}")
        files = sorted(revision_module.REJECTED_DIR.glob("rejected-*.json"))
        self.assertEqual(len(files), revision_module.MAX_REJECTED)


if __name__ == "__main__":
    unittest.main()
