"""B6: 节点网络前置检查单元测试。

覆盖：
  - NetworkCheckResult / PortCheck 数据类结构
  - to_dict() 序列化字段
  - run_network_check() 在非 Linux 环境优雅降级（不抛异常）
"""
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "node-manager"
sys.path.insert(0, str(APP_ROOT))

import json
import tempfile
from unittest import mock

from network_check import (
    NetworkCheckResult,
    PortCheck,
    REQUIRED_PORTS,
    _expected_ports,
    run_network_check,
)
import network_check


class PortCheckTest(unittest.TestCase):
    def test_defaults(self):
        check = PortCheck(name="vless", port=20168, protocol="tcp")
        self.assertFalse(check.listening)
        self.assertFalse(check.reachable)
        self.assertFalse(check.firewall_allowed)
        self.assertIsNone(check.error)

    def test_fields(self):
        check = PortCheck(
            name="socks", port=5001, protocol="tcp",
            listening=True, reachable=True, firewall_allowed=True,
        )
        self.assertTrue(check.listening)
        self.assertTrue(check.reachable)
        self.assertTrue(check.firewall_allowed)


class NetworkCheckResultTest(unittest.TestCase):
    def test_to_dict_has_expected_keys(self):
        result = NetworkCheckResult()
        data = result.to_dict()
        # 兼容字段：Control Plane 已在消费，必须保留
        legacy_keys = {
            "healthy", "ports", "ipForward", "mtu",
            "firewallStatus", "issues",
        }
        self.assertTrue(legacy_keys.issubset(set(data.keys())))

    def test_to_dict_has_b6_extension_keys(self):
        result = NetworkCheckResult()
        data = result.to_dict()
        # B6 扩展字段：DNAT/SNAT、回程、MTU 探测、conntrack、sing-box 等
        extension_keys = {
            "warnings", "ipForwardV6", "interfaces", "addresses",
            "routes", "policyRules", "returnPath", "natRules",
            "forward", "firewall", "linkTargets", "mtuProbes",
            "conntrack", "singbox", "generatedAt",
        }
        self.assertTrue(extension_keys.issubset(set(data.keys())))

    def test_defaults_healthy_true(self):
        result = NetworkCheckResult()
        self.assertTrue(result.healthy)
        self.assertEqual(result.ports, [])
        self.assertEqual(result.issues, [])
        self.assertFalse(result.ip_forward)
        self.assertEqual(result.firewall_status, "unknown")

    def test_to_dict_serializes_port_checks(self):
        result = NetworkCheckResult()
        result.ports.append(PortCheck(
            name="vless", port=20168, protocol="tcp", listening=True,
        ))
        data = result.to_dict()
        self.assertEqual(len(data["ports"]), 1)
        self.assertEqual(data["ports"][0]["name"], "vless")
        self.assertEqual(data["ports"][0]["port"], 20168)
        self.assertTrue(data["ports"][0]["listening"])

    def test_issues_propagate_to_dict(self):
        result = NetworkCheckResult()
        result.issues.append("port 20168 not listening")
        result.healthy = False
        data = result.to_dict()
        self.assertFalse(data["healthy"])
        self.assertIn("port 20168 not listening", data["issues"])


class RequiredPortsTest(unittest.TestCase):
    """B6: 确保所有必需端口都被声明。"""

    def test_all_six_protocols_covered(self):
        names = {entry[0] for entry in REQUIRED_PORTS}
        self.assertEqual(
            names,
            {"vless", "vmess", "trojan", "socks", "manager", "clash_api"},
        )

    def test_trojan_port_present(self):
        trojan_entries = [e for e in REQUIRED_PORTS if e[0] == "trojan"]
        self.assertEqual(len(trojan_entries), 1)
        self.assertEqual(trojan_entries[0][1], 20170)
        self.assertEqual(trojan_entries[0][2], "tcp")


class RunNetworkCheckTest(unittest.TestCase):
    """B6: run_network_check() 在非 Linux 开发环境优雅降级。"""

    def test_returns_network_check_result(self):
        result = run_network_check()
        self.assertIsInstance(result, NetworkCheckResult)

    def test_includes_all_required_ports(self):
        result = run_network_check()
        self.assertEqual(len(result.ports), len(REQUIRED_PORTS))

    def test_to_dict_serializable(self):
        result = run_network_check()
        data = result.to_dict()
        # 确保结果可被 JSON 序列化（API 返回时需要）
        import json
        json.dumps(data)


class ExpectedListenPortsTest(unittest.TestCase):
    """B6+: 纯转发（入口）节点没有 sing-box，需要显式声明本机期望监听端口。"""

    def setUp(self):

        # 直接取 network_check 绑定的 config 实例：其他测试模块会 importlib.reload(config)，
        # 重新导入模块可能拿到另一个实例，导致断言与实现读取的对象不一致。
        self.network = network_check.config.network
        self.original = self.network.expected_listen_ports

    def tearDown(self):
        self.network.expected_listen_ports = self.original

    def test_unset_returns_empty_list(self):
        self.network.expected_listen_ports = None
        self.assertEqual(self.network.expected_listen_port_list(), [])

    def test_parses_supported_forms(self):
        self.network.expected_listen_ports = "manager:8088,20168,socks:5001/udp"
        self.assertEqual(
            self.network.expected_listen_port_list(),
            [
                ("manager", 8088, "tcp"),
                ("local", 20168, "tcp"),
                ("socks", 5001, "udp"),
            ],
        )

    def test_skips_invalid_entries(self):
        self.network.expected_listen_ports = " ,manager:notaport, :9090 ,8088"
        self.assertEqual(
            self.network.expected_listen_port_list(),
            [("local", 9090, "tcp"), ("local", 8088, "tcp")],
        )

    def test_explicit_empty_means_no_expected_listener(self):
        self.network.expected_listen_ports = ""
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "config.json")
            with mock.patch("singbox.manager.CONFIG_PATH", missing):
                ports, source = _expected_ports()
        self.assertEqual(ports, [])
        self.assertEqual(source, "network.expected_listen_ports")

    def test_configured_list_used_when_singbox_config_missing(self):
        self.network.expected_listen_ports = "manager:8088"
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "config.json")
            with mock.patch("singbox.manager.CONFIG_PATH", missing):
                ports, source = _expected_ports()
        self.assertEqual(ports, [("manager", 8088, "tcp")])
        self.assertEqual(source, "network.expected_listen_ports")

    def test_unset_falls_back_to_defaults(self):
        self.network.expected_listen_ports = None
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "config.json")
            with mock.patch("singbox.manager.CONFIG_PATH", missing):
                ports, source = _expected_ports()
        self.assertEqual(ports, list(REQUIRED_PORTS))
        self.assertEqual(source, "defaults")

    def test_singbox_config_wins_over_configured_list(self):
        self.network.expected_listen_ports = "manager:8088"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps({"inbounds": [{"tag": "vless", "listen_port": 20168}]}),
                encoding="utf-8",
            )
            with mock.patch("singbox.manager.CONFIG_PATH", str(path)):
                ports, source = _expected_ports()
        self.assertEqual(ports, [("vless", 20168, "tcp")])
        self.assertEqual(source, str(path))


class DnatPortSemanticsTest(unittest.TestCase):
    """B6+: 入口节点（纯转发）的 DNAT 公网端口不本机监听，不得据此判定不健康。"""

    def setUp(self):
        self.network = network_check.config.network
        self.original = (
            self.network.dnat_ports,
            self.network.require_dnat,
            self.network.expected_listen_ports,
        )

    def tearDown(self):
        (
            self.network.dnat_ports,
            self.network.require_dnat,
            self.network.expected_listen_ports,
        ) = self.original

    def _patch_probe(self, listening_ports, nat_ports):
        rules = [{"kind": "dnat", "extra": f"dpt:{port}"} for port in nat_ports]
        patchers = [
            mock.patch.object(network_check.netprobe, "nat_rules", return_value=rules),
            mock.patch.object(
                network_check.netprobe,
                "is_listening",
                side_effect=lambda port, protocol="tcp": port in listening_ports,
            ),
            mock.patch.object(network_check.netprobe, "listener_process", return_value=""),
            mock.patch.object(network_check.netprobe, "tcp_reachable", return_value=True),
            mock.patch.object(
                network_check.netprobe, "firewall_backend", return_value={"ufw": "inactive"}
            ),
            mock.patch.object(network_check.netprobe, "ufw_allowed_ports", return_value=set()),
            mock.patch.object(network_check.netprobe, "input_accept_ports", return_value=set()),
            mock.patch.object(
                network_check.netprobe,
                "forward_rules",
                return_value={"policy": "ACCEPT", "rules": []},
            ),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _run_checks(self):
        result = NetworkCheckResult()
        network_check._check_ports(result)
        network_check._check_nat_and_forward(result)
        return result

    def test_dnat_ports_are_not_treated_as_local_listeners(self):
        self.network.expected_listen_ports = ""
        self.network.require_dnat = True
        self.network.dnat_ports = "24443,30169"
        self._patch_probe(listening_ports=set(), nat_ports=[24443, 30169])
        result = self._run_checks()
        self.assertTrue(result.healthy, result.issues)
        self.assertEqual(
            [(entry.name, entry.kind) for entry in result.ports],
            [("dnat-24443", "dnat"), ("dnat-30169", "dnat")],
        )
        self.assertTrue(all(entry.dnat_present for entry in result.ports))
        self.assertFalse(any("未监听" in issue for issue in result.issues))

    def test_missing_dnat_rule_still_fails(self):
        self.network.expected_listen_ports = ""
        self.network.require_dnat = True
        self.network.dnat_ports = "24443,30169"
        self._patch_probe(listening_ports=set(), nat_ports=[24443])
        result = self._run_checks()
        self.assertFalse(result.healthy)
        self.assertEqual(result.issues, ["期望的 DNAT 端口未配置: [30169]"])
        entry = next(item for item in result.ports if item.name == "dnat-30169")
        self.assertFalse(entry.dnat_present)

    def test_dnat_port_that_is_also_a_listener_is_checked_once(self):
        self.network.expected_listen_ports = "manager:8088"
        self.network.require_dnat = False
        self.network.dnat_ports = "8088"
        self._patch_probe(listening_ports={8088}, nat_ports=[8088])
        result = self._run_checks()
        self.assertEqual([entry.name for entry in result.ports], ["manager"])
        self.assertEqual(result.ports[0].kind, "listen")
        self.assertTrue(result.healthy, result.issues)


class SingboxModuleAbsenceTest(unittest.TestCase):
    """纯转发（入口）节点没有 sing-box 模块时，如实记录而不是当成异常。"""

    def test_missing_module_recorded_without_warning(self):
        result = NetworkCheckResult()
        with mock.patch.dict(
            sys.modules, {"singbox": None, "singbox.manager": None}
        ):
            network_check._check_singbox_config(result)
        self.assertFalse(result.singbox["moduleAvailable"])
        self.assertIsNone(result.singbox["configPath"])
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.issues, [])

    def test_module_present_records_config_path(self):
        result = NetworkCheckResult()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps({"log": {"level": "info"}, "inbounds": []}),
                encoding="utf-8",
            )
            with mock.patch("singbox.manager.CONFIG_PATH", str(path)):
                with mock.patch.object(
                    network_check.netprobe, "have", return_value=True
                ):
                    network_check._check_singbox_config(result)
        self.assertTrue(result.singbox["moduleAvailable"])
        self.assertEqual(result.singbox["configPath"], str(path))


if __name__ == "__main__":
    unittest.main()
