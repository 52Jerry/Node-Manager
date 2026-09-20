"""B6/B7: netprobe 与 network_check 判定逻辑单元测试。

覆盖（全部为纯字符串/打桩断言，不依赖 Linux 内核）：
  - ss / netstat / iptables -vnL 输出解析
  - 防火墙放行判定（ufw active/inactive、INPUT policy）
  - DNAT/SNAT/FORWARD 判定与期望端口校验
  - 回程路径判定（rp_filter、策略路由、ip route get 接口归属）
  - 链路丢包/RTT 阈值、MTU 阈值
  - ping 输出解析、非 Linux 降级
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "node-manager"
sys.path.insert(0, str(APP_ROOT))

import netprobe
import network_check
from network_check import NetworkCheckResult


SS_SAMPLE = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   UNCONN 0      0          0.0.0.0:20170      0.0.0.0:*    users:(("sing-box",pid=1234,fd=8))
tcp   LISTEN 0      4096       0.0.0.0:20168      0.0.0.0:*    users:(("sing-box",pid=1234,fd=9))
tcp   LISTEN 0      128        127.0.0.1:8088    0.0.0.0:*
tcp   LISTEN 0      128        [::]:9090          [::]:*
"""

NETSTAT_SAMPLE = """Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:20168           0.0.0.0:*               LISTEN      1234/sing-box
udp        0      0 0.0.0.0:20170           0.0.0.0:*                           1234/sing-box
"""

IPTABLES_SAMPLE = """Chain PREROUTING (policy ACCEPT 120 packets, 7200 bytes)
    pkts      bytes target     prot opt in     out     source               destination
     120     7200 DNAT       tcp  --  ens18  *       0.0.0.0/0            0.0.0.0/0            tcp dpt:20168 to:10.0.0.2:20168
       0        0 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0
"""

FORWARD_SAMPLE = """Chain FORWARD (policy DROP 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination
      10      600 ACCEPT     tcp  --  ens18  ens19   0.0.0.0/0            10.0.0.2
"""


INPUT_SAMPLE = """Chain INPUT (policy DROP 4 packets, 240 bytes)
    pkts      bytes target     prot opt in     out     source               destination
      12      720 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:20168
       3      180 ACCEPT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:20170
       1       60 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
"""


class SsParseTest(unittest.TestCase):
    def test_parses_tcp_udp_with_process(self):
        parsed = netprobe._parse_ss(SS_SAMPLE)
        self.assertEqual(parsed[("tcp", 20168)], "sing-box")
        self.assertEqual(parsed[("udp", 20170)], "sing-box")

    def test_parses_line_without_process_column(self):
        parsed = netprobe._parse_ss(SS_SAMPLE)
        self.assertEqual(parsed[("tcp", 8088)], "")

    def test_parses_ipv6_listener(self):
        parsed = netprobe._parse_ss(SS_SAMPLE)
        self.assertIn(("tcp", 9090), parsed)

    def test_ignores_header_and_short_lines(self):
        parsed = netprobe._parse_ss("Netid State\n")
        self.assertEqual(parsed, {})


class NetstatParseTest(unittest.TestCase):
    def test_parses_tcp_and_udp(self):
        parsed = netprobe._parse_netstat(NETSTAT_SAMPLE)
        self.assertIn(("tcp", 20168), parsed)
        self.assertIn(("udp", 20170), parsed)

    def test_keeps_program_name(self):
        parsed = netprobe._parse_netstat(NETSTAT_SAMPLE)
        self.assertEqual(parsed[("tcp", 20168)], "1234/sing-box")


class IptablesParseTest(unittest.TestCase):
    def test_chain_policy(self):
        self.assertEqual(netprobe.chain_policy(IPTABLES_SAMPLE, "PREROUTING"), "ACCEPT")
        self.assertEqual(netprobe.chain_policy(FORWARD_SAMPLE, "FORWARD"), "DROP")

    def test_chain_policy_missing(self):
        self.assertIsNone(netprobe.chain_policy(IPTABLES_SAMPLE, "OUTPUT"))

    def test_parse_rule_lines_counters_and_columns(self):
        rules = netprobe.parse_rule_lines(IPTABLES_SAMPLE)
        self.assertEqual(len(rules), 2)
        dnat = rules[0]
        self.assertEqual(dnat["packets"], 120)
        self.assertEqual(dnat["bytes"], 7200)
        self.assertEqual(dnat["target"], "DNAT")
        self.assertEqual(dnat["proto"], "tcp")
        self.assertEqual(dnat["in"], "ens18")
        self.assertEqual(dnat["out"], "*")
        self.assertIn("dpt:20168", dnat["extra"])
        self.assertIn("to:10.0.0.2:20168", dnat["extra"])

    def test_parse_rule_lines_ignores_header(self):
        for rule in netprobe.parse_rule_lines(FORWARD_SAMPLE):
            self.assertIsInstance(rule["packets"], int)

    def test_input_accept_ports_parses_explicit_dpts(self):
        with mock.patch.object(
            netprobe, "iptables_chain",
            return_value=("DROP", netprobe.parse_rule_lines(INPUT_SAMPLE), ""),
        ):
            allowed = netprobe.input_accept_ports()
        self.assertEqual(allowed, {("tcp", 20168), ("udp", 20170), ("tcp", 22)})

    def test_input_accept_ports_from_chain(self):
        with mock.patch.object(
            netprobe, "iptables_chain",
            return_value=("ACCEPT", netprobe.parse_rule_lines(FORWARD_SAMPLE), ""),
        ):
            allowed = netprobe.input_accept_ports()
        # FORWARD 样例中没有 dpt 匹配，应当解析为空集合
        self.assertEqual(allowed, set())


class RunTest(unittest.TestCase):
    def test_missing_command_returns_127(self):
        code, output = netprobe.run(["definitely-not-a-real-binary-aib"])
        self.assertEqual(code, 127)
        self.assertIn("not available", output)

    def test_empty_command(self):
        self.assertEqual(netprobe.run([])[0], -1)

    def test_have_absent_binary(self):
        self.assertFalse(netprobe.have("definitely-not-a-real-binary-aib"))


class PingParseTest(unittest.TestCase):
    PING_OK = (
        "3 packets transmitted, 3 received, 0% packet loss, time 400ms\n"
        "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms"
    )

    def test_parses_loss_and_rtt(self):
        with mock.patch.object(netprobe, "run", return_value=(0, self.PING_OK)):
            entry = netprobe.ping("10.0.0.1")
        self.assertEqual(entry["lossPct"], 0.0)
        self.assertAlmostEqual(entry["avgRttMs"], 2.345)
        self.assertTrue(entry["reachable"])

    def test_full_loss_marks_unreachable(self):
        with mock.patch.object(
            netprobe, "run",
            return_value=(1, "3 packets transmitted, 0 received, 100% packet loss"),
        ):
            entry = netprobe.ping("10.0.0.9")
        self.assertEqual(entry["lossPct"], 100.0)
        self.assertFalse(entry["reachable"])

    def test_no_output_keeps_none(self):
        with mock.patch.object(netprobe, "run", return_value=(1, "")):
            entry = netprobe.ping("10.0.0.9")
        self.assertIsNone(entry["lossPct"])
        self.assertFalse(entry["reachable"])


class NonLinuxDegradationTest(unittest.TestCase):
    def test_mtu_probe_returns_list(self):
        self.assertIsInstance(netprobe.mtu_probe("10.0.0.1"), list)

    def test_listening_map_returns_dict(self):
        self.assertIsInstance(netprobe.listening_map(), dict)

    def test_sysctl_missing_binary_is_none(self):
        with mock.patch.object(netprobe, "have", return_value=False):
            self.assertIsNone(netprobe.sysctl("net.ipv4.ip_forward"))

    def test_run_network_check_does_not_raise(self):
        result = network_check.run_network_check(probe=False)
        self.assertIsInstance(result.to_dict()["healthy"], bool)


class SubnetTest(unittest.TestCase):
    def test_inside_and_outside(self):
        self.assertTrue(network_check._in_subnet("10.0.0.1", "10.0.0.0/24"))
        self.assertFalse(network_check._in_subnet("10.0.1.1", "10.0.0.0/24"))

    def test_invalid_input(self):
        self.assertFalse(network_check._in_subnet("not-an-ip", "10.0.0.0/24"))
        self.assertFalse(network_check._in_subnet("10.0.0.1", "not-a-cidr"))


class FirewallAllowsTest(unittest.TestCase):
    def test_ufw_inactive_allows(self):
        self.assertTrue(
            network_check._firewall_allows(20168, "tcp", {"ufw": "inactive"}, set(), set())
        )

    def test_ufw_active_requires_rule(self):
        firewall = {"ufw": "active"}
        self.assertFalse(network_check._firewall_allows(20168, "tcp", firewall, set(), set()))
        self.assertTrue(
            network_check._firewall_allows(20168, "tcp", firewall, {("tcp", 20168)}, set())
        )
        self.assertTrue(
            network_check._firewall_allows(20170, "udp", firewall, set(), {("udp", 20170)})
        )

    def test_no_firewall_allows(self):
        self.assertTrue(network_check._firewall_allows(20168, "tcp", {}, set(), set()))

    def test_accept_policy_allows(self):
        firewall = {"inputPolicy": "ACCEPT", "iptables": True}
        self.assertTrue(network_check._firewall_allows(20168, "tcp", firewall, set(), set()))

    def test_drop_policy_requires_explicit_accept(self):
        firewall = {"inputPolicy": "DROP", "iptables": True}
        self.assertFalse(network_check._firewall_allows(20168, "tcp", firewall, set(), set()))
        self.assertTrue(
            network_check._firewall_allows(20168, "tcp", firewall, set(), {("tcp", 20168)})
        )


def _dnat(port, chain="PREROUTING"):
    return {
        "packets": 120, "bytes": 7200, "target": "DNAT", "proto": "tcp",
        "in": "ens18", "out": "*", "source": "0.0.0.0/0",
        "destination": "0.0.0.0/0", "extra": f"tcp dpt:{port} to:10.0.0.2:{port}",
        "kind": "dnat", "chain": chain,
    }


def _snat():
    return {
        "packets": 118, "bytes": 7080, "target": "MASQUERADE", "proto": "all",
        "in": "*", "out": "ens18", "source": "10.0.0.0/24",
        "destination": "0.0.0.0/0", "extra": "", "kind": "masquerade",
        "chain": "POSTROUTING",
    }


class NatAndForwardTest(unittest.TestCase):
    def _apply(self, nat, forward, require_dnat=True, dnat_ports="20168"):
        patches = [
            mock.patch.object(network_check.netprobe, "nat_rules", return_value=nat),
            mock.patch.object(network_check.netprobe, "forward_rules", return_value=forward),
            mock.patch.object(network_check.config.network, "require_dnat", require_dnat),
            # config.network.dnat_ports 是逗号分隔字符串，由 dnat_port_list() 解析
            mock.patch.object(network_check.config.network, "dnat_ports", dnat_ports),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        result = NetworkCheckResult()
        network_check._check_nat_and_forward(result)
        return result

    def test_healthy_dnat_snat_forward(self):
        result = self._apply([_dnat(20168), _snat()], {"policy": "ACCEPT", "rules": []})
        self.assertEqual(result.issues, [])
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.singbox["dnatRuleCount"], 1)
        self.assertEqual(result.singbox["snatRuleCount"], 1)

    def test_missing_dnat_fails_when_required(self):
        result = self._apply([], {"policy": "ACCEPT", "rules": []})
        self.assertTrue(any("DNAT" in item for item in result.issues))
        self.assertFalse(result.healthy)

    def test_missing_dnat_tolerated_when_not_required(self):
        result = self._apply([_snat()], {"policy": "ACCEPT", "rules": []}, require_dnat=False)
        self.assertEqual(result.issues, [])

    def test_dnat_without_snat_warns(self):
        result = self._apply([_dnat(20168)], {"policy": "ACCEPT", "rules": []})
        self.assertTrue(any("SNAT" in item for item in result.warnings))
        self.assertEqual(result.issues, [])

    def test_dnat_with_forward_drop_fails(self):
        result = self._apply([_dnat(20168), _snat()], {"policy": "DROP", "rules": []})
        self.assertTrue(any("FORWARD" in item for item in result.issues))

    def test_dnat_with_forward_drop_and_accept_passes(self):
        accept = {"packets": 10, "bytes": 600, "target": "ACCEPT", "proto": "tcp",
                  "in": "ens18", "out": "ens19", "source": "0.0.0.0/0",
                  "destination": "10.0.0.2", "extra": ""}
        result = self._apply([_dnat(20168), _snat()], {"policy": "DROP", "rules": [accept]})
        self.assertEqual(result.issues, [])
        self.assertEqual(len(result.forward["acceptRules"]), 1)

    def test_expected_dnat_port_missing_fails(self):
        result = self._apply([_dnat(20168), _snat()], {"policy": "ACCEPT", "rules": []},
                             dnat_ports="20168,20169")
        self.assertTrue(any("20169" in item for item in result.issues))


class ReturnPathTest(unittest.TestCase):
    def _apply(self, route_get, interfaces=("ens19",), subnets=("10.0.0.0/24",),
               peers=("10.0.0.1",), probes=()):
        patches = [
            mock.patch.object(network_check.netprobe, "policy_rules", return_value=[]),
            mock.patch.object(network_check.netprobe, "rp_filter", return_value={"all": 0}),
            mock.patch.object(network_check.netprobe, "route_get", side_effect=route_get),
            mock.patch.object(network_check.config.network, "peer_list",
                              return_value=list(peers)),
            mock.patch.object(network_check.config.network, "probe_list",
                              return_value=list(probes)),
            mock.patch.object(network_check.config.network, "subnet_list",
                              return_value=list(subnets)),
            mock.patch.object(network_check.config.network, "interface_list",
                              return_value=list(interfaces)),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        result = NetworkCheckResult()
        network_check._check_return_path(result)
        return result

    def test_expected_interface_and_src_ok(self):
        def route_get(target):
            return {"target": target, "dev": "ens19", "src": "10.0.0.2", "via": None}

        self.assertEqual(self._apply(route_get).issues, [])

    def test_wrong_interface_fails(self):
        def route_get(target):
            return {"target": target, "dev": "ens18", "src": "128.108.220.12", "via": None}

        result = self._apply(route_get)
        self.assertTrue(any("回程路径异常" in item for item in result.issues))

    def test_missing_route_fails(self):
        def route_get(target):
            return {"target": target, "dev": None, "src": None, "via": None,
                    "error": "Network is unreachable"}

        result = self._apply(route_get)
        self.assertTrue(any("无法解析到" in item for item in result.issues))

    def test_missing_src_warns(self):
        def route_get(target):
            return {"target": target, "dev": "ens19", "src": None, "via": None}

        result = self._apply(route_get)
        self.assertEqual(result.issues, [])
        self.assertTrue(any("源地址" in item for item in result.warnings))

    def test_policy_route_with_strict_rpf_warns(self):
        def route_get(target):
            return {"target": target, "dev": "ens19", "src": "10.0.0.2", "via": None}

        with mock.patch.object(network_check.netprobe, "policy_rules",
                               return_value=["0: from all lookup local"] * 5), \
             mock.patch.object(network_check.netprobe, "rp_filter",
                               return_value={"all": 0, "ens19": 1}), \
             mock.patch.object(network_check.netprobe, "route_get", side_effect=route_get), \
             mock.patch.object(network_check.config.network, "peer_list",
                               return_value=["10.0.0.1"]), \
             mock.patch.object(network_check.config.network, "probe_list", return_value=[]), \
             mock.patch.object(network_check.config.network, "subnet_list",
                               return_value=["10.0.0.0/24"]), \
             mock.patch.object(network_check.config.network, "interface_list",
                               return_value=["ens19"]):
            result = NetworkCheckResult()
            network_check._check_return_path(result)
        self.assertTrue(any("rp_filter" in item for item in result.warnings))


class LinkAndMtuTest(unittest.TestCase):
    def test_peer_total_loss_fails(self):
        loss = {"target": "10.0.0.1", "sent": 4, "lossPct": 100.0,
                "avgRttMs": None, "reachable": False}
        with mock.patch.object(network_check.netprobe, "ping", return_value=dict(loss)), \
             mock.patch.object(network_check.config.network, "peer_list",
                               return_value=["10.0.0.1"]), \
             mock.patch.object(network_check.config.network, "probe_list", return_value=[]):
            result = NetworkCheckResult()
            network_check._check_links(result, probe=False)
        self.assertTrue(any("完全不可达" in item for item in result.issues))

    def test_probe_target_loss_only_warns(self):
        loss = {"target": "1.1.1.1", "sent": 4, "lossPct": 100.0,
                "avgRttMs": None, "reachable": False}
        with mock.patch.object(network_check.netprobe, "ping", return_value=dict(loss)), \
             mock.patch.object(network_check.config.network, "peer_list", return_value=[]), \
             mock.patch.object(network_check.config.network, "probe_list",
                               return_value=["1.1.1.1"]):
            result = NetworkCheckResult()
            network_check._check_links(result, probe=False)
        self.assertEqual(result.issues, [])
        self.assertTrue(any("完全不可达" in item for item in result.warnings))

    def test_high_loss_and_rtt_warn(self):
        entry = {"target": "10.0.0.1", "sent": 4, "lossPct": 25.0,
                 "avgRttMs": 999.0, "reachable": True}
        with mock.patch.object(network_check.netprobe, "ping", return_value=dict(entry)), \
             mock.patch.object(network_check.config.network, "peer_list",
                               return_value=["10.0.0.1"]), \
             mock.patch.object(network_check.config.network, "probe_list", return_value=[]):
            result = NetworkCheckResult()
            network_check._check_links(result, probe=False)
        self.assertEqual(result.issues, [])
        self.assertTrue(any("丢包" in item for item in result.warnings))
        self.assertTrue(any("RTT" in item for item in result.warnings))

    def test_mtu_below_minimum_fails(self):
        with mock.patch.object(network_check.netprobe, "links",
                               return_value=[{"interface": "ens19", "mtu": 1200,
                                              "state": "UP"}]):
            result = NetworkCheckResult()
            network_check._check_mtu(result)
        self.assertTrue(any("MTU" in item for item in result.issues))

    def test_mtu_below_expected_warns(self):
        with mock.patch.object(network_check.netprobe, "links",
                               return_value=[{"interface": "ens19", "mtu": 1400,
                                              "state": "UP"}]), \
             mock.patch.object(network_check.config.network, "expected_mtu", 1500):
            result = NetworkCheckResult()
            network_check._check_mtu(result)
        self.assertEqual(result.issues, [])
        self.assertTrue(any("MTU" in item for item in result.warnings))

    def test_mtu_takes_minimum_across_links(self):
        with mock.patch.object(network_check.netprobe, "links",
                               return_value=[{"interface": "ens18", "mtu": 1500,
                                              "state": "UP"},
                                             {"interface": "ens19", "mtu": 9000,
                                              "state": "UP"}]):
            result = NetworkCheckResult()
            network_check._check_mtu(result)
        self.assertEqual(result.mtu, 1500)


class PortsCheckTest(unittest.TestCase):
    def _apply(self, listening, reachable=True, firewall=None):
        patches = [
            mock.patch.object(network_check, "_expected_ports",
                              return_value=([("vless", 20168, "tcp")], "defaults")),
            mock.patch.object(network_check.netprobe, "firewall_backend",
                              return_value=firewall or {"ufw": "inactive",
                                                        "nft": False, "iptables": False}),
            mock.patch.object(network_check.netprobe, "ufw_allowed_ports", return_value=set()),
            mock.patch.object(network_check.netprobe, "input_accept_ports", return_value=set()),
            mock.patch.object(network_check.netprobe, "is_listening",
                              side_effect=lambda port, proto: listening),
            mock.patch.object(network_check.netprobe, "listener_process",
                              return_value="sing-box"),
            mock.patch.object(network_check.netprobe, "tcp_reachable",
                              return_value=reachable),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        result = NetworkCheckResult()
        network_check._check_ports(result)
        return result

    def test_listening_port_is_healthy(self):
        result = self._apply(True)
        self.assertEqual(result.issues, [])
        self.assertEqual(result.ports[0].name, "vless")
        self.assertTrue(result.ports[0].firewall_allowed)

    def test_not_listening_fails(self):
        result = self._apply(False)
        self.assertTrue(any("未监听" in item for item in result.issues))

    def test_listening_but_handshake_fails(self):
        result = self._apply(True, reachable=False)
        self.assertTrue(any("握手失败" in item for item in result.issues))

    def test_firewall_blocks_port(self):
        result = self._apply(True, firewall={"ufw": "active", "nft": False,
                                             "iptables": True})
        self.assertTrue(any("未被防火墙放行" in item for item in result.issues))
        self.assertEqual(result.firewall_status, "active")


class TextFormatTest(unittest.TestCase):
    def test_format_text_contains_summary(self):
        result = NetworkCheckResult()
        result.generated_at = "2026-09-17T00:00:00+00:00"
        text = network_check._format_text(result.to_dict())
        self.assertIn("节点网络检查", text)
        self.assertIn("IPv4 转发", text)
        self.assertIn("DNAT 规则", text)


if __name__ == "__main__":
    unittest.main()
