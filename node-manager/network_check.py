"""B6: 节点网络与链路前置检查（权威实现）。

检查项：
  1. 监听端口（优先取 sing-box 实际配置，读取失败时回退默认端口表）
  2. 防火墙放行（ufw / iptables INPUT 链 / INPUT 默认策略）
  3. UDP 监听与 TCP 本地可达性
  4. IPv4 / IPv6 转发（DNAT 与 FORWARD 依赖）
  5. 接口 MTU 与 DF 路径 MTU 探测（定位分片）
  6. DNAT / SNAT / MASQUERADE 规则与包计数器
  7. FORWARD 链策略与放行（DNAT 存在但 FORWARD DROP 会直接断流）
  8. 回程路径：rp_filter、策略路由、ip route get、专线对端 ping
  9. conntrack 使用率

所有外部命令都带超时；非 Linux 环境降级为“不可用”，不抛异常。
可直接作为节点自检脚本运行：``python3 network_check.py --json``。
"""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import netprobe
from config import config

logger = logging.getLogger(__name__)

# 默认端口表：仅在无法读取 sing-box 实际配置时使用。
REQUIRED_PORTS = [
    ("vless", 20168, "tcp"),
    ("vmess", 20169, "tcp"),
    ("trojan", 20170, "tcp"),
    ("socks", 5001, "tcp"),
    ("manager", 8088, "tcp"),
    ("clash_api", 9090, "tcp"),
]

MIN_MTU = 1280


@dataclass
class PortCheck:
    name: str
    port: int
    protocol: str
    listening: bool = False
    reachable: bool = False
    firewall_allowed: bool = False
    listener: str = ""
    error: str | None = None
    # "listen": 期望本机监听的端口；"dnat": 入口节点的公网端口，由 nat PREROUTING
    # 转发到对端，本机不监听，只校验 DNAT 规则是否存在（避免纯转发节点被误判）。
    kind: str = "listen"
    dnat_present: bool = False


@dataclass
class NetworkCheckResult:
    healthy: bool = True
    ports: list[PortCheck] = field(default_factory=list)
    ip_forward: bool = False
    mtu: int | None = None
    firewall_status: str = "unknown"
    issues: list[str] = field(default_factory=list)
    # --- 以下为 B6 扩展项 ---
    warnings: list[str] = field(default_factory=list)
    ip_forward_v6: bool | None = None
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    addresses: list[dict[str, str]] = field(default_factory=list)
    routes: dict[str, list[str]] = field(default_factory=dict)
    policy_rules: list[str] = field(default_factory=list)
    return_path: dict[str, Any] = field(default_factory=dict)
    nat_rules: list[dict[str, Any]] = field(default_factory=list)
    forward: dict[str, Any] = field(default_factory=dict)
    firewall: dict[str, Any] = field(default_factory=dict)
    link_targets: list[dict[str, Any]] = field(default_factory=list)
    mtu_probes: list[dict[str, Any]] = field(default_factory=list)
    conntrack: dict[str, Any] = field(default_factory=dict)
    singbox: dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""

    def fail(self, message: str) -> None:
        self.healthy = False
        self.issues.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            # 兼容字段（Control Plane 已在使用）
            "healthy": self.healthy,
            "ports": [asdict(port) for port in self.ports],
            "ipForward": self.ip_forward,
            "mtu": self.mtu,
            "firewallStatus": self.firewall_status,
            "issues": self.issues,
            # B6 扩展字段
            "warnings": self.warnings,
            "ipForwardV6": self.ip_forward_v6,
            "interfaces": self.interfaces,
            "addresses": self.addresses,
            "routes": self.routes,
            "policyRules": self.policy_rules,
            "returnPath": self.return_path,
            "natRules": self.nat_rules,
            "forward": self.forward,
            "firewall": self.firewall,
            "linkTargets": self.link_targets,
            "mtuProbes": self.mtu_probes,
            "conntrack": self.conntrack,
            "singbox": self.singbox,
            "generatedAt": self.generated_at,
        }


# --------------------------------------------------------------------------
# 期望端口
# --------------------------------------------------------------------------


def _inbound_ports(data: dict[str, Any]) -> list[tuple[str, int, str]]:
    ports: list[tuple[str, int, str]] = []
    for inbound in data.get("inbounds", []) or []:
        if not isinstance(inbound, dict):
            continue
        port = inbound.get("listen_port")
        if not isinstance(port, int):
            continue
        tag = str(inbound.get("tag") or inbound.get("type") or "inbound")
        network = str(inbound.get("network") or "tcp").lower()
        ports.append((tag, port, "tcp"))
        if "udp" in network:
            ports.append((tag, port, "udp"))
    return ports


def _expected_ports() -> tuple[list[tuple[str, int, str]], str]:
    """期望监听端口：sing-box 配置 > network.expected_listen_ports > 默认端口表。"""
    try:
        from singbox.manager import CONFIG_PATH

        data = json.loads(Path(CONFIG_PATH).read_text(encoding="utf-8"))
        ports = _inbound_ports(data)
        if ports:
            return ports, str(CONFIG_PATH)
    except Exception as exc:  # noqa: BLE001 - 读取失败必须降级而不是中断检查
        logger.debug("could not read sing-box config for port list: %s", exc)
    # 纯转发（入口）节点没有 sing-box 监听：显式配置 expected_listen_ports 时以它为准，
    # 留空表示"本机不期望监听任何端口"，避免把入口节点误判为端口缺失。
    if config.network.expected_listen_ports is not None:
        return (
            config.network.expected_listen_port_list(),
            "network.expected_listen_ports",
        )
    return list(REQUIRED_PORTS), "defaults"


# --------------------------------------------------------------------------
# 单项检查
# --------------------------------------------------------------------------


def _dnat_rule_ports(rules: list[dict[str, Any]]) -> set[int]:
    """提取 nat 表中已配置 DNAT 的目标端口（iptables 输出的 `dpt:<port>`）。"""
    ports: set[int] = set()
    for rule in rules:
        if rule.get("kind") != "dnat":
            continue
        for token in str(rule.get("extra") or "").replace(",", " ").split():
            if token.startswith("dpt:"):
                value = token[4:].strip()
                if value.isdigit():
                    ports.add(int(value))
    return ports


def _check_ports(result: NetworkCheckResult) -> None:
    ports, source = _expected_ports()
    result.singbox["expectedPortsSource"] = source

    firewall = netprobe.firewall_backend()
    ufw_ports = netprobe.ufw_allowed_ports() if firewall.get("ufw") == "active" else set()
    iptables_ports = netprobe.input_accept_ports()
    result.firewall = {
        **firewall,
        "ufwAllowedPorts": sorted(f"{proto}/{port}" for proto, port in ufw_ports),
        "iptablesAcceptPorts": sorted(f"{proto}/{port}" for proto, port in iptables_ports),
    }
    result.firewall_status = str(firewall.get("ufw") or "unknown")

    for name, port, protocol in ports:
        check = PortCheck(name=name, port=port, protocol=protocol)
        try:
            check.listening = netprobe.is_listening(port, protocol)
            check.listener = netprobe.listener_process(port, protocol)
            if protocol == "tcp":
                check.reachable = (
                    netprobe.tcp_reachable(port) if check.listening else False
                )
            else:
                check.reachable = check.listening
            check.firewall_allowed = _firewall_allows(
                port, protocol, firewall, ufw_ports, iptables_ports
            )
        except Exception as exc:  # noqa: BLE001 - 单端口异常不影响整体检查
            check.error = str(exc)
        if not check.listening:
            result.fail(f"{name} 端口 {port}/{protocol} 未监听")
        elif protocol == "tcp" and not check.reachable:
            result.fail(f"{name} 端口 {port}/tcp 监听但本地握手失败")
        if not check.firewall_allowed:
            result.fail(f"{name} 端口 {port}/{protocol} 未被防火墙放行")
        result.ports.append(check)

    # 入口节点的公网端口由 nat PREROUTING DNAT 到对端，本机不会监听，
    # 因此只登记端口信息（kind="dnat"），规则是否缺失交给
    # _check_nat_and_forward() 判定，避免纯转发节点被误判为不健康。
    for port in config.network.dnat_port_list():
        if any(item.port == port and item.protocol == "tcp" for item in result.ports):
            continue
        check = PortCheck(name=f"dnat-{port}", port=port, protocol="tcp", kind="dnat")
        try:
            check.listening = netprobe.is_listening(port, "tcp")
            check.listener = netprobe.listener_process(port, "tcp")
            check.reachable = netprobe.tcp_reachable(port) if check.listening else False
            check.firewall_allowed = _firewall_allows(
                port, "tcp", firewall, ufw_ports, iptables_ports
            )
        except Exception as exc:  # noqa: BLE001 - 单端口异常不影响整体检查
            check.error = str(exc)
        result.ports.append(check)


def _firewall_allows(
    port: int,
    protocol: str,
    firewall: dict[str, Any],
    ufw_ports: set[tuple[str, int]],
    iptables_ports: set[tuple[str, int]],
) -> bool:
    if firewall.get("ufw") == "inactive":
        return True
    if firewall.get("ufw") == "active":
        return (protocol, port) in ufw_ports or (protocol, port) in iptables_ports
    policy = firewall.get("inputPolicy")
    if policy in (None, "ACCEPT"):
        return True
    return (protocol, port) in iptables_ports


def _check_forwarding(result: NetworkCheckResult) -> None:
    result.ip_forward = netprobe.ip_forward("ipv4")
    if not result.ip_forward:
        result.fail("IP 转发未启用（DNAT/负载均衡需要 net.ipv4.ip_forward=1）")
    result.ip_forward_v6 = netprobe.ip_forward("ipv6")
    if result.ip_forward_v6 is False:
        result.warn("IPv6 转发未启用（仅影响 IPv6 入口）")


def _check_mtu(result: NetworkCheckResult) -> None:
    links = netprobe.links()
    result.interfaces = links
    mtus = [entry["mtu"] for entry in links if isinstance(entry.get("mtu"), int)]
    result.mtu = min(mtus) if mtus else None
    if result.mtu is not None:
        if result.mtu < MIN_MTU:
            result.fail(f"MTU {result.mtu} 过小（建议 >=1280，推荐 1500）")
        elif result.mtu < config.network.expected_mtu:
            result.warn(
                f"MTU {result.mtu} 低于期望值 {config.network.expected_mtu}，大包会分片"
            )


def _check_nat_and_forward(result: NetworkCheckResult) -> None:
    nat = netprobe.nat_rules()
    result.nat_rules = nat
    dnat = [rule for rule in nat if rule.get("kind") == "dnat"]
    snat = [rule for rule in nat if rule.get("kind") in ("snat", "masquerade")]

    forward = netprobe.forward_rules()
    result.forward = {
        "policy": forward.get("policy"),
        "rules": forward.get("rules", []),
        "acceptRules": [
            rule for rule in forward.get("rules", [])
            if str(rule.get("target", "")).upper() == "ACCEPT"
        ],
    }
    result.singbox["dnatRuleCount"] = len(dnat)
    result.singbox["snatRuleCount"] = len(snat)

    if config.network.require_dnat and not dnat:
        result.fail("要求存在 DNAT 规则但 nat 表中未发现 DNAT")
    if dnat and not snat:
        result.warn("存在 DNAT 但未发现 SNAT/MASQUERADE，回程可能被丢弃")
    if dnat and forward.get("policy") == "DROP" and not result.forward["acceptRules"]:
        result.fail("FORWARD 默认 DROP 且无 ACCEPT 规则，DNAT 转发会被阻断")

    expected = set(config.network.dnat_port_list())
    configured = _dnat_rule_ports(nat)
    for entry in result.ports:
        if entry.kind == "dnat":
            entry.dnat_present = entry.port in configured
    # 仅在「本节点要求 DNAT」或「确实已配置 DNAT」时校验期望端口，
    # 避免纯转发/纯出口节点被误判为不健康。
    if expected and (config.network.require_dnat or dnat):
        missing = sorted(port for port in expected if port not in configured)
        if missing:
            result.fail(f"期望的 DNAT 端口未配置: {missing}")


def _check_return_path(result: NetworkCheckResult) -> None:
    rules = netprobe.policy_rules()
    result.policy_rules = rules
    rp = netprobe.rp_filter()
    targets = config.network.peer_list() + config.network.probe_list()
    subnets = config.network.subnet_list()
    expected_ifaces = config.network.interface_list()
    probes = [netprobe.route_get(target) for target in targets]
    result.return_path = {"rpFilter": rp, "probes": probes}

    strict = [name for name, value in rp.items() if value == 1]
    if len(rules) > 3 and strict:
        result.warn(
            f"存在策略路由且 rp_filter=1 的接口 {strict}，严格反向路径过滤可能丢包"
        )
    for probe in probes:
        target = str(probe.get("target"))
        dev = probe.get("dev")
        src = probe.get("src")
        if not dev:
            result.fail(f"无法解析到 {target} 的路由：{probe.get('error', 'no route')}")
            continue
        if any(_in_subnet(target, subnet) for subnet in subnets) and expected_ifaces:
            if dev not in expected_ifaces:
                result.fail(
                    f"专线对端 {target} 走 {dev}，期望走 {expected_ifaces}（回程路径异常）"
                )
        if not src:
            result.warn(f"到 {target} 的路由未指定源地址，可能产生非对称回程")


def _in_subnet(address: str, cidr: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _check_links(result: NetworkCheckResult, probe: bool = True) -> None:
    targets = config.network.peer_list() + config.network.probe_list()
    limit = config.network.max_rtt_ms
    warn_loss = config.network.packet_loss_warn_pct
    for target in targets:
        entry = netprobe.ping(target)
        result.link_targets.append(entry)
        loss = entry.get("lossPct")
        if loss is None:
            result.warn(f"无法 ping 通 {target}（可能被 ICMP 策略拦截）")
            continue
        if loss >= 100:
            if target in config.network.peer_list():
                result.fail(f"专线对端 {target} 完全不可达")
            else:
                result.warn(f"探测目标 {target} 完全不可达")
        elif loss > warn_loss:
            result.warn(f"{target} 丢包 {loss}%（阈值 {warn_loss}%）")
        avg = entry.get("avgRttMs")
        if avg is not None and avg > limit:
            result.warn(f"{target} 平均 RTT {avg}ms 高于阈值 {limit}ms")
    if not probe:
        return
    for target in config.network.peer_list():
        for probe_entry in netprobe.mtu_probe(target):
            result.mtu_probes.append(probe_entry)
        sizes = [item for item in result.mtu_probes if item.get("target") == target]
        if sizes:
            passing = [item["mtu"] for item in sizes if item.get("ok")]
            failing = [item["mtu"] for item in sizes if not item.get("ok")]
            if passing and failing and max(passing) < min(failing):
                result.warn(
                    f"到 {target} 的路径 MTU 约为 {max(passing)}（低于常规 1500，需确认分片策略）"
                )


def _check_conntrack(result: NetworkCheckResult) -> None:
    data = netprobe.conntrack()
    result.conntrack = data
    count, maximum = data.get("count"), data.get("max")
    if count and maximum:
        ratio = count / maximum
        if ratio >= config.network.conntrack_warn_ratio:
            result.warn(
                f"conntrack 使用率 {ratio:.0%}（{count}/{maximum}）接近上限"
            )


def _check_singbox_config(result: NetworkCheckResult) -> None:
    try:
        from singbox.manager import CONFIG_PATH, check_config
    except ImportError as exc:
        # 纯转发（入口）节点不部署 sing-box，node-manager 也可能未随包提供该模块；
        # 这属于预期形态，只如实记录，不作为告警。
        result.singbox.update(
            {
                "configPath": None,
                "installed": netprobe.have("sing-box"),
                "moduleAvailable": False,
                "reason": f"sing-box 模块不可用: {exc}",
            }
        )
        return

    path = Path(CONFIG_PATH)
    result.singbox.update(
        {
            "configPath": str(path),
            "installed": netprobe.have("sing-box"),
            "moduleAvailable": True,
        }
    )
    if not path.exists():
        result.singbox["configPresent"] = False
        result.warn(f"未找到 sing-box 配置 {path}")
        return
    result.singbox["configPresent"] = True
    valid, error = check_config(path)
    result.singbox["configValid"] = valid
    if not valid:
        result.fail(f"sing-box 配置校验失败: {error}")


def run_network_check(probe: bool = True) -> NetworkCheckResult:
    """B6: 执行完整网络前置检查（只读，任何单项失败都不影响其他项）。"""
    result = NetworkCheckResult()
    result.generated_at = datetime.now(timezone.utc).isoformat()
    steps = (
        ("ports", lambda: _check_ports(result)),
        ("singbox", lambda: _check_singbox_config(result)),
        ("forwarding", lambda: _check_forwarding(result)),
        ("mtu", lambda: _check_mtu(result)),
        ("nat", lambda: _check_nat_and_forward(result)),
        ("returnPath", lambda: _check_return_path(result)),
        ("links", lambda: _check_links(result, probe)),
        ("conntrack", lambda: _check_conntrack(result)),
    )
    for name, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - 单项异常不应中断整体体检
            logger.warning("network check step %s failed: %s", name, exc)
            result.warn(f"检查项 {name} 执行异常: {exc}")
    result.addresses = netprobe.addresses()
    result.routes = {"ipv4": netprobe.routes(4), "ipv6": netprobe.routes(6)}
    return result


def _format_text(data: dict[str, Any]) -> str:
    lines = [
        f"节点网络检查: {'通过' if data['healthy'] else '存在问题'}",
        f"生成时间: {data['generatedAt']}",
        f"IPv4 转发: {data['ipForward']}    接口最小 MTU: {data['mtu']}",
        f"防火墙: {data['firewallStatus']}",
        "",
        "端口:",
    ]
    for port in data["ports"]:
        flag = "OK " if port["listening"] and port["firewall_allowed"] else "NG "
        lines.append(
            f"  {flag}{port['name']:<12} {port['port']}/{port['protocol']} "
            f"listen={port['listening']} reachable={port['reachable']} "
            f"firewall={port['firewall_allowed']} {port['listener']}"
        )
    lines.append("")
    lines.append(f"DNAT 规则: {data['singbox'].get('dnatRuleCount', 0)}    "
                 f"SNAT/MASQUERADE 规则: {data['singbox'].get('snatRuleCount', 0)}")
    lines.append(f"FORWARD 策略: {data['forward'].get('policy')}")
    for entry in data["linkTargets"]:
        lines.append(
            f"链路 {entry['target']}: 丢包={entry['lossPct']}% 平均RTT={entry['avgRttMs']}ms"
        )
    if data["issues"]:
        lines.append("")
        lines.append("阻断项:")
        lines.extend(f"  - {item}" for item in data["issues"])
    if data["warnings"]:
        lines.append("")
        lines.append("告警项:")
        lines.extend(f"  - {item}" for item in data["warnings"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Node Manager 节点网络前置检查")
    parser.add_argument("--json", action="store_true", help="输出 JSON（供控制面解析）")
    parser.add_argument("--no-probe", action="store_true", help="跳过 ping/MTU 探测")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    result = run_network_check(probe=not args.no_probe)
    data = result.to_dict()
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(_format_text(data))
    return 0 if result.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
