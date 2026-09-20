from __future__ import annotations

import os
import socket
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import requests
import yaml


SYSTEM_CONFIG_PATH = Path("/etc/node-manager/config.yaml")
LOCAL_CONFIG_PATH = Path(__file__).with_name("config.yaml")
MACHINE_ID_PATH = Path("/etc/machine-id")


def default_node_id() -> str:
    """Return a stable node id that remains unique across same-named VPS hosts."""
    hostname = socket.gethostname().strip() or "node"
    machine_id = ""
    try:
        machine_id = MACHINE_ID_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    if machine_id:
        suffix = hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:12]
        return f"{hostname}-{suffix}"
    return hostname


def get_public_ip() -> str:
    for url in ("https://ipv4.icanhazip.com", "https://api.ipify.org"):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.text.strip()
        except requests.RequestException:
            continue

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


@dataclass
class NodeConfig:
    id: str = field(default_factory=default_node_id)
    name: str = "Default Node"
    host: str = field(default_factory=get_public_ip)
    # Optional public domain for generated acceleration links.  An empty value
    # deliberately falls back to this node's configured host, so a fresh
    # installation never emits a stale domain belonging to another deployment.
    acceleration_domain: str = ""


@dataclass
class ServerConfig:
    port: int = 8088


@dataclass
class SecurityConfig:
    token: str = ""
    # B1: 可选 Control Plane IP 白名单（逗号分隔 CIDR），留空则仅校验 Token。
    allowed_cidrs: str = ""
    # B2: revision 签名密钥，留空则复用 token。用于 desired revision 推送校验。
    revision_secret: str = ""


@dataclass
class SingboxConfig:
    config: str = "/etc/sing-box/config.json"
    api_port: int = 9090
    api_secret: str = ""
    vless_tag: str = "vless-reality"
    vmess_tag: str = "vmess"
    socks_tag: str = "socks"
    trojan_tag: str = "trojan"


@dataclass
class MonitoringConfig:
    traffic_sample_interval_seconds: float = 2.0
    device_active_window_seconds: float = 60.0
    # 健康检查：0=禁用，默认 1200 秒（20 分钟）
    health_check_interval_seconds: int = 1200
    # 连续失败多少次后标记为死亡
    health_check_fail_threshold: int = 3
    # TCP 连接测试超时（秒）
    health_check_tcp_timeout_seconds: float = 5.0
    # 每批并发检查数量
    health_check_batch_size: int = 100


@dataclass
class NetworkConfig:
    """B6: 节点网络前置检查参数（专线拓扑相关，按节点配置）。"""

    # 专线对端内网地址（逗号分隔）。深圳可填 10.0.0.1，香港可填 10.0.0.2。
    peer_targets: str = ""
    # 额外探测目标（公网出口/回程验证），逗号分隔。
    probe_targets: str = ""
    # 链路 Interface 期望值（逗号分隔，如 ens19）；留空则不做接口归属校验。
    link_interfaces: str = ""
    # 期望 MTU；低于该值只告警不判定失败（>=1280 才算通过）。
    expected_mtu: int = 1500
    # 专线内网前缀（逗号分隔 CIDR），用于判断对端是否真的走专线接口。
    internal_subnets: str = ""
    # 是否要求存在 DNAT 规则（入口节点开启，出口节点关闭）。
    require_dnat: bool = False
    # 期望存在 DNAT/放行的端口（逗号分隔）。
    dnat_ports: str = ""
    # 本机期望监听的端口（逗号分隔，形如 manager:8088、20168 或 5001/udp）。
    # 仅在 sing-box 配置不可读时作为期望值；显式留空表示纯转发节点无本机监听。
    # 保持默认 None 时回退到内置默认端口表（向后兼容）。
    expected_listen_ports: str | None = None
    # 链路质量阈值：丢包告警百分比与平均 RTT 告警毫秒。
    packet_loss_warn_pct: float = 1.0
    max_rtt_ms: float = 200.0
    # conntrack 使用率告警阈值（0-1）。
    conntrack_warn_ratio: float = 0.8

    def peer_list(self) -> list[str]:
        return [item.strip() for item in self.peer_targets.split(",") if item.strip()]

    def probe_list(self) -> list[str]:
        return [item.strip() for item in self.probe_targets.split(",") if item.strip()]

    def interface_list(self) -> list[str]:
        return [item.strip() for item in self.link_interfaces.split(",") if item.strip()]

    def subnet_list(self) -> list[str]:
        return [item.strip() for item in self.internal_subnets.split(",") if item.strip()]

    def dnat_port_list(self) -> list[int]:
        result: list[int] = []
        for item in self.dnat_ports.split(","):
            item = item.strip()
            if item.isdigit():
                result.append(int(item))
        return result

    def expected_listen_port_list(self) -> list[tuple[str, int, str]]:
        """解析 network.expected_listen_ports 为 (name, port, protocol) 列表。

        支持 `manager:8088`、`20168`、`5001/udp`、`socks:5001/udp` 四种写法；
        未配置（None）时返回空列表，由调用方决定回退策略。
        """
        if self.expected_listen_ports is None:
            return []
        parsed: list[tuple[str, int, str]] = []
        for item in self.expected_listen_ports.split(","):
            item = item.strip()
            if not item:
                continue
            protocol = "tcp"
            if "/" in item:
                item, _, raw_protocol = item.partition("/")
                item = item.strip()
                protocol = raw_protocol.strip().lower() or "tcp"
            name = "local"
            port_text = item
            if ":" in item:
                name, _, raw_port = item.partition(":")
                name = name.strip() or "local"
                port_text = raw_port.strip()
            if not port_text.isdigit():
                continue
            parsed.append((name, int(port_text), protocol))
        return parsed

@dataclass
class Config:
    node: NodeConfig = field(default_factory=NodeConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    singbox: SingboxConfig = field(default_factory=SingboxConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)


def load_config() -> Config:
    result = Config()
    env_path = os.environ.get("NODE_MANAGER_CONFIG")
    config_path = Path(env_path) if env_path else (
        SYSTEM_CONFIG_PATH if SYSTEM_CONFIG_PATH.exists() else LOCAL_CONFIG_PATH
    )

    if not config_path.exists():
        result.security.token = os.urandom(32).hex()
        return result

    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    node = data.get("node", {})
    result.node.id = node.get("id", result.node.id)
    result.node.name = node.get("name", result.node.name)
    host = node.get("host", result.node.host)
    result.node.host = get_public_ip() if not host or str(host).lower() == "auto" else str(host)
    result.node.acceleration_domain = str(
        node.get("acceleration_domain", result.node.acceleration_domain)
    )

    server = data.get("server", {})
    result.server.port = int(server.get("port", result.server.port))

    security = data.get("security", {})
    result.security.token = str(security.get("token", result.security.token))
    result.security.allowed_cidrs = str(
        security.get("allowed_cidrs", result.security.allowed_cidrs)
    )
    result.security.revision_secret = str(
        security.get("revision_secret", result.security.revision_secret)
    )

    singbox = data.get("singbox", {})
    for name in ("config", "api_secret", "vless_tag", "vmess_tag", "socks_tag", "trojan_tag"):
        if name in singbox:
            setattr(result.singbox, name, str(singbox[name]))
    result.singbox.api_port = int(singbox.get("api_port", result.singbox.api_port))

    monitoring = data.get("monitoring", {})
    interval = float(monitoring.get(
        "traffic_sample_interval_seconds",
        result.monitoring.traffic_sample_interval_seconds,
    ))
    if interval < 0.5 or interval > 300:
        raise ValueError("monitoring.traffic_sample_interval_seconds must be between 0.5 and 300")
    result.monitoring.traffic_sample_interval_seconds = interval
    device_window = float(monitoring.get(
        "device_active_window_seconds",
        result.monitoring.device_active_window_seconds,
    ))
    if device_window < 1 or device_window > 3600:
        raise ValueError(
            "monitoring.device_active_window_seconds must be between 1 and 3600"
        )
    result.monitoring.device_active_window_seconds = device_window
    network = data.get("network", {}) or {}
    result.network.peer_targets = str(network.get("peer_targets", result.network.peer_targets))
    result.network.probe_targets = str(network.get("probe_targets", result.network.probe_targets))
    result.network.link_interfaces = str(
        network.get("link_interfaces", result.network.link_interfaces)
    )
    result.network.internal_subnets = str(
        network.get("internal_subnets", result.network.internal_subnets)
    )
    result.network.dnat_ports = str(network.get("dnat_ports", result.network.dnat_ports))
    if "expected_listen_ports" in network:
        result.network.expected_listen_ports = str(network["expected_listen_ports"])
    result.network.require_dnat = bool(network.get("require_dnat", result.network.require_dnat))
    result.network.expected_mtu = int(network.get("expected_mtu", result.network.expected_mtu))
    result.network.packet_loss_warn_pct = float(
        network.get("packet_loss_warn_pct", result.network.packet_loss_warn_pct)
    )
    result.network.max_rtt_ms = float(network.get("max_rtt_ms", result.network.max_rtt_ms))
    result.network.conntrack_warn_ratio = float(
        network.get("conntrack_warn_ratio", result.network.conntrack_warn_ratio)
    )
    result.monitoring.health_check_interval_seconds = int(
        monitoring.get("health_check_interval_seconds", 1200)
    )
    result.monitoring.health_check_fail_threshold = int(
        monitoring.get("health_check_fail_threshold", 3)
    )
    result.monitoring.health_check_tcp_timeout_seconds = float(
        monitoring.get("health_check_tcp_timeout_seconds", 5.0)
    )
    result.monitoring.health_check_batch_size = int(
        monitoring.get("health_check_batch_size", 100)
    )
    return result


config = load_config()
