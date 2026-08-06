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


@dataclass
class SingboxConfig:
    config: str = "/etc/sing-box/config.json"
    api_port: int = 9090
    api_secret: str = ""
    vless_tag: str = "vless-reality"
    vmess_tag: str = "vmess"
    socks_tag: str = "socks"


@dataclass
class MonitoringConfig:
    traffic_sample_interval_seconds: float = 2.0


@dataclass
class Config:
    node: NodeConfig = field(default_factory=NodeConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    singbox: SingboxConfig = field(default_factory=SingboxConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)


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

    singbox = data.get("singbox", {})
    for name in ("config", "api_secret", "vless_tag", "vmess_tag", "socks_tag"):
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
    return result


config = load_config()
