import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

import requests
import yaml


SYSTEM_CONFIG_PATH = Path("/etc/node-manager/config.yaml")
LOCAL_CONFIG_PATH = Path(__file__).with_name("config.yaml")


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
    id: str = field(default_factory=socket.gethostname)
    name: str = "Default Node"
    host: str = field(default_factory=get_public_ip)


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
class Config:
    node: NodeConfig = field(default_factory=NodeConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    singbox: SingboxConfig = field(default_factory=SingboxConfig)


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

    server = data.get("server", {})
    result.server.port = int(server.get("port", result.server.port))

    security = data.get("security", {})
    result.security.token = str(security.get("token", result.security.token))

    singbox = data.get("singbox", {})
    for name in ("config", "api_secret", "vless_tag", "vmess_tag", "socks_tag"):
        if name in singbox:
            setattr(result.singbox, name, str(singbox[name]))
    result.singbox.api_port = int(singbox.get("api_port", result.singbox.api_port))
    return result


config = load_config()
