import yaml
import os
import socket
import requests
from typing import Optional

CONFIG_PATH = os.path.join("/etc", "node-manager", "config.yaml")
LOCAL_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

def get_config_path() -> str:
    if os.path.exists(CONFIG_PATH):
        return CONFIG_PATH
    return LOCAL_CONFIG_PATH

def get_public_ip() -> str:
    try:
        response = requests.get("https://ipv4.icanhazip.com", timeout=5)
        return response.text.strip()
    except:
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            return response.text.strip()
        except:
            return get_local_ip()

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_hostname() -> str:
    try:
        return socket.gethostname()
    except:
        return "node-unknown"

class NodeConfig:
    id: str = get_hostname()
    name: str = "Default Node"
    host: str = get_public_ip()

class ServerConfig:
    port: int = 8088

class SecurityConfig:
    token: str = ""

class SingboxConfig:
    config: str = "/etc/sing-box/config.json"
    api_port: int = 9090
    api_secret: str = ""

class Config:
    node: NodeConfig = NodeConfig()
    server: ServerConfig = ServerConfig()
    security: SecurityConfig = SecurityConfig()
    singbox: SingboxConfig = SingboxConfig()

config = Config()

def load_config():
    config_path = get_config_path()
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        if data.get("node"):
            config.node.id = data["node"].get("id", get_hostname())
            config.node.name = data["node"].get("name", "Default Node")
            host_value = data["node"].get("host", "")
            if host_value.lower() == "auto" or not host_value:
                config.node.host = get_public_ip()
            else:
                config.node.host = host_value
        
        if data.get("server"):
            config.server.port = data["server"].get("port", 8088)
        
        if data.get("security"):
            config.security.token = data["security"].get("token", "")
        
        if data.get("singbox"):
            config.singbox.config = data["singbox"].get("config", "/etc/sing-box/config.json")
            config.singbox.api_port = data["singbox"].get("api_port", 9090)
            config.singbox.api_secret = data["singbox"].get("api_secret", "")
    else:
        auto_generate_config()

def auto_generate_config():
    config_path = get_config_path()
    config_dir = os.path.dirname(config_path)
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    
    config_data = {
        "node": {
            "id": config.node.id,
            "name": config.node.name,
            "host": config.node.host
        },
        "server": {
            "port": config.server.port
        },
        "security": {
            "token": os.urandom(32).hex()
        },
        "singbox": {
            "config": config.singbox.config,
            "api_port": config.singbox.api_port,
            "api_secret": ""
        }
    }
    
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)
    
    config.security.token = config_data["security"]["token"]
    config.singbox.api_secret = config_data["singbox"]["api_secret"]

load_config()