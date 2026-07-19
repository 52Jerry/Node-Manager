import json
import os
import subprocess
import logging
from typing import Dict, Optional
from config import config
from .api import SingboxAPI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "..", "logs", "node-manager.log")),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

singbox_api = SingboxAPI()

def read_config() -> Dict:
    config_path = config.singbox.config
    if not os.path.exists(config_path):
        return {
            "inbounds": [],
            "outbounds": [],
            "route": {"rules": []}
        }
    
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_config(config_data: Dict):
    config_path = config.singbox.config
    new_path = config_path + ".new"
    
    with open(new_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2, ensure_ascii=False)
    
    if check_config(new_path):
        os.replace(new_path, config_path)
        return True
    else:
        if os.path.exists(new_path):
            os.remove(new_path)
        return False

def check_config(config_path: str) -> bool:
    try:
        result = subprocess.run(
            ["sing-box", "check", "-c", config_path],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logger.warning(f"sing-box config check failed: {result.stderr}")
        return result.returncode == 0
    except FileNotFoundError:
        logger.warning("sing-box is not installed, skipping config validation")
        return True

def reload_singbox() -> bool:
    if singbox_api.is_available():
        logger.info("Using sing-box API for reload")
        return singbox_api.reload()
    
    try:
        result = subprocess.run(
            ["systemctl", "restart", "sing-box"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logger.warning(f"Failed to restart sing-box via systemctl: {result.stderr}")
        return result.returncode == 0
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["sing-box", "reload", "-c", config.singbox.config],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                logger.warning(f"Failed to reload sing-box: {result.stderr}")
            return result.returncode == 0
        except FileNotFoundError:
            logger.warning("sing-box is not installed, reload skipped")
            return True
        except Exception as e:
            logger.warning(f"Failed to reload sing-box: {str(e)}")
            return False

def is_api_available() -> bool:
    return singbox_api.is_available()

def create_user_via_api(user_id, protocol, port, uuid=None, username=None, password=None):
    return singbox_api.create_user_inbound(user_id, protocol, port, uuid, username, password)

def bind_proxy_via_api(user_id, proxy_data):
    return singbox_api.create_user_outbound(user_id, proxy_data)

def create_route_via_api(user_id):
    return singbox_api.create_user_route(user_id)

def delete_user_via_api(user_id):
    return singbox_api.delete_user_config(user_id)

def is_singbox_running() -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "sing-box"],
            capture_output=True,
            text=True
        )
        return result.stdout.strip() == "active"
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["pgrep", "-f", "sing-box"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

def get_next_available_port(start_port: int = 5000) -> int:
    config_data = read_config()
    used_ports = set()
    
    for inbound in config_data.get("inbounds", []):
        if "listen_port" in inbound:
            used_ports.add(inbound["listen_port"])
    
    port = start_port
    while port in used_ports:
        port += 1
    
    return port
