import requests
import json
import logging
from config import config

logger = logging.getLogger(__name__)

class SingboxAPI:
    def __init__(self):
        self.base_url = f"http://127.0.0.1:{config.singbox.api_port}"
        self.headers = {}
        if config.singbox.api_secret:
            self.headers["Authorization"] = f"Bearer {config.singbox.api_secret}"

    def get_proxies(self):
        try:
            response = requests.get(f"{self.base_url}/proxies", headers=self.headers, timeout=3)
            if response.status_code == 200:
                return response.json()
            logger.error(f"Failed to get proxies: {response.text}")
            return None
        except Exception as e:
            logger.warning(f"Sing-box API not available: {e}")
            return None

    def add_proxy(self, proxy_data):
        try:
            response = requests.put(
                f"{self.base_url}/proxies/{proxy_data['name']}",
                headers=self.headers,
                json=proxy_data,
                timeout=5,
            )
            if response.status_code == 200:
                logger.info(f"Added proxy: {proxy_data['name']}")
                return True
            logger.error(f"Failed to add proxy: {response.text}")
            return False
        except Exception as e:
            logger.warning(f"Sing-box API not available: {e}")
            return False

    def remove_proxy(self, proxy_name):
        try:
            response = requests.delete(
                f"{self.base_url}/proxies/{proxy_name}",
                headers=self.headers,
                timeout=5,
            )
            if response.status_code == 200:
                logger.info(f"Removed proxy: {proxy_name}")
                return True
            logger.error(f"Failed to remove proxy: {response.text}")
            return False
        except Exception as e:
            logger.warning(f"Sing-box API not available: {e}")
            return False

    def add_rule(self, rule_data):
        try:
            response = requests.post(
                f"{self.base_url}/rules",
                headers=self.headers,
                json=rule_data,
                timeout=5,
            )
            if response.status_code == 200:
                logger.info(f"Added rule")
                return True
            logger.error(f"Failed to add rule: {response.text}")
            return False
        except Exception as e:
            logger.warning(f"Sing-box API not available: {e}")
            return False

    def remove_rule(self, rule_id):
        try:
            response = requests.delete(
                f"{self.base_url}/rules/{rule_id}",
                headers=self.headers,
                timeout=5,
            )
            if response.status_code == 200:
                logger.info(f"Removed rule: {rule_id}")
                return True
            logger.error(f"Failed to remove rule: {response.text}")
            return False
        except Exception as e:
            logger.warning(f"Sing-box API not available: {e}")
            return False

    def reload(self):
        try:
            response = requests.post(
                f"{self.base_url}/configs/reload",
                headers=self.headers,
                timeout=10,
            )
            if response.status_code == 200:
                logger.info("Sing-box config reloaded via API")
                return True
            logger.error(f"Failed to reload: {response.text}")
            return False
        except Exception as e:
            logger.warning(f"Sing-box API not available: {e}")
            return False

    def is_available(self):
        try:
            response = requests.get(f"{self.base_url}/proxies", headers=self.headers, timeout=2)
            return response.status_code == 200
        except:
            return False

    def create_user_inbound(self, user_id, protocol, port, uuid=None, username=None, password=None):
        proxy_name = f"user-{user_id}-{protocol}"
        
        if protocol == "vless":
            proxy_data = {
                "name": proxy_name,
                "type": "vless",
                "server": "0.0.0.0",
                "server_port": port,
                "uuid": uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": "www.cloudflare.com",
                    "reality": {
                        "enabled": True,
                        "handshake": {
                            "server": "www.cloudflare.com",
                            "server_port": 443
                        }
                    }
                }
            }
        elif protocol == "vmess":
            proxy_data = {
                "name": proxy_name,
                "type": "vmess",
                "server": "0.0.0.0",
                "server_port": port,
                "uuid": uuid,
                "alter_id": 0
            }
        elif protocol == "socks":
            proxy_data = {
                "name": proxy_name,
                "type": "socks5",
                "server": "0.0.0.0",
                "server_port": port,
                "username": username,
                "password": password
            }
        else:
            logger.error(f"Unknown protocol: {protocol}")
            return False
        
        return self.add_proxy(proxy_data)

    def create_user_outbound(self, user_id, proxy_data):
        proxy_name = f"user-{user_id}-outbound"
        
        outbound_data = {
            "name": proxy_name,
            "type": "socks5",
            "server": proxy_data.get("server", ""),
            "server_port": proxy_data.get("port", 1080),
            "username": proxy_data.get("username"),
            "password": proxy_data.get("password")
        }
        
        return self.add_proxy(outbound_data)

    def create_user_route(self, user_id):
        rule_data = {
            "type": "field",
            "inbound": [
                f"user-{user_id}-vless",
                f"user-{user_id}-vmess",
                f"user-{user_id}-socks"
            ],
            "outbound": f"user-{user_id}-outbound"
        }
        
        return self.add_rule(rule_data)

    def delete_user_config(self, user_id):
        success = True
        
        for protocol in ["vless", "vmess", "socks"]:
            proxy_name = f"user-{user_id}-{protocol}"
            if not self.remove_proxy(proxy_name):
                success = False
        
        outbound_name = f"user-{user_id}-outbound"
        if not self.remove_proxy(outbound_name):
            success = False
        
        return success
