import json
import uuid
from typing import List, Dict

def generate_uuid() -> str:
    return str(uuid.uuid4())

def create_vless_inbound(user_id: str, user_uuid: str, port: int) -> Dict:
    return {
        "type": "vless",
        "tag": f"user-{user_id}-vless",
        "listen": "0.0.0.0",
        "listen_port": port,
        "users": [
            {
                "uuid": user_uuid,
                "flow": ""
            }
        ],
        "network": "tcp"
    }

def create_vmess_inbound(user_id: str, user_uuid: str, port: int) -> Dict:
    return {
        "type": "vmess",
        "tag": f"user-{user_id}-vmess",
        "listen": "0.0.0.0",
        "listen_port": port,
        "users": [
            {
                "uuid": user_uuid,
                "alter_id": 0
            }
        ],
        "network": "tcp"
    }

def create_socks_inbound(user_id: str, port: int, username: str, password: str) -> Dict:
    return {
        "type": "socks",
        "tag": f"user-{user_id}-socks",
        "listen": "0.0.0.0",
        "listen_port": port,
        "users": [
            {
                "username": username,
                "password": password
            }
        ]
    }

def get_user_inbounds(config_data: Dict, user_id: str) -> List[Dict]:
    inbounds = config_data.get("inbounds", [])
    return [inb for inb in inbounds if inb.get("tag", "").startswith(f"user-{user_id}-")]

def remove_user_inbounds(config_data: Dict, user_id: str) -> Dict:
    config_data["inbounds"] = [
        inb for inb in config_data.get("inbounds", [])
        if not inb.get("tag", "").startswith(f"user-{user_id}-")
    ]
    return config_data
