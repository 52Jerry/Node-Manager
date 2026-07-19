from typing import Dict, Optional

def create_socks_outbound(user_id: str, proxy_data: Dict) -> Dict:
    return {
        "type": "socks",
        "tag": f"user-{user_id}-outbound",
        "server": proxy_data.get("server", ""),
        "server_port": proxy_data.get("port", 1080),
        "username": proxy_data.get("username", ""),
        "password": proxy_data.get("password", "")
    }

def get_user_outbound(config_data: Dict, user_id: str) -> Optional[Dict]:
    outbounds = config_data.get("outbounds", [])
    for outb in outbounds:
        if outb.get("tag", "") == f"user-{user_id}-outbound":
            return outb
    return None

def add_outbound(config_data: Dict, outbound: Dict) -> Dict:
    if "outbounds" not in config_data:
        config_data["outbounds"] = []
    
    existing = get_user_outbound(config_data, outbound["tag"].replace("-outbound", "").replace("user-", ""))
    if existing:
        config_data["outbounds"].remove(existing)
    
    config_data["outbounds"].append(outbound)
    return config_data

def remove_user_outbound(config_data: Dict, user_id: str) -> Dict:
    config_data["outbounds"] = [
        outb for outb in config_data.get("outbounds", [])
        if outb.get("tag", "") != f"user-{user_id}-outbound"
    ]
    return config_data
