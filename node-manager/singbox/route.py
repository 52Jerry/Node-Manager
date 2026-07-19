from typing import Dict

def create_user_route(user_id: str) -> Dict:
    return {
        "inbound": [
            f"user-{user_id}-vless",
            f"user-{user_id}-vmess",
            f"user-{user_id}-socks"
        ],
        "outbound": f"user-{user_id}-outbound"
    }

def add_user_rule(config_data: Dict, user_id: str) -> Dict:
    if "route" not in config_data:
        config_data["route"] = {}
    
    if "rules" not in config_data["route"]:
        config_data["route"]["rules"] = []
    
    remove_user_rule(config_data, user_id)
    
    rule = {
        "type": "field",
        "inbound": [
            f"user-{user_id}-vless",
            f"user-{user_id}-vmess",
            f"user-{user_id}-socks"
        ],
        "outbound": f"user-{user_id}-outbound"
    }
    
    config_data["route"]["rules"].append(rule)
    return config_data

def remove_user_rule(config_data: Dict, user_id: str) -> Dict:
    if "route" in config_data and "rules" in config_data["route"]:
        config_data["route"]["rules"] = [
            rule for rule in config_data["route"]["rules"]
            if not (isinstance(rule, dict) and 
                    "inbound" in rule and 
                    isinstance(rule["inbound"], list) and
                    any(inb.startswith(f"user-{user_id}-") for inb in rule["inbound"]))
        ]
    return config_data
