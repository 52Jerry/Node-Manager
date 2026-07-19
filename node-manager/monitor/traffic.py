import json
from typing import Dict
from config import config

def get_user_traffic(user_id: str) -> Dict:
    traffic_file = f"/var/log/sing-box/user-{user_id}-traffic.json"
    
    try:
        with open(traffic_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            upload = data.get("upload", 0)
            download = data.get("download", 0)
            return {
                "userId": user_id,
                "upload": upload,
                "download": download,
                "total": upload + download
            }
    except FileNotFoundError:
        return {
            "userId": user_id,
            "upload": 0,
            "download": 0,
            "total": 0
        }
    except Exception:
        return {
            "userId": user_id,
            "upload": 0,
            "download": 0,
            "total": 0
        }
