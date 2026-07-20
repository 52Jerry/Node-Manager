#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}  Python Node Manager 一键部署${NC}"
echo -e "${GREEN}====================================${NC}"
echo ""

VLESS_PORT=20168
VMESS_PORT=20169
SOCKS_PORT=5001
API_PORT=9090
NODE_MANAGER_PORT=8088

REALITY_SNI="www.cloudflare.com"
REALITY_FP="chrome"

echo -e "${YELLOW}[1/4] 安装 sing-box${NC}"
echo "------------------------"

if ! command -v apt &> /dev/null; then
    echo -e "${RED}错误: 仅支持 Debian/Ubuntu 系统${NC}"
    exit 1
fi

echo "更新系统包..."
apt update -y

echo "安装依赖工具..."
apt install -y curl openssl jq ufw coreutils python3 python3-pip python3-venv

echo "清理旧环境..."
systemctl stop sing-box 2>/dev/null || true
apt remove sing-box -y 2>/dev/null || true
rm -rf /etc/sing-box
rm -rf /etc/node-manager
rm -rf /opt/node-manager

echo "安装 sing-box..."
curl -fsSL https://sing-box.app/install.sh | sh

echo ""
echo -e "${GREEN}✅ sing-box 安装完成${NC}"
echo ""

echo -e "${YELLOW}[2/4] 配置基础节点${NC}"
echo "------------------------"

echo "获取服务器信息..."
SERVER_IP=$(curl -s ipv4.icanhazip.com)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(curl -s api.ipify.org)
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
fi

echo "生成节点参数..."
UUID=$(sing-box generate uuid)
API_SECRET=$(openssl rand -hex 32)
SOCKS_USER=$(openssl rand -hex 4)
SOCKS_PASS=$(openssl rand -hex 8)
NODE_TOKEN=$(openssl rand -hex 32)

REALITY_KEY=$(sing-box generate reality-keypair)
PRIVATE_KEY=$(echo "$REALITY_KEY" | grep PrivateKey | awk '{print $2}')
PUBLIC_KEY=$(echo "$REALITY_KEY" | grep PublicKey | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 4)

echo "创建 sing-box 配置目录..."
mkdir -p /etc/sing-box

echo "写入基础配置文件..."
cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info"
  },
  "experimental": {
    "clash_api": {
      "external_controller": "0.0.0.0:${API_PORT}",
      "secret": "${API_SECRET}"
    }
  },
  "dns": {
    "servers": [
      {
        "tag": "cloudflare",
        "type": "tls",
        "server": "1.1.1.1"
      }
    ],
    "final": "cloudflare"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "0.0.0.0",
      "listen_port": ${VLESS_PORT},
      "users": [
        {
          "uuid": "${UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_SNI}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${REALITY_SNI}",
            "server_port": 443
          },
          "private_key": "${PRIVATE_KEY}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    {
      "type": "vmess",
      "tag": "vmess",
      "listen": "0.0.0.0",
      "listen_port": ${VMESS_PORT},
      "users": [
        {
          "uuid": "${UUID}"
        }
      ]
    },
    {
      "type": "socks",
      "tag": "socks",
      "listen": "0.0.0.0",
      "listen_port": ${SOCKS_PORT},
      "users": [
        {
          "username": "${SOCKS_USER}",
          "password": "${SOCKS_PASS}"
        }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
EOF

echo "开放防火墙端口..."
ufw allow ${VLESS_PORT}/tcp
ufw allow ${VMESS_PORT}/tcp
ufw allow ${SOCKS_PORT}/tcp
ufw allow ${API_PORT}/tcp
ufw allow ${NODE_MANAGER_PORT}/tcp
ufw --force enable

echo ""
echo -e "${GREEN}✅ 基础节点配置完成${NC}"
echo ""

echo -e "${YELLOW}[3/4] 测试 sing-box 运行${NC}"
echo "------------------------"

echo "检查配置文件有效性..."
sing-box check -c /etc/sing-box/config.json
echo -e "${GREEN}配置文件有效${NC}"

echo "启动 sing-box 服务..."
systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box

echo "等待服务启动..."
sleep 3

echo "检查 sing-box 状态..."
SINGBOX_STATUS=$(systemctl is-active sing-box)
if [ "$SINGBOX_STATUS" = "active" ]; then
    echo -e "${GREEN}sing-box 运行正常${NC}"
else
    echo -e "${RED}sing-box 启动失败${NC}"
    systemctl status sing-box
    exit 1
fi

echo ""
echo -e "${GREEN}✅ sing-box 测试通过${NC}"
echo ""

echo -e "${YELLOW}[4/4] 安装 Python Node Manager${NC}"
echo "------------------------"

echo "创建安装目录..."
mkdir -p /opt/node-manager
cd /opt/node-manager

echo "创建 Python 虚拟环境..."
python3 -m venv venv
source venv/bin/activate

echo "安装 Python 依赖..."
pip install --upgrade pip
pip install fastapi uvicorn pydantic psutil requests python-jose pyyaml

echo "创建目录结构..."
mkdir -p models
mkdir -p monitor
mkdir -p singbox
mkdir -p static
mkdir -p logs

echo "写入配置文件..."
mkdir -p /etc/node-manager
cat > /etc/node-manager/config.yaml <<EOF
node:
  id: $(hostname)
  name: sing-box-node
  host: ${SERVER_IP}

server:
  port: ${NODE_MANAGER_PORT}

security:
  token: ${NODE_TOKEN}

singbox:
  config: /etc/sing-box/config.json
  api_port: ${API_PORT}
  api_secret: ${API_SECRET}
EOF

echo "写入 auth.py..."
cat > auth.py <<'AUTHEOF'
from fastapi import HTTPException
from fastapi.security import HTTPBearer

security = HTTPBearer()

def verify_token(credentials):
    from config import config
    token = credentials.credentials
    if token != config.security.token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token
AUTHEOF

echo "写入 config.py..."
cat > config.py <<'CONFIGEOF'
import os
import socket
import requests
import yaml

class SingboxConfig:
    config = ""
    api_port = 9090
    api_secret = ""

class SecurityConfig:
    token = ""

class ServerConfig:
    port = 8088

class NodeConfig:
    id = ""
    name = ""
    host = ""

class Config:
    node = NodeConfig()
    server = ServerConfig()
    security = SecurityConfig()
    singbox = SingboxConfig()

config = Config()

def get_public_ip():
    try:
        response = requests.get("https://ipv4.icanhazip.com", timeout=5)
        return response.text.strip()
    except:
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            return response.text.strip()
        except:
            return get_local_ip()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_hostname():
    return socket.gethostname()

def load_config():
    config_path = "/etc/node-manager/config.yaml"
    
    config.node.id = get_hostname()
    config.node.name = "Default Node"
    config.node.host = get_public_ip()
    
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
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

load_config()
CONFIGEOF

echo "写入 models/request.py..."
cat > models/request.py <<'MODELSEOF'
from pydantic import BaseModel
from typing import Optional, List

class CreateUserRequest(BaseModel):
    userId: str
    protocols: List[str] = ["vless", "vmess", "socks"]

class BindProxyRequest(BaseModel):
    userId: str
    proxy: dict

class CreateUserResponse(BaseModel):
    success: bool = True
    userId: str
    uuid: str
    vless: Optional[str] = None
    vmess: Optional[str] = None
    socks: Optional[dict] = None

class BindProxyResponse(BaseModel):
    success: bool = True
    userId: str

class DeleteUserResponse(BaseModel):
    success: bool = True
    userId: str

class NodeStatusResponse(BaseModel):
    node: str
    host: str
    singbox: str
    cpu: float
    memory: float
    connections: int
    api_available: bool = False

class TrafficResponse(BaseModel):
    userId: str
    upload: int = 0
    download: int = 0
    total: int = 0
MODELSEOF

echo "写入 models/__init__.py..."
cat > models/__init__.py <<'MODELINITEOF'
from .request import (
    CreateUserRequest,
    CreateUserResponse,
    BindProxyRequest,
    BindProxyResponse,
    DeleteUserResponse,
    NodeStatusResponse,
    TrafficResponse
)
MODELINITEOF

echo "写入 monitor/status.py..."
cat > monitor/status.py <<'MONITORSTATUSEOF'
import psutil
import os

def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def get_memory_usage():
    return psutil.virtual_memory().percent

def get_network_connections():
    return len(psutil.net_connections())

def get_singbox_status():
    try:
        result = os.popen("systemctl is-active sing-box").read().strip()
        return "running" if result == "active" else "stopped"
    except:
        return "unknown"

def get_system_info():
    return {
        "cpu": get_cpu_usage(),
        "memory": get_memory_usage(),
        "connections": get_network_connections(),
        "singbox": get_singbox_status()
    }
MONITORSTATUSEOF

echo "写入 monitor/traffic.py..."
cat > monitor/traffic.py <<'MONITORTRAFFICEOF'
class TrafficManager:
    def __init__(self):
        self.traffic_data = {}
    
    def get_traffic(self, user_id):
        return self.traffic_data.get(user_id, {"upload": 0, "download": 0, "total": 0})
    
    def update_traffic(self, user_id, upload, download):
        if user_id not in self.traffic_data:
            self.traffic_data[user_id] = {"upload": 0, "download": 0, "total": 0}
        self.traffic_data[user_id]["upload"] += upload
        self.traffic_data[user_id]["download"] += download
        self.traffic_data[user_id]["total"] = self.traffic_data[user_id]["upload"] + self.traffic_data[user_id]["download"]
        return self.traffic_data[user_id]
    
    def reset_traffic(self, user_id):
        if user_id in self.traffic_data:
            self.traffic_data[user_id] = {"upload": 0, "download": 0, "total": 0}

traffic_manager = TrafficManager()
MONITORTRAFFICEOF

echo "写入 monitor/__init__.py..."
cat > monitor/__init__.py <<'MONITORINITEOF'
from .status import get_system_info, get_cpu_usage, get_memory_usage, get_network_connections, get_singbox_status
from .traffic import traffic_manager
MONITORINITEOF

echo "写入 singbox/api.py..."
cat > singbox/api.py <<'SINGBOXAPEOF'
import requests
import json

class SingboxAPI:
    def __init__(self, host="127.0.0.1", port=9090, secret=""):
        self.base_url = f"http://{host}:{port}"
        self.secret = secret
    
    def _get_headers(self):
        headers = {}
        if self.secret:
            headers["Authorization"] = f"Bearer {self.secret}"
        return headers
    
    def get_proxies(self):
        try:
            response = requests.get(f"{self.base_url}/proxies", headers=self._get_headers(), timeout=3)
            return response.json()
        except:
            return None
    
    def add_proxy(self, proxy_data):
        try:
            response = requests.put(f"{self.base_url}/proxies/{proxy_data.get('name', '')}",
                                  headers={**self._get_headers(), "Content-Type": "application/json"},
                                  data=json.dumps(proxy_data), timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def remove_proxy(self, proxy_name):
        try:
            response = requests.delete(f"{self.base_url}/proxies/{proxy_name}", headers=self._get_headers(), timeout=3)
            return response.status_code == 200
        except:
            return False
    
    def get_rules(self):
        try:
            response = requests.get(f"{self.base_url}/rules", headers=self._get_headers(), timeout=3)
            return response.json()
        except:
            return None
    
    def add_rule(self, rule_data):
        try:
            response = requests.post(f"{self.base_url}/rules",
                                   headers={**self._get_headers(), "Content-Type": "application/json"},
                                   data=json.dumps(rule_data), timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def remove_rule(self, rule_name):
        try:
            response = requests.delete(f"{self.base_url}/rules/{rule_name}", headers=self._get_headers(), timeout=3)
            return response.status_code == 200
        except:
            return False
    
    def reload(self):
        try:
            response = requests.post(f"{self.base_url}/configs/reload", headers=self._get_headers(), timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def is_available(self):
        try:
            response = requests.get(f"{self.base_url}/version", headers=self._get_headers(), timeout=3)
            return response.status_code == 200
        except:
            return False
    
    def create_user_inbound(self, user_id, protocol, port, user_uuid, flow=""):
        inbound_data = {
            "name": f"user-{user_id}-{protocol}",
            "type": protocol,
            "server": "0.0.0.0",
            "port": port,
            "uuid": user_uuid
        }
        if protocol == "vless":
            inbound_data["flow"] = flow if flow else "xtls-rprx-vision"
        return self.add_proxy(inbound_data)
    
    def create_user_outbound(self, user_id):
        outbound_data = {
            "name": f"user-{user_id}-direct",
            "type": "direct"
        }
        return self.add_proxy(outbound_data)
    
    def create_user_route(self, user_id):
        rule_data = {
            "name": f"user-{user_id}-route",
            "type": "field",
            "inbound": f"user-{user_id}-inbound",
            "outbound": f"user-{user_id}-direct"
        }
        return self.add_rule(rule_data)
    
    def delete_user_config(self, user_id):
        self.remove_proxy(f"user-{user_id}-vless")
        self.remove_proxy(f"user-{user_id}-vmess")
        self.remove_proxy(f"user-{user_id}-socks")
        self.remove_proxy(f"user-{user_id}-direct")
        self.remove_rule(f"user-{user_id}-route")
        return True
SINGBOXAPEOF

echo "写入 singbox/inbound.py..."
cat > singbox/inbound.py <<'SINGBOXINBOUNDEOF'
def create_vless_inbound(tag, port, uuid, flow="xtls-rprx-vision"):
    return {
        "type": "vless",
        "tag": tag,
        "listen": "0.0.0.0",
        "listen_port": port,
        "users": [
            {
                "uuid": uuid,
                "flow": flow
            }
        ]
    }

def create_vmess_inbound(tag, port, uuid):
    return {
        "type": "vmess",
        "tag": tag,
        "listen": "0.0.0.0",
        "listen_port": port,
        "users": [
            {
                "uuid": uuid
            }
        ]
    }

def create_socks_inbound(tag, port, username, password):
    return {
        "type": "socks",
        "tag": tag,
        "listen": "0.0.0.0",
        "listen_port": port,
        "users": [
            {
                "username": username,
                "password": password
            }
        ]
    }
SINGBOXINBOUNDEOF

echo "写入 singbox/outbound.py..."
cat > singbox/outbound.py <<'SINGBOXOUTBOUNDEOF'
def create_direct_outbound(tag="direct"):
    return {
        "type": "direct",
        "tag": tag
    }

def create_socks_outbound(tag, server, port, username=None, password=None):
    outbound = {
        "type": "socks",
        "tag": tag,
        "server": server,
        "server_port": port
    }
    if username and password:
        outbound["username"] = username
        outbound["password"] = password
    return outbound
SINGBOXOUTBOUNDEOF

echo "写入 singbox/route.py..."
cat > singbox/route.py <<'SINGBOXROUTEEOF'
def create_user_route(user_id):
    return {
        "rule": f"user-{user_id}",
        "inbound": f"user-{user_id}-inbound",
        "outbound": f"user-{user_id}-outbound"
    }
SINGBOXROUTEEOF

echo "写入 singbox/manager.py..."
cat > singbox/manager.py <<'SINGBOXMANAGEREPOF'
import json
import uuid
import os
import subprocess
import base64
from .api import SingboxAPI
from .inbound import create_vless_inbound, create_vmess_inbound, create_socks_inbound
from .outbound import create_direct_outbound, create_socks_outbound
from ..config import config

api_client = None

def get_api_client():
    global api_client
    if api_client is None:
        api_client = SingboxAPI("127.0.0.1", config.singbox.api_port, config.singbox.api_secret)
    return api_client

def is_api_available():
    try:
        client = get_api_client()
        return client.is_available()
    except:
        return False

def read_config():
    try:
        with open(config.singbox.config, "r") as f:
            return json.load(f)
    except:
        return {}

def write_config(data):
    try:
        with open(config.singbox.config, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except:
        return False

def reload_singbox():
    if is_api_available():
        client = get_api_client()
        if client.reload():
            return {"success": True, "method": "api"}
    try:
        subprocess.run(["systemctl", "restart", "sing-box"], check=True)
        return {"success": True, "method": "systemctl"}
    except:
        return {"success": False}

def get_next_available_port(start_port=5000):
    import socket
    for port in range(start_port, 65535):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start_port

def create_user_via_api(user_id, protocol, port, user_uuid):
    client = get_api_client()
    if protocol == "vless":
        return client.create_user_inbound(user_id, protocol, port, user_uuid, "xtls-rprx-vision")
    elif protocol == "vmess":
        return client.create_user_inbound(user_id, protocol, port, user_uuid)
    elif protocol == "socks":
        return client.create_user_inbound(user_id, protocol, port, user_uuid)
    return False

def bind_proxy_via_api(user_id, proxy_data):
    client = get_api_client()
    outbound_name = f"user-{user_id}-proxy"
    proxy_name = proxy_data.get("server", "")
    outbound = {
        "name": outbound_name,
        "type": "socks5",
        "server": proxy_data.get("server", ""),
        "server_port": proxy_data.get("port", 1080)
    }
    if proxy_data.get("username"):
        outbound["username"] = proxy_data.get("username")
    if proxy_data.get("password"):
        outbound["password"] = proxy_data.get("password")
    if client.add_proxy(outbound):
        rule_data = {
            "name": f"user-{user_id}-proxy-rule",
            "type": "field",
            "inbound": f"user-{user_id}-inbound",
            "outbound": outbound_name
        }
        return client.add_rule(rule_data)
    return False

def create_route_via_api(user_id):
    client = get_api_client()
    return client.create_user_route(user_id)

def delete_user_via_api(user_id):
    client = get_api_client()
    return client.delete_user_config(user_id)

def create_user_config(user_id, protocols):
    user_uuid = str(uuid.uuid4())
    next_port = get_next_available_port(5000)
    
    vless_url = None
    vmess_url = None
    socks_info = None
    
    use_api = is_api_available()
    config_data = read_config()
    
    for proto in protocols:
        if proto == "vless":
            vless_port = next_port
            next_port += 1
            vless_url = f"vless://{user_uuid}@{config.node.host}:{vless_port}?encryption=none&flow=&type=tcp&host=&path="
            if use_api:
                create_user_via_api(user_id, "vless", vless_port, user_uuid)
            else:
                config_data["inbounds"].append(create_vless_inbound(f"user-{user_id}-vless", vless_port, user_uuid))
        
        elif proto == "vmess":
            vmess_port = next_port
            next_port += 1
            vmess_dict = {"v":"2","ps":"NodeManager","add":config.node.host,"port":str(vmess_port),"id":user_uuid,"aid":"0","net":"tcp","type":"none","host":"","path":"","tls":""}
            vmess_url = "vmess://" + base64.b64encode(json.dumps(vmess_dict, separators=(",",":")).encode()).decode()
            if use_api:
                create_user_via_api(user_id, "vmess", vmess_port, user_uuid)
            else:
                config_data["inbounds"].append(create_vmess_inbound(f"user-{user_id}-vmess", vmess_port, user_uuid))
        
        elif proto == "socks":
            socks_port = next_port
            next_port += 1
            socks_user = str(uuid.uuid4())[:8]
            socks_pass = str(uuid.uuid4())[:12]
            socks_info = {"host":config.node.host,"port":socks_port,"username":socks_user,"password":socks_pass}
            if use_api:
                create_user_via_api(user_id, "socks", socks_port, user_uuid)
            else:
                config_data["inbounds"].append(create_socks_inbound(f"user-{user_id}-socks", socks_port, socks_user, socks_pass))
    
    if not use_api:
        write_config(config_data)
        reload_singbox()
    
    return {"userId": user_id, "uuid": user_uuid, "vless": vless_url, "vmess": vmess_url, "socks": socks_info}

def bind_proxy_to_user(user_id, proxy_data):
    use_api = is_api_available()
    
    if use_api:
        bind_proxy_via_api(user_id, proxy_data)
    else:
        config_data = read_config()
        tag = f"user-{user_id}-proxy"
        server = proxy_data.get("server")
        port = proxy_data.get("port", 1080)
        username = proxy_data.get("username")
        password = proxy_data.get("password")
        
        config_data["outbounds"].append(create_socks_outbound(tag, server, port, username, password))
        write_config(config_data)
        reload_singbox()
    
    return {"success": True, "userId": user_id}

def delete_user_config(user_id):
    use_api = is_api_available()
    
    if use_api:
        delete_user_via_api(user_id)
    else:
        config_data = read_config()
        inbound_tags = [f"user-{user_id}-vless", f"user-{user_id}-vmess", f"user-{user_id}-socks"]
        outbound_tags = [f"user-{user_id}-proxy"]
        
        config_data["inbounds"] = [i for i in config_data.get("inbounds", []) if i.get("tag") not in inbound_tags]
        config_data["outbounds"] = [o for o in config_data.get("outbounds", []) if o.get("tag") not in outbound_tags]
        
        write_config(config_data)
        reload_singbox()
    
    return {"success": True, "userId": user_id}
SINGBOXMANAGEREPOF

echo "写入 singbox/__init__.py..."
cat > singbox/__init__.py <<'SINGBOXINITEOF'
from .manager import (
    read_config, write_config, reload_singbox, get_next_available_port,
    is_api_available, create_user_via_api, bind_proxy_via_api,
    create_route_via_api, delete_user_via_api, create_user_config,
    bind_proxy_to_user, delete_user_config
)
from .api import SingboxAPI
from .inbound import create_vless_inbound, create_vmess_inbound, create_socks_inbound
from .outbound import create_direct_outbound, create_socks_outbound
from .route import create_user_route
SINGBOXINITEOF

echo "写入 static/index.html..."
cat > static/index.html <<'INDEXEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Node Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #fff; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { font-size: 28px; color: #00d4ff; }
        .header .token { background: #16213e; padding: 10px 20px; border-radius: 8px; font-family: monospace; font-size: 12px; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: #16213e; padding: 20px; border-radius: 12px; }
        .card .label { color: #888; font-size: 14px; margin-bottom: 8px; }
        .card .value { font-size: 24px; font-weight: bold; }
        .card .value.running { color: #00ff88; }
        .card .value.stopped { color: #ff4757; }
        .card .value.warning { color: #ffa502; }
        .section { background: #16213e; padding: 25px; border-radius: 12px; margin-bottom: 20px; }
        .section h2 { font-size: 20px; margin-bottom: 20px; color: #00d4ff; }
        .btn { background: #00d4ff; color: #1a1a2e; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: bold; transition: all 0.3s; }
        .btn:hover { background: #00b8e6; transform: translateY(-2px); }
        .btn.danger { background: #ff4757; color: #fff; }
        .btn.danger:hover { background: #e8384a; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #888; }
        .form-group input, .form-group select { width: 100%; padding: 10px; background: #0f3460; border: none; border-radius: 6px; color: #fff; font-size: 14px; }
        .form-group input:focus, .form-group select:focus { outline: 2px solid #00d4ff; }
        .protocols { display: flex; gap: 10px; flex-wrap: wrap; }
        .protocol { background: #0f3460; padding: 10px 20px; border-radius: 6px; cursor: pointer; transition: all 0.3s; }
        .protocol.selected { background: #00d4ff; color: #1a1a2e; }
        .table { width: 100%; border-collapse: collapse; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #0f3460; }
        .table th { color: #888; font-weight: normal; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); justify-content: center; align-items: center; z-index: 1000; }
        .modal.active { display: flex; }
        .modal-content { background: #16213e; padding: 30px; border-radius: 12px; width: 90%; max-width: 500px; }
        .modal-content h3 { margin-bottom: 20px; }
        .modal-content .close { float: right; font-size: 24px; cursor: pointer; color: #888; }
        .modal-content .close:hover { color: #fff; }
        .result { background: #0f3460; padding: 15px; border-radius: 8px; margin-top: 15px; font-family: monospace; font-size: 12px; word-break: break-all; }
        .success { color: #00ff88; }
        .error { color: #ff4757; }
        .api-status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
        .api-status.available { background: #00ff88; }
        .api-status.unavailable { background: #ff4757; }
        @media (max-width: 768px) {
            .header { flex-direction: column; gap: 15px; }
            .header h1 { font-size: 22px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Node Manager</h1>
            <div class="token">Token: <span id="token">abc123456789</span></div>
        </div>

        <div class="cards">
            <div class="card">
                <div class="label">节点状态</div>
                <div class="value" id="node-name">-</div>
            </div>
            <div class="card">
                <div class="label">sing-box</div>
                <div class="value" id="singbox-status">...</div>
            </div>
            <div class="card">
                <div class="label">CPU 使用率</div>
                <div class="value" id="cpu-usage">...</div>
            </div>
            <div class="card">
                <div class="label">内存使用率</div>
                <div class="value" id="memory-usage">...</div>
            </div>
            <div class="card">
                <div class="label">网络连接</div>
                <div class="value" id="connections">...</div>
            </div>
            <div class="card">
                <div class="label">API 状态</div>
                <div class="value"><span class="api-status" id="api-status"></span><span id="api-text">检测中...</span></div>
            </div>
        </div>

        <div class="section">
            <h2>用户管理</h2>
            <button class="btn" onclick="showCreateUserModal()">创建用户</button>
            <table class="table">
                <thead>
                    <tr><th>用户ID</th><th>协议</th><th>UUID</th><th>操作</th></tr>
                </thead>
                <tbody id="user-list">
                    <tr><td colspan="4" style="text-align:center;color:#888;">暂无用户</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>快捷操作</h2>
            <button class="btn" onclick="reloadSingbox()">重启 sing-box</button>
            <button class="btn" onclick="refreshStatus()">刷新状态</button>
            <button class="btn" onclick="testApi()">测试 API</button>
        </div>
    </div>

    <div class="modal" id="create-user-modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('create-user-modal')">&times;</span>
            <h3>创建用户</h3>
            <div class="form-group">
                <label>用户ID</label>
                <input type="text" id="user-id" placeholder="例如: 10001">
            </div>
            <div class="form-group">
                <label>选择协议</label>
                <div class="protocols">
                    <div class="protocol selected" onclick="toggleProtocol('vless')" id="proto-vless">VLESS</div>
                    <div class="protocol selected" onclick="toggleProtocol('vmess')" id="proto-vmess">VMess</div>
                    <div class="protocol selected" onclick="toggleProtocol('socks')" id="proto-socks">SOCKS5</div>
                </div>
            </div>
            <button class="btn" onclick="createUser()">创建</button>
            <div class="result" id="create-result" style="display:none;"></div>
        </div>
    </div>

    <script>
        const BASE_URL = '';
        const TOKEN = 'abc123456789';
        
        let selectedProtocols = ['vless', 'vmess', 'socks'];
        
        function getHeaders() {
            return { 'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json' };
        }
        
        async function refreshStatus() {
            try {
                const response = await fetch(BASE_URL + '/api/node/status', { headers: getHeaders() });
                const data = await response.json();
                
                document.getElementById('node-name').textContent = data.node;
                document.getElementById('singbox-status').textContent = data.singbox;
                document.getElementById('singbox-status').className = 'value ' + (data.singbox === 'running' ? 'running' : 'stopped');
                document.getElementById('cpu-usage').textContent = data.cpu + '%';
                document.getElementById('memory-usage').textContent = data.memory + '%';
                document.getElementById('connections').textContent = data.connections;
                
                const apiStatus = document.getElementById('api-status');
                const apiText = document.getElementById('api-text');
                if (data.api_available !== undefined) {
                    apiStatus.className = 'api-status ' + (data.api_available ? 'available' : 'unavailable');
                    apiText.textContent = data.api_available ? '可用' : '不可用';
                }
            } catch (e) {
                console.error(e);
            }
        }
        
        function showCreateUserModal() {
            document.getElementById('create-user-modal').classList.add('active');
        }
        
        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
            document.getElementById('create-result').style.display = 'none';
        }
        
        function toggleProtocol(proto) {
            const index = selectedProtocols.indexOf(proto);
            const el = document.getElementById('proto-' + proto);
            if (index > -1) {
                selectedProtocols.splice(index, 1);
                el.classList.remove('selected');
            } else {
                selectedProtocols.push(proto);
                el.classList.add('selected');
            }
        }
        
        async function createUser() {
            const userId = document.getElementById('user-id').value;
            if (!userId) {
                showResult('create-result', '请输入用户ID', 'error');
                return;
            }
            
            try {
                const response = await fetch(BASE_URL + '/api/user/create', {
                    method: 'POST',
                    headers: getHeaders(),
                    body: JSON.stringify({ userId, protocols: selectedProtocols })
                });
                const data = await response.json();
                
                if (data.success) {
                    let result = '用户创建成功!\n';
                    result += 'UUID: ' + data.uuid + '\n';
                    if (data.vless) result += 'VLESS: ' + data.vless + '\n';
                    if (data.vmess) result += 'VMess: ' + data.vmess + '\n';
                    if (data.socks) result += 'SOCKS5: ' + JSON.stringify(data.socks) + '\n';
                    showResult('create-result', result, 'success');
                    document.getElementById('user-id').value = '';
                } else {
                    showResult('create-result', '创建失败', 'error');
                }
            } catch (e) {
                showResult('create-result', '错误: ' + e.message, 'error');
            }
        }
        
        function showResult(id, text, type) {
            const el = document.getElementById(id);
            el.textContent = text;
            el.className = 'result ' + type;
            el.style.display = 'block';
        }
        
        async function reloadSingbox() {
            if (!confirm('确定要重启 sing-box 吗?')) return;
            try {
                const response = await fetch(BASE_URL + '/api/singbox/reload', {
                    method: 'POST',
                    headers: getHeaders()
                });
                const data = await response.json();
                if (data.success) {
                    alert('重启成功');
                    setTimeout(refreshStatus, 3000);
                } else {
                    alert('重启失败');
                }
            } catch (e) {
                alert('错误: ' + e.message);
            }
        }
        
        async function testApi() {
            try {
                const response = await fetch(BASE_URL + '/api/singbox/api/status', {
                    method: 'GET',
                    headers: getHeaders()
                });
                const data = await response.json();
                alert('API 状态: ' + (data.available ? '可用' : '不可用'));
                refreshStatus();
            } catch (e) {
                alert('API 不可用');
            }
        }
        
        window.onclick = function(e) {
            if (e.target.classList.contains('modal')) {
                e.target.classList.remove('active');
            }
        }
        
        setInterval(refreshStatus, 10000);
        refreshStatus();
    </script>
</body>
</html>
INDEXEOF

echo "写入 main.py..."
cat > main.py <<'MAINEOF'
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

app = FastAPI(title="Node Manager", version="1.0")

from config import config
from auth import verify_token
from models.request import (
    CreateUserRequest,
    CreateUserResponse,
    BindProxyRequest,
    BindProxyResponse,
    DeleteUserResponse,
    NodeStatusResponse,
    TrafficResponse
)
from singbox.manager import (
    reload_singbox, is_api_available, create_user_config,
    bind_proxy_to_user, delete_user_config
)
from monitor.status import get_system_info

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def root():
    return FileResponse("static/index.html")

@app.get("/api/node/status", response_model=NodeStatusResponse)
def get_status(token: str = Depends(verify_token)):
    info = get_system_info()
    return {
        "node": config.node.id,
        "host": config.node.host,
        "singbox": info["singbox"],
        "cpu": info["cpu"],
        "memory": info["memory"],
        "connections": info["connections"],
        "api_available": is_api_available()
    }

@app.post("/api/user/create", response_model=CreateUserResponse)
def create_user(request: CreateUserRequest, token: str = Depends(verify_token)):
    result = create_user_config(request.userId, request.protocols)
    return result

@app.post("/api/user/bind-proxy", response_model=BindProxyResponse)
def bind_proxy(request: BindProxyRequest, token: str = Depends(verify_token)):
    result = bind_proxy_to_user(request.userId, request.proxy)
    return result

@app.delete("/api/user/delete/{userId}", response_model=DeleteUserResponse)
def delete_user(userId: str, token: str = Depends(verify_token)):
    result = delete_user_config(userId)
    return result

@app.get("/api/user/{userId}/traffic", response_model=TrafficResponse)
def get_traffic(userId: str, token: str = Depends(verify_token)):
    return {"userId": userId, "upload": 0, "download": 0, "total": 0}

@app.post("/api/singbox/reload")
def singbox_reload(token: str = Depends(verify_token)):
    result = reload_singbox()
    return result

@app.get("/api/singbox/api/status")
def api_status(token: str = Depends(verify_token)):
    return {"available": is_api_available()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.server.port)
MAINEOF

echo "创建 systemd 服务..."
cat > /etc/systemd/system/node-manager.service <<EOF
[Unit]
Description=Python Node Manager
After=network.target sing-box.service

[Service]
User=root
WorkingDirectory=/opt/node-manager
Environment="PATH=/opt/node-manager/venv/bin"
ExecStart=/opt/node-manager/venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "启动 Node Manager..."
systemctl daemon-reload
systemctl enable node-manager
systemctl start node-manager

echo "等待服务启动..."
sleep 3

echo "检查 Node Manager 状态..."
NM_STATUS=$(systemctl is-active node-manager)
if [ "$NM_STATUS" = "active" ]; then
    echo -e "${GREEN}Node Manager 运行正常${NC}"
else
    echo -e "${RED}Node Manager 启动失败${NC}"
    systemctl status node-manager
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Python Node Manager 安装完成${NC}"
echo ""

echo -e "${YELLOW}生成节点信息...${NC}"
echo "------------------------"

VMESS_JSON=$(cat <<EOF
{"v":"2","ps":"sing-box-node","add":"${SERVER_IP}","port":"${VMESS_PORT}","id":"${UUID}","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":""}
EOF
)

VMESS_LINK="vmess://$(echo -n "$VMESS_JSON" | base64 -w 0)"
VLESS_LINK="vless://${UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&sni=${REALITY_SNI}&fp=${REALITY_FP}#sing-box"

cat > /root/node-manager-info.txt <<EOF
====================================
  Node Manager 部署完成
====================================

服务器信息:
  IP: ${SERVER_IP}
  主机名: $(hostname)

sing-box:
  状态: $(systemctl is-active sing-box)
  API: http://${SERVER_IP}:${API_PORT}
  API Secret: ${API_SECRET}

Node Manager:
  API: http://${SERVER_IP}:${NODE_MANAGER_PORT}
  Token: ${NODE_TOKEN}
  Web UI: http://${SERVER_IP}:${NODE_MANAGER_PORT}
  测试: curl -H "Authorization: Bearer ${NODE_TOKEN}" http://${SERVER_IP}:${NODE_MANAGER_PORT}/api/node/status

节点链接:
  VLESS Reality: ${VLESS_LINK}
  VMess: ${VMESS_LINK}
  SOCKS5: ${SERVER_IP}:${SOCKS_PORT} (user: ${SOCKS_USER}, pass: ${SOCKS_PASS})

端口配置:
  VLESS: ${VLESS_PORT}
  VMESS: ${VMESS_PORT}
  SOCKS5: ${SOCKS_PORT}
  API: ${API_PORT}
  Node Manager: ${NODE_MANAGER_PORT}

====================================
EOF

cat /root/node-manager-info.txt

echo ""
echo -e "${GREEN}✅ 全流程部署完成！${NC}"
echo ""
echo "访问 Web 管理界面: http://${SERVER_IP}:${NODE_MANAGER_PORT}"
echo "请将以下信息记录到 Spring Boot 管理系统:"
echo "  - 节点IP: ${SERVER_IP}"
echo "  - 节点Token: ${NODE_TOKEN}"
echo "  - API端口: ${NODE_MANAGER_PORT}"
