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

if ! command -v apt &> /dev/null; then
    echo -e "${RED}错误: 仅支持 Debian/Ubuntu 系统${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/4] 安装系统依赖${NC}"
echo "------------------------"
apt update -y
apt install -y curl openssl jq python3 python3-pip python3-venv ufw

echo -e "${GREEN}✅ 依赖安装完成${NC}"
echo ""

echo -e "${YELLOW}[2/4] 安装 sing-box${NC}"
echo "------------------------"
systemctl stop sing-box 2>/dev/null || true
apt remove sing-box -y 2>/dev/null || true
rm -rf /etc/sing-box
curl -fsSL https://sing-box.app/install.sh | sh

echo -e "${GREEN}✅ sing-box 安装完成${NC}"
echo ""

echo -e "${YELLOW}[3/4] 获取服务器信息${NC}"
echo "------------------------"
SERVER_IP=$(curl -s ipv4.icanhazip.com || curl -s api.ipify.org || hostname -I | awk '{print $1}')
echo "服务器 IP: ${SERVER_IP}"

UUID=$(sing-box generate uuid)
API_SECRET=$(openssl rand -hex 32)
NODE_TOKEN=$(openssl rand -hex 32)

REALITY_KEY=$(sing-box generate reality-keypair)
PRIVATE_KEY=$(echo "$REALITY_KEY" | grep PrivateKey | awk '{print $2}')
PUBLIC_KEY=$(echo "$REALITY_KEY" | grep PublicKey | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 4)

echo -e "${GREEN}✅ 信息获取完成${NC}"
echo ""

echo -e "${YELLOW}[4/4] 配置并启动服务${NC}"
echo "------------------------"

mkdir -p /etc/sing-box
cat > /etc/sing-box/config.json << 'EOF'
{
  "log": { "level": "info" },
  "experimental": {
    "clash_api": {
      "external_controller": "0.0.0.0:9090",
      "secret": "__API_SECRET__"
    }
  },
  "dns": {
    "servers": [{"tag": "cloudflare", "type": "tls", "server": "1.1.1.1"}],
    "final": "cloudflare"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "0.0.0.0",
      "listen_port": 20168,
      "users": [{"uuid": "__UUID__", "flow": "xtls-rprx-vision"}],
      "tls": {
        "enabled": true,
        "server_name": "www.cloudflare.com",
        "reality": {
          "enabled": true,
          "handshake": {"server": "www.cloudflare.com", "server_port": 443},
          "private_key": "__PRIVATE_KEY__",
          "short_id": ["__SHORT_ID__"]
        }
      }
    },
    {"type": "vmess", "tag": "vmess", "listen": "0.0.0.0", "listen_port": 20169, "users": [{"uuid": "__UUID__"}]},
    {"type": "socks", "tag": "socks", "listen": "0.0.0.0", "listen_port": 5001}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
EOF

sed -i "s/__UUID__/$UUID/g" /etc/sing-box/config.json
sed -i "s/__API_SECRET__/$API_SECRET/g" /etc/sing-box/config.json
sed -i "s/__PRIVATE_KEY__/$PRIVATE_KEY/g" /etc/sing-box/config.json
sed -i "s/__SHORT_ID__/$SHORT_ID/g" /etc/sing-box/config.json

echo "检查配置文件..."
sing-box check -c /etc/sing-box/config.json

echo "开放防火墙端口..."
ufw allow 20168/tcp 20169/tcp 5001/tcp 9090/tcp 8088/tcp
ufw --force enable

echo "启动 sing-box..."
systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box

sleep 3

echo -e "${GREEN}✅ sing-box 启动完成${NC}"
echo ""

echo -e "${YELLOW}[5/4] 安装 Node Manager${NC}"
echo "------------------------"

INSTALL_DIR="/opt/node-manager"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

echo "创建虚拟环境..."
python3 -m venv venv
source venv/bin/activate

echo "安装 Python 依赖..."
pip install --upgrade pip
pip install fastapi uvicorn pydantic psutil requests python-jose pyyaml

echo "创建目录结构..."
mkdir -p models monitor singbox static logs

echo "写入配置文件..."
mkdir -p /etc/node-manager
cat > /etc/node-manager/config.yaml << EOF
node:
  id: $(hostname)
  name: sing-box-node
  host: ${SERVER_IP}
server:
  port: 8088
security:
  token: ${NODE_TOKEN}
singbox:
  config: /etc/sing-box/config.json
  api_port: 9090
  api_secret: ${API_SECRET}
EOF

echo "写入 auth.py..."
cat > auth.py << 'AUTHEOF'
from fastapi import HTTPException
from fastapi.security import HTTPBearer
security = HTTPBearer()

def verify_token(credentials):
    from config import config
    if credentials.credentials != config.security.token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return credentials.credentials
AUTHEOF

echo "写入 config.py..."
cat > config.py << 'CONFIGEOF'
import os, socket, requests, yaml

class Config:
    node = type('obj', (), {'id': '', 'name': '', 'host': ''})()
    server = type('obj', (), {'port': 8088})()
    security = type('obj', (), {'token': ''})()
    singbox = type('obj', (), {'config': '', 'api_port': 9090, 'api_secret': ''})()

config = Config()

def get_public_ip():
    try:
        return requests.get("https://ipv4.icanhazip.com", timeout=5).text.strip()
    except:
        try:
            return requests.get("https://api.ipify.org", timeout=5).text.strip()
        except:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
            except:
                return "127.0.0.1"

def load_config():
    config.node.host = get_public_ip()
    config_path = "/etc/node-manager/config.yaml"
    if os.path.exists(config_path):
        with open(config_path) as f:
            data = yaml.safe_load(f)
            if data.get("node"):
                config.node.id = data["node"].get("id", socket.gethostname())
                config.node.name = data["node"].get("name", "Default")
                h = data["node"].get("host", "")
                config.node.host = get_public_ip() if h.lower() == "auto" or not h else h
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
cat > models/request.py << 'MODELSEOF'
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
cat > models/__init__.py << 'MODELINITEOF'
from .request import CreateUserRequest, CreateUserResponse, BindProxyRequest, BindProxyResponse, DeleteUserResponse, NodeStatusResponse, TrafficResponse
MODELINITEOF

echo "写入 monitor/status.py..."
cat > monitor/status.py << 'MONITORSTATUSEOF'
import psutil, os

def get_system_info():
    return {
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent,
        "connections": len(psutil.net_connections()),
        "singbox": "running" if os.popen("systemctl is-active sing-box").read().strip() == "active" else "stopped"
    }
MONITORSTATUSEOF

echo "写入 monitor/__init__.py..."
cat > monitor/__init__.py << 'MONITORINITEOF'
from .status import get_system_info
MONITORINITEOF

echo "写入 singbox/api.py..."
cat > singbox/api.py << 'SINGBOXAPEOF'
import requests, json

class SingboxAPI:
    def __init__(self, host="127.0.0.1", port=9090, secret=""):
        self.base_url = f"http://{host}:{port}"
        self.secret = secret
    
    def _get_headers(self):
        return {"Authorization": f"Bearer {self.secret}"} if self.secret else {}
    
    def is_available(self):
        try:
            return requests.get(f"{self.base_url}/version", headers=self._get_headers(), timeout=3).status_code == 200
        except:
            return False
    
    def add_proxy(self, proxy_data):
        try:
            return requests.put(f"{self.base_url}/proxies/{proxy_data.get('name', '')}",
                               headers={**self._get_headers(), "Content-Type": "application/json"},
                               data=json.dumps(proxy_data), timeout=5).status_code == 200
        except:
            return False
    
    def remove_proxy(self, proxy_name):
        try:
            return requests.delete(f"{self.base_url}/proxies/{proxy_name}", headers=self._get_headers(), timeout=3).status_code == 200
        except:
            return False
    
    def add_rule(self, rule_data):
        try:
            return requests.post(f"{self.base_url}/rules",
                                headers={**self._get_headers(), "Content-Type": "application/json"},
                                data=json.dumps(rule_data), timeout=5).status_code == 200
        except:
            return False
    
    def remove_rule(self, rule_name):
        try:
            return requests.delete(f"{self.base_url}/rules/{rule_name}", headers=self._get_headers(), timeout=3).status_code == 200
        except:
            return False
    
    def reload(self):
        try:
            return requests.post(f"{self.base_url}/configs/reload", headers=self._get_headers(), timeout=10).status_code == 200
        except:
            return False
SINGBOXAPEOF

echo "写入 singbox/manager.py..."
cat > singbox/manager.py << 'SINGBOXMANAGEREPOF'
import json, uuid, os, subprocess, base64, socket
from .api import SingboxAPI
from ..config import config

api_client = None

def get_api_client():
    global api_client
    if api_client is None:
        api_client = SingboxAPI("127.0.0.1", config.singbox.api_port, config.singbox.api_secret)
    return api_client

def is_api_available():
    try:
        return get_api_client().is_available()
    except:
        return False

def read_config():
    try:
        with open(config.singbox.config) as f:
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
    if is_api_available() and get_api_client().reload():
        return {"success": True, "method": "api"}
    try:
        subprocess.run(["systemctl", "restart", "sing-box"], check=True)
        return {"success": True, "method": "systemctl"}
    except:
        return {"success": False}

def get_next_available_port(start_port=5000):
    for port in range(start_port, 65535):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start_port

def create_user_config(user_id, protocols):
    user_uuid = str(uuid.uuid4())
    next_port = get_next_available_port(5000)
    vless_url = vmess_url = socks_info = None
    use_api = is_api_available()
    config_data = read_config()
    
    for proto in protocols:
        if proto == "vless":
            vless_port = next_port
            next_port += 1
            vless_url = f"vless://{user_uuid}@{config.node.host}:{vless_port}?encryption=none&flow=&type=tcp&host=&path="
            if not use_api:
                config_data["inbounds"].append({"type": "vless", "tag": f"user-{user_id}-vless", "listen": "0.0.0.0", "listen_port": vless_port, "users": [{"uuid": user_uuid, "flow": "xtls-rprx-vision"}]})
        
        elif proto == "vmess":
            vmess_port = next_port
            next_port += 1
            vmess_dict = {"v":"2","ps":"NodeManager","add":config.node.host,"port":str(vmess_port),"id":user_uuid,"aid":"0","net":"tcp","type":"none","host":"","path":"","tls":""}
            vmess_url = "vmess://" + base64.b64encode(json.dumps(vmess_dict, separators=(",",":")).encode()).decode()
            if not use_api:
                config_data["inbounds"].append({"type": "vmess", "tag": f"user-{user_id}-vmess", "listen": "0.0.0.0", "listen_port": vmess_port, "users": [{"uuid": user_uuid}]})
        
        elif proto == "socks":
            socks_port = next_port
            next_port += 1
            socks_user = str(uuid.uuid4())[:8]
            socks_pass = str(uuid.uuid4())[:12]
            socks_info = {"host":config.node.host,"port":socks_port,"username":socks_user,"password":socks_pass}
            if not use_api:
                config_data["inbounds"].append({"type": "socks", "tag": f"user-{user_id}-socks", "listen": "0.0.0.0", "listen_port": socks_port, "users": [{"username": socks_user, "password": socks_pass}]})
    
    if not use_api:
        write_config(config_data)
        reload_singbox()
    
    return {"userId": user_id, "uuid": user_uuid, "vless": vless_url, "vmess": vmess_url, "socks": socks_info}

def bind_proxy_to_user(user_id, proxy_data):
    use_api = is_api_available()
    if not use_api:
        config_data = read_config()
        tag = f"user-{user_id}-proxy"
        outbound = {"type": "socks", "tag": tag, "server": proxy_data.get("server"), "server_port": proxy_data.get("port", 1080)}
        if proxy_data.get("username"):
            outbound["username"] = proxy_data.get("username")
            outbound["password"] = proxy_data.get("password")
        config_data["outbounds"].append(outbound)
        write_config(config_data)
        reload_singbox()
    return {"success": True, "userId": user_id}

def delete_user_config(user_id):
    use_api = is_api_available()
    if not use_api:
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
cat > singbox/__init__.py << 'SINGBOXINITEOF'
from .manager import reload_singbox, is_api_available, create_user_config, bind_proxy_to_user, delete_user_config
SINGBOXINITEOF

echo "写入 static/index.html..."
cat > static/index.html << 'INDEXEOF'
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
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: #16213e; padding: 20px; border-radius: 12px; }
        .card .label { color: #888; font-size: 14px; margin-bottom: 8px; }
        .card .value { font-size: 24px; font-weight: bold; }
        .card .value.running { color: #00ff88; }
        .card .value.stopped { color: #ff4757; }
        .section { background: #16213e; padding: 25px; border-radius: 12px; margin-bottom: 20px; }
        .section h2 { font-size: 20px; margin-bottom: 20px; color: #00d4ff; }
        .btn { background: #00d4ff; color: #1a1a2e; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: bold; }
        .btn:hover { background: #00b8e6; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #888; }
        .form-group input { width: 100%; padding: 10px; background: #0f3460; border: none; border-radius: 6px; color: #fff; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); justify-content: center; align-items: center; z-index: 1000; }
        .modal.active { display: flex; }
        .modal-content { background: #16213e; padding: 30px; border-radius: 12px; width: 90%; max-width: 500px; }
        .result { background: #0f3460; padding: 15px; border-radius: 8px; margin-top: 15px; font-family: monospace; font-size: 12px; }
        .success { color: #00ff88; }
        .error { color: #ff4757; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Node Manager</h1>
        </div>
        <div class="cards">
            <div class="card"><div class="label">节点状态</div><div class="value" id="node-name">-</div></div>
            <div class="card"><div class="label">sing-box</div><div class="value" id="singbox-status">...</div></div>
            <div class="card"><div class="label">CPU</div><div class="value" id="cpu-usage">...</div></div>
            <div class="card"><div class="label">内存</div><div class="value" id="memory-usage">...</div></div>
        </div>
        <div class="section">
            <h2>用户管理</h2>
            <button class="btn" onclick="showModal()">创建用户</button>
            <table width="100%" style="margin-top:20px;border-collapse:collapse;">
                <tr><th style="text-align:left;padding:10px;color:#888;">用户ID</th><th style="text-align:left;padding:10px;color:#888;">协议</th><th style="text-align:left;padding:10px;color:#888;">UUID</th></tr>
                <tbody id="user-list"><tr><td colspan="3" style="text-align:center;color:#888;">暂无用户</td></tr></tbody>
            </table>
        </div>
        <div class="section">
            <h2>快捷操作</h2>
            <button class="btn" onclick="reloadSingbox()">重启 sing-box</button>
            <button class="btn" onclick="refreshStatus()">刷新状态</button>
        </div>
    </div>
    <div class="modal" id="modal">
        <div class="modal-content">
            <h3>创建用户</h3>
            <div class="form-group"><label>用户ID</label><input type="text" id="user-id" placeholder="例如: 10001"></div>
            <button class="btn" onclick="createUser()">创建</button>
            <div class="result" id="result" style="display:none;"></div>
        </div>
    </div>
    <script>
        const TOKEN = 'abc123456789';
        function getHeaders() { return { 'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json' }; }
        async function refreshStatus() {
            try {
                const r = await fetch('/api/node/status', { headers: getHeaders() });
                const d = await r.json();
                document.getElementById('node-name').textContent = d.node;
                document.getElementById('singbox-status').textContent = d.singbox;
                document.getElementById('singbox-status').className = 'value ' + (d.singbox === 'running' ? 'running' : 'stopped');
                document.getElementById('cpu-usage').textContent = d.cpu + '%';
                document.getElementById('memory-usage').textContent = d.memory + '%';
            } catch(e) { console.error(e); }
        }
        function showModal() { document.getElementById('modal').classList.add('active'); }
        async function createUser() {
            const id = document.getElementById('user-id').value;
            if (!id) { alert('请输入用户ID'); return; }
            try {
                const r = await fetch('/api/user/create', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ userId: id, protocols: ['vless', 'vmess', 'socks'] }) });
                const d = await r.json();
                const el = document.getElementById('result');
                el.textContent = 'UUID: ' + d.uuid + '\nVLESS: ' + d.vless + '\nVMess: ' + d.vmess + '\nSOCKS5: ' + JSON.stringify(d.socks);
                el.className = 'result success';
                el.style.display = 'block';
            } catch(e) {
                const el = document.getElementById('result');
                el.textContent = '错误: ' + e.message;
                el.className = 'result error';
                el.style.display = 'block';
            }
        }
        async function reloadSingbox() {
            if (!confirm('确定重启?')) return;
            const r = await fetch('/api/singbox/reload', { method: 'POST', headers: getHeaders() });
            const d = await r.json();
            alert(d.success ? '重启成功' : '重启失败');
        }
        refreshStatus();
    </script>
</body>
</html>
INDEXEOF

echo "写入 main.py..."
cat > main.py << 'MAINEOF'
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

app = FastAPI(title="Node Manager", version="1.0")

from config import config
from auth import verify_token
from models.request import CreateUserRequest, CreateUserResponse, BindProxyRequest, BindProxyResponse, DeleteUserResponse, NodeStatusResponse, TrafficResponse
from singbox.manager import reload_singbox, is_api_available, create_user_config, bind_proxy_to_user, delete_user_config
from monitor.status import get_system_info

@app.get("/")
def root():
    return FileResponse("static/index.html")

@app.get("/api/node/status", response_model=NodeStatusResponse)
def get_status(token: str = Depends(verify_token)):
    info = get_system_info()
    return {"node": config.node.id, "host": config.node.host, "singbox": info["singbox"], "cpu": info["cpu"], "memory": info["memory"], "connections": info["connections"], "api_available": is_api_available()}

@app.post("/api/user/create", response_model=CreateUserResponse)
def create_user(request: CreateUserRequest, token: str = Depends(verify_token)):
    return create_user_config(request.userId, request.protocols)

@app.post("/api/user/bind-proxy", response_model=BindProxyResponse)
def bind_proxy(request: BindProxyRequest, token: str = Depends(verify_token)):
    return bind_proxy_to_user(request.userId, request.proxy)

@app.delete("/api/user/delete/{userId}", response_model=DeleteUserResponse)
def delete_user(userId: str, token: str = Depends(verify_token)):
    return delete_user_config(userId)

@app.get("/api/user/{userId}/traffic", response_model=TrafficResponse)
def get_traffic(userId: str, token: str = Depends(verify_token)):
    return {"userId": userId, "upload": 0, "download": 0, "total": 0}

@app.post("/api/singbox/reload")
def singbox_reload(token: str = Depends(verify_token)):
    return reload_singbox()

@app.get("/api/singbox/api/status")
def api_status(token: str = Depends(verify_token)):
    return {"available": is_api_available()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.server.port)
MAINEOF

echo "创建 systemd 服务..."
cat > /etc/systemd/system/node-manager.service << 'EOF'
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

sleep 3

if systemctl is-active node-manager; then
    VMESS_LINK="vmess://$(echo -n "{\"v\":\"2\",\"ps\":\"sing-box-node\",\"add\":\"${SERVER_IP}\",\"port\":\"20169\",\"id\":\"${UUID}\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\"}" | base64 -w 0)"
    VLESS_LINK="vless://${UUID}@${SERVER_IP}:20168?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&sni=www.cloudflare.com&fp=chrome#sing-box"
    
    cat > /root/node-manager-info.txt << EOF
====================================
  Node Manager 部署完成
====================================
服务器信息:
  IP: ${SERVER_IP}
  主机名: $(hostname)
sing-box:
  API: http://${SERVER_IP}:9090
  API Secret: ${API_SECRET}
Node Manager:
  API: http://${SERVER_IP}:8088
  Token: ${NODE_TOKEN}
  Web UI: http://${SERVER_IP}:8088
节点链接:
  VLESS Reality: ${VLESS_LINK}
  VMess: ${VMESS_LINK}
  SOCKS5: ${SERVER_IP}:5001
EOF
    
    echo ""
    echo -e "${GREEN}====================================${NC}"
    echo -e "${GREEN}  Node Manager 部署完成${NC}"
    echo -e "${GREEN}====================================${NC}"
    echo ""
    cat /root/node-manager-info.txt
else
    echo -e "${RED}Node Manager 启动失败${NC}"
    systemctl status node-manager
    exit 1
fi

