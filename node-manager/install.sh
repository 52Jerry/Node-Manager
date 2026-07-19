#!/bin/bash

set -e

echo "===================================="
echo "  Python Node Manager 一键部署"
echo "===================================="

VLESS_PORT=20168
VMESS_PORT=20169
SOCKS_PORT=5001
API_PORT=9090
NODE_MANAGER_PORT=8088

REALITY_SNI="www.cloudflare.com"
REALITY_FP="chrome"

echo "[1/12] 安装系统依赖"
apt update
apt install -y \
    curl \
    openssl \
    jq \
    ufw \
    coreutils \
    python3 \
    python3-pip \
    python3-venv

echo "[2/12] 清理旧环境"
systemctl stop sing-box 2>/dev/null || true
apt remove sing-box -y 2>/dev/null || true
rm -rf /etc/sing-box
rm -rf /etc/node-manager
rm -rf /opt/node-manager

echo "[3/12] 安装 sing-box"
curl -fsSL https://sing-box.app/install.sh | sh

echo "[4/12] 生成节点参数"
SERVER_IP=$(curl -s ipv4.icanhazip.com)
UUID=$(sing-box generate uuid)
API_SECRET=$(openssl rand -hex 32)
SOCKS_USER=$(openssl rand -hex 4)
SOCKS_PASS=$(openssl rand -hex 8)
NODE_TOKEN=$(openssl rand -hex 32)

REALITY_KEY=$(sing-box generate reality-keypair)
PRIVATE_KEY=$(echo "$REALITY_KEY" | grep PrivateKey | awk '{print $2}')
PUBLIC_KEY=$(echo "$REALITY_KEY" | grep PublicKey | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 4)

echo "[5/12] 配置 sing-box"
mkdir -p /etc/sing-box

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

echo "[6/12] 检查 sing-box 配置"
sing-box check -c /etc/sing-box/config.json

echo "[7/12] 开放防火墙端口"
ufw allow ${VLESS_PORT}/tcp
ufw allow ${VMESS_PORT}/tcp
ufw allow ${SOCKS_PORT}/tcp
ufw allow ${API_PORT}/tcp
ufw allow ${NODE_MANAGER_PORT}/tcp
ufw --force enable

echo "[8/12] 启动 sing-box"
systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box
sleep 3

echo "[9/12] 安装 Node Manager"
mkdir -p /opt/node-manager
cd /opt/node-manager

python3 -m venv venv
source venv/bin/activate

cat > requirements.txt <<EOF
fastapi
uvicorn
pydantic
psutil
requests
python-jose
pyyaml
EOF

pip install -r requirements.txt

cat > main.py <<'MAINEOF'
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uuid
import json
import base64
import os
import socket
import requests

CONFIG_PATH = "/etc/node-manager/config.yaml"

def get_public_ip():
    try:
        response = requests.get("https://ipv4.icanhazip.com", timeout=5)
        return response.text.strip()
    except:
        return "127.0.0.1"

class Config:
    node_id = socket.gethostname()
    node_host = get_public_ip()
    server_port = 8088
    security_token = ""
    singbox_config = "/etc/sing-box/config.json"
    singbox_api_port = 9090
    singbox_api_secret = ""

config = Config()

if os.path.exists(CONFIG_PATH):
    import yaml
    with open(CONFIG_PATH, "r") as f:
        data = yaml.safe_load(f)
        if data.get("security"):
            config.security_token = data["security"].get("token", "")
        if data.get("singbox"):
            config.singbox_api_secret = data["singbox"].get("api_secret", "")

security = HTTPBearer()

def verify_token(credentials):
    token = credentials.credentials
    if token != config.security_token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token

app = FastAPI(title="Node Manager", version="1.0")

import psutil

@app.get("/api/node/status")
def get_status(credentials=Depends(verify_token)):
    try:
        result = os.popen("systemctl is-active sing-box").read().strip()
        singbox_status = "running" if result == "active" else "stopped"
    except:
        singbox_status = "unknown"
    
    return {
        "node": config.node_id,
        "host": config.node_host,
        "singbox": singbox_status,
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent,
        "connections": len(psutil.net_connections())
    }

@app.post("/api/user/create")
def create_user(request: dict, credentials=Depends(verify_token)):
    user_id = request.get("userId")
    protocols = request.get("protocols", [])
    
    user_uuid = str(uuid.uuid4())
    next_port = 5000
    
    vless_url = None
    vmess_url = None
    socks_info = None
    
    for proto in protocols:
        if proto == "vless":
            vless_url = f"vless://{user_uuid}@{config.node_host}:{next_port}?encryption=none&flow=&type=tcp&host=&path="
            next_port += 1
        elif proto == "vmess":
            vmess_dict = {"v":"2","ps":"NodeManager","add":config.node_host,"port":str(next_port),"id":user_uuid,"aid":"0","net":"tcp","type":"none","host":"","path":"","tls":""}
            vmess_url = "vmess://" + base64.b64encode(json.dumps(vmess_dict, separators=(",",":")).encode()).decode()
            next_port += 1
        elif proto == "socks":
            socks_info = {"host":config.node_host,"port":next_port,"username":str(uuid.uuid4())[:8],"password":str(uuid.uuid4())[:12]}
            next_port += 1
    
    return {"userId": user_id, "uuid": user_uuid, "vless": vless_url, "vmess": vmess_url, "socks": socks_info}

@app.post("/api/user/bind-proxy")
def bind_proxy(request: dict, credentials=Depends(verify_token)):
    return {"success": True}

@app.delete("/api/user/delete/{userId}")
def delete_user(userId: str, credentials=Depends(verify_token)):
    return {"success": True}

@app.post("/api/singbox/reload")
def singbox_reload(credentials=Depends(verify_token)):
    try:
        os.system("systemctl restart sing-box")
        return {"success": True}
    except:
        return {"success": False}

@app.get("/api/user/{userId}/traffic")
def get_traffic(userId: str, credentials=Depends(verify_token)):
    return {"userId": userId, "upload": 0, "download": 0, "total": 0}

@app.get("/")
def root():
    return {"message": "Node Manager API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.server_port)
MAINEOF

echo "[10/12] 创建 Node Manager 配置"
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

echo "[11/12] 创建 systemd 服务"
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

systemctl daemon-reload
systemctl enable node-manager
systemctl start node-manager
sleep 3

echo "[12/12] 生成节点信息"
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
echo "✅ 部署完成！"
echo ""
echo "请将以下信息记录到 Spring Boot 管理系统:"
echo "  - 节点IP: ${SERVER_IP}"
echo "  - 节点Token: ${NODE_TOKEN}"
echo "  - API端口: ${NODE_MANAGER_PORT}"