#!/bin/bash

set -e

echo "====================================="
echo "  Python Node Manager 一键部署"
echo "====================================="
echo ""

if ! command -v apt &> /dev/null; then
    echo "错误: 仅支持 Debian/Ubuntu 系统"
    exit 1
fi

echo "[1/4] 安装依赖..."
apt update -y
apt install -y curl openssl jq python3 python3-pip python3-venv ufw git

echo "[2/4] 安装 sing-box..."
systemctl stop sing-box 2>/dev/null || true
apt remove sing-box -y 2>/dev/null || true
curl -fsSL https://sing-box.app/install.sh | sh

echo "[3/4] 克隆项目..."
rm -rf /tmp/Node-Manager
git clone https://github.com/52Jerry/Node-Manager.git /tmp/Node-Manager

echo "[4/4] 安装 Node Manager..."
cd /tmp/Node-Manager/node-manager

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn pydantic psutil requests python-jose pyyaml

SERVER_IP=$(curl -s ipv4.icanhazip.com || curl -s api.ipify.org || hostname -I | awk '{print $1}')
UUID=$(sing-box generate uuid)
API_SECRET=$(openssl rand -hex 32)
NODE_TOKEN=$(openssl rand -hex 32)

REALITY_KEY=$(sing-box generate reality-keypair)
PRIVATE_KEY=$(echo "$REALITY_KEY" | grep PrivateKey | awk '{print $2}')
PUBLIC_KEY=$(echo "$REALITY_KEY" | grep PublicKey | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 4)

mkdir -p /etc/sing-box
cat > /etc/sing-box/config.json << EOF
{
  "log": { "level": "info" },
  "experimental": {
    "clash_api": {
      "external_controller": "0.0.0.0:9090",
      "secret": "${API_SECRET}"
    }
  },
  "dns": {
    "servers": [{ "tag": "cloudflare", "type": "tls", "server": "1.1.1.1" }],
    "final": "cloudflare"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "0.0.0.0",
      "listen_port": 20168,
      "users": [{ "uuid": "${UUID}", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "www.cloudflare.com",
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.cloudflare.com", "server_port": 443 },
          "private_key": "${PRIVATE_KEY}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    { "type": "vmess", "tag": "vmess", "listen": "0.0.0.0", "listen_port": 20169, "users": [{ "uuid": "${UUID}" }] },
    { "type": "socks", "tag": "socks", "listen": "0.0.0.0", "listen_port": 5001 }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" }
}
EOF

sing-box check -c /etc/sing-box/config.json

ufw allow 20168/tcp 20169/tcp 5001/tcp 9090/tcp 8088/tcp
ufw --force enable

systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box

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

mkdir -p /opt/node-manager
cp -r * /opt/node-manager/

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
    
    cat /root/node-manager-info.txt
else
    echo "Node Manager 启动失败"
    systemctl status node-manager
    exit 1
fi


