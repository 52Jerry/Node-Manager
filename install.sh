#!/usr/bin/env bash

set -Eeuo pipefail

APP_DIR="/opt/node-manager"
CONFIG_DIR="/etc/node-manager"
SINGBOX_CONFIG="/etc/sing-box/config.json"
SERVICE_FILE="/etc/systemd/system/node-manager.service"
REPO_ARCHIVE_URL="${NODE_MANAGER_ARCHIVE_URL:-https://github.com/52Jerry/Node-Manager/archive/refs/heads/main.tar.gz}"
TEMP_DIR=""
APP_VERSION=""
INSTALLED_APP_VERSION=""
UPDATE_NODE_MANAGER=1
FRESH_SINGBOX_CONFIG=0
TEST_USER_ID="node-manager-test"
TEST_USER_UUID=""
TEST_SOCKS_USER=""
TEST_SOCKS_PASSWORD=""
TEST_VLESS_URL=""
TEST_VMESS_URL=""

log() { printf '[node-manager] %s\n' "$*"; }
fail() { printf '[node-manager] ERROR: %s\n' "$*" >&2; exit 1; }
cleanup() { [ -z "$TEMP_DIR" ] || rm -rf -- "$TEMP_DIR"; }
trap cleanup EXIT

[ "${EUID}" -eq 0 ] || fail "run this installer as root"
command -v apt-get >/dev/null 2>&1 || fail "only Debian and Ubuntu are supported"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/main.py" ]; then
  SOURCE_DIR="$SCRIPT_DIR"
  VERSION_FILE="$SCRIPT_DIR/VERSION"
elif [ -f "$SCRIPT_DIR/node-manager/main.py" ]; then
  SOURCE_DIR="$SCRIPT_DIR/node-manager"
  VERSION_FILE="$SCRIPT_DIR/VERSION"
else
  TEMP_DIR="$(mktemp -d)"
  log "downloading application source"
  curl -fsSL "$REPO_ARCHIVE_URL" -o "$TEMP_DIR/source.tar.gz"
  tar -xzf "$TEMP_DIR/source.tar.gz" -C "$TEMP_DIR"
  SOURCE_DIR="$(find "$TEMP_DIR" -type f -path '*/node-manager/main.py' -printf '%h\n' | head -n 1)"
  [ -n "$SOURCE_DIR" ] || fail "node-manager source was not found in the archive"
  VERSION_FILE="$(dirname "$SOURCE_DIR")/VERSION"
fi

[ -f "$VERSION_FILE" ] || VERSION_FILE="$SOURCE_DIR/VERSION"
[ -f "$VERSION_FILE" ] || fail "VERSION file was not found"
APP_VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
[ -n "$APP_VERSION" ] || fail "VERSION is empty"
if [ -f "$APP_DIR/VERSION" ]; then
  INSTALLED_APP_VERSION="$(tr -d '[:space:]' < "$APP_DIR/VERSION")"
fi
if [ "$INSTALLED_APP_VERSION" = "$APP_VERSION" ]; then
  UPDATE_NODE_MANAGER=0
  log "Node Manager $APP_VERSION is already installed; keeping the current application"
elif [ -n "$INSTALLED_APP_VERSION" ]; then
  log "Node Manager update required: $INSTALLED_APP_VERSION -> $APP_VERSION"
else
  log "Node Manager is not installed; installing $APP_VERSION"
fi

log "installing system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl jq openssl python3 python3-pip python3-venv ufw

INSTALLED_SINGBOX_VERSION="$(sing-box version 2>/dev/null | awk 'NR == 1 {print $3}')"
LATEST_SINGBOX_VERSION="$(curl -fsSL --max-time 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r '.tag_name // empty' | sed 's/^v//')"

if [ -z "$INSTALLED_SINGBOX_VERSION" ]; then
  log "sing-box is not installed; installing latest stable version"
  curl -fsSL https://sing-box.app/install.sh | sh
elif [ -z "$LATEST_SINGBOX_VERSION" ]; then
  log "could not query the latest sing-box version; keeping installed version $INSTALLED_SINGBOX_VERSION"
elif dpkg --compare-versions "$INSTALLED_SINGBOX_VERSION" lt "$LATEST_SINGBOX_VERSION"; then
  log "sing-box update required: $INSTALLED_SINGBOX_VERSION -> $LATEST_SINGBOX_VERSION"
  systemctl stop sing-box 2>/dev/null || true
  apt-get remove -y sing-box 2>/dev/null || true
  curl -fsSL https://sing-box.app/install.sh | sh
else
  log "sing-box $INSTALLED_SINGBOX_VERSION is current; keeping the installed version"
fi

SERVER_IP="${NODE_MANAGER_HOST:-$(curl -4fsS --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}')}"
NODE_TOKEN="$(openssl rand -hex 32)"
API_SECRET="$(openssl rand -hex 32)"
SOCKS_BOOTSTRAP_USER=""
SOCKS_BOOTSTRAP_PASSWORD=""

install -d -m 0750 /etc/sing-box
if [ -f "$SINGBOX_CONFIG" ]; then
  BACKUP_PATH="${SINGBOX_CONFIG}.backup.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a "$SINGBOX_CONFIG" "$BACKUP_PATH"
  chmod 0600 "$BACKUP_PATH"
  log "preserved existing sing-box config at $BACKUP_PATH"
  EXISTING_SECRET="$(jq -r '.experimental.clash_api.secret // empty' "$SINGBOX_CONFIG")"
  [ -z "$EXISTING_SECRET" ] || API_SECRET="$EXISTING_SECRET"
else
  FRESH_SINGBOX_CONFIG=1
  TEST_USER_UUID="$(sing-box generate uuid)"
  REALITY_KEYS="$(sing-box generate reality-keypair)"
  PRIVATE_KEY="$(printf '%s\n' "$REALITY_KEYS" | awk '/PrivateKey/ {print $2}')"
  PUBLIC_KEY="$(printf '%s\n' "$REALITY_KEYS" | awk '/PublicKey/ {print $2}')"
  SHORT_ID="$(openssl rand -hex 4)"
  TEST_SOCKS_USER="$TEST_USER_ID"
  TEST_SOCKS_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"
  SOCKS_BOOTSTRAP_USER="$TEST_SOCKS_USER"
  SOCKS_BOOTSTRAP_PASSWORD="$TEST_SOCKS_PASSWORD"
  cat > "$SINGBOX_CONFIG" <<EOF
{
  "log": {"level": "info"},
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "$API_SECRET"
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
      "users": [{"name": "node-manager:$TEST_USER_ID", "uuid": "$TEST_USER_UUID", "flow": "xtls-rprx-vision"}],
      "tls": {
        "enabled": true,
        "server_name": "www.cloudflare.com",
        "reality": {
          "enabled": true,
          "handshake": {"server": "www.cloudflare.com", "server_port": 443},
          "private_key": "$PRIVATE_KEY",
          "short_id": ["$SHORT_ID"]
        }
      }
    },
    {
      "type": "vmess",
      "tag": "vmess",
      "listen": "0.0.0.0",
      "listen_port": 20169,
      "users": [{"name": "node-manager:$TEST_USER_ID", "uuid": "$TEST_USER_UUID"}]
    },
    {
      "type": "socks",
      "tag": "socks",
      "listen": "0.0.0.0",
      "listen_port": 5001,
      "users": [{"username": "$TEST_SOCKS_USER", "password": "$TEST_SOCKS_PASSWORD"}]
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "direct", "tag": "node-manager-out:$TEST_USER_ID"}
  ],
  "route": {
    "rules": [{"auth_user": ["node-manager:$TEST_USER_ID", "$TEST_SOCKS_USER"], "action": "route", "outbound": "node-manager-out:$TEST_USER_ID"}],
    "final": "direct"
  }
}
EOF
  TEST_VLESS_URL="vless://$TEST_USER_UUID@$SERVER_IP:20168?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=$PUBLIC_KEY&sid=$SHORT_ID&sni=www.cloudflare.com&fp=chrome#$TEST_USER_ID"
  TEST_VMESS_JSON="$(jq -nc --arg ps "$TEST_USER_ID" --arg add "$SERVER_IP" --arg id "$TEST_USER_UUID" '{v:"2",ps:$ps,add:$add,port:"20169",id:$id,aid:"0",net:"tcp",type:"none",host:"",path:"",tls:""}')"
  TEST_VMESS_URL="vmess://$(printf '%s' "$TEST_VMESS_JSON" | base64 -w 0)"
fi

for tag in vless-reality vmess socks; do
  jq -e --arg tag "$tag" '.inbounds[] | select(.tag == $tag)' "$SINGBOX_CONFIG" >/dev/null \
    || fail "required sing-box inbound is missing: $tag"
done

if [ "$(jq -r '[.inbounds[] | select(.tag == "socks") | .users // []] | add | length' "$SINGBOX_CONFIG")" -eq 0 ]; then
  SOCKS_BOOTSTRAP_USER="node-manager-bootstrap"
  SOCKS_BOOTSTRAP_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"
fi

SINGBOX_TEMP="$(mktemp /etc/sing-box/config.XXXXXX.json)"
jq \
  --arg secret "$API_SECRET" \
  --arg socks_user "$SOCKS_BOOTSTRAP_USER" \
  --arg socks_password "$SOCKS_BOOTSTRAP_PASSWORD" \
  '
    .experimental = (.experimental // {}) |
    .experimental.clash_api = (.experimental.clash_api // {}) |
    .experimental.clash_api.external_controller = "127.0.0.1:9090" |
    .experimental.clash_api.secret = $secret |
    .inbounds |= map(
      if .tag == "socks" and ((.users // []) | length) == 0 and $socks_user != ""
      then .users = [{"username": $socks_user, "password": $socks_password}]
      else . end
    )
  ' "$SINGBOX_CONFIG" > "$SINGBOX_TEMP"
sing-box check -c "$SINGBOX_TEMP"
install -o root -g sing-box -m 0640 "$SINGBOX_TEMP" "$SINGBOX_CONFIG"
rm -f -- "$SINGBOX_TEMP"

if [ "$UPDATE_NODE_MANAGER" -eq 1 ]; then
  log "installing Node Manager application $APP_VERSION"
  install -d -m 0755 "$APP_DIR" "$APP_DIR/models" "$APP_DIR/monitor" "$APP_DIR/singbox" "$APP_DIR/static"
  install -m 0644 "$SOURCE_DIR"/*.py "$APP_DIR/"
  install -m 0644 "$SOURCE_DIR/models"/*.py "$APP_DIR/models/"
  install -m 0644 "$SOURCE_DIR/monitor"/*.py "$APP_DIR/monitor/"
  install -m 0644 "$SOURCE_DIR/singbox"/*.py "$APP_DIR/singbox/"
  install -m 0644 "$SOURCE_DIR/static/index.html" "$APP_DIR/static/index.html"
  install -m 0644 "$SOURCE_DIR/requirements.txt" "$APP_DIR/requirements.txt"
  install -m 0644 "$VERSION_FILE" "$APP_DIR/VERSION"

  python3 -m venv "$APP_DIR/venv"
  "$APP_DIR/venv/bin/pip" install --upgrade pip wheel
  "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
fi

install -d -m 0750 "$CONFIG_DIR"
install -d -o root -g root -m 0750 /var/lib/node-manager
if [ "$FRESH_SINGBOX_CONFIG" -eq 1 ] && [ ! -f /var/lib/node-manager/users.json ]; then
  jq -n \
    --arg user_id "$TEST_USER_ID" \
    --arg socks_username "$TEST_SOCKS_USER" \
    --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{version: 1, users: {($user_id): {socksUsername: $socks_username, createdAt: $created_at}}}' \
    > /var/lib/node-manager/users.json
  chmod 0600 /var/lib/node-manager/users.json
fi
for state_file in users.json traffic.json idempotency.json; do
  if [ -f "/var/lib/node-manager/$state_file" ]; then
    chmod 0600 "/var/lib/node-manager/$state_file"
  fi
done
if [ -f "$CONFIG_DIR/config.yaml" ]; then
  EXISTING_TOKEN="$(awk '/^[[:space:]]*token:/ {print $2; exit}' "$CONFIG_DIR/config.yaml" | tr -d '"' | tr -d "'")"
  [ -z "$EXISTING_TOKEN" ] || NODE_TOKEN="$EXISTING_TOKEN"
fi
cat > "$CONFIG_DIR/config.yaml" <<EOF
node:
  id: "$(hostname)"
  name: "sing-box-node"
  host: "$SERVER_IP"
server:
  port: 8088
security:
  token: "$NODE_TOKEN"
singbox:
  config: "$SINGBOX_CONFIG"
  api_port: 9090
  api_secret: "$API_SECRET"
  vless_tag: "vless-reality"
  vmess_tag: "vmess"
  socks_tag: "socks"
EOF
chmod 0640 "$CONFIG_DIR/config.yaml"

cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Python Node Manager
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/node-manager
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/node-manager/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8088
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

log "configuring firewall"
ufw allow 22/tcp >/dev/null
ufw allow 20168/tcp >/dev/null
ufw allow 20169/tcp >/dev/null
ufw allow 5001/tcp >/dev/null
ufw allow 5001/udp >/dev/null
ufw allow 8088/tcp >/dev/null
ufw --force delete allow 9090/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null

systemctl daemon-reload
systemctl enable sing-box node-manager >/dev/null
systemctl restart sing-box
systemctl restart node-manager

for _ in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8088/health >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:8088/health >/dev/null || {
  journalctl -u node-manager -n 80 --no-pager >&2
  fail "Node Manager health check failed"
}

INFO_FILE="/root/node-manager-info.txt"
cat > "$INFO_FILE" <<EOF
Node Manager deployment
=======================
Node Manager version: $APP_VERSION
sing-box version: $(sing-box version | awk 'NR == 1 {print $3}')
Server: $SERVER_IP
Web UI: http://$SERVER_IP:8088/
OpenAPI UI: http://$SERVER_IP:8088/docs
OpenAPI JSON: http://$SERVER_IP:8088/openapi.json
API token: $NODE_TOKEN
Clash API: http://127.0.0.1:9090 (local only)
Clash API secret: $API_SECRET
EOF
if [ "$FRESH_SINGBOX_CONFIG" -eq 1 ]; then
  cat >> "$INFO_FILE" <<EOF
Test user: $TEST_USER_ID
Test VLESS: $TEST_VLESS_URL
Test VMess: $TEST_VMESS_URL
Test SOCKS5: $SERVER_IP:5001
Test SOCKS5 username: $TEST_SOCKS_USER
Test SOCKS5 password: $TEST_SOCKS_PASSWORD
EOF
fi
chmod 0600 "$INFO_FILE"

log "deployment completed"
cat "$INFO_FILE"
