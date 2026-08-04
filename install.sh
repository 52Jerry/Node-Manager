#!/usr/bin/env bash

set -Eeuo pipefail

APP_DIR="/opt/node-manager"
CONFIG_DIR="/etc/node-manager"
SINGBOX_CONFIG="/etc/sing-box/config.json"
SERVICE_FILE="/etc/systemd/system/node-manager.service"
REPO_ARCHIVE_URL="${NODE_MANAGER_ARCHIVE_URL:-https://github.com/52Jerry/Node-Manager/archive/refs/heads/main.tar.gz}"
TEMP_DIR=""
REGISTRATION_TEMP_DIR=""
SINGBOX_TEMP_DIR=""
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
CONTROL_PLANE_REGISTRATION_STATUS="not-configured"
CONTROL_PLANE_NODE_ID=""
CONTROL_PLANE_RESPONSE=""
CONTROL_PLANE_INSTALL_TOKEN="${CONTROL_PLANE_INSTALL_TOKEN:-}"
APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-300}"

log() { printf '[node-manager] %s\n' "$*"; }
fail() { printf '[node-manager] ERROR: %s\n' "$*" >&2; exit 1; }
cleanup() {
  [ -z "$REGISTRATION_TEMP_DIR" ] || rm -rf -- "$REGISTRATION_TEMP_DIR"
  [ -z "$SINGBOX_TEMP_DIR" ] || rm -rf -- "$SINGBOX_TEMP_DIR"
  [ -z "$TEMP_DIR" ] || rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

[ "${EUID}" -eq 0 ] || fail "run this installer as root"
command -v apt-get >/dev/null 2>&1 || fail "only Debian and Ubuntu are supported"
case "$APT_LOCK_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) fail "APT_LOCK_TIMEOUT_SECONDS must be a non-negative integer" ;;
esac

apt_get() {
  apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_TIMEOUT_SECONDS" "$@"
}

# 页面一键安装会传入 Control Plane 地址和短时一次性安装码。
# 只传地址时仍可隐藏输入长期注册令牌，环境变量方式也继续兼容。
[ "$#" -le 2 ] || fail "usage: bash install.sh [CONTROL_PLANE_URL] [ONE_TIME_INSTALL_TOKEN]"
if [ "$#" -ge 1 ]; then
  CONTROL_PLANE_URL="${1%/}"
  case "$CONTROL_PLANE_URL" in
    http://*|https://*) ;;
    *) fail "CONTROL_PLANE_URL must start with http:// or https://" ;;
  esac
  CONTROL_PLANE_REGISTRATION_REQUIRED="${CONTROL_PLANE_REGISTRATION_REQUIRED:-1}"
  if [ "$#" -eq 2 ]; then
    CONTROL_PLANE_INSTALL_TOKEN="$2"
    [ -n "$CONTROL_PLANE_INSTALL_TOKEN" ] || fail "one-time install token cannot be empty"
  elif [ -z "$CONTROL_PLANE_INSTALL_TOKEN" ] && [ -z "${CONTROL_PLANE_REGISTRATION_TOKEN:-}" ]; then
    [ -r /dev/tty ] || fail "a registration token is required; set CONTROL_PLANE_REGISTRATION_TOKEN for non-interactive installation"
    printf '请输入 Control Plane 节点注册令牌: ' > /dev/tty
    IFS= read -r -s CONTROL_PLANE_REGISTRATION_TOKEN < /dev/tty
    printf '\n' > /dev/tty
    [ -n "$CONTROL_PLANE_REGISTRATION_TOKEN" ] || fail "registration token cannot be empty"
  fi
fi

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
apt_get update -y
apt_get install -y ca-certificates curl jq openssl python3 python3-pip python3-venv ufw

INSTALLED_SINGBOX_VERSION=""
if command -v sing-box >/dev/null 2>&1; then
  INSTALLED_SINGBOX_VERSION="$(sing-box version 2>/dev/null | awk 'NR == 1 {print $3}' || true)"
fi
LATEST_SINGBOX_VERSION="${SINGBOX_VERSION:-}"
if [ -z "$LATEST_SINGBOX_VERSION" ]; then
  LATEST_SINGBOX_VERSION="$(
    curl --retry 3 --retry-delay 2 --retry-all-errors -fsSL \
      --connect-timeout 10 --max-time 30 \
      https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null \
      | jq -r '.tag_name // empty' \
      | sed 's/^v//' \
      || true
  )"
fi

install_singbox() {
  local version="$1"
  local architecture package_name package_url package_path

  [ -n "$version" ] || fail "could not determine the latest sing-box version; set SINGBOX_VERSION and retry"
  architecture="$(dpkg --print-architecture)"
  case "$architecture" in
    amd64|arm64|armhf|i386) ;;
    *) fail "unsupported sing-box architecture: $architecture" ;;
  esac

  package_name="sing-box_${version}_linux_${architecture}.deb"
  package_url="https://github.com/SagerNet/sing-box/releases/download/v${version}/${package_name}"
  SINGBOX_TEMP_DIR="$(mktemp -d)"
  chmod 0700 "$SINGBOX_TEMP_DIR"
  package_path="$SINGBOX_TEMP_DIR/$package_name"

  log "downloading sing-box $version for $architecture"
  curl --retry 3 --retry-delay 2 --retry-all-errors -fL \
    --connect-timeout 10 --max-time 180 \
    "$package_url" -o "$package_path" \
    || fail "could not download sing-box package from GitHub Releases"
  apt_get install -y "$package_path"
  command -v sing-box >/dev/null 2>&1 || fail "sing-box installation completed without installing the executable"
  rm -rf -- "$SINGBOX_TEMP_DIR"
  SINGBOX_TEMP_DIR=""
}

is_packaged_default_singbox_config() {
  local expected_md5 current_md5

  [ -f "$SINGBOX_CONFIG" ] || return 1
  expected_md5="$(
    dpkg-query -W -f='${Conffiles}\n' sing-box 2>/dev/null \
      | awk -v path="$SINGBOX_CONFIG" '$1 == path {print $2; exit}' \
      || true
  )"
  [ -n "$expected_md5" ] || return 1
  current_md5="$(md5sum "$SINGBOX_CONFIG" | awk '{print $1}')"
  [ "$current_md5" = "$expected_md5" ]
}

if [ -z "$INSTALLED_SINGBOX_VERSION" ]; then
  log "sing-box is not installed; installing latest stable version"
  install_singbox "$LATEST_SINGBOX_VERSION"
elif [ -z "$LATEST_SINGBOX_VERSION" ]; then
  log "could not query the latest sing-box version; keeping installed version $INSTALLED_SINGBOX_VERSION"
elif dpkg --compare-versions "$INSTALLED_SINGBOX_VERSION" lt "$LATEST_SINGBOX_VERSION"; then
  log "sing-box update required: $INSTALLED_SINGBOX_VERSION -> $LATEST_SINGBOX_VERSION"
  systemctl stop sing-box 2>/dev/null || true
  install_singbox "$LATEST_SINGBOX_VERSION"
else
  log "sing-box $INSTALLED_SINGBOX_VERSION is current; keeping the installed version"
fi

SERVER_IP="${NODE_MANAGER_HOST:-$(curl -4fsS --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}')}"
NODE_TOKEN="$(openssl rand -hex 32)"
API_SECRET="$(openssl rand -hex 32)"
SOCKS_BOOTSTRAP_USER=""
SOCKS_BOOTSTRAP_PASSWORD=""

install -d -m 0750 /etc/sing-box
if [ -f "$SINGBOX_CONFIG" ] && ! is_packaged_default_singbox_config; then
  BACKUP_PATH="${SINGBOX_CONFIG}.backup.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a "$SINGBOX_CONFIG" "$BACKUP_PATH"
  chmod 0600 "$BACKUP_PATH"
  log "preserved existing sing-box config at $BACKUP_PATH"
  EXISTING_SECRET="$(jq -r '.experimental.clash_api.secret // empty' "$SINGBOX_CONFIG")"
  [ -z "$EXISTING_SECRET" ] || API_SECRET="$EXISTING_SECRET"
else
  if [ -f "$SINGBOX_CONFIG" ]; then
    log "replacing the sing-box package default config with the Node Manager config"
  fi
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
EXISTING_NODE_ID=""
if [ -f "$CONFIG_DIR/config.yaml" ]; then
  EXISTING_NODE_ID="$(awk '
    /^[^[:space:]]/ {section = ($1 == "node:") ? "node" : ""}
    section == "node" && /^[[:space:]]+id:/ {print $2; exit}
  ' "$CONFIG_DIR/config.yaml" | tr -d '"' | tr -d "'")"
fi
NODE_ID="${NODE_MANAGER_NODE_ID:-${EXISTING_NODE_ID:-$(hostname)}}"
NODE_NAME="${NODE_MANAGER_NAME:-$NODE_ID}"
cat > "$CONFIG_DIR/config.yaml" <<EOF
node:
  id: "$NODE_ID"
  name: "$NODE_NAME"
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

register_with_control_plane() {
  local control_plane_url="${CONTROL_PLANE_URL:-}"
  local install_token="${CONTROL_PLANE_INSTALL_TOKEN:-}"
  local registration_token="${CONTROL_PLANE_REGISTRATION_TOKEN:-}"
  local registration_required="${CONTROL_PLANE_REGISTRATION_REQUIRED:-0}"
  local public_url="${NODE_MANAGER_PUBLIC_URL:-http://$SERVER_IP:8088}"
  local max_users="${NODE_MANAGER_MAX_USERS:-500}"
  local response_file request_file header_file http_code delay

  if [ -z "$control_plane_url" ] && [ -z "$install_token" ] && [ -z "$registration_token" ]; then
    CONTROL_PLANE_REGISTRATION_STATUS="not-configured"
    [ "$registration_required" != "1" ] || fail "control-plane registration is required but the URL and registration credential are missing"
    return 0
  fi
  if [ -z "$control_plane_url" ] || { [ -z "$install_token" ] && [ -z "$registration_token" ]; }; then
    CONTROL_PLANE_REGISTRATION_STATUS="incomplete-configuration"
    [ "$registration_required" != "1" ] || fail "control-plane registration requires a URL and either an install token or registration token"
    log "control-plane registration skipped because its configuration is incomplete"
    return 0
  fi
  case "$max_users" in
    ''|*[!0-9]*) fail "NODE_MANAGER_MAX_USERS must be a positive integer" ;;
  esac
  [ "$max_users" -ge 1 ] || fail "NODE_MANAGER_MAX_USERS must be a positive integer"

  control_plane_url="${control_plane_url%/}"
  public_url="${public_url%/}"
  REGISTRATION_TEMP_DIR="$(mktemp -d)"
  chmod 0700 "$REGISTRATION_TEMP_DIR"
  response_file="$REGISTRATION_TEMP_DIR/response.json"
  request_file="$REGISTRATION_TEMP_DIR/request.json"
  header_file="$REGISTRATION_TEMP_DIR/headers.txt"
  : > "$response_file"
  : > "$request_file"
  : > "$header_file"
  chmod 0600 "$response_file" "$request_file" "$header_file"
  if [ -n "$install_token" ]; then
    printf 'X-Install-Token: %s\n' "$install_token" > "$header_file"
  else
    printf 'X-Registration-Token: %s\n' "$registration_token" > "$header_file"
  fi
  jq -nc \
    --arg nodeId "$NODE_ID" \
    --arg name "$NODE_NAME" \
    --arg baseUrl "$public_url" \
    --arg apiToken "$NODE_TOKEN" \
    --arg host "$SERVER_IP" \
    --arg managerVersion "$APP_VERSION" \
    --argjson maxUsers "$max_users" \
    '{nodeId:$nodeId,name:$name,baseUrl:$baseUrl,apiToken:$apiToken,host:$host,managerVersion:$managerVersion,maxUsers:$maxUsers}' \
    > "$request_file"
  for delay in 0 2 4 8 16; do
    [ "$delay" -eq 0 ] || sleep "$delay"
    log "registering Node Manager with control-plane"
    http_code="$(curl -sS --connect-timeout 10 --max-time 30 \
      -o "$response_file" -w '%{http_code}' \
      -X POST "$control_plane_url/api/control/agent/register" \
      -H 'Content-Type: application/json' \
      --header "@$header_file" \
      --data-binary "@$request_file" \
      || true)"
    [ -n "$http_code" ] || http_code="000"
    if [ "$http_code" = "200" ]; then
      CONTROL_PLANE_NODE_ID="$(jq -r '.id // empty' "$response_file" 2>/dev/null || true)"
      CONTROL_PLANE_REGISTRATION_STATUS="registered"
      CONTROL_PLANE_RESPONSE="$(jq -r 'if .created then "created" else "updated" end' "$response_file" 2>/dev/null || true)"
      install_token=""
      CONTROL_PLANE_INSTALL_TOKEN=""
      registration_token=""
      CONTROL_PLANE_REGISTRATION_TOKEN=""
      rm -rf -- "$REGISTRATION_TEMP_DIR"
      REGISTRATION_TEMP_DIR=""
      log "control-plane registration completed"
      return 0
    fi
    CONTROL_PLANE_REGISTRATION_STATUS="failed-http-$http_code"
  done

  rm -rf -- "$REGISTRATION_TEMP_DIR"
  REGISTRATION_TEMP_DIR=""
  if [ "$registration_required" = "1" ]; then
    fail "control-plane registration failed after retries ($CONTROL_PLANE_REGISTRATION_STATUS)"
  fi
  log "control-plane registration failed after retries; Node Manager remains installed"
}

register_with_control_plane

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
Control-plane URL: ${CONTROL_PLANE_URL:-not configured}
Control-plane registration: $CONTROL_PLANE_REGISTRATION_STATUS
Control-plane node ID: ${CONTROL_PLANE_NODE_ID:-not assigned}
Control-plane registration action: ${CONTROL_PLANE_RESPONSE:-none}
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
log "deployment details and generated credentials were saved to $INFO_FILE (mode 0600)"
