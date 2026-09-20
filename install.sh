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
FORCE_NODE_MANAGER_UPDATE="${NODE_MANAGER_FORCE_UPDATE:-0}"
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
case "$FORCE_NODE_MANAGER_UPDATE" in
  0|1) ;;
  *) fail "NODE_MANAGER_FORCE_UPDATE must be 0 or 1" ;;
esac

apt_get() {
  apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_TIMEOUT_SECONDS" "$@"
}

# B7: 空白节点生命周期管理子命令。
# 默认（无子命令或 $1 是 http(s):// URL）走原有安装/升级流程；
# 以下子命令在到达安装流程之前分发并退出，便于空白节点恢复与排障。
NM_API_BASE="${NODE_MANAGER_API_BASE:-http://127.0.0.1:8088}"
NM_API_TOKEN="${NODE_MANAGER_API_TOKEN:-}"
NM_CONFIG_DIR="${NODE_MANAGER_CONFIG_DIR:-/etc/node-manager}"
NM_DATA_DIR="${NODE_MANAGER_DATA_DIR:-/var/lib/node-manager}"
NM_REVISIONS_DIR="${NODE_MANAGER_REVISIONS_DIR:-/var/lib/node-manager/revisions}"
NM_SINGBOX_CONFIG="${NODE_MANAGER_SINGBOX_CONFIG:-/etc/sing-box/config.json}"
NM_BACKUP_DIR="${NODE_MANAGER_BACKUP_DIR:-/var/backups/node-manager}"

api_call() {
  # 调用本地 Node Manager API：$1=方法 $2=路径 [$3=JSON body]
  # 只返回 HTTP 状态码到 stdout；响应体写到 /tmp/nm-api.out 供调用方读取。
  local method="$1" path="$2" body="${3:-}"
  local curl_args=(-sS --connect-timeout 5 --max-time 20 -o /tmp/nm-api.out -w '%{http_code}')
  [ -z "$NM_API_TOKEN" ] || curl_args+=(-H "Authorization: Bearer $NM_API_TOKEN")
  [ "$method" = "GET" ] || curl_args+=(-H 'Content-Type: application/json')
  [ -z "$body" ] || curl_args+=(--data-binary "$body")
  curl "${curl_args[@]}" -X "$method" "${NM_API_BASE}${path}" 2>/dev/null
}

do_uninstall() {
  log "B7: uninstalling Node Manager (sing-box package preserved)"
  systemctl stop node-manager 2>/dev/null || true
  systemctl disable node-manager 2>/dev/null || true
  rm -f "$SERVICE_FILE"

  # 备份状态目录后再删除，便于事后排查或重装恢复
  if [ -d "$NM_DATA_DIR" ]; then
    install -d -m 0750 "$NM_BACKUP_DIR"
    local backup="${NM_BACKUP_DIR}/data-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
    tar -czf "$backup" -C "$(dirname "$NM_DATA_DIR")" "$(basename "$NM_DATA_DIR")" 2>/dev/null || true
    chmod 0600 "$backup"
    log "state directory backed up to $backup"
    rm -rf -- "$NM_DATA_DIR"
  fi
  rm -rf -- "$NM_CONFIG_DIR" "$APP_DIR" "$NM_REVISIONS_DIR"
  systemctl daemon-reload
  log "Node Manager uninstalled; run 'bash install.sh' to reinstall"
}

do_rollback() {
  log "B7: rolling back sing-box config to last known good revision"
  # 优先通过 API 走 revision.py 的回滚逻辑（含归档、状态更新、告警）
  if curl -fsS --connect-timeout 5 --max-time 20 \
       -o /dev/null "http://127.0.0.1:8088/health" 2>/dev/null; then
    local code
    code="$(api_call POST /api/agent/revision/rollback)"
    case "$code" in
      200) log "rollback completed via API" ; return 0 ;;
      *) fail "API rollback failed (http $code); falling back to file-level rollback" ;;
    esac
  fi

  # 节点离线时直接用 last_good.json 覆盖 config.json 并重启 sing-box
  local last_good="$NM_REVISIONS_DIR/last_good.json"
  [ -f "$last_good" ] || fail "no last_good.json found at $last_good; nothing to roll back to"
  command -v sing-box >/dev/null 2>&1 || fail "sing-box not installed"
  sing-box check -c "$last_good" || fail "last_good.json failed sing-box check; refusing to apply"
  install -o root -g sing-box -m 0640 "$last_good" "$NM_SINGBOX_CONFIG"
  systemctl restart sing-box 2>/dev/null || true
  log "rolled back to $last_good and restarted sing-box"
}

do_recover() {
  log "B7: recovery — restarting services and running health checks"
  systemctl daemon-reload
  systemctl enable sing-box node-manager 2>/dev/null || true
  systemctl restart sing-box 2>/dev/null || log "WARNING: sing-box restart failed"
  systemctl restart node-manager 2>/dev/null || log "WARNING: node-manager restart failed"

  local retries=0
  while [ "$retries" -lt 30 ]; do
    curl -fsS --connect-timeout 2 --max-time 5 \
      "http://127.0.0.1:8088/health" >/dev/null 2>&1 && break
    retries=$((retries + 1))
    sleep 1
  done
  if ! curl -fsS "http://127.0.0.1:8088/health" >/dev/null 2>&1; then
    log "node-manager still unhealthy after recovery; recent logs:"
    journalctl -u node-manager -n 40 --no-pager >&2 || true
    journalctl -u sing-box -n 20 --no-pager >&2 || true
    fail "recovery failed: node-manager did not become healthy"
  fi
  log "node-manager healthy; running network check"
  do_network_check || true
  log "recovery completed"
}

do_network_check() {
  log "checking Node Manager connectivity only"
  if curl -fsS --connect-timeout 5 --max-time 20 \
       -o /dev/null "http://127.0.0.1:8088/health" 2>/dev/null; then
    log "ok: Node Manager health endpoint is reachable"
    return 0
  fi
  fail "connectivity check failed: Node Manager health endpoint is not reachable"
}

NM_SUBCOMMAND="${1:-}"
case "$NM_SUBCOMMAND" in
  uninstall|rollback|recover|network-check)
    log "lifecycle subcommand: $NM_SUBCOMMAND"
    shift
    ;;
  *)
    NM_SUBCOMMAND=""
    ;;
esac

if [ -n "$NM_SUBCOMMAND" ]; then
  case "$NM_SUBCOMMAND" in
    uninstall)      do_uninstall ;;
    rollback)       do_rollback ;;
    recover)        do_recover ;;
    network-check)  do_network_check ;;
  esac
  exit 0
fi

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
if [ "$FORCE_NODE_MANAGER_UPDATE" = "1" ]; then
  UPDATE_NODE_MANAGER=1
  log "Node Manager force update requested; installing application $APP_VERSION"
elif [ "$INSTALLED_APP_VERSION" = "$APP_VERSION" ]; then
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

SERVER_IP="$(curl -4fsS --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}')"
NODE_TOKEN=''
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
      "type": "trojan",
      "tag": "trojan",
      "listen": "0.0.0.0",
      "listen_port": 20170,
      "users": [{"name": "node-manager:$TEST_USER_ID", "password": "$TEST_USER_UUID"}],
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
  TEST_TROJAN_URL="trojan://$TEST_USER_UUID@$SERVER_IP:20170?type=tcp&security=reality&pbk=$PUBLIC_KEY&sid=$SHORT_ID&sni=www.cloudflare.com&fp=chrome#$TEST_USER_ID"
fi

for tag in vless-reality vmess trojan socks; do
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
EXISTING_TOKEN=''
if [ -f "$CONFIG_DIR/config.yaml" ]; then
  EXISTING_TOKEN="$(awk '/^[[:space:]]*token:/ {print $2; exit}' "$CONFIG_DIR/config.yaml" | tr -d '"' | tr -d ''')"
fi
if [ -n "${NODE_MANAGER_API_TOKEN:-}" ]; then
  NODE_TOKEN="$NODE_MANAGER_API_TOKEN"
elif [ -n "$EXISTING_TOKEN" ]; then
  NODE_TOKEN="$EXISTING_TOKEN"
else
  NODE_TOKEN="$(openssl rand -hex 32)"
fi
EXISTING_NODE_ID=""
if [ -f "$CONFIG_DIR/config.yaml" ]; then
  EXISTING_NODE_ID="$(awk '
    /^[^[:space:]]/ {section = ($1 == "node:") ? "node" : ""}
    section == "node" && /^[[:space:]]+id:/ {print $2; exit}
  ' "$CONFIG_DIR/config.yaml" | tr -d '"' | tr -d "'")"
fi
default_node_id() {
  local host machine_id suffix
  host="$(hostname)"
  machine_id=""
  if [ -r /etc/machine-id ]; then
    machine_id="$(tr -d '[:space:]' < /etc/machine-id)"
  fi
  if [ -n "$machine_id" ] && command -v sha256sum >/dev/null 2>&1; then
    suffix="$(printf '%s' "$machine_id" | sha256sum | awk '{print substr($1, 1, 12)}')"
    printf '%s-%s' "$host" "$suffix"
  else
    printf '%s' "$host"
  fi
}
NODE_ID="${NODE_MANAGER_NODE_ID:-${EXISTING_NODE_ID:-$(default_node_id)}}"
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
  trojan_tag: "trojan"
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
ufw allow 20170/tcp >/dev/null
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
  local response_file request_file header_file http_code delay curl_exit_code

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
    --arg nodeKey "$NODE_ID" \
    --arg name "$NODE_NAME" \
    --arg managerBaseUrl "$public_url" \
    --arg managerToken "$NODE_TOKEN" \
    '{nodeKey:$nodeKey,managerBaseUrl:$managerBaseUrl,managerToken:$managerToken}' \
    > "$request_file"
  for delay in 0 2 4 8 16; do
    [ "$delay" -eq 0 ] || sleep "$delay"
    log "registering Node Manager with control-plane"
    set +e
    http_code="$(curl -sS --connect-timeout 10 --max-time 30 \
      -o "$response_file" -w '%{http_code}' \
    -X POST "$control_plane_url/api/admin/singbox/agent/register" \
      -H 'Content-Type: application/json' \
      --header "@$header_file" \
      --data-binary "@$request_file")"
    curl_exit_code=$?
    set -e
    [ -n "$http_code" ] || http_code="000"
    if [ "$http_code" = "200" ]; then
      CONTROL_PLANE_NODE_ID="$(jq -r '.data.id // .id // empty' "$response_file" 2>/dev/null || true)"
      CONTROL_PLANE_REGISTRATION_STATUS="registered"
      CONTROL_PLANE_RESPONSE="ok"
      install_token=""
      CONTROL_PLANE_INSTALL_TOKEN=""
      registration_token=""
      CONTROL_PLANE_REGISTRATION_TOKEN=""
      rm -rf -- "$REGISTRATION_TEMP_DIR"
      REGISTRATION_TEMP_DIR=""
      log "control-plane registration completed"
      return 0
    fi
    if [ "$curl_exit_code" -ne 0 ] && [ -n "$install_token" ]; then
      CONTROL_PLANE_REGISTRATION_STATUS="transport-error-$curl_exit_code"
      rm -rf -- "$REGISTRATION_TEMP_DIR"
      REGISTRATION_TEMP_DIR=""
      fail "control-plane registration request did not complete; verify that the Control Plane server can reach $public_url (including the provider cloud firewall/security group for TCP 8088), then generate a new one-time install command"
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
Test Trojan: $TEST_TROJAN_URL
Test SOCKS5: $SERVER_IP:5001
Test SOCKS5 username: $TEST_SOCKS_USER
Test SOCKS5 password: $TEST_SOCKS_PASSWORD
EOF
fi
chmod 0600 "$INFO_FILE"

log "deployment completed"
log "deployment details and generated credentials were saved to $INFO_FILE (mode 0600)"
