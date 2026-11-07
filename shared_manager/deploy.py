"""Prepare a new isolated installation; never overwrites an existing instance.

Run on the HK host from the extracted source checkout. Service activation and
entry forwarding are separate, explicit operations in the deployment driver.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shutil

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

if __package__:
    from .transport import PrivateTransport
else:
    from transport import PrivateTransport


def write(path: Path, content: str, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def env_text(values):
    return "".join(name + "=" + json.dumps(str(value)) + "\n" for name, value in values.items())


def service(description, directory, command, *, user="root", after="network-online.target", extra=""):
    return f"""[Unit]
Description={description}
After={after}
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={directory}
ExecStart={command}
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
LimitNOFILE=65536
{extra}
[Install]
WantedBy=multi-user.target
"""


def prepare(source: Path, root: Path, binary: Path, panel_host: str, proxy_host: str, *, transport=None):
    transport = transport or PrivateTransport()
    if root.exists():
        raise ValueError("独立实例目录已存在，拒绝覆盖")
    root.mkdir(parents=True, mode=0o755)
    for name in ("bin", "config", "units", "state", "state/portal", "state/core", "state/agent"):
        (root / name).mkdir(mode=0o700 if name.startswith("state") else 0o755, exist_ok=True)
    for name in ("node-manager", "shared_manager"):
        shutil.copytree(source / name, root / ("agent" if name == "node-manager" else name),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "config.yaml", "config.json", "logs", "tests"))
    shutil.copy2(binary, root / "bin/sing-box")
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    core = {"log": {"level": "warn", "timestamp": True},
            "dns": {"servers": [{"type": "udp", "tag": "public-dns", "server": "1.1.1.1"}]},
            "inbounds": [
                {"type": "vless", "tag": "vless-reality", "listen": transport.exit_private, "listen_port": 6666, "users": [],
                 "tls": {"enabled": True, "server_name": "www.cloudflare.com", "reality": {"enabled": True,
                    "handshake": {"server": "www.cloudflare.com", "server_port": 443},
                    "private_key": base64.urlsafe_b64encode(raw).decode().rstrip("="), "short_id": [secrets.token_hex(8)]}}},
                {"type": "vmess", "tag": "vmess", "listen": transport.exit_private, "listen_port": 7777, "users": []},
                {"type": "socks", "tag": "socks", "listen": transport.exit_private, "listen_port": 9999, "users": []}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct", "default_domain_resolver": "public-dns"},
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:9091", "secret": secrets.token_urlsafe(32)}}}
    write(root / "config/sing-box.json", json.dumps(core, indent=2) + "\n", 0o640)
    token = secrets.token_urlsafe(48)
    agent = {"node": {"id": "shared-hk", "name": "共享节点", "host": proxy_host, "acceleration_domain": proxy_host},
             "server": {"port": 8089}, "security": {"token": token, "allowed_cidrs": "127.0.0.1/32"},
             "singbox": {"config": str(root / "config/sing-box.json"), "binary": str(root / "bin/sing-box"),
                         "service": "sing-box-shared", "api_port": 9091, "api_secret": core["experimental"]["clash_api"]["secret"]},
             "monitoring": {"health_check_interval_seconds": 0, "traffic_sample_interval_seconds": 2}, "wireguard": {"enabled": False}}
    # JSON is a strict YAML subset, read by the existing agent YAML loader.
    write(root / "state/agent.yaml", json.dumps(agent, ensure_ascii=False, indent=2) + "\n")
    write(root / "state/agent.env", env_text({
        "NODE_MANAGER_CONFIG": root / "state/agent.yaml", "NODE_MANAGER_CONFIG_LOCK": root / "state/agent/config.lock",
        "NODE_MANAGER_USER_REGISTRY": root / "state/agent/users.json", "NODE_MANAGER_TRAFFIC_STORE": root / "state/agent/traffic.json",
        "NODE_MANAGER_IDEMPOTENCY_STORE": root / "state/agent/idempotency.json", "NODE_MANAGER_REVISIONS_DIR": root / "state/agent/revisions",
        "NODE_MANAGER_RUNTIME_STATE_DIR": root / "state/agent/runtime", "NODE_MANAGER_WIREGUARD_REGISTRY": root / "state/agent/wireguard.json",
        "NODE_MANAGER_WIREGUARD_LOCK": root / "state/agent/wireguard.lock"}))
    write(root / "state/portal.env", env_text({
        "SHARED_SECRET": secrets.token_urlsafe(48), "SHARED_AGENT_TOKEN": token, "SHARED_ORIGIN": "https://" + panel_host,
        "SHARED_AGENT_URL": "http://127.0.0.1:8089", "SHARED_DATABASE": root / "state/portal/accounts.json",
        "SHARED_UPSTREAM_DENY_HOSTS": ",".join(("168.93.208.118", transport.entry_public, transport.entry_private, transport.exit_private, "10.44.0.1", "10.44.0.2")),
        "SHARED_NODE_NAME": "共享节点", "SHARED_REGISTRATION_ENABLED": "true"}))
    write(root / "units/sing-box-shared.service", service("Isolated shared sing-box", root / "state/core",
        f"{root}/bin/sing-box run -c {root}/config/sing-box.json", user="shared-singbox",
        extra="ExecReload=/bin/kill -HUP $MAINPID\nMemoryMax=2G"), 0o644)
    write(root / "units/node-manager-shared.service", service("Isolated shared Node Manager", root / "agent",
        f"{root}/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8089 --workers 1 --no-access-log",
        after="network-online.target sing-box-shared.service", extra=f"EnvironmentFile={root}/state/agent.env\nMemoryMax=1G"), 0o644)
    write(root / "units/shared-node-portal.service", service("Shared node account portal", root,
        f"{root}/venv/bin/uvicorn shared_manager.app:create_app --factory --host 127.0.0.1 --port 8090 --workers 1 --no-access-log --proxy-headers --forwarded-allow-ips=127.0.0.1",
        user="shared-node-portal", after="network-online.target node-manager-shared.service",
        extra=f"EnvironmentFile={root}/state/portal.env\nMemoryMax=512M"), 0o644)
    write(root / "Caddyfile", f"""{{
    admin 127.0.0.1:2020
    servers {{
        protocols h1 h2
    }}
}}
{panel_host} {{
    encode gzip
    reverse_proxy 127.0.0.1:8090
}}
""", 0o644)
    write(root / "units/shared-node-web.service", service("Shared node HTTPS portal", root,
        f"{root}/bin/caddy run --config {root}/Caddyfile --adapter caddyfile", user="shared-node-web",
        after="network-online.target shared-node-portal.service",
        extra=f"Environment=HOME={root}/state/web\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nMemoryMax=256M"), 0o644)
    return {"root": str(root), "panel": "https://" + panel_host, "proxy": proxy_host,
            "ports": {"vless": 6666, "vmess": 7777, "socks": 9999}, "service_names": [p.stem for p in (root / "units").glob("*.service")]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("/opt/shared-node-manager"))
    parser.add_argument("--binary", type=Path, default=Path("/usr/local/bin/sing-box"))
    parser.add_argument("--panel-host", default="panel.aliproxy.cc.cd")
    parser.add_argument("--proxy-host", default="proxy.aliproxy.cc.cd")
    parser.add_argument("--entry-public", default="150.242.80.15")
    parser.add_argument("--entry-private", default="172.16.80.15")
    parser.add_argument("--exit-private", default="172.16.208.118")
    parser.add_argument("--interface", default="ens19")
    args = parser.parse_args()
    transport = PrivateTransport(args.entry_public, args.entry_private, args.exit_private, args.interface)
    print(json.dumps(prepare(args.source, args.root, args.binary, args.panel_host, args.proxy_host, transport=transport)))
