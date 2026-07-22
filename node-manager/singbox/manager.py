import base64
import copy
import json
import logging
import os
import secrets
import subprocess
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from config import config
from .api import SingboxAPI

try:
    import fcntl
except ImportError:  # Windows development fallback; production deployment uses Linux flock.
    fcntl = None


logger = logging.getLogger(__name__)
CONFIG_PATH = Path(config.singbox.config)
LOCK_PATH = Path("/run/lock/node-manager-singbox.lock")
REGISTRY_PATH = Path(os.environ.get("NODE_MANAGER_USER_REGISTRY", "/var/lib/node-manager/users.json"))
USER_PREFIX = "node-manager:"
singbox_api = SingboxAPI()
thread_lock = threading.Lock()


class SingboxConfigError(RuntimeError):
    pass


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


def read_config() -> dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _empty_registry() -> dict[str, Any]:
    return {"version": 1, "users": {}}


def read_registry() -> dict[str, Any]:
    if not REGISTRY_PATH.exists():
        return _empty_registry()
    try:
        with REGISTRY_PATH.open("r", encoding="utf-8") as handle:
            registry = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SingboxConfigError(f"could not read the user registry: {exc}") from exc
    if not isinstance(registry, dict) or not isinstance(registry.get("users"), dict):
        raise SingboxConfigError("the user registry has an invalid structure")
    return registry


def check_config(config_path: str | Path) -> tuple[bool, str]:
    try:
        result = _run(["sing-box", "check", "-c", str(config_path)])
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return result.returncode == 0, (result.stderr or result.stdout).strip()


def is_singbox_running() -> bool:
    try:
        result = _run(["systemctl", "is-active", "sing-box"])
        return result.stdout.strip() == "active"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def reload_singbox() -> bool:
    for command in (
        ["systemctl", "reload", "sing-box"],
        ["systemctl", "restart", "sing-box"],
    ):
        try:
            result = _run(command)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and is_singbox_running():
            return True
        logger.warning("%s failed: %s", " ".join(command), result.stderr.strip())
    return False


def is_api_available() -> bool:
    return singbox_api.is_available()


@contextmanager
def _config_lock():
    if fcntl is None:
        with thread_lock:
            yield
        return

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("w", encoding="ascii") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield


def _write_and_reload(updated: dict[str, Any]) -> None:
    original = CONFIG_PATH.read_bytes()
    original_stat = CONFIG_PATH.stat()
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="config.", suffix=".json", dir=CONFIG_PATH.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(updated, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        valid, error = check_config(temp_path)
        if not valid:
            raise SingboxConfigError(f"sing-box config validation failed: {error}")

        os.chmod(temp_path, original_stat.st_mode)
        if hasattr(os, "chown"):
            os.chown(temp_path, original_stat.st_uid, original_stat.st_gid)
        os.replace(temp_path, CONFIG_PATH)
        if reload_singbox():
            return

        CONFIG_PATH.write_bytes(original)
        reload_singbox()
        raise SingboxConfigError("sing-box reload failed; the previous config was restored")
    finally:
        temp_path.unlink(missing_ok=True)


def _write_registry(registry: dict[str, Any]) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, temp_name = tempfile.mkstemp(prefix="users.", suffix=".json", dir=REGISTRY_PATH.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(registry, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, REGISTRY_PATH)
    finally:
        temp_path.unlink(missing_ok=True)


def _restore_registry(original: bytes | None) -> None:
    if original is None:
        REGISTRY_PATH.unlink(missing_ok=True)
        return
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    REGISTRY_PATH.write_bytes(original)
    os.chmod(REGISTRY_PATH, 0o600)


def mutate_config(mutator: Callable[[dict[str, Any], dict[str, Any]], Any]) -> Any:
    with _config_lock():
        current = read_config()
        registry = read_registry()
        updated = copy.deepcopy(current)
        updated_registry = copy.deepcopy(registry)
        result = mutator(updated, updated_registry)
        original_registry = REGISTRY_PATH.read_bytes() if REGISTRY_PATH.exists() else None
        _write_registry(updated_registry)
        try:
            _write_and_reload(updated)
        except Exception:
            _restore_registry(original_registry)
            raise
        return result


def _find_inbound(data: dict[str, Any], tag: str) -> dict[str, Any]:
    for inbound in data.get("inbounds", []):
        if inbound.get("tag") == tag:
            inbound.setdefault("users", [])
            return inbound
    raise SingboxConfigError(f"required inbound not found: {tag}")


def _auth_name(user_id: str) -> str:
    return f"{USER_PREFIX}{user_id}"


def _registry_user(registry: dict[str, Any], user_id: str) -> dict[str, Any]:
    value = registry.get("users", {}).get(user_id, {})
    return value if isinstance(value, dict) else {}


def _user_auth_names(registry: dict[str, Any], user_id: str) -> set[str]:
    names = {_auth_name(user_id)}
    socks_username = _registry_user(registry, user_id).get("socksUsername")
    if socks_username:
        names.add(str(socks_username))
    return names


def _user_exists(data: dict[str, Any], registry: dict[str, Any], user_id: str) -> bool:
    auth_names = _user_auth_names(registry, user_id)
    for inbound in data.get("inbounds", []):
        for user in inbound.get("users", []):
            if user.get("name") in auth_names or user.get("username") in auth_names:
                return True
    return False


def _auth_identifier_exists(data: dict[str, Any], identifier: str) -> bool:
    for inbound in data.get("inbounds", []):
        for user in inbound.get("users", []):
            if user.get("name") == identifier or user.get("username") == identifier:
                return True
    return False


def _base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _reality_client_options(inbound: dict[str, Any]) -> tuple[str, str, str]:
    tls = inbound.get("tls", {})
    reality = tls.get("reality", {})
    private_key = reality.get("private_key")
    short_ids = reality.get("short_id") or []
    server_name = tls.get("server_name") or reality.get("handshake", {}).get("server")
    if not private_key or not short_ids or not server_name:
        raise SingboxConfigError("the VLESS inbound is missing Reality client parameters")

    padded = private_key + "=" * (-len(private_key) % 4)
    private = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(padded))
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _base64url(public_raw), str(short_ids[0]), str(server_name)


def create_user(
    user_id: str,
    protocols: list[str],
    socks_username: str | None = None,
    socks_password: str | None = None,
    proxy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    user_uuid = str(uuid.uuid4())
    effective_socks_username = socks_username or (proxy or {}).get("username") or _auth_name(user_id)
    effective_socks_password = socks_password or (proxy or {}).get("password") or secrets.token_urlsafe(18)

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user already exists: {user_id}")
        if "socks" in protocols and _auth_identifier_exists(data, effective_socks_username):
            raise SingboxConfigError(f"SOCKS username already exists: {effective_socks_username}")

        auth_name = _auth_name(user_id)
        response: dict[str, Any] = {
            "success": True,
            "userId": user_id,
            "uuid": user_uuid,
            "protocols": protocols,
            "vless": None,
            "vmess": None,
            "socks": None,
            "proxyBound": proxy is not None,
        }

        if "vless" in protocols:
            inbound = _find_inbound(data, config.singbox.vless_tag)
            inbound["users"].append(
                {"name": auth_name, "uuid": user_uuid, "flow": "xtls-rprx-vision"}
            )
            public_key, short_id, server_name = _reality_client_options(inbound)
            port = int(inbound["listen_port"])
            response["vless"] = (
                f"vless://{user_uuid}@{config.node.host}:{port}"
                f"?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality"
                f"&pbk={public_key}&sid={short_id}&sni={server_name}&fp=chrome"
                f"#{user_id}"
            )

        if "vmess" in protocols:
            inbound = _find_inbound(data, config.singbox.vmess_tag)
            inbound["users"].append({"name": auth_name, "uuid": user_uuid})
            vmess = {
                "v": "2",
                "ps": user_id,
                "add": config.node.host,
                "port": str(inbound["listen_port"]),
                "id": user_uuid,
                "aid": "0",
                "net": "tcp",
                "type": "none",
                "host": "",
                "path": "",
                "tls": "",
            }
            encoded = base64.b64encode(
                json.dumps(vmess, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            response["vmess"] = f"vmess://{encoded}"

        if "socks" in protocols:
            inbound = _find_inbound(data, config.singbox.socks_tag)
            inbound["users"].append(
                {"username": effective_socks_username, "password": effective_socks_password}
            )
            response["socks"] = {
                "host": config.node.host,
                "port": int(inbound["listen_port"]),
                "username": effective_socks_username,
                "password": effective_socks_password,
            }

        registry.setdefault("users", {})[user_id] = {
            "socksUsername": effective_socks_username if "socks" in protocols else None,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        if proxy is not None:
            _set_proxy_binding(data, registry, user_id, proxy)
        return response

    return mutate_config(apply)


def _set_proxy_binding(
    data: dict[str, Any], registry: dict[str, Any], user_id: str, proxy: dict[str, Any]
) -> None:
    outbound_tag = f"node-manager-out:{user_id}"
    outbound = {
        "type": "socks",
        "tag": outbound_tag,
        "server": proxy["server"],
        "server_port": proxy["port"],
    }
    if proxy.get("username"):
        outbound["username"] = proxy["username"]
        outbound["password"] = proxy.get("password") or ""

    data.setdefault("outbounds", [])
    data["outbounds"] = [item for item in data["outbounds"] if item.get("tag") != outbound_tag]
    data["outbounds"].append(outbound)

    route = data.setdefault("route", {})
    rules = route.setdefault("rules", [])
    rules[:] = [rule for rule in rules if rule.get("outbound") != outbound_tag]
    auth_names = sorted(_user_auth_names(registry, user_id))
    rules.insert(0, {"auth_user": auth_names, "action": "route", "outbound": outbound_tag})


def bind_proxy(user_id: str, proxy: dict[str, Any]) -> dict[str, Any]:
    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")

        _set_proxy_binding(data, registry, user_id, proxy)
        return {"success": True, "userId": user_id, "message": "proxy bound"}

    return mutate_config(apply)


def delete_user(user_id: str) -> dict[str, Any]:
    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")

        auth_names = _user_auth_names(registry, user_id)
        for inbound in data.get("inbounds", []):
            inbound["users"] = [
                user
                for user in inbound.get("users", [])
                if user.get("name") not in auth_names and user.get("username") not in auth_names
            ]

        outbound_tag = f"node-manager-out:{user_id}"
        data["outbounds"] = [item for item in data.get("outbounds", []) if item.get("tag") != outbound_tag]
        route = data.get("route", {})
        route["rules"] = [
            rule for rule in route.get("rules", []) if rule.get("outbound") != outbound_tag
        ]
        registry.setdefault("users", {}).pop(user_id, None)
        return {"success": True, "userId": user_id, "message": "user deleted"}

    return mutate_config(apply)


def _extract_user_id(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith(USER_PREFIX):
        return value[len(USER_PREFIX):]
    return None


def list_users() -> list[dict[str, Any]]:
    with _config_lock():
        data = read_config()
        registry = read_registry()

    users: dict[str, dict[str, Any]] = {}
    registry_users = registry.get("users", {})
    socks_to_user = {
        str(item.get("socksUsername")): user_id
        for user_id, item in registry_users.items()
        if isinstance(item, dict) and item.get("socksUsername")
    }

    inbound_protocols = {
        config.singbox.vless_tag: ("vless", "name"),
        config.singbox.vmess_tag: ("vmess", "name"),
        config.singbox.socks_tag: ("socks", "username"),
    }
    for inbound in data.get("inbounds", []):
        mapping = inbound_protocols.get(inbound.get("tag"))
        if mapping is None:
            continue
        protocol, auth_field = mapping
        for auth_user in inbound.get("users", []):
            auth_value = auth_user.get(auth_field)
            user_id = _extract_user_id(auth_value)
            if protocol == "socks" and auth_value in socks_to_user:
                user_id = socks_to_user[auth_value]
            if not user_id:
                continue
            item = users.setdefault(user_id, {"userId": user_id, "protocols": []})
            if protocol not in item["protocols"]:
                item["protocols"].append(protocol)
            if protocol == "socks":
                item["socksUsername"] = auth_value

    protocol_order = {"vless": 0, "vmess": 1, "socks": 2}
    outbounds = {item.get("tag"): item for item in data.get("outbounds", [])}
    result: list[dict[str, Any]] = []
    for user_id, item in users.items():
        metadata = _registry_user(registry, user_id)
        outbound = outbounds.get(f"node-manager-out:{user_id}")
        item["protocols"].sort(key=protocol_order.get)
        item["socksUsername"] = item.get("socksUsername") or metadata.get("socksUsername")
        item["proxyBound"] = outbound is not None
        item["proxyServer"] = (
            f"{outbound.get('server')}:{outbound.get('server_port')}" if outbound else None
        )
        item["createdAt"] = metadata.get("createdAt")
        item["status"] = "active"
        result.append(item)

    return sorted(result, key=lambda item: item["userId"].lower())
