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


def mutate_config(mutator: Callable[[dict[str, Any]], Any]) -> Any:
    with _config_lock():
        current = read_config()
        updated = copy.deepcopy(current)
        result = mutator(updated)
        _write_and_reload(updated)
        return result


def _find_inbound(data: dict[str, Any], tag: str) -> dict[str, Any]:
    for inbound in data.get("inbounds", []):
        if inbound.get("tag") == tag:
            inbound.setdefault("users", [])
            return inbound
    raise SingboxConfigError(f"required inbound not found: {tag}")


def _auth_name(user_id: str) -> str:
    return f"{USER_PREFIX}{user_id}"


def _user_exists(data: dict[str, Any], user_id: str) -> bool:
    auth_name = _auth_name(user_id)
    for inbound in data.get("inbounds", []):
        for user in inbound.get("users", []):
            if user.get("name") == auth_name or user.get("username") == auth_name:
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


def create_user(user_id: str, protocols: list[str]) -> dict[str, Any]:
    user_uuid = str(uuid.uuid4())
    socks_password = secrets.token_urlsafe(18)

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        if _user_exists(data, user_id):
            raise SingboxConfigError(f"user already exists: {user_id}")

        auth_name = _auth_name(user_id)
        response: dict[str, Any] = {
            "success": True,
            "userId": user_id,
            "uuid": user_uuid,
            "protocols": protocols,
            "vless": None,
            "vmess": None,
            "socks": None,
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
            inbound["users"].append({"username": auth_name, "password": socks_password})
            response["socks"] = {
                "host": config.node.host,
                "port": int(inbound["listen_port"]),
                "username": auth_name,
                "password": socks_password,
            }

        return response

    return mutate_config(apply)


def bind_proxy(user_id: str, proxy: dict[str, Any]) -> dict[str, Any]:
    def apply(data: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")

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
        auth_name = _auth_name(user_id)
        rules[:] = [rule for rule in rules if rule.get("auth_user") != [auth_name]]
        rules.insert(0, {"auth_user": [auth_name], "action": "route", "outbound": outbound_tag})
        return {"success": True, "userId": user_id, "message": "proxy bound"}

    return mutate_config(apply)


def delete_user(user_id: str) -> dict[str, Any]:
    def apply(data: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")

        auth_name = _auth_name(user_id)
        for inbound in data.get("inbounds", []):
            inbound["users"] = [
                user
                for user in inbound.get("users", [])
                if user.get("name") != auth_name and user.get("username") != auth_name
            ]

        outbound_tag = f"node-manager-out:{user_id}"
        data["outbounds"] = [item for item in data.get("outbounds", []) if item.get("tag") != outbound_tag]
        route = data.get("route", {})
        route["rules"] = [
            rule for rule in route.get("rules", []) if rule.get("auth_user") != [auth_name]
        ]
        return {"success": True, "userId": user_id, "message": "user deleted"}

    return mutate_config(apply)
