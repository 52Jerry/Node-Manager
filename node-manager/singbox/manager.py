import base64
import copy
import ipaddress
import json
import logging
import os
import secrets
import socket
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
from protocols import (
    ProtocolData,
    bitbrowser,
    protocol_info,
    socks5_original,
    socks_acceleration,
    vmess,
    vless,
)
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
USER_OUTBOUND_PREFIX = "node-manager-out:"
singbox_api = SingboxAPI()
thread_lock = threading.Lock()


def _audit(action: str, user_id: str, **fields: Any) -> None:
    """记录关键操作审计日志。绝不记录密码、Token 或完整连接 URI。

    仅将非敏感元数据并入日志消息，便于排查而不泄露凭据。
    """
    safe: dict[str, Any] = {"action": action, "userId": user_id}
    for key, value in fields.items():
        if key in {"password", "token", "secret", "connection"}:
            continue
        if isinstance(value, str) and len(value) > 256:
            value = value[:256] + "...(truncated)"
        safe[key] = value
    logger.info("audit %s modules=%s", action, json.dumps(safe, ensure_ascii=False))


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


def get_socks_inbound_port() -> int | None:
    """Return the public SOCKS inbound port from the active sing-box config."""
    try:
        data = read_config()
        inbound = _find_inbound(data, config.singbox.socks_tag)
        port = int(inbound.get("listen_port"))
        return port if 1 <= port <= 65535 else None
    except (OSError, TypeError, ValueError, SingboxConfigError):
        return None


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
    try:
        current = json.loads(original.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SingboxConfigError(f"could not read the current sing-box config: {exc}") from exc
    if current == updated:
        return
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


def _legacy_auth_names(user_id: str) -> set[str]:
    """Names used by older installations; never expose these as public IDs."""
    return {_auth_name(user_id), user_id}


def _registry_user(registry: dict[str, Any], user_id: str) -> dict[str, Any]:
    value = registry.get("users", {}).get(user_id, {})
    return value if isinstance(value, dict) else {}


def _user_auth_names(registry: dict[str, Any], user_id: str) -> set[str]:
    names = _legacy_auth_names(user_id)
    socks_username = _registry_user(registry, user_id).get("socksUsername")
    if socks_username:
        names.add(str(socks_username))
    return names


def _route_auth_names(
    data: dict[str, Any], registry: dict[str, Any], user_id: str
) -> set[str]:
    """Return names that should be routed for this user.

    New users authenticate with the internal ``node-manager:<id>`` name and,
    when SOCKS is enabled, the supplied SOCKS username.  A bare user id is
    accepted only when it is actually present in a legacy sing-box config;
    this keeps backward compatibility without adding a redundant public
    alias to every newly-created route rule.
    """
    names = {_auth_name(user_id)}
    socks_username = _registry_user(registry, user_id).get("socksUsername")
    if socks_username:
        names.add(str(socks_username))
    if any(
        user.get("name") == user_id or user.get("username") == user_id
        for inbound in data.get("inbounds", [])
        for user in inbound.get("users", [])
    ):
        names.add(user_id)
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


def _acceleration_host() -> str:
    """Return the configured public endpoint, accepting either IP or DNS."""
    value = str(config.node.acceleration_domain or config.node.host or "").strip()
    return value or str(config.node.host)


def _uri_host(value: str) -> str:
    raw = str(value or "").strip()
    if ":" in raw and not raw.startswith("["):
        return f"[{raw}]"
    return raw


def _vless_connection(user_id: str, user_uuid: str, inbound: dict[str, Any]) -> str:
    public_key, short_id, server_name = _reality_client_options(inbound)
    port = int(inbound["listen_port"])
    return (
        f"vless://{user_uuid}@{_uri_host(_acceleration_host())}:{port}"
        f"?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality"
        f"&pbk={public_key}&sid={short_id}&sni={server_name}&fp=chrome"
        f"#{user_id}"
    )


def _vmess_connection(user_id: str, user_uuid: str, inbound: dict[str, Any]) -> str:
    vmess = {
        "v": "2",
        "ps": user_id,
        "add": _acceleration_host(),
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
    return f"vmess://{encoded}"


def _socks_connection(
    username: str, password: str, inbound: dict[str, Any]
) -> dict[str, Any]:
    return {
        "host": _acceleration_host(),
        "port": int(inbound["listen_port"]),
        "username": username,
        "password": password,
    }


def _inbound_port(inbound: dict[str, Any] | None, fallback: int) -> int:
    """Read a valid public inbound port, retaining the documented default as fallback."""
    try:
        port = int((inbound or {}).get("listen_port"))
    except (TypeError, ValueError):
        return fallback
    return port if 1 <= port <= 65535 else fallback


def build_all_protocols(
    user_id: str,
    user_uuid: str,
    socks: dict[str, Any] | None,
    vless_inbound: dict[str, Any] | None = None,
    vmess_inbound: dict[str, Any] | None = None,
    socks_inbound: dict[str, Any] | None = None,
    vless_security: str = "reality",
    include_original: bool = False,
    enabled_protocols: set[str] | None = None,
    proxy: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Generate the public links for one Node Manager user.

    The three Node Manager acceleration links are generated from the local
    inbounds and are independent of any upstream residential proxy.  The two
    legacy/original links are opt-in and are only emitted when a local SOCKS
    connection exists *and* the caller explicitly requests them (residential
    provisioning).  When ``proxy`` is supplied the original links use the
    upstream proxy's server/port/credentials so the resulting URIs match
    what the residential provider (e.g. IPVelo) issued for this allocation.
    """
    enabled = enabled_protocols or {"vless", "vmess", "socks"}
    acceleration_host = _acceleration_host()

    # VLESS/VMess do not need SOCKS credentials.  For SOCKS acceleration,
    # however, use the actual local inbound credentials only.
    local_username = str((socks or {}).get("username") or _auth_name(user_id))
    local_password = str((socks or {}).get("password") or "")
    data = ProtocolData(
        ip=str((socks or {}).get("host") or config.node.host),
        port=int((socks or {}).get("port") or _inbound_port(socks_inbound, 5001)),
        username=local_username,
        password=local_password,
        uuid=user_uuid or "",
        acceleration_domain=acceleration_host,
        acceleration_port_socks=_inbound_port(socks_inbound, 5001),
        vless_port=_inbound_port(vless_inbound, 20168),
        vmess_port=_inbound_port(vmess_inbound, 20169),
    )
    if vless_inbound is not None:
        try:
            public_key, short_id, server_name = _reality_client_options(vless_inbound)
            data.vless_pbk = public_key
            data.vless_sid = short_id
            data.vless_sni = server_name
        except SingboxConfigError:
            logger.warning("could not derive Reality client params for %s", user_id)
    data.vless_security = vless_security
    links: dict[str, str] = {}
    if include_original and socks is not None:
        original_data = data
        if proxy is not None:
            original_data = ProtocolData(
                ip=str(proxy.get("sourceIp") or proxy.get("server") or data.ip),
                port=int(proxy.get("port") or data.port),
                username=str(proxy.get("username") or data.username),
                password=str(proxy.get("password") or data.password),
                country_code=str(proxy.get("countryCode") or data.country_code or "XX"),
                country_name=str(proxy.get("countryName") or data.country_name or ""),
                city_name=str(proxy.get("cityName") or data.city_name or ""),
                uuid=data.uuid,
                acceleration_domain=data.acceleration_domain,
                acceleration_port_socks=data.acceleration_port_socks,
                vless_port=data.vless_port,
                vmess_port=data.vmess_port,
            )
        links["socks5"] = socks5_original(original_data)
        links["bitbrowser"] = bitbrowser(original_data)
    if "vless" in enabled and vless_inbound is not None and user_uuid:
        links["vless"] = vless(data)
    if "socks" in enabled and socks is not None and socks_inbound is not None:
        links["socksAcceleration"] = socks_acceleration(data)
    if "vmess" in enabled and vmess_inbound is not None and user_uuid:
        links["vmess"] = vmess(data)
    return links


def build_protocol_info(
    user_id: str,
    user_uuid: str,
    socks: dict[str, Any] | None,
    vless_inbound: dict[str, Any] | None = None,
    vmess_inbound: dict[str, Any] | None = None,
    socks_inbound: dict[str, Any] | None = None,
    *,
    include_original: bool = False,
    proxy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the structured protocol contract from the active sing-box config.

    Mirrors ``build_all_protocols`` so the ports, Reality public key and
    acceleration host stay identical.  When ``proxy`` is supplied the
    returned map also contains ``sourceIp``/``rawUsername``/``rawPassword``
    that describe the upstream residential proxy's original SOCKS/BitBrowser
    credentials, instead of leaking the local node SOCKS credentials.
    """
    acceleration_host = _acceleration_host()
    local_username = str((socks or {}).get("username") or _auth_name(user_id))
    local_password = str((socks or {}).get("password") or "")
    data = ProtocolData(
        ip=str((socks or {}).get("host") or config.node.host),
        port=int((socks or {}).get("port") or _inbound_port(socks_inbound, 5001)),
        username=local_username,
        password=local_password,
        uuid=user_uuid or "",
        acceleration_domain=acceleration_host,
        acceleration_port_socks=_inbound_port(socks_inbound, 5001),
        vless_port=_inbound_port(vless_inbound, 20168),
        vmess_port=_inbound_port(vmess_inbound, 20169),
    )
    if vless_inbound is not None:
        try:
            public_key, short_id, server_name = _reality_client_options(vless_inbound)
            data.vless_pbk = public_key
            data.vless_sid = short_id
            data.vless_sni = server_name
        except SingboxConfigError:
            logger.warning("could not derive Reality client params for %s", user_id)
    info = protocol_info(
        data,
        protocol_id=user_uuid or user_id,
        include_original=include_original and socks is not None,
    )
    if include_original and proxy is not None:
        upstream_server = str(proxy.get("sourceIp") or proxy.get("server") or data.ip)
        upstream_port = proxy.get("port")
        upstream_username = proxy.get("username")
        upstream_password = proxy.get("password")
        if upstream_server:
            info["sourceIp"] = upstream_server
        if upstream_port is not None:
            info["rawPort"] = int(upstream_port)
        if upstream_username:
            info["rawUsername"] = str(upstream_username)
        if upstream_password:
            info["rawPassword"] = str(upstream_password)
        info["countryCode"] = str(proxy.get("countryCode") or info.get("countryCode") or "XX")
        if proxy.get("countryName"):
            info["countryName"] = str(proxy["countryName"])
        if proxy.get("cityName"):
            info["cityName"] = str(proxy["cityName"])
    return info


def create_user(
    user_id: str,
    protocols: list[str],
    socks_username: str | None = None,
    socks_password: str | None = None,
    proxy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    user_uuid = str(uuid.uuid4())
    # The local SOCKS inbound credentials are distinct from the upstream
    # residential proxy credentials.  The latter are used only by the
    # per-user outbound and must never leak into a public node link.
    effective_socks_username = socks_username or _auth_name(user_id)
    effective_socks_password = socks_password or secrets.token_urlsafe(18)

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
            response["vless"] = _vless_connection(user_id, user_uuid, inbound)

        if "vmess" in protocols:
            inbound = _find_inbound(data, config.singbox.vmess_tag)
            inbound["users"].append({"name": auth_name, "uuid": user_uuid})
            response["vmess"] = _vmess_connection(user_id, user_uuid, inbound)

        if "socks" in protocols:
            inbound = _find_inbound(data, config.singbox.socks_tag)
            inbound["users"].append(
                {"username": effective_socks_username, "password": effective_socks_password}
            )
            response["socks"] = _socks_connection(
                effective_socks_username, effective_socks_password, inbound
            )

        # Generate the dynamic protocol set after all requested inbounds are
        # known.  Residential users get the two original proxy links in
        # addition to the three local acceleration links; direct users get
        # only the local links.
        vless_inbound = next(
            (item for item in data.get("inbounds", [])
             if item.get("tag") == config.singbox.vless_tag), None
        )
        vmess_inbound = next(
            (item for item in data.get("inbounds", [])
             if item.get("tag") == config.singbox.vmess_tag), None
        )
        socks_inbound = next(
            (item for item in data.get("inbounds", [])
             if item.get("tag") == config.singbox.socks_tag), None
        )
        response["protocolsAll"] = build_all_protocols(
            user_id,
            user_uuid,
            response["socks"],
            vless_inbound=vless_inbound,
            vmess_inbound=vmess_inbound,
            socks_inbound=socks_inbound,
            include_original=proxy is not None,
            enabled_protocols=set(protocols),
            proxy=proxy,
        )
        # 兼容链接与结构化参数统一使用同一个加速地址：legacy vless/vmess
        # 直接复用 protocolsAll 的生成结果，避免两套逻辑产生差异。
        if response["protocolsAll"].get("vless"):
            response["vless"] = response["protocolsAll"]["vless"]
        if response["protocolsAll"].get("vmess"):
            response["vmess"] = response["protocolsAll"]["vmess"]
        response["protocolInfo"] = build_protocol_info(
            user_id,
            user_uuid,
            response["socks"],
            vless_inbound=vless_inbound,
            vmess_inbound=vmess_inbound,
            socks_inbound=socks_inbound,
            include_original=proxy is not None,
            proxy=proxy,
        )

        registry.setdefault("users", {})[user_id] = {
            "socksUsername": effective_socks_username if "socks" in protocols else None,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        if proxy is not None:
            _set_proxy_binding(data, registry, user_id, proxy)
        else:
            _set_direct_binding(data, registry, user_id)
        _audit(
            "user.create",
            user_id,
            protocols=",".join(protocols),
            proxyBound=proxy is not None,
        )
        return response

    return mutate_config(apply)


def _set_proxy_binding(
    data: dict[str, Any], registry: dict[str, Any], user_id: str, proxy: dict[str, Any]
) -> None:
    _validate_proxy_does_not_loop_to_local_socks(data, proxy)
    outbound_tag = f"{USER_OUTBOUND_PREFIX}{user_id}"
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
    auth_names = sorted(_route_auth_names(data, registry, user_id))
    rules.insert(0, {"auth_user": auth_names, "action": "route", "outbound": outbound_tag})


def _canonical_ip(value: str) -> str | None:
    normalized = value.strip().strip("[]").split("%", 1)[0]
    try:
        return ipaddress.ip_address(normalized).compressed.lower()
    except ValueError:
        return None


def _resolve_host_addresses(host: str | None) -> set[str]:
    if host is None or not str(host).strip():
        return set()
    normalized_host = str(host).strip().strip("[]")
    literal = _canonical_ip(normalized_host)
    if literal is not None:
        return {literal}
    try:
        addresses = socket.getaddrinfo(normalized_host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return set()
    return {
        canonical
        for item in addresses
        if (canonical := _canonical_ip(str(item[4][0]))) is not None
    }


def _local_host_addresses() -> set[str]:
    addresses = {"127.0.0.1", "::1"}
    addresses.update(_resolve_host_addresses(config.node.host))
    for local_name in {socket.gethostname(), socket.getfqdn()}:
        addresses.update(_resolve_host_addresses(local_name))
    return addresses


def _validate_proxy_does_not_loop_to_local_socks(
    data: dict[str, Any], proxy: dict[str, Any]
) -> None:
    """Warn if the upstream SOCKS points back to this very node's SOCKS inbound.

    Historically this was treated as a hard error, but a VPS may legitimately host
    both the Node Manager and the upstream residential SOCKS (e.g. IPVelo assigns
    the same VPS IP as the access point).  In that case the traffic flow is:

        client -> VLESS(20168) -> sing-box route -> outbound SOCKS(5001, loopback) -> exit

    which *does not* create a proxy loop because the outbound is a separate
    sing-box chain.  We therefore allow same-host bindings and emit a warning
    only, so the UI can still display a soft notice without blocking the user.
    """
    socks_inbound = _find_inbound(data, config.singbox.socks_tag)
    try:
        proxy_port = int(proxy["port"])
        socks_port = int(socks_inbound["listen_port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SingboxConfigError("the proxy or SOCKS inbound port is invalid") from exc
    if proxy_port != socks_port:
        return

    proxy_addresses = _resolve_host_addresses(str(proxy.get("server") or ""))
    if proxy_addresses and proxy_addresses.intersection(_local_host_addresses()):
        logger.warning(
            "upstream SOCKS points to this node's own SOCKS inbound (%s:%d); "
            "allowing binding because Node Manager routes traffic through a "
            "separate outbound chain, which is not a proxy loop.",
            proxy.get("server"), proxy_port,
        )


def _set_direct_binding(data: dict[str, Any], registry: dict[str, Any], user_id: str) -> None:
    outbound_tag = f"{USER_OUTBOUND_PREFIX}{user_id}"
    data.setdefault("outbounds", [])
    if not any(item.get("tag") == outbound_tag for item in data["outbounds"]):
        data["outbounds"].append({"type": "direct", "tag": outbound_tag})

    route = data.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not any(rule.get("outbound") == outbound_tag for rule in rules):
        rules.insert(
            0,
            {
                "auth_user": sorted(_route_auth_names(data, registry, user_id)),
                "action": "route",
                "outbound": outbound_tag,
            },
        )


def bind_proxy(user_id: str, proxy: dict[str, Any]) -> dict[str, Any]:
    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")

        _set_proxy_binding(data, registry, user_id, proxy)
        _audit("proxy.bind", user_id, server=str(proxy.get("server")), port=int(proxy.get("port")))
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

        outbound_tag = f"{USER_OUTBOUND_PREFIX}{user_id}"
        data["outbounds"] = [item for item in data.get("outbounds", []) if item.get("tag") != outbound_tag]
        route = data.get("route", {})
        route["rules"] = [
            rule for rule in route.get("rules", []) if rule.get("outbound") != outbound_tag
        ]
        registry.setdefault("users", {}).pop(user_id, None)
        _audit("user.delete", user_id)
        return {"success": True, "userId": user_id, "message": "user deleted"}

    return mutate_config(apply)


def _extract_user_id(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith(USER_PREFIX):
        return value[len(USER_PREFIX):]
    return None


def _discover_user_ids(data: dict[str, Any], registry: dict[str, Any]) -> set[str]:
    user_ids = set(registry.get("users", {}))
    for inbound in data.get("inbounds", []):
        for user in inbound.get("users", []):
            for field in ("name", "username"):
                user_id = _extract_user_id(user.get(field))
                if user_id:
                    user_ids.add(user_id)
    return user_ids


def ensure_user_outbounds() -> int:
    with _config_lock():
        current = read_config()
        registry = read_registry()
        user_ids = _discover_user_ids(current, registry)
        outbound_tags = {item.get("tag") for item in current.get("outbounds", [])}
        route_tags = {
            rule.get("outbound") for rule in current.get("route", {}).get("rules", [])
        }
        missing = [
            user_id
            for user_id in user_ids
            if f"{USER_OUTBOUND_PREFIX}{user_id}" not in outbound_tags
            or f"{USER_OUTBOUND_PREFIX}{user_id}" not in route_tags
        ]
    if not missing:
        return 0

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> int:
        for user_id in missing:
            _set_direct_binding(data, registry, user_id)
        return len(missing)

    return mutate_config(apply)


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
        outbound = outbounds.get(f"{USER_OUTBOUND_PREFIX}{user_id}")
        item["protocols"].sort(key=protocol_order.get)
        item["socksUsername"] = item.get("socksUsername") or metadata.get("socksUsername")
        item["proxyBound"] = bool(outbound and outbound.get("type") == "socks")
        item["proxyServer"] = (
            f"{outbound.get('server')}:{outbound.get('server_port')}"
            if item["proxyBound"]
            else None
        )
        item["createdAt"] = metadata.get("createdAt")
        item["status"] = "active"
        result.append(item)

    return sorted(result, key=lambda item: item["userId"].lower())


def get_user_connection(user_id: str) -> dict[str, Any]:
    with _config_lock():
        data = read_config()
        registry = read_registry()

    metadata = _registry_user(registry, user_id)
    auth_name = _auth_name(user_id)
    socks_username = metadata.get("socksUsername") or auth_name
    protocols: list[str] = []
    user_uuid: str | None = None
    response: dict[str, Any] = {
        "success": True,
        "userId": user_id,
        "uuid": "",
        "protocols": protocols,
        "vless": None,
        "vmess": None,
        "socks": None,
        "protocolsAll": {},
        "protocolInfo": {},
        "proxyBound": False,
        "createdAt": metadata.get("createdAt"),
    }

    vless_inbound: dict[str, Any] | None = None
    vmess_inbound: dict[str, Any] | None = None
    socks_inbound: dict[str, Any] | None = None
    for inbound in data.get("inbounds", []):
        tag = inbound.get("tag")
        if tag == config.singbox.vless_tag:
            vless_inbound = inbound
            user = next(
                (
                    item
                    for item in inbound.get("users", [])
                    if item.get("name") in _legacy_auth_names(user_id)
                ),
                None,
            )
            if user:
                user_uuid = str(user.get("uuid") or "")
                protocols.append("vless")
                response["vless"] = _vless_connection(user_id, user_uuid, inbound)
        elif tag == config.singbox.vmess_tag:
            vmess_inbound = inbound
            user = next(
                (
                    item
                    for item in inbound.get("users", [])
                    if item.get("name") in _legacy_auth_names(user_id)
                ),
                None,
            )
            if user:
                vmess_uuid = str(user.get("uuid") or "")
                user_uuid = user_uuid or vmess_uuid
                protocols.append("vmess")
                response["vmess"] = _vmess_connection(user_id, vmess_uuid, inbound)
        elif tag == config.singbox.socks_tag and socks_username:
            socks_inbound = inbound
            user = next(
                (
                    item
                    for item in inbound.get("users", [])
                    if item.get("username") == socks_username
                ),
                None,
            )
            if user:
                protocols.append("socks")
                response["socks"] = _socks_connection(
                    str(user.get("username") or ""),
                    str(user.get("password") or ""),
                    inbound,
                )

    if not protocols:
        raise SingboxConfigError(f"user not found: {user_id}")

    outbound = next(
        (
            item
            for item in data.get("outbounds", [])
            if item.get("tag") == f"{USER_OUTBOUND_PREFIX}{user_id}"
        ),
        None,
    )
    response["uuid"] = user_uuid or ""
    response["proxyBound"] = bool(outbound and outbound.get("type") == "socks")
    all_protocols = build_all_protocols(
        user_id,
        response["uuid"],
        response.get("socks"),
        vless_inbound=vless_inbound,
        vmess_inbound=vmess_inbound,
        socks_inbound=socks_inbound,
        include_original=response["proxyBound"],
        enabled_protocols=set(protocols),
    )
    if all_protocols:
        response["protocolsAll"] = all_protocols
        # 兼容链接与结构化参数统一使用同一个加速地址。
        if all_protocols.get("vless"):
            response["vless"] = all_protocols["vless"]
        if all_protocols.get("vmess"):
            response["vmess"] = all_protocols["vmess"]
    response["protocolInfo"] = build_protocol_info(
        user_id,
        response["uuid"],
        response.get("socks"),
        vless_inbound=vless_inbound,
        vmess_inbound=vmess_inbound,
        socks_inbound=socks_inbound,
        include_original=response["proxyBound"],
    )
    return response


def get_user_proxy(user_id: str) -> dict[str, Any]:
    with _config_lock():
        data = read_config()
        registry = read_registry()

    if not _user_exists(data, registry, user_id):
        raise SingboxConfigError(f"user not found: {user_id}")

    outbound = next(
        (
            item
            for item in data.get("outbounds", [])
            if item.get("tag") == f"{USER_OUTBOUND_PREFIX}{user_id}"
        ),
        None,
    )
    if not outbound or outbound.get("type") not in {"socks", "socks5"}:
        return {
            "userId": user_id,
            "proxyBound": False,
            "server": None,
            "port": None,
            "username": None,
            "password": None,
        }

    return {
        "userId": user_id,
        "proxyBound": True,
        "server": outbound.get("server"),
        "port": outbound.get("server_port"),
        "username": outbound.get("username"),
        "password": outbound.get("password"),
    }
