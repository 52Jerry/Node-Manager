from __future__ import annotations

import base64
import copy
import hashlib
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
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from config import config
from protocols import (
    ProtocolData,
    bitbrowser,
    normalize_country_code,
    protocol_info,
    socks5_original,
    socks_acceleration,
    vmess,
    vless,
    trojan,
)
from .api import SingboxAPI
from .connection_snapshot import ConnectionSnapshotCache
from .errors import SingboxConfigError

try:
    import fcntl
except ImportError:  # Windows development fallback; production deployment uses Linux flock.
    fcntl = None


logger = logging.getLogger(__name__)
_restart_allowed = ContextVar("singbox_restart_allowed", default=True)
_config_lock_depth = ContextVar("singbox_config_lock_depth", default=0)
_config_read_lock_depth = ContextVar("singbox_config_read_lock_depth", default=0)
_mutation_workspace = ContextVar("singbox_mutation_workspace", default=None)
_mutation_baseline = ContextVar("singbox_mutation_baseline", default=None)
_mutation_registry_baseline = ContextVar("singbox_registry_baseline",default=None)
_mutation_capture = ContextVar("singbox_mutation_capture", default=False)


class CapturedMutation(Exception):
    def __init__(self, callback):
        self.callback = callback


def capture_mutation(call):
    """Compile an existing operation before any publication/post-commit work."""
    token = _mutation_capture.set(True)
    try:
        call()
    except CapturedMutation as captured:
        return captured.callback
    finally:
        _mutation_capture.reset(token)
    raise SingboxConfigError("operation has no supported configuration mutation")


@contextmanager
def without_restart():
    token = _restart_allowed.set(False)
    try:
        yield
    finally:
        _restart_allowed.reset(token)


CONFIG_PATH = Path(config.singbox.config)
LOCK_PATH = Path("/run/lock/node-manager-singbox.lock")
REGISTRY_PATH = Path(os.environ.get("NODE_MANAGER_USER_REGISTRY", "/var/lib/node-manager/users.json"))
USER_PREFIX = "node-manager:"
USER_OUTBOUND_PREFIX = "node-manager-out:"
ENFORCEMENT_TRAFFIC_KEY = "enforcementTrafficBlocked"
ENFORCEMENT_SOURCE_CIDRS_KEY = "enforcementBlockedSourceCidrs"
ENFORCEMENT_AUTH_USERS_KEY = "enforcementAuthUsers"
EXPIRATION_AUTH_USERS_KEY = "expirationAuthUsers"
EXPIRATION_BLOCKED_KEY = "expirationBlocked"
ACCESS_AUTH_USERS_KEY = "accessBlockedAuthUsers"
ACCESS_BLOCKED_KEY = "accessBlocked"
DEFAULT_USER_LIFETIME = timedelta(days=30)
RESTORE_WINDOW = timedelta(hours=24)
EXPIRATION_ENABLED = os.environ.get("NODE_MANAGER_EXPIRATION_ENABLED", "true").lower() not in {
    "false", "0", "no", "off"
}
expiration_stop = threading.Event()
expiration_thread: threading.Thread | None = None
singbox_api = SingboxAPI()
_connection_snapshot_cache = ConnectionSnapshotCache()
_connection_snapshot_cache_lock = threading.Lock()
thread_lock = threading.Lock()
_enforcement_noop_cache: tuple | None = None


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


def _run(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def read_config() -> dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _empty_registry() -> dict[str, Any]:
    return {"version": 2, "users": {}, "expiredUsers": {}}


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
    registry.setdefault("version", 2)
    registry.setdefault("expiredUsers", {})
    if not isinstance(registry.get("expiredUsers"), dict):
        raise SingboxConfigError("the expired user registry has an invalid structure")
    return registry


def _as_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _expiration_status(metadata: dict[str, Any], now: datetime | None = None) -> str:
    if not EXPIRATION_ENABLED:
        return "ACTIVE"
    expires_at = _as_utc(metadata.get("expiresAt"))
    return "EXPIRED" if expires_at is not None and expires_at <= (now or datetime.now(timezone.utc)) else "ACTIVE"


def _config_mtime() -> datetime:
    """返回旧配置迁移时可用的最早本地时间依据。"""
    try:
        return datetime.fromtimestamp(CONFIG_PATH.stat().st_mtime, timezone.utc)
    except OSError:
        return datetime.now(timezone.utc)


def _config_user_ids(data: dict[str, Any], registry: dict[str, Any]) -> set[str]:
    """从受管入站发现注册表缺失的旧用户。"""
    user_ids = set(registry.get("users", {}))
    protocol_tags = {
        config.singbox.vless_tag,
        config.singbox.vmess_tag,
        config.singbox.socks_tag,
    }
    socks_names = {
        str(item.get("socksUsername"))
        for item in registry.get("users", {}).values()
        if isinstance(item, dict) and item.get("socksUsername")
    }
    managed_protocol_names: set[str] = set()
    for inbound in data.get("inbounds", []):
        if not isinstance(inbound, dict) or inbound.get("tag") not in protocol_tags:
            continue
        for user in inbound.get("users", []):
            if not isinstance(user, dict):
                continue
            values = [user.get("name"), user.get("username")]
            for value in values:
                if not value:
                    continue
                text = str(value)
                user_id = _extract_user_id(text)
                if user_id:
                    user_ids.add(user_id)
                elif inbound.get("tag") in {
                    config.singbox.vless_tag,
                    config.singbox.vmess_tag,
                }:
                    # A few older configs used the bare user ID for the
                    # VLESS/VMess name. These protocol entries are managed
                    # identities, so they are safe to use as migration hints.
                    user_ids.add(text)
                    managed_protocol_names.add(text)

    for inbound in data.get("inbounds", []):
        if not isinstance(inbound, dict) or inbound.get("tag") != config.singbox.socks_tag:
            continue
        for user in inbound.get("users", []):
            if not isinstance(user, dict) or not user.get("username"):
                continue
            text = str(user["username"])
            if text in socks_names:
                mapped_user_id = next(
                    user_id
                    for user_id, metadata in registry.get("users", {}).items()
                    if isinstance(metadata, dict)
                    and str(metadata.get("socksUsername")) == text
                )
                user_ids.add(mapped_user_id)
            elif text in managed_protocol_names:
                user_ids.add(text)
    return user_ids


def migrate_user_expirations() -> int:
    """Register historical users without inventing expiration dates."""
    if not EXPIRATION_ENABLED:
        return 0
    fallback_created_at = _config_mtime()

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> int:
        changed = 0
        registry["version"] = max(int(registry.get("version") or 1), 2)
        registry.setdefault("expiredUsers", {})
        users = registry.setdefault("users", {})
        for user_id in _config_user_ids(data, registry):
            metadata = users.setdefault(user_id, {})
            if (not isinstance(metadata, dict)
                    or _as_utc(metadata.get("expiresAt")) is not None
                    or _as_utc(metadata.get("createdAt")) is not None):
                continue
            metadata["createdAt"] = _iso(fallback_created_at)
            changed += 1
        return changed

    return mutate_config(apply)


def recover_wireguard_user_metadata(user_expirations: dict[str, datetime]) -> int:
    """Recover registry rows for legacy users proven by their live config.

    WireGuard reconciliation supplies the authoritative subscription expiry,
    but recovery is allowed only when the same user identity already exists in
    a managed inbound and owns an exact residential SOCKS outbound. Existing
    registry rows are never changed here, including suspended or blocked rows.
    """
    if not isinstance(user_expirations, dict) or not user_expirations:
        return 0

    normalized: dict[str, datetime] = {}
    now = datetime.now(timezone.utc)
    for raw_user_id, raw_expiry in user_expirations.items():
        user_id = str(raw_user_id or "").strip()
        expires_at = _as_utc(raw_expiry)
        if not user_id or expires_at is None or expires_at <= now:
            raise SingboxConfigError("legacy WireGuard user recovery requires a future expiration")
        normalized[user_id] = expires_at

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> int:
        users = registry.setdefault("users", {})
        if not isinstance(users, dict):
            raise SingboxConfigError("the user registry has an invalid structure")

        outbounds = {
            str(item.get("tag")): item
            for item in data.get("outbounds", [])
            if isinstance(item, dict) and item.get("tag")
        }
        recovered = 0
        for user_id, expires_at in normalized.items():
            existing = users.get(user_id)
            if user_id in users:
                if not isinstance(existing, dict):
                    raise SingboxConfigError("the user registry has an invalid user entry")
                if _as_utc(existing.get("expiresAt")) is not None:
                    continue
                if (existing.get("accessEnabled") is False
                        or any(existing.get(flag) for flag in (
                            ACCESS_BLOCKED_KEY,
                            EXPIRATION_BLOCKED_KEY,
                            ENFORCEMENT_TRAFFIC_KEY,
                        ))):
                    continue

            auth_names = {_auth_name(user_id), user_id}
            matching_users = [
                auth_user
                for inbound in data.get("inbounds", [])
                if isinstance(inbound, dict)
                and inbound.get("tag") in {
                    config.singbox.vless_tag,
                    config.singbox.vmess_tag,
                    config.singbox.socks_tag,
                }
                for auth_user in inbound.get("users", [])
                if isinstance(auth_user, dict)
                and (auth_user.get("name") in auth_names
                     or auth_user.get("username") in auth_names)
            ]
            if not matching_users:
                raise SingboxConfigError("legacy WireGuard user is absent from managed inbounds")

            outbound = outbounds.get(USER_OUTBOUND_PREFIX + user_id)
            server = str((outbound or {}).get("server") or "").strip()
            port = (outbound or {}).get("server_port")
            if (not isinstance(outbound, dict) or outbound.get("type") != "socks"
                    or not server or not isinstance(port, int) or isinstance(port, bool)
                    or not 1 <= port <= 65535):
                raise SingboxConfigError("legacy WireGuard user has no residential SOCKS outbound")

            socks_username = next(
                (str(item.get("username")) for item in matching_users if item.get("username")),
                None,
            )
            metadata = existing if isinstance(existing, dict) else {}
            metadata.setdefault("socksUsername", socks_username)
            metadata.setdefault("createdAt", _iso(now))
            metadata["expiresAt"] = _iso(expires_at)
            metadata.setdefault("accessEnabled", True)
            metadata.setdefault("sourceIp", server)
            metadata.setdefault("sourceAddress", server)
            metadata.setdefault("sourcePort", port)
            users[user_id] = metadata
            recovered += 1
            _audit("user.registry.recover.wireguard", user_id, expiresAt=_iso(expires_at))
        return recovered

    return mutate_config(apply)


def get_user_policy(user_id: str) -> dict[str, int | None]:
    with _config_lock():
        metadata = _registry_user(read_registry(), user_id)
    return {
        "trafficLimitBytes": _positive_policy_value(metadata.get("trafficLimitBytes")),
        "maxSourceIps": _positive_policy_value(metadata.get("maxSourceIps")),
        "maxConnections": _positive_policy_value(metadata.get("maxConnections")),
    }


def get_user_policies() -> dict[str, dict[str, int | None]]:
    with _config_read_lock():
        registry = read_registry()
    return {
        user_id: {
            "trafficLimitBytes": _positive_policy_value(item.get("trafficLimitBytes")),
            "maxSourceIps": _positive_policy_value(item.get("maxSourceIps")),
            "maxConnections": _positive_policy_value(item.get("maxConnections")),
        }
        for user_id, item in registry.get("users", {}).items()
        if isinstance(item, dict)
    }


def get_user_auth_map() -> dict[str, str]:
    """Map sing-box authentication names back to control-plane user IDs."""
    with _config_read_lock():
        data = read_config()
        registry = read_registry()

    configured_auth_names = {
        str(value)
        for inbound in data.get("inbounds", [])
        if isinstance(inbound, dict)
        for user in inbound.get("users", [])
        if isinstance(user, dict)
        for value in (user.get("name"), user.get("username"))
        if value
    }
    result: dict[str, str] = {}
    for user_id in _discover_user_ids(data, registry):
        auth_names = {
            _auth_name(user_id),
            _public_socks_username(registry, user_id),
        }
        if user_id in configured_auth_names:
            auth_names.add(user_id)
        for auth_name in auth_names:
            if auth_name:
                result[str(auth_name)] = user_id
    return result


def _positive_policy_value(value: Any) -> int | None:
    try:
        normalized = int(value or 0)
    except (TypeError, ValueError):
        return None
    return normalized if normalized > 0 else None


def check_config(config_path: str | Path) -> tuple[bool, str]:
    try:
        result = _run([getattr(config.singbox, "binary", "sing-box"), "check", "-c", str(config_path)])
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return result.returncode == 0, (result.stderr or result.stdout).strip()


def is_singbox_running() -> bool:
    try:
        result = _run(["systemctl", "is-active", "sing-box"])
        return result.stdout.strip() == "active"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def reload_singbox(restart_if_reload_fails: bool = False) -> bool:
    """Hot-reload sing-box without restarting shared processes by default.

    A failed reload keeps the current process and lets mutate_config restore the
    previous config/registry. Only an explicit emergency caller may request the
    restart fallback; ordinary user, route, credential and rollback writes must
    never restart the shared proxy.
    """
    from .runtime_client import enabled as runtime_enabled
    if runtime_enabled():
        import runtime_publication
        try:
            runtime_publication.apply_disk()
            return True
        except SingboxConfigError:
            logger.warning("runtime publication failed; no reload or restart fallback")
            return False
    # Optional VLESS publisher owns its separate process generations. The
    # original instance still serves the legacy non-VLESS protocols.
    publication_path = os.environ.get("NODE_MANAGER_VLESS_PUBLICATION_SPEC")
    if publication_path:
        try:
            import sys
            import vless_publication
            if vless_publication.configured_spec() is not None:
                result = _run([sys.executable, str(Path(vless_publication.__file__)),
                               "--spec", publication_path, "apply"], timeout=180)
                receipt = json.loads(result.stdout) if result.returncode == 0 else {}
                return result.returncode == 0 and receipt.get("ok") is True
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            logger.warning("VLESS publication failed; preserving existing generations")
            return False
    commands = [["systemctl", "reload", "sing-box"]]
    if restart_if_reload_fails and _restart_allowed.get():
        commands.append(["systemctl", "restart", "sing-box"])
    for command in commands:
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
    if _config_read_lock_depth.get() and not _config_lock_depth.get():
        raise SingboxConfigError("cannot mutate sing-box configuration while holding a read lock")
    depth = _config_lock_depth.get()
    token = _config_lock_depth.set(depth + 1)
    try:
        if depth:
            yield
        elif fcntl is None:
            with thread_lock:
                yield
        else:
            LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LOCK_PATH.open("w", encoding="ascii") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                yield
    finally:
        _config_lock_depth.reset(token)


@contextmanager
def _config_read_lock():
    """Share consistent file reads while excluding multi-file configuration writes."""
    depth = _config_read_lock_depth.get()
    token = _config_read_lock_depth.set(depth + 1)
    try:
        if depth or _config_lock_depth.get():
            yield
        elif fcntl is None:
            with thread_lock:
                yield
        else:
            LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LOCK_PATH.open("a", encoding="ascii") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
                yield
    finally:
        _config_read_lock_depth.reset(token)


def _write_and_reload(updated: dict[str, Any]) -> None:
    from .runtime_client import enabled as runtime_enabled
    if runtime_enabled():
        import runtime_publication
        runtime_publication.commit(updated, read_registry(), read_config())
        return
    import runtime_write_queue
    if runtime_write_queue.current() is not None:
        raise SingboxConfigError("active native writer refuses reload/restart fallback")
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
    if _mutation_capture.get():
        raise CapturedMutation(mutator)
    workspace = _mutation_workspace.get()
    if workspace is not None:
        return mutator(*workspace)
    import runtime_write_queue
    writer = runtime_write_queue.current()
    if writer is not None and not _config_lock_depth.get():
        import runtime_publication
        from idempotency import execution_identity, execution_ordinal
        identity = execution_identity.get()
        ordinal = execution_ordinal.get()
        execution_ordinal.set(ordinal + 1)
        captured = dict(zip(mutator.__code__.co_freevars, (cell.cell_contents for cell in (mutator.__closure__ or ()))))
        user_id = captured.get("user_id")
        keys = {user_id} if isinstance(user_id, str) else set()
        def versioned(data, registry):
            result = mutator(data, registry)
            for user in keys:
                versions = registry.setdefault("runtimeUserVersions", {})
                from runtime_history import user_version
                versions[user] = user_version(user,registry) + 1
            return result
        task_id, _ = writer.submit(versioned, key=f"legacy:{identity['key']}:{ordinal}" if identity else None,
                                   payload={"request": identity, "mutation": mutator.__qualname__, "scope": sorted(keys)},
                                   size=runtime_write_queue.submission_size.get(), keys=keys,
                                   isolated=not keys or runtime_publication.related_targets.get() is not None)
        return writer.wait(task_id)
    return _mutate_config_direct(mutator)


def _mutate_config_direct(mutator: Callable[[dict[str, Any], dict[str, Any]], Any]) -> Any:
    with _config_lock():
        import runtime_write_queue
        from .runtime_client import enabled as runtime_enabled
        if runtime_write_queue.current() is not None and not runtime_enabled():
            raise SingboxConfigError("active native writer refuses publication mode changes")
        from revision_transaction import assert_no_pending_transaction
        assert_no_pending_transaction()
        current = read_config()
        registry = read_registry()
        updated = copy.deepcopy(current)
        updated_registry = copy.deepcopy(registry)
        baseline_token = _mutation_baseline.set(current)
        registry_token = _mutation_registry_baseline.set(registry)
        try:
            result = mutator(updated, updated_registry)
        finally:
            _mutation_baseline.reset(baseline_token)
            _mutation_registry_baseline.reset(registry_token)
        config_changed = current != updated
        registry_changed = registry != updated_registry
        from .runtime_client import enabled as runtime_enabled
        if not config_changed and not registry_changed:
            if runtime_enabled():
                import runtime_publication
                if runtime_publication.related_targets.get():
                    runtime_publication.commit(updated, updated_registry, current)
            return result
        if runtime_enabled():
            import runtime_publication
            # Keep empty SOCKS tables authenticated after the next process boot.
            for inbound in updated.get("inbounds", []):
                if inbound.get("type") == "socks" and inbound.get("tag") == config.singbox.socks_tag:
                    inbound["require_auth"] = True
            runtime_publication.commit(updated, updated_registry, current)
            return result
        original_registry = REGISTRY_PATH.read_bytes() if REGISTRY_PATH.exists() else None
        if registry_changed:
            _write_registry(updated_registry)
        try:
            if config_changed:
                _write_and_reload(updated)
        except Exception:
            if registry_changed:
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
    socks_username = _public_socks_username(registry, user_id)
    if socks_username:
        names.add(socks_username)
    return names


def _public_socks_username(registry: dict[str, Any], user_id: str) -> str:
    """Return the username that must be shown to SOCKS clients.

    ``node-manager:<id>`` is an internal VLESS/VMess auth alias used by old
    installations.  It is never a valid public SOCKS username.  Historical
    registries may contain that value, so normalize it to the user id here as
    a final compatibility guard.
    """
    configured = str(_registry_user(registry, user_id).get("socksUsername") or "").strip()
    if not configured or configured == _auth_name(user_id):
        return user_id
    return configured


def migrate_legacy_socks_usernames() -> int:
    """Migrate old ``node-manager:<id>`` SOCKS users to the public user id.

    The migration is idempotent and updates route auth lists and the local
    registry in the same atomic config transaction.  Passwords are retained
    byte-for-byte and are never written to logs.
    """
    def apply(data: dict[str, Any], registry: dict[str, Any]) -> int:
        changed = 0
        users_by_name = {
            str(user.get("username"))
            for inbound in data.get("inbounds", [])
            if inbound.get("tag") == config.singbox.socks_tag
            for user in inbound.get("users", [])
            if user.get("username")
        }
        replacements: dict[str, str] = {}
        for inbound in data.get("inbounds", []):
            if inbound.get("tag") != config.singbox.socks_tag:
                continue
            for user in inbound.get("users", []):
                username = str(user.get("username") or "")
                if not username.startswith(USER_PREFIX):
                    continue
                user_id = username[len(USER_PREFIX):]
                if not user_id or user_id in users_by_name:
                    # A real public username already exists; do not merge two
                    # accounts implicitly.
                    continue
                user["username"] = user_id
                replacements[username] = user_id
                changed += 1
                item = registry.setdefault("users", {}).setdefault(user_id, {})
                if item.get("socksUsername") in (None, "", username):
                    item["socksUsername"] = user_id

        if replacements:
            for rule in data.get("route", {}).get("rules", []):
                auth_users = rule.get("auth_user")
                if not isinstance(auth_users, list):
                    continue
                rule["auth_user"] = [replacements.get(str(value), value) for value in auth_users]
        return changed

    return mutate_config(apply)


def _find_user_uuid(data: dict[str, Any], registry: dict[str, Any], user_id: str) -> str:
    """Find the UUID used by the user's VLESS/VMess inbound entries.

    The proxy-details endpoint must expose the same UUID as the connection
    endpoint.  Older installations may authenticate with either
    ``node-manager:<id>`` or the bare user id, so inspect both aliases.
    """
    names = _legacy_auth_names(user_id)
    for inbound in data.get("inbounds", []):
        if inbound.get("tag") not in {config.singbox.vless_tag, config.singbox.vmess_tag}:
            continue
        for user in inbound.get("users", []):
            if user.get("name") in names and user.get("uuid"):
                return str(user["uuid"])
    return ""


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
    socks_username = _public_socks_username(registry, user_id)
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
    value = str(config.node.random_acceleration_domain() or config.node.host or "").strip()
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


def _trojan_connection(user_id: str, password: str, inbound: dict[str, Any]) -> str:
    """第 6 种协议：Trojan 连接 URI。复用 Reality TLS（pbk/sid/sni 与 VLESS 共享）。"""
    public_key, short_id, server_name = _reality_client_options(inbound)
    port = int(inbound["listen_port"])
    return (
        f"trojan://{password}@{_uri_host(_acceleration_host())}:{port}"
        f"?type=tcp&security=reality"
        f"&pbk={public_key}&sid={short_id}&sni={server_name}&fp=chrome"
        f"#{user_id}"
    )


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
    trojan_inbound: dict[str, Any] | None = None,
    socks_inbound: dict[str, Any] | None = None,
    vless_security: str = "reality",
    include_original: bool = False,
    enabled_protocols: set[str] | None = None,
    proxy: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Generate the public links for one Node Manager user.

    The three/four Node Manager acceleration links are generated from the local
    inbounds and are independent of any upstream residential proxy.  The two
    legacy/original links are opt-in and are only emitted when a local SOCKS
    connection exists *and* the caller explicitly requests them (residential
    provisioning).  When ``proxy`` is supplied the original links use the
    upstream proxy's server/port/credentials so the resulting URIs match
    what the residential provider (e.g. IPVelo) issued for this allocation.
    """
    enabled = enabled_protocols or {"vless", "vmess", "socks", "trojan"}
    acceleration_host = _acceleration_host()

    # VLESS/VMess do not need SOCKS credentials.  For SOCKS acceleration,
    # use the local inbound credentials.  The public default username is the
    # node user id; the historical ``node-manager:<id>`` name remains an
    # internal VLESS/VMess alias only.
    local_username = str((socks or {}).get("username") or user_id)
    local_password = str((socks or {}).get("password") or "")
    display_ip = str(
        (proxy or {}).get("sourceIp")
        or (proxy or {}).get("source_ip")
        or (socks or {}).get("host")
        or config.node.host
    )
    country_code = str(
        (proxy or {}).get("countryCode")
        or (proxy or {}).get("country_code")
        or "XX"
    )
    data = ProtocolData(
        ip=display_ip,
        port=int((socks or {}).get("port") or _inbound_port(socks_inbound, 5001)),
        username=local_username,
        password=local_password,
        country_code=country_code,
        country_name=str(
            (proxy or {}).get("countryName")
            or (proxy or {}).get("country_name")
            or ""
        ),
        province_name=str(
            (proxy or {}).get("provinceName")
            or (proxy or {}).get("province_name")
            or ""
        ),
        city_name=str(
            (proxy or {}).get("cityName")
            or (proxy or {}).get("city_name")
            or ""
        ),
        uuid=user_uuid or "",
        acceleration_domain=acceleration_host,
        acceleration_port_socks=_inbound_port(socks_inbound, 5001),
        vless_port=_inbound_port(vless_inbound, 20168),
        vmess_port=_inbound_port(vmess_inbound, 20169),
        trojan_port=_inbound_port(trojan_inbound, 20170),
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
    # Trojan 复用 VLESS 的 Reality 参数（同节点共享密钥），并回退到默认 pbk/sid。
    if trojan_inbound is not None:
        try:
            trojan_pbk, trojan_sid, trojan_sni = _reality_client_options(trojan_inbound)
            data.trojan_pbk = trojan_pbk
            data.trojan_sid = trojan_sid
            data.trojan_sni = trojan_sni
        except SingboxConfigError:
            logger.warning("could not derive Reality client params for trojan %s", user_id)
            # 回退到 VLESS 的 Reality 参数（若已设置）
            data.trojan_pbk = data.trojan_pbk or data.vless_pbk
            data.trojan_sid = data.trojan_sid or data.vless_sid
            data.trojan_sni = data.trojan_sni or data.vless_sni
    links: dict[str, str] = {}
    if include_original and socks is not None:
        original_data = data
        if proxy is not None:
            upstream_server = str(
                proxy.get("server")
                or proxy.get("sourceAddress")
                or proxy.get("source_address")
                or ""
            ).strip()
            if not upstream_server:
                raise SingboxConfigError("住宅 SOCKS 缺少上游服务器地址")
            upstream_port = proxy.get("port") or proxy.get("server_port")
            try:
                upstream_port = int(upstream_port)
            except (TypeError, ValueError) as exc:
                raise SingboxConfigError("residential SOCKS upstream port is missing") from exc
            if not 1 <= upstream_port <= 65535:
                raise SingboxConfigError("residential SOCKS upstream port is invalid")
            original_data = ProtocolData(
                ip=data.ip,
                port=upstream_port,
                username=str(proxy.get("username") or data.username),
                password=str(proxy.get("password") or data.password),
                country_code=str(proxy.get("countryCode") or proxy.get("country_code") or data.country_code or "XX"),
                country_name=str(proxy.get("countryName") or proxy.get("country_name") or data.country_name or ""),
                province_name=str(proxy.get("provinceName") or proxy.get("province_name") or data.province_name or ""),
                city_name=str(proxy.get("cityName") or proxy.get("city_name") or data.city_name or ""),
                uuid=data.uuid,
                acceleration_domain=data.acceleration_domain,
                acceleration_port_socks=data.acceleration_port_socks,
                vless_port=data.vless_port,
                vmess_port=data.vmess_port,
                trojan_port=data.trojan_port,
                endpoint_host=upstream_server,
            )
        links["socks5"] = socks5_original(original_data)
        links["bitbrowser"] = bitbrowser(original_data)
    if "vless" in enabled and vless_inbound is not None and user_uuid:
        links["vless"] = vless(data)
    if "socks" in enabled and socks is not None and socks_inbound is not None:
        links["socksAcceleration"] = socks_acceleration(data)
    if "vmess" in enabled and vmess_inbound is not None and user_uuid:
        links["vmess"] = vmess(data)
    if "trojan" in enabled and trojan_inbound is not None and user_uuid:
        links["trojan"] = trojan(data)
    return links


def build_protocol_info(
    user_id: str,
    user_uuid: str,
    socks: dict[str, Any] | None,
    vless_inbound: dict[str, Any] | None = None,
    vmess_inbound: dict[str, Any] | None = None,
    trojan_inbound: dict[str, Any] | None = None,
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
    local_username = str((socks or {}).get("username") or user_id)
    local_password = str((socks or {}).get("password") or "")
    display_ip = str(
        (proxy or {}).get("sourceIp")
        or (proxy or {}).get("source_ip")
        or (socks or {}).get("host")
        or config.node.host
    )
    country_code = str(
        (proxy or {}).get("countryCode")
        or (proxy or {}).get("country_code")
        or "XX"
    )
    data = ProtocolData(
        ip=display_ip,
        port=int((socks or {}).get("port") or _inbound_port(socks_inbound, 5001)),
        username=local_username,
        password=local_password,
        country_code=country_code,
        country_name=str(
            (proxy or {}).get("countryName")
            or (proxy or {}).get("country_name")
            or ""
        ),
        province_name=str(
            (proxy or {}).get("provinceName")
            or (proxy or {}).get("province_name")
            or ""
        ),
        city_name=str(
            (proxy or {}).get("cityName")
            or (proxy or {}).get("city_name")
            or ""
        ),
        uuid=user_uuid or "",
        acceleration_domain=acceleration_host,
        acceleration_port_socks=_inbound_port(socks_inbound, 5001),
        vless_port=_inbound_port(vless_inbound, 20168),
        vmess_port=_inbound_port(vmess_inbound, 20169),
        trojan_port=_inbound_port(trojan_inbound, 20170),
    )
    if vless_inbound is not None:
        try:
            public_key, short_id, server_name = _reality_client_options(vless_inbound)
            data.vless_pbk = public_key
            data.vless_sid = short_id
            data.vless_sni = server_name
        except SingboxConfigError:
            logger.warning("could not derive Reality client params for %s", user_id)
    if trojan_inbound is not None:
        try:
            trojan_pbk, trojan_sid, trojan_sni = _reality_client_options(trojan_inbound)
            data.trojan_pbk = trojan_pbk
            data.trojan_sid = trojan_sid
            data.trojan_sni = trojan_sni
        except SingboxConfigError:
            data.trojan_pbk = data.trojan_pbk or data.vless_pbk
            data.trojan_sid = data.trojan_sid or data.vless_sid
            data.trojan_sni = data.trojan_sni or data.vless_sni
    info = protocol_info(
        data,
        protocol_id=user_uuid or user_id,
        include_original=include_original and socks is not None,
    )
    if include_original and proxy is not None:
        upstream_server = str(
            proxy.get("server")
            or proxy.get("sourceAddress")
            or proxy.get("source_address")
            or ""
        ).strip()
        if not upstream_server:
            raise SingboxConfigError("住宅 SOCKS 缺少上游服务器地址")
        upstream_port = proxy.get("port") or proxy.get("server_port")
        try:
            upstream_port = int(upstream_port)
        except (TypeError, ValueError) as exc:
            raise SingboxConfigError("residential SOCKS upstream port is missing") from exc
        if not 1 <= upstream_port <= 65535:
            raise SingboxConfigError("residential SOCKS upstream port is invalid")
        upstream_username = proxy.get("username")
        upstream_password = proxy.get("password")
        source_ip = proxy.get("sourceIp") or proxy.get("source_ip")
        if source_ip:
            info["sourceIp"] = str(source_ip)
        if upstream_server:
            info["sourceAddress"] = upstream_server
            info["rawServer"] = upstream_server
        if upstream_port is not None:
            info["rawPort"] = int(upstream_port)
            info["sourcePort"] = int(upstream_port)
        if upstream_username:
            info["rawUsername"] = str(upstream_username)
        if upstream_password:
            info["rawPassword"] = str(upstream_password)
        info["countryCode"] = normalize_country_code(
            proxy.get("countryCode")
            or proxy.get("country_code")
            or info.get("countryCode")
        )
        if proxy.get("countryName") or proxy.get("country_name"):
            info["countryName"] = str(proxy.get("countryName") or proxy.get("country_name"))
        if proxy.get("provinceName") or proxy.get("province_name"):
            info["provinceName"] = str(proxy.get("provinceName") or proxy.get("province_name"))
        if proxy.get("cityName") or proxy.get("city_name"):
            info["cityName"] = str(proxy.get("cityName") or proxy.get("city_name"))
    return info


def create_user(
    user_id: str,
    protocols: list[str],
    user_uuid: str | None = None,
    socks_username: str | None = None,
    socks_password: str | None = None,
    proxy: dict[str, Any] | None = None,
    traffic_limit_bytes: int | None = None,
    max_source_ips: int | None = None,
    expires_at: datetime | None = None,
    require_readiness: bool = False,
) -> dict[str, Any]:
    # B1: 优先使用 Control Plane 指定的 UUID，确保多节点共享同一凭据。
    # 传入时严格校验格式，未传时回退到随机生成（保持向后兼容）。
    if user_uuid:
        try:
            uuid.UUID(str(user_uuid))
        except (ValueError, AttributeError, TypeError) as exc:
            raise SingboxConfigError(f"invalid uuid from control plane: {user_uuid}") from exc
        user_uuid = str(user_uuid)
    else:
        user_uuid = str(uuid.uuid4())
    # The local SOCKS inbound credentials are distinct from the upstream
    # residential proxy credentials.  The latter are used only by the
    # per-user outbound and must never leak into a public node link.
    # Do not expose the internal VLESS/VMess auth prefix in public SOCKS
    # links.  Explicit credentials still take precedence for compatibility.
    effective_socks_username = socks_username or user_id
    effective_socks_password = socks_password or secrets.token_urlsafe(18)
    created_at = datetime.now(timezone.utc)
    effective_expires_at = _as_utc(expires_at) or (created_at + DEFAULT_USER_LIFETIME)
    if effective_expires_at <= created_at:
        raise SingboxConfigError("expiresAt must be in the future")

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if require_readiness:
            from provisioning_readiness import assert_user_provisioning_allowed
            # A coalesced batch may already contain earlier users in its work
            # copy. Compare disk against the locked transaction baseline.
            baseline = _mutation_baseline.get()
            assert_user_provisioning_allowed(baseline if baseline is not None else data, protocols)
        if proxy is not None:
            _assert_proxy_available(data, "", proxy)
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
            "trojan": None,
            "socks": None,
            "proxyBound": proxy is not None,
            "expiresAt": _iso(effective_expires_at),
            "expirationStatus": "ACTIVE",
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

        if "trojan" in protocols:
            # 第 6 种协议：Trojan 用 password 认证，复用 user_uuid 作为 password
            inbound = _find_inbound(data, config.singbox.trojan_tag)
            inbound["users"].append({"name": auth_name, "password": user_uuid})
            response["trojan"] = _trojan_connection(user_id, user_uuid, inbound)

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
        trojan_inbound = next(
            (item for item in data.get("inbounds", [])
             if item.get("tag") == config.singbox.trojan_tag), None
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
            trojan_inbound=trojan_inbound,
            socks_inbound=socks_inbound,
            include_original=proxy is not None,
            enabled_protocols=set(protocols),
            proxy=proxy,
        )
        # 兼容链接与结构化参数统一使用同一个加速地址：legacy vless/vmess/trojan
        # 直接复用 protocolsAll 的生成结果，避免两套逻辑产生差异。
        if response["protocolsAll"].get("vless"):
            response["vless"] = response["protocolsAll"]["vless"]
        if response["protocolsAll"].get("vmess"):
            response["vmess"] = response["protocolsAll"]["vmess"]
        if response["protocolsAll"].get("trojan"):
            response["trojan"] = response["protocolsAll"]["trojan"]
        response["protocolInfo"] = build_protocol_info(
            user_id,
            user_uuid,
            response["socks"],
            vless_inbound=vless_inbound,
            vmess_inbound=vmess_inbound,
            trojan_inbound=trojan_inbound,
            socks_inbound=socks_inbound,
            include_original=proxy is not None,
            proxy=proxy,
        )

        registry.setdefault("users", {})[user_id] = {
            "socksUsername": effective_socks_username if "socks" in protocols else None,
            "createdAt": _iso(created_at),
            "expiresAt": _iso(effective_expires_at),
            "trafficLimitBytes": _positive_policy_value(traffic_limit_bytes),
            "maxSourceIps": _positive_policy_value(max_source_ips),
        }
        if proxy is not None:
            _save_proxy_metadata(registry, user_id, proxy)
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


def migrate_residential_ownership(payload: dict[str, Any]) -> dict[str, Any]:
    """Transfer a proven legacy owner without a delete/create availability gap.

    Keep this inside one mutate_config transaction: WireGuard snapshots take the
    same configuration lock, so they see either the old owner or the new owner.
    Existing WireGuard peers are deliberately not adopted by a different user.
    """
    from models.request import MigrateResidentialOwnershipRequest

    try:
        request = MigrateResidentialOwnershipRequest.model_validate(payload)
    except ValueError:
        raise SingboxConfigError("invalid residential ownership migration request") from None
    source, target = request.sourceUserId, request.targetUserId
    expected = request.expectedProxy.model_dump()
    identity = _proxy_identity(expected["server"], expected["port"],
                               expected.get("username"), expected.get("password"))
    proof = {
        "sourceUserId": source, "resourceId": request.resourceId,
        "subscriptionId": request.subscriptionId,
        "accessProfileId": request.accessProfileId,
        "fingerprint": hashlib.sha256(json.dumps(
            [identity, request.targetUuid.lower(), _iso(_as_utc(request.expiresAt))],
            separators=(",", ":"), ensure_ascii=True).encode()).hexdigest(),
    }

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        users = registry.setdefault("users", {})
        source_tag, target_tag = USER_OUTBOUND_PREFIX + source, USER_OUTBOUND_PREFIX + target
        source_present = _user_exists(data, registry, source)
        target_present = _user_exists(data, registry, target)
        replay = not source_present and target_present
        merge_existing_target = source_present and target_present
        owner = target if replay else source
        metadata = _registry_user(registry, owner)
        if replay:
            if (metadata.get("residentialOwnershipMigration") != proof
                    or _as_utc(metadata.get("expiresAt")) != _as_utc(request.expiresAt)):
                raise SingboxConfigError("residential target belongs to another allocation or has changed")
        elif not source_present:
            raise SingboxConfigError("residential source is missing or target is already occupied")
        if not metadata:
            raise SingboxConfigError("residential source registry is required")
        for field, value in (("resourceId", request.resourceId), ("userIpResourceId", request.resourceId),
                             ("subscriptionId", request.subscriptionId),
                             ("accessProfileId", request.accessProfileId)):
            if metadata.get(field) is not None and str(metadata[field]) != str(value):
                raise SingboxConfigError("residential owner belongs to another resource")
        if metadata.get("accessEnabled") is False or any(metadata.get(key) for key in (
                ACCESS_BLOCKED_KEY, ENFORCEMENT_TRAFFIC_KEY)):
            raise SingboxConfigError("blocked residential owner cannot be migrated")
        target_metadata = _registry_user(registry, target) if merge_existing_target else {}
        if merge_existing_target:
            if not target_metadata or target_metadata.get("residentialOwnershipMigration"):
                raise SingboxConfigError("residential target belongs to another allocation or has changed")
            for field, value in (("resourceId", request.resourceId),
                                 ("userIpResourceId", request.resourceId),
                                 ("subscriptionId", request.subscriptionId),
                                 ("accessProfileId", request.accessProfileId)):
                if target_metadata.get(field) is not None and str(target_metadata[field]) != str(value):
                    raise SingboxConfigError("residential target belongs to another resource")
            if target_metadata.get("accessEnabled") is False or any(target_metadata.get(key) for key in (
                    ACCESS_BLOCKED_KEY, ENFORCEMENT_TRAFFIC_KEY)):
                raise SingboxConfigError("blocked residential target cannot be migrated")
        owned = [item for item in data.get("outbounds", [])
                 if _is_user_proxy_outbound_tag(str(item.get("tag") or ""), owner)]
        if len(owned) != 1 or owned[0].get("tag") != USER_OUTBOUND_PREFIX + owner:
            raise SingboxConfigError("ambiguous residential outbound ownership")
        outbound = owned[0]
        if (outbound.get("type") != "socks"
                or not isinstance(outbound.get("server_port"), int)
                or isinstance(outbound.get("server_port"), bool)
                or _proxy_identity(str(outbound.get("server") or ""), outbound["server_port"],
                                   outbound.get("username"), outbound.get("password")) != identity):
            raise SingboxConfigError("residential proxy identity does not match")
        _assert_proxy_available(data, owner, expected)
        auth_names = _user_auth_names(registry, owner)
        managed_tags = {config.singbox.vless_tag, config.singbox.vmess_tag,
                        config.singbox.socks_tag, config.singbox.trojan_tag}
        matched = []
        for inbound in data.get("inbounds", []):
            for auth in inbound.get("users", []):
                if auth.get("name") in auth_names or auth.get("username") in auth_names:
                    if inbound.get("tag") not in managed_tags:
                        raise SingboxConfigError("residential identity appears in an unmanaged inbound")
                    matched.append(auth)
        uuids = {str(item["uuid"]).lower() for item in matched if item.get("uuid")}
        if len(uuids) != 1 or (replay and uuids != {request.targetUuid.lower()}):
            raise SingboxConfigError("residential UUID ownership is ambiguous or changed")
        source_uuid = next(iter(uuids))
        target_auth_names = _user_auth_names(registry, target) if merge_existing_target else set()
        target_matched = [auth for inbound in data.get("inbounds", [])
                          if inbound.get("tag") in managed_tags
                          for auth in inbound.get("users", [])
                          if auth.get("name") in target_auth_names or auth.get("username") in target_auth_names]
        if merge_existing_target:
            target_uuids = {str(item["uuid"]).lower() for item in target_matched if item.get("uuid")}
            if not target_matched or target_uuids != {request.targetUuid.lower()}:
                raise SingboxConfigError("residential target UUID is missing or changed")
        for inbound in data.get("inbounds", []):
            for auth in inbound.get("users", []):
                if any(auth is item for item in matched):
                    if inbound.get("tag") == config.singbox.trojan_tag and str(auth.get("password", "")).lower() != source_uuid:
                        raise SingboxConfigError("residential protocol credentials are inconsistent")
                elif merge_existing_target and any(auth is item for item in target_matched):
                    continue
                elif (str(auth.get("uuid", "")).lower() in {source_uuid, request.targetUuid.lower()}
                      or (inbound.get("type") == "trojan" and str(auth.get("password", "")).lower()
                          in {source_uuid, request.targetUuid.lower()})):
                    raise SingboxConfigError("residential UUID is shared by another owner")
        if any(other != owner and auth_names.intersection(_user_auth_names(registry, other))
               for other in users):
            raise SingboxConfigError("residential authentication identity is shared")
        rules = data.setdefault("route", {}).setdefault("rules", [])
        owned_tag = USER_OUTBOUND_PREFIX + owner
        owned_rules = [rule for rule in rules if rule.get("outbound") == owned_tag]
        if not owned_rules or any(not rule.get("auth_user")
                                  or not set(rule["auth_user"]).issubset(auth_names)
                                  for rule in owned_rules):
            raise SingboxConfigError("residential route ownership does not match")
        if any(owned_tag in item.get("outbounds", []) for item in data.get("outbounds", [])):
            raise SingboxConfigError("residential outbound is referenced by another owner")
        if merge_existing_target:
            target_outbounds = [item for item in data.get("outbounds", [])
                                if _is_user_proxy_outbound_tag(str(item.get("tag") or ""), target)]
            if len(target_outbounds) != 1 or target_outbounds[0].get("tag") != target_tag \
                    or target_outbounds[0].get("type") != "direct":
                raise SingboxConfigError("residential target is not an unbound direct user")
            target_rules = [rule for rule in rules if rule.get("outbound") == target_tag]
            if not target_rules or any(not rule.get("auth_user")
                                       or not set(rule["auth_user"]).issubset(target_auth_names)
                                       for rule in target_rules):
                raise SingboxConfigError("residential target route ownership does not match")
            if any(target_tag in item.get("outbounds", []) for item in data.get("outbounds", [])):
                raise SingboxConfigError("residential target outbound is referenced by another owner")
        result = {"success": True, "userId": target, "sourceUserId": source,
                  "resourceId": request.resourceId, "subscriptionId": request.subscriptionId,
                  "uuid": request.targetUuid, "expiresAt": _iso(_as_utc(request.expiresAt)),
                  "migrated": not replay}
        if replay:
            return result
        if merge_existing_target:
            _remove_expiration_rule(data, metadata)
            _remove_managed_enforcement_rules(rules, metadata)
            for inbound in data.get("inbounds", []):
                inbound["users"] = [auth for auth in inbound.get("users", [])
                                    if auth.get("name") not in auth_names
                                    and auth.get("username") not in auth_names]
            rules[:] = [rule for rule in rules
                        if rule.get("outbound") not in {source_tag, target_tag}]
            data["outbounds"] = [item for item in data.get("outbounds", [])
                                 if item.get("tag") not in {source_tag, target_tag}]
            merged_metadata = copy.deepcopy(target_metadata)
            for field in ("sourceIp", "sourceAddress", "sourcePort", "countryCode",
                          "countryName", "provinceName", "cityName"):
                if metadata.get(field) not in (None, ""):
                    merged_metadata[field] = metadata[field]
            merged_metadata.update(resourceId=request.resourceId, subscriptionId=request.subscriptionId,
                                   accessProfileId=request.accessProfileId,
                                   expiresAt=result["expiresAt"], residentialOwnershipMigration=proof)
            users[target] = merged_metadata
            users.pop(source)
            _set_proxy_binding(data, registry, target, expected)
            _audit("user.residential.ownership.migrate", target, sourceUserId=source,
                   resourceId=request.resourceId, subscriptionId=request.subscriptionId,
                   mergedExistingTarget=True)
            return result
        if any(_is_user_proxy_outbound_tag(str(item.get("tag") or ""), target)
               for item in data.get("outbounds", [])):
            raise SingboxConfigError("residential target outbound is already occupied")
        replacements = {_auth_name(source): _auth_name(target), source: target}
        replacement_names = set(replacements.values())
        if any(_auth_identifier_exists(data, name) for name in replacement_names):
            raise SingboxConfigError("residential target authentication is already occupied")
        _remove_expiration_rule(data, metadata)
        for auth in matched:
            if "uuid" in auth:
                auth["uuid"] = request.targetUuid
            elif "password" in auth and auth.get("name") in auth_names:
                auth["password"] = request.targetUuid
            for field in ("name", "username"):
                if auth.get(field) in replacements:
                    auth[field] = replacements[auth[field]]
        for rule in rules:
            if "auth_user" in rule:
                rule["auth_user"] = [replacements.get(value, value) for value in rule["auth_user"]]
            if rule.get("outbound") == source_tag:
                rule["outbound"] = target_tag
        outbound["tag"] = target_tag
        metadata = copy.deepcopy(metadata)
        metadata["socksUsername"] = replacements.get(metadata.get("socksUsername"), metadata.get("socksUsername"))
        for field in (ENFORCEMENT_AUTH_USERS_KEY, EXPIRATION_AUTH_USERS_KEY, ACCESS_AUTH_USERS_KEY):
            if isinstance(metadata.get(field), list):
                metadata[field] = [replacements.get(value, value) for value in metadata[field]]
        metadata.update(resourceId=request.resourceId, subscriptionId=request.subscriptionId,
                        accessProfileId=request.accessProfileId,
                        expiresAt=result["expiresAt"], residentialOwnershipMigration=proof)
        users[target] = metadata
        users.pop(source)
        _audit("user.residential.ownership.migrate", target, sourceUserId=source,
               resourceId=request.resourceId, subscriptionId=request.subscriptionId)
        return result

    return mutate_config(apply)


def update_user_policy(user_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    supported = {"trafficLimitBytes", "maxSourceIps", "maxConnections"}
    unknown = set(updates) - supported
    if unknown:
        raise SingboxConfigError(f"unsupported policy fields: {', '.join(sorted(unknown))}")

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")
        item = registry.setdefault("users", {}).setdefault(user_id, {})
        for field in supported & set(updates):
            item[field] = _positive_policy_value(updates[field])
        policy = {
            "trafficLimitBytes": _positive_policy_value(item.get("trafficLimitBytes")),
            "maxSourceIps": _positive_policy_value(item.get("maxSourceIps")),
            "maxConnections": _positive_policy_value(item.get("maxConnections")),
        }
        _audit("user.policy.update", user_id, **policy)
        return {"success": True, "userId": user_id, **policy}

    return mutate_config(apply)


def apply_default_traffic_limit(traffic_limit_bytes: int) -> dict[str, Any]:
    """Update active users' quotas atomically without resetting traffic or reloading sing-box."""
    if not isinstance(traffic_limit_bytes, int) or isinstance(traffic_limit_bytes, bool) or not 0 <= traffic_limit_bytes <= 1073741824000000:
        raise SingboxConfigError("invalid trafficLimitBytes")
    limit = _positive_policy_value(traffic_limit_bytes)

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        user_ids = _discover_user_ids(data, registry)
        updated = 0
        for user_id in user_ids:
            metadata = registry.setdefault("users", {}).setdefault(user_id, {})
            if metadata.get("trafficLimitBytes") != limit:
                metadata["trafficLimitBytes"] = limit
                updated += 1
        _audit("users.traffic-limit.default", "all", trafficLimitBytes=limit, userCount=len(user_ids), updatedCount=updated)
        return {"success": True, "trafficLimitBytes": traffic_limit_bytes,
                "userCount": len(user_ids), "updatedCount": updated}

    return mutate_config(apply)


def renew_users(
    user_ids: list[str],
    expires_at: datetime,
    traffic_limit_bytes: int | None = None,
    max_source_ips: int | None = None,
) -> dict[str, Any]:
    """Atomically renew up to one full node snapshot with one hot reload.

    All identities are validated and committed inside the same config lock.
    If any item fails validation, no item is published; mutate_config also
    restores the prior registry/config and never restarts sing-box by default.
    """
    unique_ids = list(dict.fromkeys(user_id for user_id in user_ids if user_id))
    if not unique_ids or len(unique_ids) != len(user_ids):
        raise SingboxConfigError("userIds must be non-empty and unique")
    if len(unique_ids) > 1000:
        raise SingboxConfigError("too many users in one renewal batch")
    new_expiry = _as_utc(expires_at)
    now = datetime.now(timezone.utc)
    if new_expiry is None or new_expiry <= now:
        raise SingboxConfigError("expiresAt must be in the future")

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for user_id in unique_ids:
            if not _user_exists(data, registry, user_id):
                raise SingboxConfigError(f"user not found: {user_id}")
            metadata = _registry_user(registry, user_id)
            old_expiry = _as_utc(metadata.get("expiresAt"))
            if old_expiry is not None and now >= old_expiry + RESTORE_WINDOW:
                raise SingboxConfigError(f"user restore window has expired: {user_id}")
            # Legacy clients round timestamps to seconds; that is not a new renewal cycle.
            if old_expiry is not None and timedelta(0) < abs(new_expiry - old_expiry) < timedelta(seconds=1):
                items.append({
                    "success": True,
                    "userId": user_id,
                    "expiresAt": metadata["expiresAt"],
                    "expirationStatus": "ACTIVE" if old_expiry > now else "EXPIRED",
                    "expirationPrecisionOnly": True,
                    "trafficLimitBytes": _positive_policy_value(metadata.get("trafficLimitBytes")),
                    "maxSourceIps": _positive_policy_value(metadata.get("maxSourceIps")),
                })
                continue
            if old_expiry is not None and new_expiry < old_expiry:
                raise SingboxConfigError(f"renewal cannot shorten the existing expiration: {user_id}")

            if traffic_limit_bytes is not None:
                metadata["trafficLimitBytes"] = _positive_policy_value(traffic_limit_bytes)
            if max_source_ips is not None:
                metadata["maxSourceIps"] = _positive_policy_value(max_source_ips)

            metadata["expiresAt"] = _iso(new_expiry)
            metadata["expirationUpdatedAt"] = _iso(now)
            _remove_expiration_rule(data, metadata)
            policy = {
                "trafficLimitBytes": _positive_policy_value(metadata.get("trafficLimitBytes")),
                "maxSourceIps": _positive_policy_value(metadata.get("maxSourceIps")),
            }
            _audit("user.renew", user_id, expiresAt=metadata["expiresAt"], **policy)
            items.append({
                "success": True,
                "userId": user_id,
                "expiresAt": metadata["expiresAt"],
                "expirationStatus": "ACTIVE",
                **policy,
            })
        return {"success": True, "items": items, "userCount": len(items)}

    return mutate_config(apply)


def renew_user(
    user_id: str,
    expires_at: datetime,
    traffic_limit_bytes: int | None = None,
    max_source_ips: int | None = None,
) -> dict[str, Any]:
    """Compatibility wrapper for the atomic batch renewal implementation."""
    return renew_users([user_id], expires_at, traffic_limit_bytes, max_source_ips)["items"][0]

def _remove_expiration_rule(data: dict[str, Any], metadata: dict[str, Any]) -> None:
    rules = data.setdefault("route", {}).setdefault("rules", [])
    raw_auth_users = metadata.get(EXPIRATION_AUTH_USERS_KEY)
    if isinstance(raw_auth_users, list) and raw_auth_users:
        expected = {"auth_user": sorted(str(value) for value in raw_auth_users if value), "action": "reject"}
        # Traffic enforcement can have the same sing-box rule shape. The
        # expiration rule is inserted before enforcement rules, so remove
        # only its first matching occurrence instead of all equal rules.
        for index, rule in enumerate(rules):
            if isinstance(rule, dict) and rule == expected:
                rules.pop(index)
                break
    metadata.pop(EXPIRATION_AUTH_USERS_KEY, None)
    metadata.pop(EXPIRATION_BLOCKED_KEY, None)


def _remove_access_rule(data: dict[str, Any], metadata: dict[str, Any]) -> None:
    raw_auth_users = metadata.get(ACCESS_AUTH_USERS_KEY)
    if metadata.get(ACCESS_BLOCKED_KEY) is True and isinstance(raw_auth_users, list) and raw_auth_users:
        expected = {"auth_user": sorted(str(value) for value in raw_auth_users if value), "action": "reject"}
        rules = data.setdefault("route", {}).setdefault("rules", [])
        for index, rule in enumerate(rules):
            if isinstance(rule, dict) and _same_rule(rule, expected):
                rules.pop(index)
                break
    metadata.pop(ACCESS_AUTH_USERS_KEY, None)
    metadata.pop(ACCESS_BLOCKED_KEY, None)


class UserAccessConnectionError(SingboxConfigError):
    pass


def set_user_access(user_id: str, enabled: bool) -> dict[str, Any]:
    """Enable or suspend all managed protocols for one user."""
    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")
        metadata = _registry_user(registry, user_id)
        rules = data.setdefault("route", {}).setdefault("rules", [])
        if enabled:
            _remove_access_rule(data, metadata)
            metadata["accessEnabled"] = True
        else:
            auth_users = sorted(_user_auth_names(registry, user_id))
            expected = {"auth_user": auth_users, "action": "reject"}
            if (metadata.get(ACCESS_BLOCKED_KEY) is not True
                    or metadata.get(ACCESS_AUTH_USERS_KEY) != auth_users
                    or expected not in rules):
                _remove_access_rule(data, metadata)
                rules.insert(0, expected)
                metadata[ACCESS_AUTH_USERS_KEY] = auth_users
                metadata[ACCESS_BLOCKED_KEY] = True
            metadata["accessEnabled"] = False
        _audit("user.access.update", user_id, enabled=enabled)
        return {"success": True, "userId": user_id, "enabled": enabled,
                "status": "active" if enabled else "suspended",
                "blockedProtocols": [] if enabled else [
                    protocol for protocol, tag in (("vless", config.singbox.vless_tag),
                                                   ("vmess", config.singbox.vmess_tag),
                                                   ("trojan", config.singbox.trojan_tag),
                                                   ("socks", config.singbox.socks_tag))
                    if any(item.get("tag") == tag and any(
                        user.get("name") in _user_auth_names(registry, user_id)
                        or user.get("username") in _user_auth_names(registry, user_id)
                        for user in item.get("users", [])) for item in data.get("inbounds", []))
                ], "configApplied": True, "activeConnectionsClosed": 0}

    result = mutate_config(apply)
    if enabled:
        return result

    snapshot = singbox_api.get_connections()
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("connections"), list):
        raise UserAccessConnectionError("user blocked, but active connections could not be inspected")
    with _config_lock():
        registry = read_registry()
    names = _user_auth_names(registry, user_id)
    outbound_tag = USER_OUTBOUND_PREFIX + user_id
    auth_fields = ("inboundUser", "inbound_user", "authUser", "auth_user", "user")

    def belongs_to_user(connection: dict[str, Any]) -> bool:
        if outbound_tag in (connection.get("chains") or []):
            return True
        connection_metadata = connection.get("metadata")
        candidates = [connection.get(field) for field in auth_fields]
        if isinstance(connection_metadata, dict):
            candidates.extend(connection_metadata.get(field) for field in auth_fields)
        return any(value is not None and str(value) in names for value in candidates)

    connections: set[str] = set()
    for connection in snapshot["connections"]:
        if not isinstance(connection, dict) or not connection.get("id"):
            raise UserAccessConnectionError("user blocked, but a connection entry could not be identified")
        if belongs_to_user(connection):
            connections.add(str(connection["id"]))
    closed = 0
    for connection_id in connections:
        if not singbox_api.close_connection(connection_id):
            raise UserAccessConnectionError("user blocked, but an active connection could not be closed")
        closed += 1
    verified = singbox_api.get_connections()
    if not isinstance(verified, dict) or not isinstance(verified.get("connections"), list):
        raise UserAccessConnectionError("user blocked, but connection closure could not be verified")
    for connection in verified["connections"]:
        if not isinstance(connection, dict) or not connection.get("id"):
            raise UserAccessConnectionError("user blocked, but connection closure could not be verified")
        if belongs_to_user(connection):
            raise UserAccessConnectionError("user blocked, but an active connection remains")
    result["activeConnectionsClosed"] = closed
    return result


def _add_expiration_rule(data: dict[str, Any], registry: dict[str, Any], user_id: str) -> bool:
    metadata = _registry_user(registry, user_id)
    auth_users = sorted(_user_auth_names(registry, user_id))
    rules = data.setdefault("route", {}).setdefault("rules", [])
    expected = {"auth_user": auth_users, "action": "reject"}
    if metadata.get(EXPIRATION_BLOCKED_KEY) is True and metadata.get(EXPIRATION_AUTH_USERS_KEY) == auth_users and expected in rules:
        return False
    _remove_expiration_rule(data, metadata)
    rules.insert(0, expected)
    metadata[EXPIRATION_AUTH_USERS_KEY] = auth_users
    metadata[EXPIRATION_BLOCKED_KEY] = True
    return True


def _connections_to_close_for_expired_users(
    registry: dict[str, Any], user_ids: set[str]
) -> set[str]:
    """获取到期用户的现有连接，API 不可用时留待下一轮重试。"""
    if not user_ids:
        return set()
    snapshot = singbox_api.get_connections()
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("connections"), list):
        logger.warning("could not inspect sing-box connections for expired users")
        return set()

    # Index expired identities once instead of scanning all users per connection.
    outbound_tags = {f"{USER_OUTBOUND_PREFIX}{user_id}" for user_id in user_ids}
    auth_names = set().union(*(_user_auth_names(registry, user_id) for user_id in user_ids))
    auth_fields = ("inboundUser", "inbound_user", "authUser", "auth_user", "user")
    connection_ids: set[str] = set()
    for connection in snapshot["connections"]:
        if not isinstance(connection, dict) or not connection.get("id"):
            continue
        if any(tag in outbound_tags for tag in (connection.get("chains") or [])):
            connection_ids.add(str(connection["id"]))
            continue
        metadata = connection.get("metadata")
        candidates = [connection.get(field) for field in auth_fields]
        if isinstance(metadata, dict):
            candidates.extend(metadata.get(field) for field in auth_fields)
        if any(value is not None and str(value) in auth_names for value in candidates):
            connection_ids.add(str(connection["id"]))
    return connection_ids


def _archive_user(data: dict[str, Any], registry: dict[str, Any], user_id: str, now: datetime) -> None:
    metadata = _registry_user(registry, user_id)
    auth_names = _user_auth_names(registry, user_id)
    protocols: list[str] = []
    protocol_tags = {
        config.singbox.vless_tag: "vless",
        config.singbox.vmess_tag: "vmess",
        config.singbox.socks_tag: "socks",
    }
    for inbound in data.get("inbounds", []):
        protocol = protocol_tags.get(inbound.get("tag"))
        if protocol and any(
            user.get("name") in auth_names or user.get("username") in auth_names
            for user in inbound.get("users", [])
        ):
            protocols.append(protocol)
        inbound["users"] = [
            user for user in inbound.get("users", [])
            if user.get("name") not in auth_names and user.get("username") not in auth_names
        ]
    outbound_tag = f"{USER_OUTBOUND_PREFIX}{user_id}"
    data["outbounds"] = [item for item in data.get("outbounds", []) if item.get("tag") != outbound_tag]
    route = data.setdefault("route", {})
    _remove_expiration_rule(data, metadata)
    _remove_managed_enforcement_rules(route.setdefault("rules", []), metadata)
    route["rules"] = [rule for rule in route.get("rules", []) if rule.get("outbound") != outbound_tag]
    expired_at = _as_utc(metadata.get("expiresAt")) or now
    registry.setdefault("expiredUsers", {})[user_id] = {
        "userId": user_id,
        "createdAt": metadata.get("createdAt"),
        "expiresAt": metadata.get("expiresAt"),
        "expiredAt": _iso(expired_at),
        "archivedAt": _iso(now),
        "status": "ARCHIVED",
        "protocols": sorted(set(protocols)),
    }
    registry.setdefault("users", {}).pop(user_id, None)
    _audit("user.expired.archive", user_id, protocols=",".join(sorted(set(protocols))))


def process_user_expirations(now: datetime | None = None) -> int:
    if not EXPIRATION_ENABLED:
        return 0
    current_time = _as_utc(now) or datetime.now(timezone.utc)
    with _config_read_lock():
        current_registry = read_registry()
    expired_user_ids = {
        user_id
        for user_id, metadata in current_registry.get("users", {}).items()
        if isinstance(metadata, dict)
        and (expires_at := _as_utc(metadata.get("expiresAt"))) is not None
        and expires_at <= current_time
    }
    if not expired_user_ids:
        return 0
    connections_to_close = _connections_to_close_for_expired_users(
        current_registry, expired_user_ids
    )

    # The scheduler runs every five seconds. Only enter the durable writer when
    # an expired user still needs a reject rule; already blocked users still
    # have their live connections inspected and closed above.
    with _config_read_lock():
        current_config = read_config()
        current_registry = read_registry()
    rules = current_config.get("route", {}).get("rules", [])
    pending = any(
        not isinstance((metadata := current_registry.get("users", {}).get(user_id)), dict)
        or metadata.get(EXPIRATION_BLOCKED_KEY) is not True
        or metadata.get(EXPIRATION_AUTH_USERS_KEY) != (names := sorted(_user_auth_names(current_registry, user_id)))
        or {"auth_user": names, "action": "reject"} not in rules
        for user_id in expired_user_ids
    )

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> int:
        changed = 0
        for user_id, metadata in list(registry.get("users", {}).items()):
            if not isinstance(metadata, dict):
                continue
            expires_at = _as_utc(metadata.get("expiresAt"))
            if expires_at is None:
                # Historical users need an authoritative date before enforcement.
                continue
            if expires_at > current_time:
                continue
            # Removing a route requires an encrypted website DB backup and a
            # fresh invalid SOCKS proof via user_cleanup; age alone is insufficient.
            if _add_expiration_rule(data, registry, user_id):
                changed += 1
        return changed

    changed = mutate_config(apply) if pending else 0
    for connection_id in connections_to_close:
        if not singbox_api.close_connection(connection_id):
            logger.warning("could not close expired user connection %s", connection_id)
    return changed


def update_user_expiration(user_id: str, expires_at: datetime) -> dict[str, Any]:
    new_expiry = _as_utc(expires_at)
    now = datetime.now(timezone.utc)
    if new_expiry is None or new_expiry <= now:
        raise SingboxConfigError("expiresAt must be in the future")

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")
        metadata = _registry_user(registry, user_id)
        old_expiry = _as_utc(metadata.get("expiresAt"))
        if old_expiry is not None and now >= old_expiry + RESTORE_WINDOW:
            raise SingboxConfigError("user restore window has expired")
        metadata["expiresAt"] = _iso(new_expiry)
        metadata["expirationUpdatedAt"] = _iso(now)
        _remove_expiration_rule(data, metadata)
        _audit("user.expiration.update", user_id, expiresAt=metadata["expiresAt"])
        return {"success": True, "userId": user_id, "expiresAt": metadata["expiresAt"], "expirationStatus": "ACTIVE"}

    return mutate_config(apply)


def sync_user_expiration(user_id: str, expires_at: datetime, expected_proxy: dict[str, Any],
                         expected_expires_at: datetime | None, snapshot_started_at: datetime | None = None) -> dict[str, Any]:
    result = sync_user_expirations([{"userId": user_id, "expiresAt": expires_at,
                                    "expectedProxy": expected_proxy, "expectedExpiresAt": expected_expires_at,
                                    "snapshotStartedAt": snapshot_started_at}])
    item = result["items"][0]
    if not item["success"]:
        raise SingboxConfigError(item["error"])
    return item


def sync_user_expirations(items: list[dict[str, Any]]) -> dict[str, Any]:
    """One atomic write per batch; each identity and previous date is checked under the same lock."""
    if len({item["userId"] for item in items}) != len(items):
        raise SingboxConfigError("duplicate userId in expiration synchronization")
    now = datetime.now(timezone.utc)

    def apply_one(data: dict[str, Any], registry: dict[str, Any], item: dict[str, Any],
                  outbounds: dict[str, Any]) -> dict[str, Any]:
        user_id = item["userId"]
        new_expiry = _as_utc(item["expiresAt"])
        if new_expiry is None:
            raise SingboxConfigError("invalid expiration")
        expected_proxy = item["expectedProxy"]
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError("user not found; expiration synchronization refused")
        metadata = _registry_user(registry, user_id)
        outbound = outbounds.get(f"{USER_OUTBOUND_PREFIX}{user_id}")
        if not outbound or outbound.get("type") not in {"socks", "socks5"}:
            raise SingboxConfigError("upstream proxy mismatch; expiration synchronization refused")
        actual = (str(metadata.get("sourceIp") or outbound.get("server") or "").strip().lower(),
                  outbound.get("server_port"), outbound.get("username"), outbound.get("password"))
        expected = (expected_proxy["server"].strip().lower(), expected_proxy["port"],
                    expected_proxy["username"], expected_proxy["password"])
        if actual != expected:
            raise SingboxConfigError("upstream proxy mismatch; expiration synchronization refused")
        old_expiry = _as_utc(metadata.get("expiresAt"))
        if old_expiry != _as_utc(item["expectedExpiresAt"]) and old_expiry != new_expiry:
            raise SingboxConfigError("expiration changed concurrently; synchronization refused")
        snapshot_started = _as_utc(item.get("snapshotStartedAt"))
        updated_at = _as_utc(metadata.get("expirationUpdatedAt"))
        if old_expiry != new_expiry and snapshot_started and updated_at and updated_at > snapshot_started:
            raise SingboxConfigError("expiration newer than upstream snapshot; synchronization refused")
        metadata["expiresAt"] = _iso(new_expiry)
        if new_expiry > now:
            _remove_expiration_rule(data, metadata)
        elif EXPIRATION_ENABLED:
            _add_expiration_rule(data, registry, user_id)
        _audit("user.expiration.sync", user_id, expiresAt=metadata["expiresAt"])
        return {"success": True, "userId": user_id, "expiresAt": metadata["expiresAt"],
                "expirationStatus": "ACTIVE" if new_expiry > now else "EXPIRED"}

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        results = []
        outbounds = {outbound.get("tag"): outbound for outbound in data.get("outbounds", [])}
        for item in items:
            try:
                results.append(apply_one(data, registry, item, outbounds))
            except SingboxConfigError as error:
                results.append({"userId": item["userId"], "success": False, "error": str(error)})
        return {"success": all(item["success"] for item in results), "items": results}

    result = mutate_config(apply)
    expired_ids = {item["userId"] for item in result["items"]
                   if item["success"] and item["expirationStatus"] == "EXPIRED"}
    if expired_ids and EXPIRATION_ENABLED:
        registry = read_registry()
        for connection_id in _connections_to_close_for_expired_users(registry, expired_ids):
            singbox_api.close_connection(connection_id)
    return result


def restore_user(user_id: str, expires_at: datetime) -> dict[str, Any]:
    new_expiry = _as_utc(expires_at)
    now = datetime.now(timezone.utc)
    if new_expiry is None or new_expiry <= now:
        raise SingboxConfigError("expiresAt must be in the future")

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        metadata = _registry_user(registry, user_id)
        old_expiry = _as_utc(metadata.get("expiresAt"))
        if not _user_exists(data, registry, user_id):
            if user_id in registry.get("expiredUsers", {}):
                raise SingboxConfigError("user is archived and must be recreated")
            raise SingboxConfigError(f"user not found: {user_id}")
        if old_expiry is None or now >= old_expiry + RESTORE_WINDOW:
            raise SingboxConfigError("user restore window has expired")
        metadata["expiresAt"] = _iso(new_expiry)
        metadata["expirationUpdatedAt"] = _iso(now)
        _remove_expiration_rule(data, metadata)
        _audit("user.expiration.restore", user_id, expiresAt=metadata["expiresAt"])
        return {"success": True, "userId": user_id, "expiresAt": metadata["expiresAt"], "expirationStatus": "ACTIVE"}

    return mutate_config(apply)


def list_expired_users() -> list[dict[str, Any]]:
    with _config_lock():
        registry = read_registry()
    now = datetime.now(timezone.utc)
    items: list[dict[str, Any]] = []
    for user_id, metadata in registry.get("users", {}).items():
        if not isinstance(metadata, dict) or _expiration_status(metadata, now) != "EXPIRED":
            continue
        items.append({
            "userId": user_id,
            "createdAt": metadata.get("createdAt"),
            "expiresAt": metadata.get("expiresAt"),
            "expiredAt": metadata.get("expiresAt"),
            "archivedAt": None,
            "status": "EXPIRED",
            "protocols": [],
        })
    items.extend(registry.get("expiredUsers", {}).values())
    return sorted(items, key=lambda item: str(item.get("expiresAt") or ""), reverse=True)


def start_expiration_scheduler() -> None:
    global expiration_thread
    if not EXPIRATION_ENABLED:
        logger.warning("node user expiration processing is disabled by operator")
        return
    if expiration_thread is not None and expiration_thread.is_alive():
        return
    expiration_stop.clear()
    process_user_expirations()

    def run() -> None:
        while not expiration_stop.wait(5):
            try:
                process_user_expirations()
            except Exception:
                logger.exception("could not process user expirations")

    expiration_thread = threading.Thread(target=run, name="user-expiration", daemon=True)
    expiration_thread.start()


def stop_expiration_scheduler() -> None:
    global expiration_thread
    expiration_stop.set()
    if expiration_thread is not None and expiration_thread.is_alive():
        expiration_thread.join(timeout=2)
    expiration_thread = None


def _source_ip_cidr(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    suffix = 32 if address.version == 4 else 128
    return f"{address.compressed.lower()}/{suffix}"


def _same_rule(rule: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(rule.get(key) == value for key, value in expected.items()) and set(rule) == set(expected)


def _managed_enforcement_rules(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    auth_users = metadata.get(ENFORCEMENT_AUTH_USERS_KEY)
    if not isinstance(auth_users, list) or not auth_users:
        return []

    managed_rules = []
    if metadata.get(ENFORCEMENT_TRAFFIC_KEY) is True:
        managed_rules.append({"auth_user": auth_users, "action": "reject"})
    source_cidrs = metadata.get(ENFORCEMENT_SOURCE_CIDRS_KEY)
    if isinstance(source_cidrs, list) and source_cidrs:
        managed_rules.append(
            {
                "auth_user": auth_users,
                "source_ip_cidr": source_cidrs,
                "action": "reject",
            }
        )
    return managed_rules


def _after_managed_enforcement_rules(
    rules: list[dict[str, Any]], metadata: dict[str, Any]
) -> int:
    managed_rules = _managed_enforcement_rules(metadata)
    raw_expiration_auth_users = metadata.get(EXPIRATION_AUTH_USERS_KEY)
    if isinstance(raw_expiration_auth_users, list) and raw_expiration_auth_users:
        managed_rules = [
            {
                "auth_user": sorted(str(value) for value in raw_expiration_auth_users if value),
                "action": "reject",
            },
            *managed_rules,
        ]
    managed_indexes = [
        index
        for index, rule in enumerate(rules)
        if isinstance(rule, dict)
        and any(_same_rule(rule, managed) for managed in managed_rules)
    ]
    return max(managed_indexes, default=-1) + 1


def _remove_managed_enforcement_rules(
    rules: list[dict[str, Any]], metadata: dict[str, Any]
) -> None:
    managed_rules = _managed_enforcement_rules(metadata)
    if not managed_rules:
        return
    # An expired user and a traffic-limited user may intentionally have two
    # identical reject rules. Preserve the first one when it is tracked as
    # the expiration block; remove only the occurrence owned by enforcement.
    expiration_rule = None
    raw_auth_users = metadata.get(EXPIRATION_AUTH_USERS_KEY)
    if metadata.get(EXPIRATION_BLOCKED_KEY) is True and isinstance(raw_auth_users, list) and raw_auth_users:
        expiration_rule = {
            "auth_user": sorted(str(value) for value in raw_auth_users if value),
            "action": "reject",
        }
    removed_expiration = False
    remaining: list[dict[str, Any]] = []
    for rule in rules:
        if isinstance(rule, dict) and any(_same_rule(rule, managed) for managed in managed_rules):
            if expiration_rule is not None and not removed_expiration and _same_rule(rule, expiration_rule):
                removed_expiration = True
                remaining.append(rule)
                continue
            continue
        remaining.append(rule)
    rules[:] = remaining


def sync_user_enforcements(
    enforcements: dict[str, dict[str, Any]],
    *,
    persist_source_blocks: bool = False,
) -> bool:
    """Persist stable traffic blocks as sing-box reject rules.

    The registry stores the exact rule identity so later policy changes can
    remove only rules created by Node Manager. Reapplying the same desired
    state is a no-op and does not reload sing-box. Dynamic source-IP limits
    are runtime-only by default because writing their constantly changing
    CIDRs to the static config would repeatedly reload sing-box.
    """

    # The collector submits the same 4k+ decisions on every sample. A verified
    # no-op needs no durable write task until the desired state or either file
    # changes. Keep the file versions in the key so external edits invalidate it.
    global _enforcement_noop_cache
    desired = hashlib.sha256(json.dumps([
        (user_id, bool(value.get("trafficBlocked")),
         sorted(value.get("blockedSourceIps") or []) if persist_source_blocks else [])
        for user_id, value in sorted(enforcements.items())
    ], ensure_ascii=False, separators=(",", ":")).encode()).digest()
    def versions() -> tuple | None:
        try:
            return tuple((str(path), stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
                         for path in (CONFIG_PATH, REGISTRY_PATH) for stat in (path.stat(),))
        except FileNotFoundError:
            return None
    before = versions()
    cache_key = (persist_source_blocks, desired, before)
    if before is not None and _enforcement_noop_cache == cache_key:
        return False

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> bool:
        changed = False
        rules = data.setdefault("route", {}).setdefault("rules", [])
        registry_users = registry.setdefault("users", {})
        existing_auth_names = {
            str(value)
            for inbound in data.get("inbounds", [])
            if isinstance(inbound, dict)
            for user in inbound.get("users", [])
            if isinstance(user, dict)
            for value in (user.get("name"), user.get("username"))
            if value
        }
        legacy_user_ids = {
            str(value)
            for value in existing_auth_names
            if value in registry_users
        }

        for user_id, desired in enforcements.items():
            metadata = registry_users.get(user_id)
            if not isinstance(metadata, dict):
                continue

            traffic_blocked = bool(desired.get("trafficBlocked"))
            source_cidrs = sorted(
                {
                    cidr
                    for source_ip in desired.get("blockedSourceIps") or []
                    if (cidr := _source_ip_cidr(str(source_ip))) is not None
                }
            )
            if not persist_source_blocks:
                source_cidrs = []
            raw_current_auth_users = metadata.get(ENFORCEMENT_AUTH_USERS_KEY)
            current_auth_users = sorted(
                str(value) for value in raw_current_auth_users if value
            ) if isinstance(raw_current_auth_users, list) else []
            raw_current_source_cidrs = metadata.get(ENFORCEMENT_SOURCE_CIDRS_KEY)
            current_source_cidrs = sorted(
                str(value) for value in raw_current_source_cidrs if value
            ) if isinstance(raw_current_source_cidrs, list) else []
            current_traffic_blocked = metadata.get(ENFORCEMENT_TRAFFIC_KEY) is True
            has_enforcement = traffic_blocked or bool(source_cidrs) or current_traffic_blocked or bool(current_source_cidrs)
            if not has_enforcement and not current_auth_users:
                continue

            desired_auth_users = {
                _auth_name(user_id),
                _public_socks_username(registry, user_id),
            }
            if user_id in legacy_user_ids:
                desired_auth_users.add(user_id)
            desired_auth_users = sorted(value for value in desired_auth_users if value)
            if not existing_auth_names.intersection(_user_auth_names(registry, user_id)):
                continue
            if (
                current_traffic_blocked == traffic_blocked
                and current_source_cidrs == source_cidrs
                and current_auth_users == (desired_auth_users if traffic_blocked or source_cidrs else [])
            ):
                # The collector evaluates every registered user on every pass.
                # Avoid copying and rescanning the full sing-box route list when
                # this user's persisted enforcement state is already current.
                continue

            before_rules = copy.deepcopy(rules)
            before_metadata = copy.deepcopy(metadata)
            managed_rules = _managed_enforcement_rules(metadata)
            managed_indexes = [
                index
                for index, rule in enumerate(rules)
                if isinstance(rule, dict)
                and any(_same_rule(rule, managed) for managed in managed_rules)
            ]
            insert_at = min(managed_indexes, default=0)
            _remove_managed_enforcement_rules(rules, metadata)
            insert_at = min(insert_at, len(rules))

            auth_users = desired_auth_users

            if traffic_blocked:
                rules.insert(insert_at, {"auth_user": auth_users, "action": "reject"})
                source_cidrs = []
            elif source_cidrs:
                rules.insert(
                    insert_at,
                    {
                        "auth_user": auth_users,
                        "source_ip_cidr": source_cidrs,
                        "action": "reject",
                    },
                )

            if traffic_blocked or source_cidrs:
                metadata[ENFORCEMENT_AUTH_USERS_KEY] = auth_users
            else:
                metadata.pop(ENFORCEMENT_AUTH_USERS_KEY, None)
            if traffic_blocked:
                metadata[ENFORCEMENT_TRAFFIC_KEY] = True
            else:
                metadata.pop(ENFORCEMENT_TRAFFIC_KEY, None)
            if source_cidrs:
                metadata[ENFORCEMENT_SOURCE_CIDRS_KEY] = source_cidrs
            else:
                metadata.pop(ENFORCEMENT_SOURCE_CIDRS_KEY, None)

            user_changed = before_rules != rules or before_metadata != metadata
            changed = changed or user_changed
            if user_changed:
                _audit(
                    "user.enforcement.sync",
                    user_id,
                    trafficBlocked=traffic_blocked,
                    blockedSourceIps=len(source_cidrs),
                )
        return changed

    changed = mutate_config(apply)
    after = versions()
    _enforcement_noop_cache = cache_key if not changed and before is not None and before == after else None
    return changed


def _set_proxy_binding(
    data: dict[str, Any], registry: dict[str, Any], user_id: str, proxy: dict[str, Any]
) -> None:
    # The proxy server is the real upstream SOCKS endpoint.  ``sourceIp`` is
    # only residential exit metadata and must never be used as the outbound
    # server when the two addresses differ.
    server = str(
        proxy.get("server")
        or proxy.get("sourceAddress")
        or proxy.get("source_address")
        or ""
    ).strip()
    if not server:
        raise SingboxConfigError("住宅 SOCKS 缺少上游服务器地址")
    try:
        port = int(proxy.get("port") or proxy.get("server_port") or proxy.get("sourcePort"))
    except (TypeError, ValueError) as exc:
        raise SingboxConfigError("住宅 SOCKS 上游端口无效") from exc
    if not 1 <= port <= 65535:
        raise SingboxConfigError("住宅 SOCKS 上游端口无效")
    normalized_proxy = dict(proxy)
    normalized_proxy["server"] = server
    normalized_proxy["port"] = port
    _assert_proxy_available(data, user_id, normalized_proxy)
    _validate_proxy_does_not_loop_to_local_socks(data, normalized_proxy)
    outbound_tag = f"{USER_OUTBOUND_PREFIX}{user_id}"
    outbound = {
        "type": "socks",
        "tag": outbound_tag,
        "server": server,
        "server_port": port,
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
    insert_at = _after_managed_enforcement_rules(
        rules, _registry_user(registry, user_id)
    )
    rules.insert(
        insert_at,
        {"auth_user": auth_names, "action": "route", "outbound": outbound_tag},
    )


def _save_proxy_metadata(registry: dict[str, Any], user_id: str, proxy: dict[str, Any]) -> None:
    """Persist non-secret residential metadata for refresh/restart recovery."""
    item = registry.setdefault("users", {}).setdefault(user_id, {})
    fields = {
        "sourceIp": ("sourceIp", "source_ip"),
        "sourceAddress": ("sourceAddress", "source_address", "server"),
        "sourcePort": ("sourcePort", "source_port", "port", "server_port"),
        "countryCode": ("countryCode", "country_code"),
        "countryName": ("countryName", "country_name"),
        "provinceName": ("provinceName", "province_name"),
        "cityName": ("cityName", "city_name"),
    }
    for target, keys in fields.items():
        value = next((proxy.get(key) for key in keys if proxy.get(key) not in (None, "")), None)
        if value is not None:
            item[target] = normalize_country_code(value) if target == "countryCode" else value


def _canonical_ip(value: str) -> str | None:
    normalized = value.strip().strip("[]").split("%", 1)[0]
    try:
        return ipaddress.ip_address(normalized).compressed.lower()
    except ValueError:
        return None


def _canonical_proxy_server(value: str) -> str:
    normalized = value.strip().strip("[]")
    return _canonical_ip(normalized) or normalized.lower()


def _proxy_identity(
    server: str, port: int, username: Any = None, password: Any = None
) -> tuple[str, int, str, str]:
    return (
        _canonical_proxy_server(server),
        int(port),
        str(username or ""),
        str(password or ""),
    )


def _is_user_proxy_outbound_tag(tag: str, user_id: str) -> bool:
    prefix = f"{USER_OUTBOUND_PREFIX}{user_id}"
    if tag == prefix:
        return True
    suffix = tag[len(prefix) :] if tag.startswith(prefix) else ""
    return suffix.startswith("-") and suffix[1:].isdigit()


def _configured_proxy_identities(
    data: dict[str, Any], exclude_user_id: str | None = None
) -> set[tuple[str, int, str, str]]:
    identities: set[tuple[str, int, str, str]] = set()
    for outbound in data.get("outbounds", []):
        if outbound.get("type") != "socks":
            continue
        tag = str(outbound.get("tag") or "")
        if exclude_user_id and _is_user_proxy_outbound_tag(tag, exclude_user_id):
            continue
        server = str(outbound.get("server") or "").strip()
        try:
            port = int(outbound.get("server_port"))
        except (TypeError, ValueError):
            continue
        if server:
            identities.add(
                _proxy_identity(
                    server,
                    port,
                    outbound.get("username"),
                    outbound.get("password"),
                )
            )
    return identities


def _assert_proxy_available(
    data: dict[str, Any],
    user_id: str,
    proxy: dict[str, Any],
    batch_identities: set[tuple[str, int, str, str]] | None = None,
) -> None:
    identity = _proxy_identity(
        str(proxy["server"]),
        int(proxy["port"]),
        proxy.get("username"),
        proxy.get("password"),
    )
    if identity in _configured_proxy_identities(data, exclude_user_id=user_id):
        raise SingboxConfigError("当前已有这条住宅IP的连接了")
    if batch_identities is not None:
        if identity in batch_identities:
            raise SingboxConfigError("当前已有这条住宅IP的连接了")
        batch_identities.add(identity)


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
    """Reject an upstream SOCKS endpoint that points to this node's own inbound.

    The user outbound is routed into the public SOCKS inbound again in this case,
    so every request recursively re-enters the same route and never reaches an
    external upstream. Same-host bindings are therefore rejected when the port
    and resolved address identify the local SOCKS service.
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
        raise SingboxConfigError(
            f"proxy loop: upstream SOCKS points to this node's own SOCKS inbound "
            f"({proxy.get('server')}:{proxy_port})"
        )


def _set_direct_binding(data: dict[str, Any], registry: dict[str, Any], user_id: str) -> None:
    outbound_tag = f"{USER_OUTBOUND_PREFIX}{user_id}"
    data.setdefault("outbounds", [])
    if not any(item.get("tag") == outbound_tag for item in data["outbounds"]):
        data["outbounds"].append({"type": "direct", "tag": outbound_tag})

    route = data.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not any(rule.get("outbound") == outbound_tag for rule in rules):
        insert_at = _after_managed_enforcement_rules(
            rules, _registry_user(registry, user_id)
        )
        rules.insert(
            insert_at,
            {
                "auth_user": sorted(_route_auth_names(data, registry, user_id)),
                "action": "route",
                "outbound": outbound_tag,
            },
        )


def _update_socks_credentials(
    data: dict[str, Any], registry: dict[str, Any], user_id: str, username: str, password: str
) -> None:
    if not username or not password or len(username.encode("utf-8")) > 255 or len(password.encode("utf-8")) > 255:
        raise SingboxConfigError("SOCKS credentials must contain 1 to 255 bytes")
    if username.startswith(USER_PREFIX):
        raise SingboxConfigError("SOCKS username uses a reserved prefix")
    old_names = _user_auth_names(registry, user_id)
    targets = [
        user for inbound in data.get("inbounds", [])
        if inbound.get("tag") == config.singbox.socks_tag
        for user in inbound.get("users", []) if user.get("username") in old_names
    ]
    if not targets:
        return
    if any(
        (user.get("username") == username or user.get("name") == username)
        and not any(user is target for target in targets)
        for inbound in data.get("inbounds", []) for user in inbound.get("users", [])
    ):
        raise SingboxConfigError("SOCKS username already exists")

    replaced_names = {str(user["username"]) for user in targets}
    retained_names = {
        str(user["name"]) for inbound in data.get("inbounds", [])
        for user in inbound.get("users", []) if user.get("name") in replaced_names
    }

    def replace_names(names):
        return sorted({
            username if str(name) in replaced_names else str(name) for name in names
        } | (retained_names & set(names)))

    # Keep routing, expiration and traffic/source-IP enforcement on the new identity.
    for rule in data.get("route", {}).get("rules", []):
        if isinstance(rule.get("auth_user"), list):
            rule["auth_user"] = replace_names(rule["auth_user"])
    metadata = registry.setdefault("users", {}).setdefault(user_id, {})
    for key in (ENFORCEMENT_AUTH_USERS_KEY, EXPIRATION_AUTH_USERS_KEY):
        if isinstance(metadata.get(key), list):
            metadata[key] = replace_names(metadata[key])
    for user in targets:
        user.update(username=username, password=password)
    metadata["socksUsername"] = username


def _rotate_protocol_credentials(
    data: dict[str, Any], registry: dict[str, Any], user_id: str, new_uuid: str
) -> int:
    try:
        parsed = uuid.UUID(str(new_uuid))
    except (ValueError, AttributeError, TypeError) as exc:
        raise SingboxConfigError("invalid uuid for credential rotation") from exc
    if parsed.version != 4:
        raise SingboxConfigError("credential rotation requires a UUID v4")

    normalized_uuid = str(parsed)
    auth_names = _user_auth_names(registry, user_id)
    credential_fields = {
        config.singbox.vless_tag: "uuid",
        config.singbox.vmess_tag: "uuid",
        config.singbox.trojan_tag: "password",
    }

    # Do not silently create a duplicate inbound credential for another user.
    for inbound in data.get("inbounds", []):
        field = credential_fields.get(str(inbound.get("tag")))
        if field is None:
            continue
        for user in inbound.get("users", []):
            identity = user.get("name") or user.get("username")
            if identity not in auth_names and user.get(field) == normalized_uuid:
                raise SingboxConfigError("uuid already exists")

    changed = 0
    for inbound in data.get("inbounds", []):
        field = credential_fields.get(str(inbound.get("tag")))
        if field is None:
            continue
        for user in inbound.get("users", []):
            if user.get("name") in auth_names or user.get("username") in auth_names:
                user[field] = normalized_uuid
                changed += 1
    return changed


def bind_proxy(
    user_id: str,
    proxy: dict[str, Any],
    sync_socks_credentials: bool = False,
    new_uuid: str | None = None,
) -> dict[str, Any]:
    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")

        rotated_protocols = 0
        if new_uuid:
            rotated_protocols = _rotate_protocol_credentials(
                data, registry, user_id, new_uuid
            )
        if sync_socks_credentials:
            _update_socks_credentials(
                data, registry, user_id, str(proxy.get("username") or ""),
                str(proxy.get("password") or ""),
            )
        _save_proxy_metadata(registry, user_id, proxy)
        _set_proxy_binding(data, registry, user_id, proxy)
        _audit("proxy.bind", user_id, server=str(proxy.get("server")), port=int(proxy.get("port")))
        if rotated_protocols:
            _audit("credentials.rotate", user_id, protocols=rotated_protocols)
        return {"success": True, "userId": user_id, "message": "proxy bound"}

    return mutate_config(apply)


def bind_multiple_proxies(
    user_id: str,
    proxies: list[dict[str, Any]],
    mode: str = "urltest",
    health_check_url: str = "https://www.gstatic.com/generate_204",
    interval: str = "3m",
    tolerance: int = 50,
) -> dict[str, Any]:
    """负载均衡：为一个用户绑定多个上游 SOCKS 出口。

    sing-box 原生 selector/urltest outbound 聚合多个出口：
      - 为每个上游代理创建独立 socks outbound（tag=node-manager-out:user-N）
      - 用 selector/urltest 聚合 outbound（tag=node-manager-out:user）作为路由目标
      - urltest 自动探测延迟最低、故障自动转移
      - selector 支持通过 Clash API 手动切换默认出口
    """
    if not proxies or len(proxies) < 2:
        raise SingboxConfigError("at least 2 proxies are required for load balancing")
    if mode not in {"selector", "urltest"}:
        raise SingboxConfigError(f"unsupported lb mode: {mode}")

    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")

        # 校验并归一化每个上游代理
        normalized: list[dict[str, Any]] = []
        batch_identities: set[tuple[str, int, str, str]] = set()
        for index, proxy in enumerate(proxies):
            server = str(
                proxy.get("server")
                or proxy.get("sourceAddress")
                or proxy.get("source_address")
                or ""
            ).strip()
            if not server:
                raise SingboxConfigError(f"proxy #{index} 缺少上游服务器地址")
            try:
                port = int(proxy.get("port") or proxy.get("server_port") or proxy.get("sourcePort"))
            except (TypeError, ValueError) as exc:
                raise SingboxConfigError(f"proxy #{index} 端口无效") from exc
            if not 1 <= port <= 65535:
                raise SingboxConfigError(f"proxy #{index} 端口超出范围")
            entry = {
                "server": server,
                "port": port,
                "username": proxy.get("username"),
                "password": proxy.get("password"),
            }
            _assert_proxy_available(data, user_id, entry, batch_identities)
            normalized.append(entry)

        # 清理旧的子 outbound 与聚合 outbound
        prefix = f"{USER_OUTBOUND_PREFIX}{user_id}"
        data["outbounds"] = [
            outb for outb in data.get("outbounds", [])
            if not (
                outb.get("tag", "").startswith(prefix + "-")
                or outb.get("tag") == prefix
            )
        ]

        # 为每个上游创建独立 socks outbound
        member_tags: list[str] = []
        for index, entry in enumerate(normalized):
            member_tag = f"{prefix}-{index}"
            outbound: dict[str, Any] = {
                "type": "socks",
                "tag": member_tag,
                "server": entry["server"],
                "server_port": entry["port"],
            }
            if entry["username"]:
                outbound["username"] = entry["username"]
                outbound["password"] = entry["password"] or ""
            data["outbounds"].append(outbound)
            member_tags.append(member_tag)

        # 创建聚合 outbound（selector/urltest）
        aggregate: dict[str, Any] = {
            "type": mode,
            "tag": prefix,
            "outbounds": member_tags,
        }
        if mode == "urltest":
            aggregate["url"] = health_check_url
            aggregate["interval"] = interval
            aggregate["tolerance"] = tolerance
        else:  # selector
            aggregate["default"] = member_tags[0]
        data["outbounds"].append(aggregate)

        # 路由规则指向聚合 outbound（复用现有规则结构）
        route = data.setdefault("route", {})
        rules = route.setdefault("rules", [])
        rules[:] = [rule for rule in rules if rule.get("outbound") != prefix]
        auth_names = sorted(_route_auth_names(data, registry, user_id))
        insert_at = _after_managed_enforcement_rules(
            rules, _registry_user(registry, user_id)
        )
        rules.insert(
            insert_at,
            {"auth_user": auth_names, "action": "route", "outbound": prefix},
        )

        # 用第一个代理的元数据更新 registry（展示用）
        first_proxy = proxies[0]
        _save_proxy_metadata(registry, user_id, first_proxy)
        _audit(
            "proxy.bind.multiple",
            user_id,
            count=len(normalized),
            mode=mode,
        )
        return {
            "success": True,
            "userId": user_id,
            "mode": mode,
            "outbounds": member_tags,
            "aggregate": prefix,
            "message": f"bound {len(normalized)} proxies in {mode} mode",
        }

    return mutate_config(apply)


def update_proxy_metadata(user_id: str, metadata: dict[str, Any]) -> dict[str, Any]:
    """Update persisted residential metadata without changing the active route."""
    with _config_lock():
        from revision_transaction import assert_no_pending_transaction
        assert_no_pending_transaction()
        data = read_config()
        registry = read_registry()
        if not _user_exists(data, registry, user_id):
            raise SingboxConfigError(f"user not found: {user_id}")

        updated_registry = copy.deepcopy(registry)
        _save_proxy_metadata(updated_registry, user_id, metadata)
        _write_registry(updated_registry)

    _audit(
        "proxy.metadata.update",
        user_id,
        sourceIp=str(metadata.get("sourceIp") or ""),
        countryCode=str(metadata.get("countryCode") or ""),
    )
    return {"success": True, "userId": user_id, "message": "proxy metadata updated"}


def delete_user(user_id: str) -> dict[str, Any]:
    def apply(data: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
        existed = _user_exists(data, registry, user_id)
        metadata = _registry_user(registry, user_id)
        auth_names = _user_auth_names(registry, user_id)
        for inbound in data.get("inbounds", []):
            inbound["users"] = [
                user
                for user in inbound.get("users", [])
                if user.get("name") not in auth_names and user.get("username") not in auth_names
            ]

        outbound_tag = f"{USER_OUTBOUND_PREFIX}{user_id}"
        data["outbounds"] = [item for item in data.get("outbounds", []) if item.get("tag") != outbound_tag]
        route = data.setdefault("route", {})
        _remove_expiration_rule(data, metadata)
        _remove_managed_enforcement_rules(
            route.setdefault("rules", []), metadata
        )
        route["rules"] = [
            rule for rule in route.get("rules", []) if rule.get("outbound") != outbound_tag
        ]
        registry.setdefault("users", {}).pop(user_id, None)
        if existed:
            _audit("user.delete", user_id)
        return {"success": True, "userId": user_id,
                "message": "user deleted" if existed else "user already absent"}

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


def get_history_user_snapshot() -> dict[str, Any]:
    """Read matching identity and dates without collecting traffic or protocol credentials."""
    with _config_lock():
        data, registry = read_config(), read_registry()
    outbounds: dict[str, list[dict[str, Any]]] = {}
    for outbound in data.get("outbounds", []):
        outbounds.setdefault(str(outbound.get("tag") or ""), []).append(outbound)
    users = []
    for user_id in sorted(_discover_user_ids(data, registry)):
        metadata = _registry_user(registry, user_id)
        candidates = outbounds.get(USER_OUTBOUND_PREFIX + user_id, [])
        if len(candidates) > 1:
            raise SingboxConfigError("ambiguous proxy; historical snapshot refused")
        outbound = candidates[0] if candidates else None
        proxy = None
        if outbound and outbound.get("type") in {"socks", "socks5"}:
            proxy = {
                "server": outbound.get("server"), "port": outbound.get("server_port"),
                "username": outbound.get("username"), "password": outbound.get("password"),
                "sourceIp": metadata.get("sourceIp"),
            }
        users.append({"userId": user_id, "createdAt": metadata.get("createdAt"),
                      "expiresAt": metadata.get("expiresAt"), "proxy": proxy})
    return {"version": 1, "users": users}


def get_user_access_snapshot() -> dict[str, bool]:
    """Read the effective access flag for every configured user without mutation."""
    with _config_lock():
        data = read_config()
        registry = read_registry()
    return {
        user_id: _registry_user(registry, user_id).get("accessEnabled") is not False
        for user_id in sorted(_discover_user_ids(data, registry))
    }


def ensure_user_outbounds() -> int:
    with _config_lock():
        current = read_config()
        registry = read_registry()
        archived_user_ids = set(registry.get("expiredUsers", {}))
        user_ids = _discover_user_ids(current, registry) - archived_user_ids
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
    with _config_read_lock():
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
        config.singbox.trojan_tag: ("trojan", "name"),
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
                # Never expose the internal node-manager:<id> alias.  Prefer
                # the registry's configured public username and normalize
                # legacy configs to the bare user id.
                item["socksUsername"] = _public_socks_username(registry, user_id)

    protocol_order = {"vless": 0, "vmess": 1, "trojan": 2, "socks": 3}
    outbounds = {item.get("tag"): item for item in data.get("outbounds", [])}
    result: list[dict[str, Any]] = []
    for user_id, item in users.items():
        metadata = _registry_user(registry, user_id)
        outbound = outbounds.get(f"{USER_OUTBOUND_PREFIX}{user_id}")
        item["protocols"].sort(key=protocol_order.get)
        item["socksUsername"] = item.get("socksUsername") or _public_socks_username(registry, user_id)
        item["proxyBound"] = bool(outbound and outbound.get("type") == "socks")
        item["proxyServer"] = (
            f"{outbound.get('server')}:{outbound.get('server_port')}"
            if item["proxyBound"]
            else None
        )
        item["createdAt"] = metadata.get("createdAt")
        item["expiresAt"] = metadata.get("expiresAt")
        item["expirationStatus"] = _expiration_status(metadata)
        item["accessEnabled"] = metadata.get("accessEnabled") is not False
        item["sourceIp"] = metadata.get("sourceIp")
        item["countryCode"] = metadata.get("countryCode")
        item["countryName"] = metadata.get("countryName")
        item["provinceName"] = metadata.get("provinceName")
        item["cityName"] = metadata.get("cityName")
        item["trafficLimitBytes"] = _positive_policy_value(metadata.get("trafficLimitBytes"))
        item["maxSourceIps"] = _positive_policy_value(metadata.get("maxSourceIps"))
        item["status"] = "suspended" if metadata.get("accessEnabled") is False else "active"
        result.append(item)

    return sorted(result, key=lambda item: item["userId"].lower())


def get_user_connection(user_id: str, inspect_suspended: bool = False) -> dict[str, Any]:
    with _connection_snapshot_cache_lock:
        snapshot = _connection_snapshot_cache.current(CONFIG_PATH, REGISTRY_PATH, read_config, read_registry)
    if snapshot is None:
        with _config_read_lock(), _connection_snapshot_cache_lock:
            snapshot = _connection_snapshot_cache.get(CONFIG_PATH, REGISTRY_PATH, read_config, read_registry)
    data, registry = snapshot.data, snapshot.registry

    metadata = _registry_user(registry, user_id)
    expiration_status = _expiration_status(metadata)
    if expiration_status == "EXPIRED":
        raise SingboxConfigError(f"user connection expired: {user_id}")
    if metadata.get("accessEnabled") is False and not inspect_suspended:
        raise SingboxConfigError(f"user access suspended: {user_id}")
    auth_name = _auth_name(user_id)
    socks_username = _public_socks_username(registry, user_id)
    protocols: list[str] = []
    user_uuid: str | None = None
    response: dict[str, Any] = {
        "success": True,
        "userId": user_id,
        "uuid": "",
        "protocols": protocols,
        "vless": None,
        "vmess": None,
        "trojan": None,
        "socks": None,
        "protocolsAll": {},
        "protocolInfo": {},
        "proxyBound": False,
        "createdAt": metadata.get("createdAt"),
        "expiresAt": metadata.get("expiresAt"),
        "expirationStatus": expiration_status,
    }

    vless_inbound: dict[str, Any] | None = None
    vmess_inbound: dict[str, Any] | None = None
    trojan_inbound: dict[str, Any] | None = None
    socks_inbound: dict[str, Any] | None = None
    for inbound in data.get("inbounds", []):
        tag = inbound.get("tag")
        if tag == config.singbox.vless_tag:
            vless_inbound = inbound
            user = snapshot.find(inbound, _legacy_auth_names(user_id))
            if user:
                user_uuid = str(user.get("uuid") or "")
                protocols.append("vless")
                response["vless"] = _vless_connection(user_id, user_uuid, inbound)
        elif tag == config.singbox.vmess_tag:
            vmess_inbound = inbound
            user = snapshot.find(inbound, _legacy_auth_names(user_id))
            if user:
                vmess_uuid = str(user.get("uuid") or "")
                user_uuid = user_uuid or vmess_uuid
                protocols.append("vmess")
                response["vmess"] = _vmess_connection(user_id, vmess_uuid, inbound)
        elif tag == config.singbox.trojan_tag:
            trojan_inbound = inbound
            user = snapshot.find(inbound, _legacy_auth_names(user_id))
            if user:
                # Trojan 用 password 认证；回退到 user_uuid 保持单凭据体验
                trojan_password = str(user.get("password") or user_uuid or "")
                protocols.append("trojan")
                response["trojan"] = _trojan_connection(user_id, trojan_password, inbound)
        elif tag == config.singbox.socks_tag and socks_username:
            socks_inbound = inbound
            user = snapshot.find(inbound, _user_auth_names(registry, user_id), "username")
            if user:
                protocols.append("socks")
                response["socks"] = _socks_connection(
                    socks_username,
                    str(user.get("password") or ""),
                    inbound,
                )

    if not protocols:
        raise SingboxConfigError(f"user not found: {user_id}")

    outbound = snapshot.outbounds.get(f"{USER_OUTBOUND_PREFIX}{user_id}")
    response["uuid"] = user_uuid or ""
    response["proxyBound"] = bool(outbound and outbound.get("type") == "socks")
    proxy = None
    if response["proxyBound"]:
        proxy = {
            "type": "socks5",
            "server": outbound.get("server"),
            "port": outbound.get("server_port"),
            "username": outbound.get("username"),
            "password": outbound.get("password"),
            **{
                key: metadata[key]
                for key in (
                    "sourceIp", "sourceAddress", "sourcePort",
                    "countryCode", "countryName", "cityName",
                )
                if metadata.get(key) is not None
            },
        }
        response["proxyServer"] = f"{outbound.get('server')}:{outbound.get('server_port')}"
    all_protocols = build_all_protocols(
        user_id,
        response["uuid"],
        response.get("socks"),
        vless_inbound=vless_inbound,
        vmess_inbound=vmess_inbound,
        trojan_inbound=trojan_inbound,
        socks_inbound=socks_inbound,
        # 普通连接接口只返回 Node Manager 的加速协议。原始住宅
        # SOCKS/BitBrowser 凭据只能通过显式的 /proxy 接口获取。
        include_original=False,
        enabled_protocols=set(protocols),
        proxy=proxy,
    )
    if all_protocols:
        response["protocolsAll"] = all_protocols
        # 兼容链接与结构化参数统一使用同一个加速地址。
        if all_protocols.get("vless"):
            response["vless"] = all_protocols["vless"]
        if all_protocols.get("vmess"):
            response["vmess"] = all_protocols["vmess"]
        if all_protocols.get("trojan"):
            response["trojan"] = all_protocols["trojan"]
    response["protocolInfo"] = build_protocol_info(
        user_id,
        response["uuid"],
        response.get("socks"),
        vless_inbound=vless_inbound,
        vmess_inbound=vmess_inbound,
        trojan_inbound=trojan_inbound,
        socks_inbound=socks_inbound,
        # 不把上游住宅 SOCKS 凭据带入普通连接详情。
        include_original=False,
        proxy=proxy,
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
    metadata = _registry_user(registry, user_id)
    if metadata.get("accessEnabled") is False:
        raise SingboxConfigError(f"user access suspended: {user_id}")
    if not outbound or outbound.get("type") not in {"socks", "socks5"}:
        return {
            "userId": user_id,
            "proxyBound": False,
            "nodeHost": config.node.host,
            "server": None,
            "port": None,
            "username": None,
            "password": None,
            "sourceIp": metadata.get("sourceIp"),
            "sourceAddress": metadata.get("sourceAddress"),
            "sourcePort": metadata.get("sourcePort"),
            "countryCode": metadata.get("countryCode"),
            "countryName": metadata.get("countryName"),
            "provinceName": metadata.get("provinceName"),
            "cityName": metadata.get("cityName"),
            "protocolInfo": {},
        }

    # This endpoint is intentionally explicit: it is the only proxy-details
    # response that may contain the upstream credentials.  The regular user
    # list, connection response, audit log and registry metadata never expose
    # these values.
    user_uuid = _find_user_uuid(data, registry, user_id)
    protocol_info_data = build_protocol_info(
        user_id,
        user_uuid,
        {
            "host": str(outbound.get("server") or metadata.get("sourceAddress") or ""),
            "port": int(outbound.get("server_port") or metadata.get("sourcePort") or 5001),
            "username": user_id,
            "password": "",
        },
        include_original=True,
        proxy={
            "server": outbound.get("server"),
            "port": outbound.get("server_port"),
            "username": outbound.get("username"),
            "password": outbound.get("password"),
            **metadata,
        },
    )
    return {
        "userId": user_id,
        "proxyBound": True,
        "nodeHost": config.node.host,
        "server": outbound.get("server"),
        "port": outbound.get("server_port"),
        "username": outbound.get("username"),
        "password": outbound.get("password"),
        "sourceIp": metadata.get("sourceIp"),
        "sourceAddress": metadata.get("sourceAddress") or outbound.get("server"),
        "sourcePort": metadata.get("sourcePort") or outbound.get("server_port"),
        "countryCode": metadata.get("countryCode"),
        "countryName": metadata.get("countryName"),
        "provinceName": metadata.get("provinceName"),
        "cityName": metadata.get("cityName"),
        "protocolInfo": protocol_info_data,
    }
