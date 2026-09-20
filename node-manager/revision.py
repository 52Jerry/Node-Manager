"""节点配置 revision 管理（B2/B3/B4）。

职责：
  B2: desired revision 拉取/应用接口 + HMAC-SHA256 签名校验 + 配置 SHA-256 哈希。
  B3: sing-box check → 临时文件 → 原子 rename → reload → 失败回滚。
  B4: 保留 last_known_good_revision；apply 失败或显式 rollback 时自动回滚并告警。

存储布局（/var/lib/node-manager/revisions/）：
  state.json      - revision 元数据（当前/上次可用 ID、哈希、状态、时间戳）
  current.json    - 当前生效配置快照（仅当通过本模块 apply 时存在）
  last_good.json  - 上一个已知良好配置快照
  rejected/       - 校验或 reload 失败的配置归档（便于事后排查）

签名约定：
  Control Plane 对 config JSON 做 HMAC-SHA256(key=revision_secret, msg=canonical_json)，
  将 hex digest 放入请求头 X-Revision-Signature，revision_id 放入 X-Revision-Id。
  canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))。
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import config
from singbox.manager import (
    CONFIG_PATH,
    SingboxConfigError,
    check_config,
    read_config,
    reload_singbox,
    is_singbox_running,
)

logger = logging.getLogger(__name__)

REVISIONS_DIR = Path(
    os.environ.get("NODE_MANAGER_REVISIONS_DIR", "/var/lib/node-manager/revisions")
)
STATE_PATH = REVISIONS_DIR / "state.json"
CURRENT_PATH = REVISIONS_DIR / "current.json"
LAST_GOOD_PATH = REVISIONS_DIR / "last_good.json"
REJECTED_DIR = REVISIONS_DIR / "rejected"
MAX_REJECTED = 10


def _revision_secret() -> bytes:
    """Revision 签名密钥：优先使用 revision_secret，回退到 node token。"""
    secret = getattr(config.security, "revision_secret", "") or config.security.token
    return str(secret).encode("utf-8")


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sign(payload: Any) -> str:
    return hmac.new(
        _revision_secret(), _canonical_json(payload).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_signature(payload: Any, signature: str) -> bool:
    """B2: HMAC-SHA256 常时比较，防止时序攻击。"""
    if not signature:
        return False
    expected = _sign(payload)
    return hmac.compare_digest(expected, str(signature))


def _expand_networks(value: Any) -> tuple[str, ...]:
    """把 inbounds[].network 归一化为 {tcp, udp} 子集。缺省视为两者都有。"""
    if value is None:
        return ("tcp", "udp")
    text = str(value).strip().lower()
    if not text:
        return ("tcp", "udp")
    parts = {item.strip() for item in text.replace("/", ",").replace("+", ",").split(",") if item.strip()}
    parts &= {"tcp", "udp"}
    if not parts:
        return ("tcp", "udp")
    return tuple(sorted(parts))


def _desired_listen_endpoints(desired_config: dict[str, Any]) -> list[dict[str, Any]]:
    """提取 desired 配置中声明的监听端点（listen/port/network/tag/type）。"""
    endpoints: list[dict[str, Any]] = []
    inbounds = desired_config.get("inbounds") if isinstance(desired_config, dict) else None
    if not isinstance(inbounds, list):
        return endpoints
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        raw_port = inbound.get("listen_port")
        if raw_port in (None, ""):
            continue
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        listen = str(inbound.get("listen") or "")
        for network in _expand_networks(inbound.get("network")):
            endpoints.append(
                {
                    "tag": str(inbound.get("tag") or ""),
                    "type": str(inbound.get("type") or ""),
                    "listen": listen,
                    "port": port,
                    "network": network,
                }
            )
    return endpoints


def _find_port_conflicts(desired_config: dict[str, Any]) -> list[str]:
    """B2: 本机监听端口冲突预检。

    sing-box check 只做 schema 校验，重复 listen_port 不会报错（真机实测），
    因此必须在发布前显式拦截：
      1. 同 address + 同 port + 同 protocol 重复声明；
      2. 通配地址（空 / 0.0.0.0 / ::）与具体地址在同一 port+protocol 上重叠；
      3. 与 node-manager 自身 API 端口（config.server.port）冲突。
    """
    conflicts: list[str] = []
    seen: dict[tuple[str, int, str], str] = {}
    wildcards = {"", "0.0.0.0", "::", "::0", "*"}
    manager_port = int(getattr(config.server, "port", 0) or 0)

    for endpoint in _desired_listen_endpoints(desired_config):
        listen = endpoint["listen"]
        port = endpoint["port"]
        network = endpoint["network"]
        label = "{type}:{tag} {listen}:{port}/{network}".format(
            type=endpoint["type"] or "?", tag=endpoint["tag"] or "-",
            listen=listen or "*", port=port, network=network,
        )
        for (seen_listen, seen_port, seen_network), previous in list(seen.items()):
            if seen_port != port or seen_network != network:
                continue
            if seen_listen == listen or seen_listen in wildcards or listen in wildcards:
                conflicts.append(
                    "duplicate listen endpoint {p}/{n}: {prev} vs {cur}".format(
                        p=port, n=network, prev=previous, cur=label,
                    )
                )
        seen[(listen, port, network)] = label

        if manager_port and port == manager_port and listen in wildcards:
            conflicts.append(
                "{cur} conflicts with node-manager API port {p}".format(
                    cur=label, p=manager_port,
                )
            )
    return conflicts


def _desired_node_targets(desired_config: dict[str, Any], desired_registry: dict[str, Any]) -> list[str]:
    """提取 desired 载荷中显式声明的目标节点标识（可选字段，兼容多种命名）。"""
    keys = ("nodeId", "node_id", "targetNodeId", "target_node_id")
    targets: list[str] = []
    for source in (desired_config, desired_registry):
        if not isinstance(source, dict):
            continue
        for key in keys:
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                targets.append(value.strip())
    return targets


def _find_node_target_mismatch(
    desired_config: dict[str, Any], desired_registry: dict[str, Any]
) -> str | None:
    """B2: 节点目标校验。载荷显式声明目标节点时，必须与本机 node.id 一致。"""
    local_id = str(getattr(config.node, "id", "") or "").strip()
    if not local_id:
        return None
    for target in _desired_node_targets(desired_config, desired_registry):
        if target != local_id:
            return "revision targets node {t!r} but this node is {l!r}".format(t=target, l=local_id)
    return None


def _validate_registry_payload(desired_registry: Any) -> tuple[dict[str, Any], str | None]:
    """B2: desired registry 结构校验 + 归一化。

    singbox.manager.read_registry 要求 `{"users": {...}}`；香港真机隔离验证确认：
    若把结构非法的 registry 直接落盘，之后所有 apply / 读取都会抛
    "the user registry has an invalid structure"，节点进入不可发布状态。
    因此发布前先归一化/校验：
      - None 或仅含 version 字段 -> 归一化为空 registry
      - users 为 dict -> 原样放行
      - 其它 -> 返回错误原因（拒绝并归档 registry-invalid）
    """
    if desired_registry is None:
        return {"version": 1, "users": {}}, None
    if not isinstance(desired_registry, dict):
        return {}, "registry must be a JSON object, got " + type(desired_registry).__name__
    users = desired_registry.get("users")
    if users is None:
        if set(desired_registry) - {"version"}:
            return {}, "registry is missing the 'users' object"
        normalized = dict(desired_registry)
        normalized.setdefault("version", 1)
        normalized["users"] = {}
        return normalized, None
    if not isinstance(users, dict):
        return {}, "registry 'users' must be a JSON object"
    return desired_registry, None


def _empty_state() -> dict[str, Any]:
    return {
        "version": 1,
        "currentRevisionId": None,
        "currentHash": None,
        "lastGoodRevisionId": None,
        "lastGoodHash": None,
        "status": "unknown",
        "appliedAt": None,
        "lastError": None,
        "history": [],
    }


def _read_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return _empty_state()
    try:
        with STATE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return _empty_state()
        return data
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("could not read revision state: %s", exc)
        return _empty_state()


def _write_state(state: dict[str, Any]) -> None:
    REVISIONS_DIR.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="state.", suffix=".json", dir=REVISIONS_DIR)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, STATE_PATH)
    finally:
        temp_path.unlink(missing_ok=True)


def _write_config_snapshot(path: Path, payload: dict[str, Any]) -> None:
    REVISIONS_DIR.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".json", dir=REVISIONS_DIR)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _archive_rejected(payload: dict[str, Any], reason: str) -> None:
    """B4: 保留被拒绝的配置样本，便于事后排查，最多保留 MAX_REJECTED 份。"""
    try:
        REJECTED_DIR.mkdir(parents=True, exist_ok=True)
        moment = datetime.now(timezone.utc)
        timestamp = moment.strftime("%Y%m%dT%H%M%SZ")
        # 文件名带微秒：同一秒内多次拒绝必须各自留档（真机验证曾出现互相覆盖）
        target = REJECTED_DIR / ("rejected-{stamp}.json".format(
            stamp=moment.strftime("%Y%m%dT%H%M%S%fZ")
        ))
        fd, temp_name = tempfile.mkstemp(prefix="rejected.", suffix=".json", dir=REJECTED_DIR)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(
                    {"rejectedAt": timestamp, "reason": reason, "config": payload},
                    handle,
                    indent=2,
                    ensure_ascii=False,
                )
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, target)
        finally:
            temp_path.unlink(missing_ok=True)
        rejects = sorted(REJECTED_DIR.glob("rejected-*.json"))
        for stale in rejects[:-MAX_REJECTED]:
            stale.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("could not archive rejected revision: %s", exc)


def get_revision_state() -> dict[str, Any]:
    """B2: 返回当前节点 revision 状态，供 Control Plane 拉取。"""
    state = _read_state()
    state["nodeId"] = config.node.id
    state["configPath"] = str(CONFIG_PATH)
    state["singboxRunning"] = is_singbox_running()
    return state


def apply_desired_revision(
    desired_config: dict[str, Any],
    desired_registry: dict[str, Any],
    signature: str,
    revision_id: str,
    allow_user_deletion: bool = False,
) -> dict[str, Any]:
    """B2+B3+B4+B5: 应用 Control Plane 推送的期望配置。

    流程：
      1. 签名校验（HMAC-SHA256，签名覆盖 config+registry 组合载荷）
      2. B2 预检：节点目标一致 / 监听端口不冲突 / registry 结构合法，
         任一不过即归档 rejected/ 并以 409 失败返回（不写盘）
      3. 配置 SHA-256 哈希记录
      4. B5: 用户集合缩减保护——desired 不得意外删除现有用户，
         除非显式声明 allow_user_deletion=True（对照删除审计）
      5. 备份当前配置为 last_known_good
      6. 临时文件写入 → sing-box check → 原子 rename → reload
      7. 失败回滚到 last_known_good 并告警
    """
    if not revision_id:
        raise SingboxConfigError("revision_id is required")

    # B2: 签名校验。签名覆盖 config+registry 组合载荷，防止单独篡改。
    combined_payload = {"config": desired_config, "registry": desired_registry}
    if not verify_signature(combined_payload, signature):
        _archive_rejected(combined_payload, "signature-mismatch")
        raise SingboxConfigError("revision signature verification failed")

    # B2: 节点目标校验（载荷显式声明目标节点时必须一致）
    target_error = _find_node_target_mismatch(desired_config, desired_registry)
    if target_error:
        _archive_rejected(combined_payload, f"node-target-mismatch: {target_error}")
        raise SingboxConfigError(f"revision node target mismatch: {target_error}")

    # B2: 端口冲突预检（sing-box check 不覆盖此项，必须显式拦截）
    port_conflicts = _find_port_conflicts(desired_config)
    if port_conflicts:
        _archive_rejected(combined_payload, "port-conflict: " + "; ".join(port_conflicts))
        raise SingboxConfigError(
            "revision config has port conflicts: " + "; ".join(port_conflicts)
        )

    # B2: desired registry 结构校验（防止非法 registry 落盘后污染节点）
    registry_payload, registry_error = _validate_registry_payload(desired_registry)
    if registry_error:
        _archive_rejected(combined_payload, f"registry-invalid: {registry_error}")
        raise SingboxConfigError(f"revision registry is invalid: {registry_error}")

    config_hash = _sha256(_canonical_json(desired_config))

    # B5: 用户集合缩减保护。对比当前生效配置与 desired 的用户集合，
    # 若 desired 删除了现有用户且未显式声明，则拒绝应用以防误操作。
    try:
        current_config = read_config()
        from singbox.manager import _discover_user_ids, read_registry, _config_lock
        with _config_lock():
            current_registry = read_registry()
        current_users = _discover_user_ids(current_config, current_registry)
        desired_users = _discover_user_ids(desired_config, registry_payload)
        removed = current_users - desired_users
        if removed and not allow_user_deletion:
            _archive_rejected(
                combined_payload,
                f"user-shrink-blocked: removed={sorted(removed)}",
            )
            raise SingboxConfigError(
                f"revision would remove {len(removed)} existing user(s): "
                f"{sorted(removed)}; set allowUserDeletion=true to override"
            )
    except SingboxConfigError:
        raise
    except Exception as exc:
        # B5 校验失败不应阻塞首次部署（无现有配置/registry 时跳过）
        logger.warning("B5 user-shrink check skipped: %s", exc)

    # 幂等：相同 revision + 哈希已生效则跳过
    state = _read_state()
    if (
        state.get("currentRevisionId") == revision_id
        and state.get("currentHash") == config_hash
        and state.get("status") == "applied"
    ):
        return {"success": True, "revisionId": revision_id, "replayed": True, **state}

    # B3: 原子发布。先读当前生效配置作为回滚源。
    original_bytes = b""
    original_stat = None
    try:
        original_bytes = CONFIG_PATH.read_bytes()
        original_stat = CONFIG_PATH.stat()
    except OSError:
        # 无现有配置（首次部署），跳过回滚备份。
        pass

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="revision.", suffix=".json", dir=CONFIG_PATH.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(desired_config, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        # B3: sing-box check 在写入生效路径之前执行
        valid, error = check_config(temp_path)
        if not valid:
            _archive_rejected(combined_payload, f"check-failed: {error}")
            raise SingboxConfigError(f"sing-box config validation failed: {error}")

        if original_stat is not None:
            os.chmod(temp_path, original_stat.st_mode)
            if hasattr(os, "chown"):
                try:
                    os.chown(temp_path, original_stat.st_uid, original_stat.st_gid)
                except OSError:
                    pass
        os.replace(temp_path, CONFIG_PATH)

        # 同步 registry（与 config 原子性分离，失败时 config 已生效）
        from singbox.manager import _write_registry, REGISTRY_PATH
        original_registry_bytes = b""
        if REGISTRY_PATH.exists():
            original_registry_bytes = REGISTRY_PATH.read_bytes()
        try:
            _write_registry(registry_payload)
        except Exception as exc:
            logger.warning("could not persist desired registry: %s", exc)
            if original_registry_bytes:
                REGISTRY_PATH.write_bytes(original_registry_bytes)

        if reload_singbox():
            # B4: 成功则把上一个生效配置提升为 last_known_good
            if original_bytes:
                try:
                    previous = json.loads(original_bytes.decode("utf-8"))
                    _write_config_snapshot(LAST_GOOD_PATH, previous)
                    state["lastGoodRevisionId"] = state.get("currentRevisionId")
                    state["lastGoodHash"] = state.get("currentHash")
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            _write_config_snapshot(CURRENT_PATH, desired_config)
            state.update(
                {
                    "currentRevisionId": revision_id,
                    "currentHash": config_hash,
                    "status": "applied",
                    "appliedAt": datetime.now(timezone.utc).isoformat(),
                    "lastError": None,
                }
            )
            _append_history(state, revision_id, config_hash, "applied", None)
            _write_state(state)
            logger.info("revision %s applied successfully", revision_id)
            return {"success": True, "revisionId": revision_id, "replayed": False, **state}

        # B4: reload 失败 → 回滚到 original + 告警
        if original_bytes:
            CONFIG_PATH.write_bytes(original_bytes)
            if original_stat is not None:
                os.chmod(CONFIG_PATH, original_stat.st_mode)
            reload_singbox()
        if original_registry_bytes:
            REGISTRY_PATH.write_bytes(original_registry_bytes)
        _archive_rejected(combined_payload, "reload-failed")
        state.update(
            {
                "status": "rolled-back",
                "lastError": "sing-box reload failed; previous config restored",
                "appliedAt": datetime.now(timezone.utc).isoformat(),
            }
        )
        _append_history(state, revision_id, config_hash, "reload-failed", "reload failed")
        _write_state(state)
        logger.error(
            "revision %s reload failed; rolled back to previous config", revision_id
        )
        raise SingboxConfigError(
            "sing-box reload failed after applying revision; the previous config was restored"
        )
    finally:
        temp_path.unlink(missing_ok=True)


def rollback_to_last_known_good() -> dict[str, Any]:
    """B4: 显式回滚到上一个已知良好配置。"""
    state = _read_state()
    if not LAST_GOOD_PATH.exists():
        raise SingboxConfigError("no last_known_good revision available")
    try:
        last_good = json.loads(LAST_GOOD_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SingboxConfigError(f"could not read last_known_good: {exc}") from exc

    original_bytes = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else b""
    original_stat = CONFIG_PATH.stat() if CONFIG_PATH.exists() else None

    valid, error = check_config(LAST_GOOD_PATH)
    if not valid:
        raise SingboxConfigError(f"last_known_good config is invalid: {error}")

    if original_stat is not None:
        os.chmod(LAST_GOOD_PATH, original_stat.st_mode)
        if hasattr(os, "chown"):
            try:
                os.chown(LAST_GOOD_PATH, original_stat.st_uid, original_stat.st_gid)
            except OSError:
                pass
    os.replace(LAST_GOOD_PATH, CONFIG_PATH)
    if not reload_singbox():
        # 回滚也失败：尽量恢复原状
        if original_bytes:
            CONFIG_PATH.write_bytes(original_bytes)
            reload_singbox()
        raise SingboxConfigError("rollback reload failed; original config restored")

    last_hash = _sha256(_canonical_json(last_good))
    state.update(
        {
            "currentRevisionId": state.get("lastGoodRevisionId"),
            "currentHash": last_hash,
            "status": "rolled-back",
            "appliedAt": datetime.now(timezone.utc).isoformat(),
            "lastError": "manual rollback to last_known_good",
        }
    )
    _append_history(state, state.get("currentRevisionId"), last_hash, "manual-rollback", None)
    _write_state(state)
    _write_config_snapshot(CURRENT_PATH, last_good)
    logger.warning(
        "rolled back to last_known_good revision %s",
        state.get("currentRevisionId"),
    )
    return {"success": True, **state}


def _append_history(
    state: dict[str, Any],
    revision_id: str | None,
    config_hash: str | None,
    action: str,
    error: str | None,
) -> None:
    history = state.setdefault("history", [])
    history.append(
        {
            "revisionId": revision_id,
            "hash": config_hash,
            "action": action,
            "error": error,
            "at": datetime.now(timezone.utc).isoformat(),
        }
    )
    # 仅保留最近 20 条历史，避免无限增长
    state["history"] = history[-20:]
