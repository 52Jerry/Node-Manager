"""节点配置 revision 管理（B2/B3/B4）。

职责：
  B2: desired revision 接口、HMAC-SHA256 签名与完整发布包 SHA-256 摘要。
  B3/B4: revision_transaction 在统一配置锁内写入完整包、回读、reload，
  以持久化 undo journal 支持失败回滚与启动恢复。无法证实恢复时保留日志并拒绝修改。

存储布局（/var/lib/node-manager/revisions/）：
  state.json      - revision 元数据（当前/上次可用 ID、哈希、状态、时间戳）
  current.json / last_good.json - 兼容旧工具的配置快照，不单独用于回滚
  current.bundle.json / last_good.bundle.json - config + registry + nodeId + revisionId
  transaction.json - 发布事务日志，包含敏感配置，禁止上传到日志或工单
  rejected/       - 校验或 reload 失败的配置归档（便于事后排查）

签名约定：
  兼容原协议：对 {config, registry} 做 HMAC-SHA256，放入 X-Revision-Signature；
  revisionId 放入 JSON 请求体。完整回执摘要还绑定本机 nodeId 和 revisionId。
  canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import tempfile
import uuid
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
CURRENT_BUNDLE_PATH = REVISIONS_DIR / "current.bundle.json"
LAST_GOOD_BUNDLE_PATH = REVISIONS_DIR / "last_good.bundle.json"
JOURNAL_PATH = REVISIONS_DIR / "transaction.json"


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
        # Keep a random suffix because datetime precision can collide on fast retries.
        target = REJECTED_DIR / ("rejected-{stamp}.json".format(
            stamp=moment.strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex
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


def get_revision_state():
    from revision_transaction import get_revision_state as implementation
    return implementation()


def apply_desired_revision(desired_config, desired_registry, signature, revision_id, allow_user_deletion=False):
    from revision_transaction import apply_desired_revision as implementation
    return implementation(desired_config, desired_registry, signature, revision_id, allow_user_deletion)


def rollback_to_last_known_good():
    from revision_transaction import rollback_to_last_known_good as implementation
    return implementation()


def recover_pending_revision():
    from revision_transaction import recover_pending_revision as implementation
    return implementation()


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
