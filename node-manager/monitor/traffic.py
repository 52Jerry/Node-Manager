from __future__ import annotations

import json
import ipaddress
import logging
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from singbox.manager import (
    USER_OUTBOUND_PREFIX,
    get_user_auth_map,
    get_user_policies,
    singbox_api,
    sync_user_enforcements,
)
from config import config


logger = logging.getLogger(__name__)
TRAFFIC_PATH = Path(
    os.environ.get("NODE_MANAGER_TRAFFIC_STORE", "/var/lib/node-manager/traffic.json")
)
SAMPLE_INTERVAL_SECONDS = config.monitoring.traffic_sample_interval_seconds
DEVICE_ACTIVE_WINDOW_SECONDS = config.monitoring.device_active_window_seconds
traffic_lock = threading.Lock()
collection_lock = threading.Lock()
stop_event = threading.Event()
collector_thread: threading.Thread | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty_store() -> dict[str, Any]:
    return {"version": 1, "users": {}, "connections": {}, "collectedAt": None}


def _read_store() -> dict[str, Any]:
    if not TRAFFIC_PATH.exists():
        return _empty_store()
    try:
        with TRAFFIC_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _empty_store()
    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        return _empty_store()
    data.setdefault("connections", {})
    data.setdefault("collectedAt", None)
    return data


def _write_store(data: dict[str, Any]) -> None:
    TRAFFIC_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, temp_name = tempfile.mkstemp(prefix="traffic.", suffix=".json", dir=TRAFFIC_PATH.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, TRAFFIC_PATH)
    finally:
        temp_path.unlink(missing_ok=True)


def _connection_user_id(
    connection: dict[str, Any], auth_map: dict[str, str] | None = None
) -> str | None:
    for chain in connection.get("chains") or []:
        if isinstance(chain, str) and chain.startswith(USER_OUTBOUND_PREFIX):
            return chain[len(USER_OUTBOUND_PREFIX):]

    metadata = connection.get("metadata")
    candidates: list[Any] = []
    if isinstance(metadata, dict):
        candidates.extend(
            metadata.get(field)
            for field in ("inboundUser", "inbound_user", "authUser", "auth_user", "user")
        )
    candidates.extend(
        connection.get(field)
        for field in ("inboundUser", "inbound_user", "authUser", "auth_user", "user")
    )
    for value in candidates:
        if value is None:
            continue
        auth_name = str(value)
        if auth_map and auth_name in auth_map:
            return auth_map[auth_name]
        if auth_name.startswith("node-manager:"):
            return auth_name[len("node-manager:"):]
    return None


def _connection_source_ip(connection: dict[str, Any]) -> str | None:
    metadata = connection.get("metadata")
    candidates = []
    if isinstance(metadata, dict):
        candidates.extend((metadata.get("sourceIP"), metadata.get("source_ip")))
    candidates.extend((connection.get("sourceIP"), connection.get("source_ip")))
    for value in candidates:
        if not value:
            continue
        try:
            return ipaddress.ip_address(str(value).strip().strip("[]")).compressed.lower()
        except ValueError:
            continue
    return None


def _enforce_policies(
    store: dict[str, Any],
    connections_by_user: dict[str, list[dict[str, Any]]],
    policies: dict[str, dict[str, int | None]],
    sampled_at: float,
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    enforcements: dict[str, dict[str, Any]] = {}
    connections_to_close: set[str] = set()
    active_cutoff = sampled_at - DEVICE_ACTIVE_WINDOW_SECONDS
    for user_id in set(store["users"]) | set(policies) | set(connections_by_user):
        connections = connections_by_user.get(user_id, [])
        user = store["users"].setdefault(user_id, {})
        policy = policies.get(user_id, {})
        traffic_limit = policy.get("trafficLimitBytes")
        max_source_ips = policy.get("maxSourceIps")
        user["trafficLimitBytes"] = traffic_limit
        user["maxSourceIps"] = max_source_ips
        user["status"] = "active"

        last_seen = user.get("sourceIpLastSeen")
        if not isinstance(last_seen, dict):
            last_seen = {}
        normalized_last_seen: dict[str, float] = {}
        for source_ip, seen_at in last_seen.items():
            try:
                seen_value = float(seen_at)
            except (TypeError, ValueError):
                continue
            if seen_value >= active_cutoff:
                normalized_last_seen[str(source_ip)] = seen_value
        for connection in connections:
            source_ip = connection.get("sourceIp")
            if source_ip is not None:
                normalized_last_seen[str(source_ip)] = sampled_at
        user["sourceIpLastSeen"] = normalized_last_seen

        if traffic_limit and int(user.get("upload") or 0) + int(user.get("download") or 0) >= traffic_limit:
            user["status"] = "traffic_limited"
            user["activeSourceIps"] = []
            user["blockedSourceIps"] = []
            connections_to_close.update(str(connection["id"]) for connection in connections)
            enforcements[user_id] = {"trafficBlocked": True, "blockedSourceIps": []}
            continue

        active_ips = set(normalized_last_seen)
        previous_allowed_ips = [
            source_ip for source_ip in user.get("activeSourceIps", []) if source_ip in active_ips
        ]
        previous_blocked_ips = {
            str(source_ip)
            for source_ip in user.get("blockedSourceIps", [])
            if source_ip
        }
        if max_source_ips:
            allowed = list(dict.fromkeys(previous_allowed_ips))[:max_source_ips]
            # Once a slot is available, release old rejected addresses so one
            # of them can become the next active device. While all slots stay
            # occupied, keep rejecting them even after their failed connection
            # falls out of the activity window.
            retained_blocked_ips = (
                previous_blocked_ips if len(allowed) >= max_source_ips else set()
            )
            allowed.extend(
                source_ip
                for source_ip in sorted(
                    active_ips - retained_blocked_ips,
                    key=lambda item: (-normalized_last_seen[item], item),
                )
                if source_ip not in allowed and len(allowed) < max_source_ips
            )
            allowed_set = set(allowed)
            blocked_ips = retained_blocked_ips | (active_ips - allowed_set)
            for connection in connections:
                source_ip = connection.get("sourceIp")
                if source_ip is not None and source_ip in blocked_ips:
                    connections_to_close.add(str(connection["id"]))
            user["activeSourceIps"] = sorted(allowed_set)
            user["blockedSourceIps"] = sorted(blocked_ips)
            user["status"] = "device_limited" if blocked_ips else "active"
            enforcements[user_id] = {
                "trafficBlocked": False,
                "blockedSourceIps": sorted(blocked_ips),
            }
        else:
            user["activeSourceIps"] = sorted(active_ips)
            user["blockedSourceIps"] = []
            enforcements[user_id] = {"trafficBlocked": False, "blockedSourceIps": []}
    return enforcements, connections_to_close


def _collect_traffic() -> bool:
    snapshot = singbox_api.get_connections()
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("connections"), list):
        return False

    policies = get_user_policies()
    auth_map = get_user_auth_map()
    sampled_at = time.time()
    with traffic_lock:
        store = _read_store()
        previous_connections = store.get("connections", {})
        active_connections: dict[str, Any] = {}
        connections_by_user: dict[str, list[dict[str, Any]]] = {}
        collected_at = _now()
        for connection in snapshot["connections"]:
            if not isinstance(connection, dict):
                continue
            user_id = _connection_user_id(connection, auth_map)
            connection_id = connection.get("id")
            if not user_id or not connection_id:
                continue
            upload = max(0, int(connection.get("upload") or 0))
            download = max(0, int(connection.get("download") or 0))
            previous = previous_connections.get(connection_id, {})
            previous_upload = int(previous.get("upload") or 0)
            previous_download = int(previous.get("download") or 0)
            source_ip = _connection_source_ip(connection)
            user = store["users"].setdefault(
                user_id, {"upload": 0, "download": 0, "updatedAt": collected_at}
            )
            user["upload"] = int(user.get("upload") or 0) + max(0, upload - previous_upload)
            user["download"] = int(user.get("download") or 0) + max(
                0, download - previous_download
            )
            user["updatedAt"] = collected_at
            active_connections[connection_id] = {
                "userId": user_id,
                "upload": upload,
                "download": download,
                "sourceIp": source_ip,
            }
            connections_by_user.setdefault(user_id, []).append(
                {"id": connection_id, "sourceIp": source_ip}
            )
        enforcements, connections_to_close = _enforce_policies(
            store, connections_by_user, policies, sampled_at
        )
        store["connections"] = active_connections
        store["collectedAt"] = collected_at
        _write_store(store)

    enforcement_available = True
    try:
        sync_user_enforcements(enforcements)
    except Exception:
        enforcement_available = False
        logger.exception("could not synchronize sing-box user enforcement rules")
    for connection_id in connections_to_close:
        if not singbox_api.close_connection(connection_id):
            enforcement_available = False
    return enforcement_available


def collect_traffic() -> bool:
    # API requests and the background collector share one connection baseline.
    # Serialize complete samples so an older snapshot cannot overwrite a newer
    # baseline and cause traffic to be counted twice on the next pass.
    with collection_lock:
        return _collect_traffic()


def get_traffic_store_snapshot() -> dict[str, Any]:
    """Read one consistent traffic snapshot for a multi-user API response."""
    with traffic_lock:
        return _read_store()


def get_user_traffic(
    user_id: str,
    refresh: bool = True,
    available: bool | None = None,
    policy: dict[str, int | None] | None = None,
    store: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if refresh:
        available = collect_traffic()
    if store is None:
        with traffic_lock:
            store = _read_store()
    if available is None:
        available = store.get("collectedAt") is not None
    user = store["users"].get(user_id, {})
    policy = get_user_policies().get(user_id, {}) if policy is None else policy
    upload = int(user.get("upload") or 0)
    download = int(user.get("download") or 0)
    traffic_limit = user.get("trafficLimitBytes")
    if traffic_limit is None:
        traffic_limit = policy.get("trafficLimitBytes")
    max_source_ips = user.get("maxSourceIps")
    if max_source_ips is None:
        max_source_ips = policy.get("maxSourceIps")
    status = user.get("status", "active")
    if traffic_limit and upload + download >= int(traffic_limit):
        status = "traffic_limited"
    return {
        "userId": user_id,
        "upload": upload,
        "download": download,
        "total": upload + download,
        "available": available,
        "source": "clash-api-sampled",
        "collectedAt": store.get("collectedAt"),
        "trafficLimitBytes": traffic_limit,
        "maxSourceIps": max_source_ips,
        "activeSourceIps": user.get("activeSourceIps", []),
        "status": status,
    }


def get_traffic_totals(refresh: bool = True) -> dict[str, Any]:
    available = collect_traffic() if refresh else None
    with traffic_lock:
        store = _read_store()
    if available is None:
        available = store.get("collectedAt") is not None
    upload = sum(int(item.get("upload") or 0) for item in store["users"].values())
    download = sum(int(item.get("download") or 0) for item in store["users"].values())
    return {
        "upload": upload,
        "download": download,
        "total": upload + download,
        "available": available,
        "source": "clash-api-sampled",
        "collectedAt": store.get("collectedAt"),
    }


def delete_user_traffic(user_id: str) -> None:
    with collection_lock:
        with traffic_lock:
            store = _read_store()
            store["users"].pop(user_id, None)
            store["connections"] = {
                connection_id: item
                for connection_id, item in store.get("connections", {}).items()
                if item.get("userId") != user_id
            }
            _write_store(store)


def _collector_loop() -> None:
    while not stop_event.is_set():
        try:
            collect_traffic()
        except Exception:
            logger.exception("traffic collection failed")
        if stop_event.wait(SAMPLE_INTERVAL_SECONDS):
            break


def start_traffic_collector() -> None:
    global collector_thread
    if collector_thread and collector_thread.is_alive():
        return
    stop_event.clear()
    collector_thread = threading.Thread(
        target=_collector_loop, name="node-manager-traffic", daemon=True
    )
    collector_thread.start()


def stop_traffic_collector() -> None:
    stop_event.set()
    if collector_thread and collector_thread.is_alive():
        collector_thread.join(timeout=SAMPLE_INTERVAL_SECONDS + 1)
