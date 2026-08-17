import json
import ipaddress
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from singbox.manager import USER_OUTBOUND_PREFIX, get_user_policies, singbox_api
from config import config


logger = logging.getLogger(__name__)
TRAFFIC_PATH = Path(
    os.environ.get("NODE_MANAGER_TRAFFIC_STORE", "/var/lib/node-manager/traffic.json")
)
SAMPLE_INTERVAL_SECONDS = config.monitoring.traffic_sample_interval_seconds
traffic_lock = threading.Lock()
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


def _connection_user_id(connection: dict[str, Any]) -> str | None:
    for chain in connection.get("chains") or []:
        if isinstance(chain, str) and chain.startswith(USER_OUTBOUND_PREFIX):
            return chain[len(USER_OUTBOUND_PREFIX):]
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
    store: dict[str, Any], connections_by_user: dict[str, list[dict[str, Any]]]
) -> None:
    policies = get_user_policies()
    for user_id in set(store["users"]) | set(policies) | set(connections_by_user):
        connections = connections_by_user.get(user_id, [])
        user = store["users"].setdefault(user_id, {})
        policy = policies.get(user_id, {})
        traffic_limit = policy.get("trafficLimitBytes")
        max_source_ips = policy.get("maxSourceIps")
        user["trafficLimitBytes"] = traffic_limit
        user["maxSourceIps"] = max_source_ips
        user["status"] = "active"

        if traffic_limit and int(user.get("upload") or 0) + int(user.get("download") or 0) >= traffic_limit:
            user["status"] = "traffic_limited"
            for connection in connections:
                singbox_api.close_connection(str(connection["id"]))
            continue

        current_ips = {
            source_ip
            for connection in connections
            if (source_ip := connection.get("sourceIp")) is not None
        }
        previous_ips = [
            source_ip for source_ip in user.get("activeSourceIps", []) if source_ip in current_ips
        ]
        if max_source_ips and len(current_ips) > max_source_ips:
            allowed = list(dict.fromkeys(previous_ips))[:max_source_ips]
            allowed.extend(
                source_ip
                for source_ip in sorted(current_ips)
                if source_ip not in allowed and len(allowed) < max_source_ips
            )
            allowed_set = set(allowed)
            for connection in connections:
                source_ip = connection.get("sourceIp")
                if source_ip is not None and source_ip not in allowed_set:
                    singbox_api.close_connection(str(connection["id"]))
            user["activeSourceIps"] = sorted(allowed_set)
            user["status"] = "device_limited"
        else:
            user["activeSourceIps"] = sorted(current_ips)


def collect_traffic() -> bool:
    snapshot = singbox_api.get_connections()
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("connections"), list):
        return False

    with traffic_lock:
        store = _read_store()
        previous_connections = store.get("connections", {})
        active_connections: dict[str, Any] = {}
        connections_by_user: dict[str, list[dict[str, Any]]] = {}
        collected_at = _now()
        for connection in snapshot["connections"]:
            if not isinstance(connection, dict):
                continue
            user_id = _connection_user_id(connection)
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
        _enforce_policies(store, connections_by_user)
        store["connections"] = active_connections
        store["collectedAt"] = collected_at
        _write_store(store)
    return True


def get_user_traffic(
    user_id: str, refresh: bool = True, available: bool | None = None
) -> dict[str, Any]:
    if refresh:
        available = collect_traffic()
    with traffic_lock:
        store = _read_store()
    if available is None:
        available = store.get("collectedAt") is not None
    user = store["users"].get(user_id, {})
    upload = int(user.get("upload") or 0)
    download = int(user.get("download") or 0)
    return {
        "userId": user_id,
        "upload": upload,
        "download": download,
        "total": upload + download,
        "available": available,
        "source": "clash-api-sampled",
        "collectedAt": store.get("collectedAt"),
        "trafficLimitBytes": user.get("trafficLimitBytes"),
        "maxSourceIps": user.get("maxSourceIps"),
        "activeSourceIps": user.get("activeSourceIps", []),
        "status": user.get("status", "active"),
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
    while not stop_event.wait(SAMPLE_INTERVAL_SECONDS):
        try:
            collect_traffic()
        except Exception:
            logger.exception("traffic collection failed")


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
