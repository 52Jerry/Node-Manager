from __future__ import annotations

import json
import hashlib
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
from monitor.source_identity import normalize_ip, source_ip_diagnostics
from monitor.telemetry import connection_summary, sample_state


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
collection_health: dict[str, dict[str, Any]] = {}
connection_details: dict[str, dict[str, dict[str, Any]]] = {}


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
    except (OSError, json.JSONDecodeError) as exc:
        raise OSError("traffic_store_unreadable") from exc
    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        raise OSError("traffic_store_invalid")
    if not isinstance(data.get("connections", {}), dict):
        raise OSError("traffic_store_invalid")
    for section in (data["users"], data.get("connections", {})):
        for item in section.values():
            if not isinstance(item, dict) or any(
                    type(item[field]) is not int or not 0 <= item[field] <= 2**63 - 1
                    for field in ("upload", "download") if field in item):
                raise OSError("traffic_store_invalid_counters")
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


def _connection_ip(connection: dict[str, Any], *fields: str) -> str | None:
    metadata = connection.get("metadata")
    candidates = []
    if isinstance(metadata, dict):
        candidates.extend(metadata.get(field) for field in fields)
    candidates.extend(connection.get(field) for field in fields)
    for value in candidates:
        if not value:
            continue
        normalized = normalize_ip(value)
        if normalized is not None:
            return normalized
    return None


def _connection_source_ip(connection: dict[str, Any]) -> str | None:
    return _connection_ip(connection, "sourceIP", "source_ip")


def _normalized_source_cidrs(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(
        {
            normalized
            for source_ip in value
            if (normalized := normalize_ip(source_ip)) is not None
        }
    )


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
        max_connections = policy.get("maxConnections")
        user["trafficLimitBytes"] = traffic_limit
        user["maxSourceIps"] = max_source_ips
        user["maxConnections"] = max_connections
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
            normalized_ip = normalize_ip(source_ip)
            if normalized_ip and seen_value >= active_cutoff:
                normalized_last_seen[normalized_ip] = max(
                    seen_value, normalized_last_seen.get(normalized_ip, 0)
                )
        for connection in connections:
            source_ip = connection.get("sourceIp")
            if source_ip is not None:
                normalized_last_seen[str(source_ip)] = sampled_at
        user["sourceIpLastSeen"] = normalized_last_seen
        confidence = source_ip_diagnostics(
            [{"sourceIp": source} for source in normalized_last_seen]
            + [{"sourceIp": None} for connection in connections if connection.get("sourceIp") is None]
        )["sourceConfidence"]
        reliable_source_policy = confidence in {"observed", "idle"}
        user["sourceLimitDecision"] = (
            "not_configured" if not max_source_ips else "observed_address_only"
            if reliable_source_policy else "suspended_unreliable_source_review_required"
        )

        if traffic_limit and int(user.get("upload") or 0) + int(user.get("download") or 0) >= traffic_limit:
            user["status"] = "traffic_limited"
            user["activeSourceIps"] = []
            user["blockedSourceIps"] = []
            connections_to_close.update(str(connection["id"]) for connection in connections)
            enforcements[user_id] = {"trafficBlocked": True, "blockedSourceIps": []}
            continue

        active_ips = set(normalized_last_seen)
        previous_allowed_ips = [
            normalize_ip(source_ip) for source_ip in user.get("activeSourceIps", [])
            if normalize_ip(source_ip) in active_ips
        ]
        previous_blocked_ips = {
            normalize_ip(source_ip)
            for source_ip in user.get("blockedSourceIps", [])
            if normalize_ip(source_ip)
        }
        if max_source_ips and reliable_source_policy:
            allowed = list(dict.fromkeys(previous_allowed_ips))[:max_source_ips]
            # Once a slot is available, release old rejected addresses so one
            # of them can become the next active source. While all slots stay
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
        else:
            allowed_set = set(active_ips)
            blocked_ips = set()

        blocked_source_ips = sorted(blocked_ips)
        for connection in connections:
            source_ip = connection.get("sourceIp")
            if source_ip is not None and source_ip in blocked_ips:
                connections_to_close.add(str(connection["id"]))
        user["activeSourceIps"] = sorted(allowed_set)
        user["blockedSourceIps"] = blocked_source_ips
        user["status"] = "device_limited" if blocked_source_ips else "active"
        user["enforcedBlockedSourceIps"] = blocked_source_ips
        enforcements[user_id] = {
            "trafficBlocked": False,
            "blockedSourceIps": blocked_source_ips,
        }
        if max_connections:
            candidates = [item for item in connections if str(item["id"]) not in connections_to_close]
            # Retain admitted sessions before new arrivals to avoid evicting long-lived connections.
            candidates.sort(key=lambda item: (
                not store.get("connections", {}).get(str(item["id"]), {}).get("online", False),
                str(item.get("startedAt") or ""), str(item["id"]),
            ))
            excess = candidates[int(max_connections):]
            connections_to_close.update(str(item["id"]) for item in excess)
            if excess and user["status"] == "active":
                user["status"] = "connection_limited"
    return enforcements, connections_to_close


def _collect_traffic() -> bool:
    snapshot = singbox_api.get_connections()
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("connections"), list):
        collection_health[str(TRAFFIC_PATH)] = {"reason": "api_unavailable"}
        connection_details.pop(str(TRAFFIC_PATH), None)
        logger.warning("traffic telemetry unavailable; retaining prior enforcement, review required")
        return False

    policies = get_user_policies()
    auth_map = get_user_auth_map()
    sampled_at = time.time()
    with traffic_lock:
        store = _read_store()
        previous_connections = store.get("connections", {})
        active_connections: dict[str, Any] = {}
        transient_details: dict[str, dict[str, Any]] = {}
        seen_connection_ids: set[str] = set()
        connections_by_user: dict[str, list[dict[str, Any]]] = {}
        collected_at = _now()
        for connection in snapshot["connections"]:
            if not isinstance(connection, dict):
                continue
            user_id = _connection_user_id(connection, auth_map)
            connection_id = connection.get("id")
            if not user_id or not connection_id:
                continue
            if not isinstance(connection_id, str) or connection_id in seen_connection_ids:
                raise ValueError("invalid_or_duplicate_connection_id")
            seen_connection_ids.add(connection_id)
            upload = connection.get("upload", 0)
            download = connection.get("download", 0)
            if any(type(value) is not int or not 0 <= value <= 2**63 - 1
                   for value in (upload, download)):
                raise ValueError("invalid_connection_counter")
            previous = previous_connections.get(connection_id, {})
            previous_upload = int(previous.get("upload") or 0)
            previous_download = int(previous.get("download") or 0)
            if previous and (previous.get("userId") != user_id or upload < previous_upload
                             or download < previous_download):
                raise ValueError("connection_identity_or_counter_reset")
            source_ip = _connection_source_ip(connection)
            metadata = connection.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            user = store["users"].setdefault(
                user_id, {"upload": 0, "download": 0, "updatedAt": collected_at}
            )
            user["upload"] = int(user.get("upload") or 0) + max(0, upload - previous_upload)
            user["download"] = int(user.get("download") or 0) + max(
                0, download - previous_download
            )
            user["updatedAt"] = collected_at
            transient_details[connection_id] = {
                "destinationIp": _connection_ip(connection, "destinationIP", "destination_ip"),
                "destinationPort": metadata.get("destinationPort"),
                "host": metadata.get("host"),
            }
            active_connections[connection_id] = {
                "userId": user_id,
                "upload": upload,
                "download": download,
                "sourceIp": source_ip,
                "sourcePort": metadata.get("sourcePort"),
                "network": metadata.get("network"),
                "protocol": metadata.get("type"),
                "startedAt": connection.get("start"),
                # Stock VLESS/Clash telemetry has no verified per-device identity.
                "deviceId": None,
            }
            connections_by_user.setdefault(user_id, []).append(
                {"id": connection_id, "sourceIp": source_ip, "startedAt": connection.get("start")}
            )
        enforcements, connections_to_close = _enforce_policies(
            store, connections_by_user, policies, sampled_at
        )
        # Keep closed-session counters as baselines, but never report them as online.
        for connection_id, connection in active_connections.items():
            connection["online"] = connection_id not in connections_to_close
        store["connections"] = active_connections
        store["collectedAt"] = collected_at
        store["nodeCumulativeCounters"] = singbox_api.cumulative_counters(snapshot)
        _write_store(store)
        connection_details[str(TRAFFIC_PATH)] = transient_details

    enforcement_available = True
    try:
        # Source-IP limits are runtime decisions enforced by closing the
        # offending Clash connections. Persisting those volatile CIDRs into
        # sing-box would rewrite the full config and reload the process as
        # clients move between source addresses.
        sync_user_enforcements(
            {
                user_id: {
                    "trafficBlocked": bool(desired.get("trafficBlocked")),
                    "blockedSourceIps": [],
                }
                for user_id, desired in enforcements.items()
            }
        )
    except Exception:
        enforcement_available = False
        logger.exception("could not synchronize sing-box user enforcement rules")
    for connection_id in connections_to_close:
        if not singbox_api.close_connection(connection_id):
            enforcement_available = False
    collection_health[str(TRAFFIC_PATH)] = {
        "reason": None if enforcement_available else "enforcement_unavailable"}
    if not enforcement_available:
        connection_details.pop(str(TRAFFIC_PATH), None)
    return enforcement_available


def collect_traffic() -> bool:
    # API requests and the background collector share one connection baseline.
    # Serialize complete samples so an older snapshot cannot overwrite a newer
    # baseline and cause traffic to be counted twice on the next pass.
    with collection_lock:
        try:
            return _collect_traffic()
        except (OSError, ValueError, TypeError, KeyError):
            collection_health[str(TRAFFIC_PATH)] = {"reason": "collection_or_persistence_failed"}
            connection_details.pop(str(TRAFFIC_PATH), None)
            logger.exception("traffic collection failed; no new enforcement applied")
            return False


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
    include_online: bool = True,
) -> dict[str, Any]:
    if refresh:
        available = collect_traffic()
    if store is None:
        with traffic_lock:
            try:
                store = _read_store()
            except OSError:
                store = _empty_store()
                available = False
                collection_health[str(TRAFFIC_PATH)] = {"reason": "traffic_store_unreadable"}
    if available is None:
        available = (store.get("collectedAt") is not None
                     and not collection_health.get(str(TRAFFIC_PATH), {}).get("reason"))
    freshness = sample_state(store.get("collectedAt"), bool(available),
                             SAMPLE_INTERVAL_SECONDS * 3,
                             collection_health.get(str(TRAFFIC_PATH), {}).get("reason"))
    if not freshness["telemetryAvailable"]:
        connection_details.pop(str(TRAFFIC_PATH), None)
    user = store["users"].get(user_id, {})
    policy = get_user_policies().get(user_id, {}) if policy is None else policy
    upload = int(user.get("upload") or 0)
    download = int(user.get("download") or 0)
    # The registry is authoritative even if telemetry fails or a limit was removed.
    traffic_limit = policy.get("trafficLimitBytes", user.get("trafficLimitBytes"))
    max_source_ips = policy.get("maxSourceIps", user.get("maxSourceIps"))
    max_connections = policy.get("maxConnections", user.get("maxConnections"))
    status = user.get("status", "active")
    if traffic_limit and upload + download >= int(traffic_limit):
        status = "traffic_limited"
    elif status == "traffic_limited":
        status = "active"
    online_connections = [
        {"id": connection_id, **{
            field: item.get(field) for field in (
                "sourceIp", "sourcePort", "network", "protocol", "startedAt", "upload", "download",
            )
        }, **{field: connection_details.get(str(TRAFFIC_PATH), {}).get(connection_id, {}).get(field)
              for field in ("destinationIp", "destinationPort", "host")},
         "deviceId": None,
         "credentialId": hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:24]}
        for connection_id, item in store.get("connections", {}).items()
        if item.get("userId") == user_id and item.get("online", True)
    ] if freshness["telemetryAvailable"] and include_online else None
    return {
        "userId": user_id,
        "upload": upload,
        "download": download,
        "total": upload + download,
        "available": freshness["telemetryAvailable"],
        "source": "clash-api-sampled",
        "collectedAt": store.get("collectedAt"),
        "trafficLimitBytes": traffic_limit,
        "maxSourceIps": max_source_ips,
        "maxConnections": max_connections,
        "connectionLimitSupported": True,
        "activeSourceIps": user.get("activeSourceIps", []),
        "onlineConnections": online_connections,
        "sourceIpActiveWindowSeconds": DEVICE_ACTIVE_WINDOW_SECONDS,
        "blockedSourceIps": user.get("blockedSourceIps", []) if freshness["telemetryAvailable"] else [],
        **source_ip_diagnostics(online_connections),
        **connection_summary(online_connections),
        **freshness,
        "measurementQuality": "sampled_lower_bound",
        "measuredTotal": upload + download if freshness["telemetryAvailable"] else None,
        "lastKnownTotal": upload + download if store.get("collectedAt") else None,
        "quotaDecision": "legacy_sampled_enforcement" if freshness["telemetryAvailable"]
                         else "retain_prior_enforcement_review_required",
        "sourceLimitDecision": user.get("sourceLimitDecision", "not_evaluated"),
        "alertRequired": (not freshness["telemetryAvailable"] or
                          user.get("sourceLimitDecision") == "suspended_unreliable_source_review_required"),
        "policyStatus": "source_limited" if status == "device_limited" else status,
        "status": status,
    }


def get_traffic_totals(refresh: bool = True) -> dict[str, Any]:
    available = collect_traffic() if refresh else None
    with traffic_lock:
        try:
            store = _read_store()
        except OSError:
            store = _empty_store()
            available = False
            collection_health[str(TRAFFIC_PATH)] = {"reason": "traffic_store_unreadable"}
    if available is None:
        available = (store.get("collectedAt") is not None
                     and not collection_health.get(str(TRAFFIC_PATH), {}).get("reason"))
    freshness = sample_state(store.get("collectedAt"), bool(available),
                             SAMPLE_INTERVAL_SECONDS * 3,
                             collection_health.get(str(TRAFFIC_PATH), {}).get("reason"))
    upload = sum(int(item.get("upload") or 0) for item in store["users"].values())
    download = sum(int(item.get("download") or 0) for item in store["users"].values())
    return {
        "upload": upload,
        "download": download,
        "total": upload + download,
        "available": freshness["telemetryAvailable"],
        "source": "clash-api-sampled",
        "collectedAt": store.get("collectedAt"),
        **freshness,
        "measurementQuality": "sampled_lower_bound",
        "measuredTotal": upload + download if freshness["telemetryAvailable"] else None,
        "lastKnownTotal": upload + download if store.get("collectedAt") else None,
        "nodeCumulativeCounters": store.get("nodeCumulativeCounters")
                                  if freshness["telemetryAvailable"] else None,
        "alertRequired": not freshness["telemetryAvailable"],
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


def reset_user_traffic(user_id: str, renewal_key: str | None = None) -> dict[str, Any]:
    """Reset a user's usage while preserving the connection sampling baseline.

    The active connection counters must remain in the store. Otherwise the
    next sample treats the full counter as new traffic and adds the pre-renewal
    usage back to the user.
    """
    with collection_lock:
        with traffic_lock:
            store = _read_store()
            user = store["users"].setdefault(user_id, {})
            if renewal_key is not None and user.get("lastRenewalResetKey") == renewal_key:
                return {"success": True, "userId": user_id, "trafficReset": False}
            user.update(
                {
                    "upload": 0,
                    "download": 0,
                    "activeSourceIps": [],
                    "blockedSourceIps": [],
                    "sourceIpLastSeen": {},
                    "status": "active",
                    "updatedAt": _now(),
                }
            )
            if renewal_key is not None:
                user["lastRenewalResetKey"] = renewal_key
            _write_store(store)

    sync_user_enforcements(
        {user_id: {"trafficBlocked": False, "blockedSourceIps": []}}
    )
    return {"success": True, "userId": user_id, "trafficReset": True}


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
    connection_details.clear()
