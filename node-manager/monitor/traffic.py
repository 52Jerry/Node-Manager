from __future__ import annotations

import json
import copy
import hashlib
import logging
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import runtime_metrics

from singbox.manager import (
    USER_OUTBOUND_PREFIX,
    get_user_auth_map,
    get_user_policies,
    get_user_monitoring_snapshot,
    singbox_api,
    sync_user_enforcements,
)
from config import config
from monitor.shared_quota import peer_used_bytes, clear_for_reset, native_accounting_proven
from monitor.source_identity import normalize_ip, source_ip_diagnostics
from monitor.telemetry import connection_summary, sample_state
from monitor.enforcement_wait import PendingEnforcement


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
_enforcement_wait = PendingEnforcement()

# Dashboard reads share one small projection of the last durable file version.
# Mutable accounting transactions continue to use _read_store() under their
# existing locks; no complete user/connection graph is retained by this cache.
_read_summary_lock = threading.Lock()
_read_summary_key: tuple | None = None
_read_summary: dict[str, Any] | None = None


def _store_version() -> tuple:
    path = Path(TRAFFIC_PATH)
    try:
        stat = path.stat()
    except FileNotFoundError:
        return (str(path.resolve()), None)
    return (str(path.resolve()), stat.st_dev, stat.st_ino, stat.st_size,
            stat.st_mtime_ns, stat.st_ctime_ns)


def _summarize_store(store: dict[str, Any]) -> dict[str, Any]:
    users = store.get("users")
    connections = store.get("connections", {})
    if not isinstance(users, dict) or not isinstance(connections, dict):
        raise OSError("traffic_store_invalid")
    # Publications from writers must obey the same counter validation as a
    # cold disk read; a cache must not make malformed counters look valid.
    for section in (users, connections):
        for item in section.values():
            if not isinstance(item, dict) or any(
                    type(item[field]) is not int or not 0 <= item[field] <= 2**63 - 1
                    for field in ("upload", "download") if field in item):
                raise OSError("traffic_store_invalid_counters")
    return {
        "upload": sum(int(item.get("upload") or 0) for item in users.values()),
        "download": sum(int(item.get("download") or 0) for item in users.values()),
        "connections": sum(1 for item in connections.values()
                           if item.get("online", True)),
        "collectedAt": store.get("collectedAt"),
        "connectionsCollectedAt": store.get("connectionsCollectedAt", store.get("collectedAt")),
        "runtime": bool(store.get("runtimeCounters")),
        # Only IDs are needed to exclude hot users from archived totals.
        "userIds": tuple(users) if store.get("runtimeCounters") else (),
        "nodeCumulativeCounters": copy.deepcopy(store.get("nodeCumulativeCounters")),
    }


def _reset_read_summary_cache() -> None:
    global _read_summary_key, _read_summary
    with _read_summary_lock:
        _read_summary_key = None
        _read_summary = None


def _get_read_summary() -> dict[str, Any]:
    global _read_summary_key, _read_summary
    # Never acquire traffic_lock here. A reader may run while a collector owns
    # it; atomic replacement and the before/after version check provide a
    # coherent file snapshot without blocking behind a complete collection.
    with _read_summary_lock:
        for _ in range(3):
            version = _store_version()
            if version == _read_summary_key and _read_summary is not None:
                return copy.deepcopy(_read_summary)
            try:
                store = _read_store()
                summary = _summarize_store(store)
            except Exception:
                _read_summary_key = None
                _read_summary = None
                raise
            if version == _store_version():
                _read_summary_key, _read_summary = version, summary
                return copy.deepcopy(summary)
        # Do not associate an old sample with a newer on-disk version.
        _read_summary_key = None
        _read_summary = None
        raise OSError("traffic_store_changed_during_read")


def _publish_read_summary(store: dict[str, Any], committed: os.stat_result) -> None:
    global _read_summary_key, _read_summary
    # Cache maintenance must never make an accounting write fail or wait for a
    # dashboard cache miss. A skipped publication is rebuilt by the next reader.
    if not _read_summary_lock.acquire(blocking=False):
        return
    try:
        version = _store_version()
        if (len(version) == 6 and version[1:5] ==
                (committed.st_dev, committed.st_ino, committed.st_size,
                 committed.st_mtime_ns)):
            _read_summary_key, _read_summary = version, _summarize_store(store)
    except (OSError, ValueError, TypeError, KeyError):
        _read_summary_key = None
        _read_summary = None
    finally:
        _read_summary_lock.release()


def _observation_metadata(collected_at: str | None) -> dict[str, Any]:
    health = collection_health.get(str(TRAFFIC_PATH), {})
    reason = health.get("reason")
    # Pending policy execution does not erase a successful connection sample.
    # Other failures still make the observation unusable for current decisions.
    observation_reason = health.get("observationReason", reason)
    if "observationReason" not in health and reason and reason.startswith("enforcement_"):
        observation_reason = None
    freshness = sample_state(collected_at, not observation_reason,
                             SAMPLE_INTERVAL_SECONDS * 3, observation_reason)
    age = freshness["stalenessSeconds"]
    return {**freshness,
            "observationAvailable": age is not None and age >= 0,
            "staleAfterSeconds": SAMPLE_INTERVAL_SECONDS * 3,
            "enforcementAvailable": bool(collected_at) and not reason,
            "enforcementReason": reason}


def get_proxy_connection_count_snapshot() -> dict[str, Any]:
    """Read sampled connection counts without fetching/decoding all sessions."""
    try:
        summary = _get_read_summary()
    except (OSError, ValueError, TypeError, KeyError):
        return {"connections": None, "collectedAt": None, "available": False,
                **_observation_metadata(None)}
    collected_at = summary.get("connectionsCollectedAt")
    observation = _observation_metadata(collected_at)
    return {"connections": summary["connections"] if collected_at else None,
            "collectedAt": collected_at,
            "available": observation["telemetryAvailable"] and observation["enforcementAvailable"],
            **observation}


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


@runtime_metrics.timed("traffic_persistence")
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
        committed = temp_path.stat()
        os.replace(temp_path, TRAFFIC_PATH)
        if os.name != "nt":
            from runtime_publication import sync_dir
            sync_dir(TRAFFIC_PATH.parent)
        _publish_read_summary(data, committed)
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
        if not native_accounting_proven(user):
            # Preserve the existing routing decision until historical provenance
            # is reconciled; don't add/subtract mixed counters or clear a block.
            user["quotaDecision"] = "legacy_mixed_traffic_review_required"
            continue
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

        if traffic_limit and int(user.get("upload") or 0) + int(user.get("download") or 0) + peer_used_bytes(user, traffic_limit) >= traffic_limit:
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


def _apply_native_counters(store, snapshot, auth_map, active_ids=()):
    import runtime_history as history
    import runtime_publication
    from singbox.runtime_client import RuntimeClient
    from .runtime_counters import apply_counters, finalize_retirements
    snapshot = finalize_retirements(store, snapshot, RuntimeClient(), _write_store)
    aliases = runtime_publication.read_aliases()
    aliases.update(history.owners(row["user"] for row in snapshot["users"] if row["user"] not in auth_map))
    user_ids = {auth_map.get(row["user"]) or aliases.get(row["user"]) for row in snapshot["users"]}
    user_ids.update(auth_map.values())
    user_ids.update(active_ids)
    store["users"].update(history.usage(user_ids - set(store["users"]) - {None}))
    apply_counters(store, snapshot, auth_map, aliases)


def _archive_inactive_usage(store, active_ids):
    import runtime_history as history
    retained = {row.get("userId") for row in store.get("runtimeCounters", {}).get("rows", {}).values()}
    retained.update(row.get("userId") for row in store.get("connections", {}).values())
    cold = {uid: row for uid, row in store["users"].items() if uid not in active_ids and uid not in retained}
    history.archive_usage(cold)
    for uid in cold:
        del store["users"][uid]


@runtime_metrics.timed("collector_sample")
def _sample_traffic() -> tuple[dict[str, dict[str, Any]], set[str]] | None:
    from singbox.runtime_client import enabled as runtime_enabled, RuntimeClient
    runtime_mode = runtime_enabled()
    with runtime_metrics.measure("collector_native"):
        native_snapshot = RuntimeClient().counters() if runtime_mode else None
    with runtime_metrics.measure("collector_connections"):
        snapshot = singbox_api.get_connections()
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("connections"), list):
        if native_snapshot is not None:
            with runtime_metrics.measure("collector_projection"):
                auth_map = get_user_monitoring_snapshot().auth_map
            with traffic_lock:
                store = _read_store()
                # Native counters can advance when connection telemetry fails;
                # that must not give the retained connection list a new time.
                store.setdefault("connectionsCollectedAt", store.get("collectedAt"))
                _apply_native_counters(store, native_snapshot, auth_map)
                _archive_inactive_usage(store, set(auth_map.values()))
                store["collectedAt"] = _now()
                _write_store(store)
        collection_health[str(TRAFFIC_PATH)] = {"reason": "api_unavailable",
                                                "observationReason": "api_unavailable"}
        connection_details.pop(str(TRAFFIC_PATH), None)
        logger.warning("traffic telemetry unavailable; retaining prior enforcement, review required")
        return None

    with runtime_metrics.measure("collector_projection"):
        monitoring = get_user_monitoring_snapshot()
    policies, auth_map = monitoring.policies, monitoring.auth_map
    sampled_at = time.time()
    with traffic_lock:
        store = _read_store()
        if runtime_mode:
            _apply_native_counters(store, native_snapshot, auth_map, policies)
        elif store.get("runtimeCounters"):
            raise ValueError("runtime_counter_mode_requires_explicit_migration")
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
            if not runtime_mode:
                user["upload"] = int(user.get("upload") or 0) + max(0, upload - previous_upload)
                user["download"] = int(user.get("download") or 0) + max(0, download - previous_download)
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
        store["connectionsCollectedAt"] = collected_at
        store["nodeCumulativeCounters"] = singbox_api.cumulative_counters(snapshot)
        if runtime_mode:
            _archive_inactive_usage(store, set(auth_map.values()) | set(policies))
        _write_store(store)
        connection_details[str(TRAFFIC_PATH)] = transient_details

    return enforcements, connections_to_close


@runtime_metrics.timed("collector_enforcement")
def _synchronize_sample_enforcements(enforcements: dict[str, dict[str, Any]]) -> None:
    from singbox.runtime_client import enabled as runtime_enabled
    desired = {user_id: {"trafficBlocked": bool(value.get("trafficBlocked")),
                         "blockedSourceIps": []}
               for user_id, value in enforcements.items()}
    if not runtime_enabled():
        sync_user_enforcements(desired)
        return
    import runtime_write_queue
    token = runtime_write_queue.wait_timeout.set(0)
    try:
        sync_user_enforcements(desired)
    finally:
        runtime_write_queue.wait_timeout.reset(token)


def _collect_traffic() -> bool:
    # Native configuration writes can wait behind other user updates. Finish
    # the sampling frame first so raw core/native snapshots, the old baseline
    # and the complete mutable store are released before waiting on the writer.
    # Keep the existing collection transaction lock and enforcement ordering.
    sampled = _sample_traffic()
    if sampled is None:
        return False
    enforcements, connections_to_close = sampled

    enforcement_available = True
    try:
        # Source-IP limits are runtime decisions enforced by closing the
        # offending Clash connections. Persisting those volatile CIDRs into
        # sing-box would rewrite the full config and reload the process as
        # clients move between source addresses.
        enforcement_available = _enforcement_wait.run(str(TRAFFIC_PATH),
            lambda: _synchronize_sample_enforcements(enforcements))
    except Exception:
        enforcement_available = False
        logger.exception("could not synchronize sing-box user enforcement rules")
    for connection_id in connections_to_close:
        if not singbox_api.close_connection(connection_id):
            enforcement_available = False
    collection_health[str(TRAFFIC_PATH)] = {
        "reason": None if enforcement_available else (_enforcement_wait.reason or "enforcement_unavailable"),
        "observationReason": None}
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
        except (OSError, ValueError, TypeError, KeyError, RuntimeError):
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
    user = store["users"].get(user_id)
    if user is None:
        from singbox.runtime_client import enabled
        if enabled() or store.get("runtimeCounters"):
            import runtime_history
            user = runtime_history.usage([user_id]).get(user_id)
        user = user or {}
    policy = get_user_policies().get(user_id, {}) if policy is None else policy
    upload = int(user.get("upload") or 0)
    download = int(user.get("download") or 0)
    # The registry is authoritative even if telemetry fails or a limit was removed.
    traffic_limit = policy.get("trafficLimitBytes", user.get("trafficLimitBytes"))
    max_source_ips = policy.get("maxSourceIps", user.get("maxSourceIps"))
    max_connections = policy.get("maxConnections", user.get("maxConnections"))
    status = user.get("status", "active")
    accounting_proven = native_accounting_proven(user)
    if accounting_proven and traffic_limit and upload + download + peer_used_bytes(user, traffic_limit) >= int(traffic_limit):
        status = "traffic_limited"
    elif accounting_proven and status == "traffic_limited":
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
        "peerObservedBytes": peer_used_bytes(user, traffic_limit),
        "quotaUsedBytes": upload + download + peer_used_bytes(user, traffic_limit) if accounting_proven else None,
        "nativeAccountingProven": accounting_proven,
        "available": freshness["telemetryAvailable"],
        "source": "singbox-runtime-cumulative" if store.get("runtimeCounters") else "clash-api-sampled",
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
        "measurementQuality": ("runtime_cumulative_since_baseline" if store.get("runtimeCounters") else "sampled_lower_bound") if accounting_proven else "legacy_mixed_review_required",
        "measuredTotal": upload + download if freshness["telemetryAvailable"] and accounting_proven else None,
        "lastKnownTotal": upload + download if store.get("collectedAt") else None,
        "quotaDecision": "legacy_mixed_traffic_review_required" if not accounting_proven else ("runtime_cumulative_enforcement" if store.get("runtimeCounters") else "legacy_sampled_enforcement") if freshness["telemetryAvailable"]
                         else "retain_prior_enforcement_review_required",
        "sourceLimitDecision": user.get("sourceLimitDecision", "not_evaluated"),
        "alertRequired": (not accounting_proven or not freshness["telemetryAvailable"] or
                          user.get("sourceLimitDecision") == "suspended_unreliable_source_review_required"),
        "policyStatus": "source_limited" if status == "device_limited" else status,
        "status": status,
    }


def get_traffic_totals(refresh: bool = True) -> dict[str, Any]:
    available = collect_traffic() if refresh else None
    try:
        summary = _get_read_summary()
    except OSError:
        summary = _summarize_store(_empty_store())
        available = False
        collection_health[str(TRAFFIC_PATH)] = {"reason": "traffic_store_unreadable"}
    if available is None:
        available = (summary.get("collectedAt") is not None
                     and not collection_health.get(str(TRAFFIC_PATH), {}).get("reason"))
    freshness = sample_state(summary.get("collectedAt"), bool(available),
                             SAMPLE_INTERVAL_SECONDS * 3,
                             collection_health.get(str(TRAFFIC_PATH), {}).get("reason"))
    upload, download = summary["upload"], summary["download"]
    if summary["runtime"]:
        import runtime_history
        cold_upload, cold_download = runtime_history.archived_totals(summary["userIds"])
        upload += cold_upload
        download += cold_download
    return {
        "upload": upload,
        "download": download,
        "total": upload + download,
        "available": freshness["telemetryAvailable"],
        "source": "singbox-runtime-cumulative" if summary["runtime"] else "clash-api-sampled",
        "collectedAt": summary.get("collectedAt"),
        **{key: value for key, value in _observation_metadata(summary.get("collectedAt")).items()
           if key in ("observationAvailable", "staleAfterSeconds", "enforcementAvailable", "enforcementReason")},
        **freshness,
        "measurementQuality": "runtime_cumulative_since_baseline" if summary["runtime"] else "sampled_lower_bound",
        "measuredTotal": upload + download if freshness["telemetryAvailable"] else None,
        "lastKnownTotal": upload + download if summary.get("collectedAt") else None,
        "nodeCumulativeCounters": summary.get("nodeCumulativeCounters")
                                  if freshness["telemetryAvailable"] else None,
        "alertRequired": not freshness["telemetryAvailable"],
    }


def delete_user_traffic(user_id: str) -> None:
    with collection_lock:
        with traffic_lock:
            store = _read_store()
            from singbox.runtime_client import enabled
            if (enabled() or store.get("runtimeCounters")) and user_id in store["users"]:
                import runtime_history
                runtime_history.archive_usage({user_id: store["users"][user_id]})
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
            from singbox.runtime_client import enabled
            if (enabled() or store.get("runtimeCounters")) and user_id not in store["users"]:
                import runtime_history
                store["users"].update(runtime_history.usage([user_id]))
            user = store["users"].setdefault(user_id, {})
            if renewal_key is not None and user.get("lastRenewalResetKey") == renewal_key:
                return {"success": True, "userId": user_id, "trafficReset": False}
            clear_for_reset(user)
            if renewal_key is None:
                user["lastManualTrafficResetAt"] = int(datetime.now(timezone.utc).timestamp() * 1000000)
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
    _reset_read_summary_cache()
