"""Reviewed peer usage evidence, separate from native byte counters.

The control plane compares real node observations. No peer traffic is copied
into upload/download, and imported observations never become native usage.
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

EVIDENCE_KEY = "sharedQuotaEvidence"
RESET_VERSION_KEY = "sharedQuotaResetVersion"
MAX_BYTES = 2**63 - 1


class QuotaEvidenceRejected(ValueError):
    pass


def epoch(user: dict[str, Any]) -> dict[str, Any]:
    return {"cycleStart": user.get("lastTrafficCycleStart"),
            "manualResetAt": user.get("lastManualTrafficResetAt"),
            "renewalResetKey": user.get("lastRenewalResetKey"),
            "version": user.get(RESET_VERSION_KEY, 0)}


def epoch_token(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def same_cycle(a: dict[str, Any], b: dict[str, Any]) -> bool:
    # Absent/zero fields from legacy records have the same meaning.
    return all((a.get(k) or None) == (b.get(k) or None)
               for k in ("cycleStart", "manualResetAt", "renewalResetKey"))


def _advanced(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Whether source reset evidence advances a previously accepted epoch."""
    old_cycle, new_cycle = a.get("cycleStart") or 0, b.get("cycleStart") or 0
    if type(old_cycle) is not int or type(new_cycle) is not int or new_cycle < old_cycle:
        return False
    if new_cycle > old_cycle:
        return True
    old, new = a.get("renewalResetKey"), b.get("renewalResetKey")
    if old != new:
        try:
            return bool(new and (not old or datetime.fromisoformat(new) > datetime.fromisoformat(old)))
        except (ValueError, TypeError):
            return False
    for key in ("manualResetAt", "version"):
        old, new = a.get(key) or 0, b.get(key) or 0
        if type(old) is not int or type(new) is not int or new < old:
            return False
    return any((a.get(k) or 0) != (b.get(k) or 0) for k in ("manualResetAt", "version"))


def clear_for_reset(user: dict[str, Any]) -> None:
    """Called only inside an existing authorized native usage reset."""
    version = user.get(RESET_VERSION_KEY, 0)
    if type(version) is not int or version < 0:
        raise QuotaEvidenceRejected("INVALID_RESET_VERSION")
    retired = user.setdefault("sharedQuotaRetiredSources", {})
    for source, record in user.get(EVIDENCE_KEY, {}).items():
        retired[source] = {"epoch": record["sourceEpoch"], "epochToken": record["sourceEpochToken"]}
    user.pop(EVIDENCE_KEY, None)
    user[RESET_VERSION_KEY] = version + 1


def peer_used_bytes(user: dict[str, Any], limit: int | None) -> int:
    records = user.get(EVIDENCE_KEY, {})
    if not isinstance(records, dict):
        raise QuotaEvidenceRejected("INVALID_STORED_QUOTA_EVIDENCE")
    total = 0
    token = epoch_token(epoch(user))
    for record in records.values():
        if not isinstance(record, dict):
            raise QuotaEvidenceRejected("INVALID_STORED_QUOTA_EVIDENCE")
        if record.get("targetEpochToken") != token or record.get("limitBytes") != limit:
            continue
        count = record.get("nativeTotalBytes")
        if type(count) is not int or not 0 <= count <= MAX_BYTES:
            raise QuotaEvidenceRejected("INVALID_STORED_QUOTA_EVIDENCE")
        total += count
    return min(MAX_BYTES, total)


def identity_digest(row: dict[str, Any]) -> str:
    if row.get("serializationIssues") or not row.get("auth"):
        raise QuotaEvidenceRejected("IDENTITY_UNAVAILABLE")
    material = {"auth": sorted(row["auth"], key=lambda v: v["protocol"]),
                "proxy": {k: (row.get("proxy") or {}).get(k)
                          for k in ("server", "port", "username", "password")},
                "directConfirmed": bool(row.get("directConfirmed"))}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _rows() -> dict[str, Any]:
    from singbox import manager
    from replication_snapshot import capture
    with manager._config_lock():
        data, registry = manager.read_config(), manager.read_registry()
    snapshot = capture(data, registry, False)
    if snapshot.get("errors"):
        raise QuotaEvidenceRejected("NODE_IDENTITY_CONFLICT")
    return {row["userId"]: row for row in snapshot["users"]}


def inspect_users(user_ids: list[str] | None = None) -> dict[str, Any]:
    from config import config
    from monitor import traffic
    now = datetime.now(timezone.utc).isoformat()
    # Read one stable counter and configuration projection without collecting or writing.
    with traffic.collection_lock:
        with traffic.traffic_lock:
            store = traffic._read_store()
            rows = _rows()
            result = []; issues = []
            for uid in (user_ids if user_ids is not None else sorted(rows)):
                row = rows.get(uid)
                if row is None:
                    raise QuotaEvidenceRejected("USER_NOT_FOUND")
                user = store["users"].get(uid, {})
                count = int(user.get("upload") or 0) + int(user.get("download") or 0)
                try:
                    digest = identity_digest(row)
                except QuotaEvidenceRejected as error:
                    issues.append({"userId": uid, "reason": str(error)})
                    continue
                result.append({"userId": uid, "identityDigest": digest,
                               "limitBytes": row.get("trafficLimitBytes"),
                               "nativeTotalBytes": count, "epoch": epoch(user),
                               "epochToken": epoch_token(epoch(user)),
                               "peerObservedBytes": peer_used_bytes(user, row.get("trafficLimitBytes")),
                               "peerEvidenceCount": len(user.get(EVIDENCE_KEY, {}))})
    return {"nodeId": str(config.node.id), "observedAt": now, "users": result, "issues": issues}


def apply_observation(store: dict[str, Any], rows: dict[str, Any], local_node: str,
                      source_node: str, observed_at: str, updates: list[dict[str, Any]],
                      now: datetime | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Pure validation/CAS; return a new store and desired stable rule decisions."""
    now = now or datetime.now(timezone.utc)
    try:
        seen = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        age = (now - seen).total_seconds()
    except (TypeError, ValueError):
        raise QuotaEvidenceRejected("INVALID_OBSERVATION_TIME") from None
    if not -15 <= age <= 120:
        raise QuotaEvidenceRejected("STALE_OBSERVATION")
    if not source_node or source_node == local_node:
        raise QuotaEvidenceRejected("INVALID_SOURCE_NODE")
    if not updates or len(updates) > 50:
        raise QuotaEvidenceRejected("INVALID_BATCH_SIZE")
    if len({item["targetUserId"] for item in updates}) != len(updates):
        raise QuotaEvidenceRejected("DUPLICATE_TARGET")
    staged = copy.deepcopy(store)
    desired = {}
    for item in updates:
        uid = item["targetUserId"]
        source = item["source"]
        row = rows.get(uid)
        if row is None:
            raise QuotaEvidenceRejected("USER_NOT_FOUND")
        identity = identity_digest(row)
        if identity != source["identityDigest"]:
            raise QuotaEvidenceRejected("IDENTITY_MISMATCH")
        limit = row.get("trafficLimitBytes")
        if type(limit) is not int or limit <= 0 or limit != source["limitBytes"]:
            raise QuotaEvidenceRejected("LIMIT_MISMATCH")
        count = source["nativeTotalBytes"]
        if type(count) is not int or not 0 <= count <= MAX_BYTES:
            raise QuotaEvidenceRejected("INVALID_NATIVE_COUNTER")
        user = staged["users"].setdefault(uid, {})
        local_epoch = epoch(user)
        token = epoch_token(local_epoch)
        if token != item["expectedTargetEpochToken"]:
            raise QuotaEvidenceRejected("TARGET_RESET_CHANGED")
        records = user.setdefault(EVIDENCE_KEY, {})
        if not isinstance(records, dict) or (source_node not in records and len(records) >= 8):
            raise QuotaEvidenceRejected("INVALID_STORED_QUOTA_EVIDENCE")
        previous = records.get(source_node)
        incoming_epoch = source["epoch"]
        incoming_token = epoch_token(incoming_epoch)
        if incoming_token != source["epochToken"]:
            raise QuotaEvidenceRejected("INVALID_SOURCE_EPOCH")
        retired = user.get("sharedQuotaRetiredSources", {}).get(source_node)
        if retired and (retired["epochToken"] == incoming_token or not _advanced(retired["epoch"], incoming_epoch)):
            raise QuotaEvidenceRejected("SOURCE_RESET_REQUIRED")
        if previous:
            if previous["sourceUserId"] != source["userId"]:
                raise QuotaEvidenceRejected("SOURCE_USER_CHANGED")
            if previous["identityDigest"] != identity:
                raise QuotaEvidenceRejected("IDENTITY_CHANGED")
            old_epoch = previous["sourceEpoch"]
            if previous["sourceEpochToken"] == incoming_token:
                if count < previous["nativeTotalBytes"]:
                    raise QuotaEvidenceRejected("COUNTER_ROLLBACK")
            elif not _advanced(old_epoch, incoming_epoch):
                raise QuotaEvidenceRejected("SOURCE_RESET_NOT_ADVANCED")
        # A legitimate source cycle advance retires its old proof. It must not
        # carry the previous epoch's bytes into the target's next cycle.
        if not same_cycle(local_epoch, incoming_epoch):
            if previous and previous["sourceEpochToken"] != incoming_token:
                user.setdefault("sharedQuotaRetiredSources", {})[source_node] = {
                    "epoch": previous["sourceEpoch"], "epochToken": previous["sourceEpochToken"]}
                records.pop(source_node, None)
            else:
                raise QuotaEvidenceRejected("CYCLE_MISMATCH")
        else:
            records[source_node] = {"sourceUserId": source["userId"],
                "identityDigest": identity, "limitBytes": limit,
                "nativeTotalBytes": count, "sourceEpoch": incoming_epoch,
                "sourceEpochToken": incoming_token, "targetEpochToken": token,
                "observedAt": observed_at}
        native = int(user.get("upload") or 0) + int(user.get("download") or 0)
        blocked = native + peer_used_bytes(user, limit) >= limit
        desired[uid] = {"trafficBlocked": blocked, "blockedSourceIps": []}
        user["status"] = "traffic_limited" if blocked else "active"
    return staged, desired


def apply_users(source_node: str, observed_at: str, updates: list[dict[str, Any]]) -> dict[str, Any]:
    from config import config
    from monitor import traffic
    with traffic.collection_lock:
        with traffic.traffic_lock:
            store = traffic._read_store()
            staged, desired = apply_observation(store, _rows(), str(config.node.id),
                                                 source_node, observed_at, updates)
            if staged != store:
                traffic._write_store(staged)
            # Persist proof before routing; a routing failure can be retried,
            # and the next collector pass retains the reviewed quota block.
            traffic.sync_user_enforcements(desired)
    return {"success": True, "updatedCount": sum(staged["users"].get(k) != store["users"].get(k)
                                                for k in desired),
            "blockedUsers": [uid for uid, value in desired.items() if value["trafficBlocked"]]}
