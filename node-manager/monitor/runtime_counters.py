"""Persistent per-process/per-credential baselines for the native user counters."""
from __future__ import annotations
import hashlib
from typing import Any

MAX_BYTES = 2**63 - 1


def counter_key(row: dict) -> str:
    parts = [row["inbound"], row["user"]]
    if row.get("id"):
        parts.append(row["id"])
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()

def apply_counters(store: dict, snapshot: dict, auth_map: dict, historical_aliases: dict) -> None:
    state = store.get("runtimeCounters")
    instance = snapshot["instanceId"]
    version = snapshot.get("counterVersion", 1)
    migrate = state is None and bool(store.get("collectedAt") or any(
        int(row.get("upload") or 0) + int(row.get("download") or 0) for row in store["users"].values()))
    if state is None:
        state = {"instanceId": instance, "rows": {}, "retiredInstances": [], "migrationBaseline": migrate}
    else:
        if not isinstance(state, dict) or not isinstance(state.get("rows"), dict) or not isinstance(state.get("retiredInstances"), list):
            raise ValueError("invalid_runtime_counter_baselines")
        state = {**state, "rows": dict(state["rows"]), "retiredInstances": list(state["retiredInstances"])}
        state["retirementPending"] = dict(state.get("retirementPending", {}))
        if instance != state["instanceId"]:
            from runtime_history import epoch_retired, retire_epochs
            if instance in state["retiredInstances"] or (version == 2 and epoch_retired(instance)):
                raise ValueError("retired_runtime_counter_instance")
            state["retiredInstances"].append(state["instanceId"])
            state.update(instanceId=instance, rows={}, retirementPending={}, epochGapPossible=True)
    if version == 2 and state["retiredInstances"]:
        from runtime_history import retire_epochs
        retire_epochs(state["retiredInstances"])
        state["retiredInstances"] = []
    pending = dict(state.get("retirementPending", {}))
    seen = set()
    for row in snapshot["users"]:
        key = counter_key(row)
        if key in seen:
            raise ValueError("duplicate_runtime_counter")
        seen.add(key)
        previous = state["rows"].get(key)
        if previous is None and version == 2:
            previous = state["rows"].pop(counter_key({"inbound": row["inbound"], "user": row["user"]}), None)
        user_id = auth_map.get(row["user"]) or historical_aliases.get(row["user"])
        if previous:
            if user_id and previous.get("userId") and user_id != previous["userId"]:
                raise ValueError("runtime_counter_owner_changed")
            user_id = user_id or previous.get("userId")
        elif not user_id and row["user"].startswith("node-manager:"):
            user_id = row["user"][len("node-manager:"):]
        upload, download = row["upload"], row["download"]
        if any(type(value) is not int or not 0 <= value <= MAX_BYTES for value in (upload, download)):
            raise ValueError("invalid_runtime_counter")
        old_upload = previous["upload"] if previous else upload if migrate else 0
        old_download = previous["download"] if previous else download if migrate else 0
        if upload < old_upload or download < old_download:
            raise ValueError("runtime_counter_regression")
        state["rows"][key] = {"upload": upload, "download": download, "userId": user_id}
        if version == 2:
            if row["retirable"]:
                pending[key] = {k: row[k] for k in ("inbound", "user", "id", "upload", "download")}
            else:
                pending.pop(key, None)
        if not user_id:
            # Baseline unmanaged credentials but never attribute them by outbound naming.
            continue
        user = store["users"].setdefault(user_id, {"upload": 0, "download": 0})
        total_upload = int(user.get("upload") or 0) + upload - old_upload
        total_download = int(user.get("download") or 0) + download - old_download
        if max(total_upload, total_download) > MAX_BYTES:
            raise ValueError("runtime_counter_overflow")
        user.update(upload=total_upload, download=total_download)
    # Previously seen credentials must remain in a process-lifetime snapshot,
    # including removed users. A partial response must not erase a baseline.
    if not set(state["rows"]).issubset(seen):
        raise ValueError("runtime_counter_snapshot_incomplete")
    if version == 2:
        state["counterVersion"] = 2
        state["retirementPending"] = pending
    store["runtimeCounters"] = state


def finalize_retirements(store: dict, snapshot: dict, client, persist) -> dict:
    """The intent and accounted bytes were fsynced before this call.

    Lost ACK replies are retried by immutable counter ID. Persist each confirmed
    batch before taking a new sample, including when the previous ACK already
    deleted those IDs. Never infer settlement from absence in a snapshot.
    """
    state = store.get("runtimeCounters") or {}
    pending = state.get("retirementPending", {})
    if not pending or state.get("instanceId") != snapshot["instanceId"]:
        return snapshot
    keys = list(pending)
    for offset in range(0, len(keys), 256):
        rows = [pending[key] for key in keys[offset:offset + 256]]
        confirmed = client.acknowledge_counters(snapshot["instanceId"], rows)
        for row in confirmed:
            key = counter_key(row)
            state["rows"].pop(key, None)
            pending.pop(key, None)
        if confirmed:
            persist(store)
    return client.counters()
