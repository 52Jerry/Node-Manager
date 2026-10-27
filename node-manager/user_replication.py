"""Portable users and opt-in shared protocol configuration, applied atomically."""
from __future__ import annotations

from datetime import datetime, timezone
import copy
import re
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from config import config
from monitor import traffic
from monitor.shared_quota import export_origins, import_origins, peer_used_bytes, epoch, validate_origins, QuotaEvidenceRejected
from singbox import manager
from ha_template import export_template, apply_template
from replication_snapshot import capture, ReplicationConflict


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuthEntry(StrictModel):
    protocol: Literal["vless", "vmess", "trojan", "socks"]
    credential: str = Field(min_length=1, max_length=512)
    username: str | None = Field(default=None, max_length=128)
    flow: str | None = Field(default=None, max_length=64)


class ProxyEntry(StrictModel):
    server: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=512)
    sourceIp: str | None = None
    countryCode: str | None = None
    countryName: str | None = None
    provinceName: str | None = None
    cityName: str | None = None


class PortableUser(StrictModel):
    userId: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    auth: list[AuthEntry] = Field(min_length=1, max_length=4)
    proxy: ProxyEntry | None = None
    createdAt: datetime
    expiresAt: datetime
    trafficLimitBytes: int | None = Field(default=None, gt=0)
    maxSourceIps: int | None = Field(default=None, gt=0)
    maxConnections: int | None = Field(default=None, gt=0, le=100000)
    upload: int = Field(default=0, ge=0)
    download: int = Field(default=0, ge=0)
    trafficOrigins: dict | None = None
    trafficEpoch: dict | None = None
    trafficCycleStart: int | None = Field(default=None, ge=0)
    manualTrafficResetAt: int = Field(default=0, ge=0)
    accessEnabled: bool | None = None
    remark: str | None = Field(default=None, max_length=1024)
    tags: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def unique_protocols(self):
        if len({entry.protocol for entry in self.auth}) != len(self.auth):
            raise ValueError("duplicate protocol")
        for entry in self.auth:
            if entry.protocol == "socks" and (not entry.username or entry.username.startswith(manager.USER_PREFIX)):
                raise ValueError("invalid public SOCKS username")
        return self


class ReplicationRequest(StrictModel):
    groupKey: str = Field(pattern=r"^[A-Za-z0-9-]{1,64}$")
    users: list[PortableUser] = Field(max_length=10000)
    retired: list[PortableUser] = Field(default_factory=list, max_length=10000)
    aliases: dict[str, str] = Field(default_factory=dict)
    sharedConfig: dict | None = None
    generation: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def unique_users(self):
        if len({user.userId for user in self.users}) != len(self.users):
            raise ValueError("duplicate user id")
        if {user.userId for user in self.retired} & {user.userId for user in self.users}:
            raise ValueError("retired user is still active")
        if len(self.aliases) > 10000 or any(not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value)
                                          for pair in self.aliases.items() for value in pair):
            raise ValueError("invalid aliases")
        if self.sharedConfig is not None and self.generation is None:
            raise ValueError("shared configuration requires a generation")
        if any(len(tag) > 128 for user in [*self.users, *self.retired] for tag in user.tags):
            raise ValueError("tag too long")
        return self


def _tags():
    return {
        "vless": config.singbox.vless_tag,
        "vmess": config.singbox.vmess_tag,
        "trojan": config.singbox.trojan_tag,
        "socks": config.singbox.socks_tag,
    }


def _auth(data, registry, user_id):
    names = manager._user_auth_names(registry, user_id)
    entries = []
    for protocol, tag in _tags().items():
        inbound = next((item for item in data.get("inbounds", []) if item.get("tag") == tag), None)
        if inbound is None:
            continue
        matches = [user for user in inbound.get("users", [])
                   if user.get("name") in names or user.get("username") in names]
        if len(matches) > 1:
            raise manager.SingboxConfigError("ambiguous user credentials; replication refused")
        if matches:
            entry = matches[0]
            entries.append({"protocol": protocol,
                            "credential": entry.get("uuid") if protocol in {"vless", "vmess"} else entry.get("password"),
                            "username": entry.get("username") if protocol == "socks" else None,
                            "flow": entry.get("flow") if protocol == "vless" else None})
    return entries


def export_users(shared_config=False):
    # Collection always takes this lock before accessing config or traffic.
    with traffic.collection_lock:
        with manager._config_lock():
            data, registry = manager.read_config(), manager.read_registry()
        store = traffic.get_traffic_store_snapshot()
    snapshot = capture(data, registry, shared_config)
    if snapshot["errors"]:
        raise ReplicationConflict(snapshot["errors"][0])
    users = []
    for row in snapshot["users"]:
        user_id = row["userId"]
        if row["serializationIssues"]:
            raise ReplicationConflict(row["serializationIssues"][0])
        if manager._as_utc(row.get("expiresAt")) is None:
            raise ReplicationConflict("MISSING_EXPIRATION")
        usage = store["users"].get(user_id, {})
        try:
            origins = export_origins(usage, str(config.node.id))
        except QuotaEvidenceRejected as error:
            raise ReplicationConflict(str(error)) from None
        portable = {key: value for key, value in row.items()
                    if key not in {"serializationIssues", "directConfirmed"}}
        portable.update(upload=sum(v["upload"] for v in origins.values()),
            download=sum(v["download"] for v in origins.values()), trafficOrigins=origins,
            trafficEpoch=epoch(usage),
            trafficCycleStart=usage.get("lastTrafficCycleStart"),
            manualTrafficResetAt=int(usage.get("lastManualTrafficResetAt") or 0))
        try:
            users.append(PortableUser(**portable).model_dump(mode="json"))
        except ValueError:
            raise ReplicationConflict("INVALID_PORTABLE_USER") from None
    result = {"version": 1, "users": users}
    if shared_config:
        result["sharedConfig"] = snapshot["sharedConfig"]
    return result


def _remove(data, registry, user_id):
    names = manager._user_auth_names(registry, user_id)
    for inbound in data.get("inbounds", []):
        if inbound.get("tag") not in _tags().values() or "users" not in inbound:
            continue
        inbound["users"] = [entry for entry in inbound.get("users", [])
                            if entry.get("name") not in names and entry.get("username") not in names]
    tag = manager.USER_OUTBOUND_PREFIX + user_id
    data["outbounds"] = [entry for entry in data.get("outbounds", []) if entry.get("tag") != tag]
    rules = data.setdefault("route", {}).setdefault("rules", [])
    manager._remove_managed_enforcement_rules(rules, manager._registry_user(registry, user_id))
    manager._remove_access_rule(data, manager._registry_user(registry, user_id))
    manager._remove_expiration_rule(data, manager._registry_user(registry, user_id))
    rules[:] = [rule for rule in rules if rule.get("outbound") != tag]
    registry.setdefault("users", {}).pop(user_id, None)


def apply_users(request: ReplicationRequest):
    now = datetime.now(timezone.utc)
    # Expired accounts are never recreated, even from an old disaster-recovery snapshot.
    desired = {user.userId: user for user in request.users if manager._as_utc(user.expiresAt) > now}
    retired = {user.userId: user for user in [*request.users, *request.retired] if user.userId not in desired}
    digest = hashlib.sha256(json.dumps(request.model_dump(mode="json"), sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    with traffic.collection_lock:
        store = traffic.get_traffic_store_snapshot()
        original_store = copy.deepcopy(store)
        store_existed = traffic.TRAFFIC_PATH.exists()
        removed = set()

        def apply(data, registry):
            previous = registry.get("replicationVersions", {}).get(request.groupKey, {})
            if request.generation is None and previous:
                raise manager.SingboxConfigError("versioned group cannot accept unversioned replication")
            if request.generation is not None:
                if request.generation < previous.get("generation", 0):
                    raise manager.SingboxConfigError("stale replication generation refused")
                if request.generation == previous.get("generation") and digest != previous.get("digest"):
                    raise manager.SingboxConfigError("replication generation content conflict")
            enforcement_rules = []
            existing_ids = manager._discover_user_ids(data, registry)
            if set(retired) & existing_ids or any(old in existing_ids and new in retired
                                                  for old, new in request.aliases.items()):
                raise ReplicationConflict("RETIREMENT_REVIEW_REQUIRED")
            if any(manager._registry_user(registry, user_id).get("replicationOwner") == request.groupKey
                   and user_id not in desired and request.aliases.get(user_id) not in desired
                   for user_id in existing_ids):
                raise ReplicationConflict("OMITTED_MANAGED_USER_REVIEW_REQUIRED")
            previous_metadata = {user_id: dict(manager._registry_user(registry, user_id)) for user_id in existing_ids}
            for user_id in existing_ids:
                owned = previous_metadata[user_id].get("replicationOwner") == request.groupKey
                if owned and any(manager._is_user_proxy_outbound_tag(str(item.get("tag") or ""), user_id)
                                 and item.get("tag") != manager.USER_OUTBOUND_PREFIX + user_id
                                 for item in data.get("outbounds", [])):
                    raise manager.SingboxConfigError("target has unsupported multi-proxy configuration")
            for old_id, new_id in request.aliases.items():
                if old_id == new_id or old_id not in existing_ids:
                    continue
                user = desired.get(new_id) or retired.get(new_id)
                if not user:
                    continue
                owner = manager._registry_user(registry, old_id).get("replicationOwner")
                if not user or (owner and owner != request.groupKey) or _auth(data, registry, old_id) != [entry.model_dump() for entry in user.auth]:
                    raise manager.SingboxConfigError("target alias credential conflict; replication refused")
                _remove(data, registry, old_id)
                if old_id in store["users"] and new_id not in store["users"]:
                    store["users"][new_id] = dict(store["users"][old_id])
                    previous_metadata[new_id] = previous_metadata.get(old_id, {})
                removed.add(old_id)
                existing_ids.remove(old_id)
            for user_id, user in retired.items():
                if user_id not in existing_ids:
                    continue
                owner = manager._registry_user(registry, user_id).get("replicationOwner")
                if owner != request.groupKey and (owner or _auth(data, registry, user_id) != [entry.model_dump() for entry in user.auth]):
                    raise manager.SingboxConfigError("retired user credential conflict; replication refused")
                _remove(data, registry, user_id)
                removed.add(user_id)
                existing_ids.remove(user_id)
            for user_id, user in desired.items():
                metadata = manager._registry_user(registry, user_id)
                archived_owner = registry.get("expiredUsers", {}).get(user_id, {}).get("replicationOwner")
                if archived_owner and archived_owner != request.groupKey:
                    raise manager.SingboxConfigError("archived user belongs to another replication group")
                if user_id in existing_ids and metadata.get("replicationOwner") != request.groupKey:
                    # A former source may be adopted only when its credentials are identical.
                    current = _auth(data, registry, user_id)
                    wanted = [entry.model_dump() for entry in user.auth]
                    if metadata.get("replicationOwner") or current != wanted:
                        raise manager.SingboxConfigError("target user conflict; replication refused")
            owned_ids = {user_id for user_id in existing_ids
                         if manager._registry_user(registry, user_id).get("replicationOwner") == request.groupKey}
            for user_id in owned_ids | (existing_ids & set(desired)):
                _remove(data, registry, user_id)
                if user_id not in desired:
                    removed.add(user_id)
            if request.sharedConfig is not None:
                apply_template(data, registry, request.sharedConfig, request.groupKey, desired, retired)
            for user_id, user in desired.items():
                metadata = {"replicationOwner": request.groupKey, "createdAt": manager._iso(manager._as_utc(user.createdAt)),
                            "expiresAt": manager._iso(manager._as_utc(user.expiresAt)),
                            "trafficLimitBytes": user.trafficLimitBytes, "maxSourceIps": user.maxSourceIps,
                            "maxConnections": user.maxConnections,
                            "accessEnabled": (user.accessEnabled if user.accessEnabled is not None
                                              else previous_metadata.get(user_id, {}).get("accessEnabled", True) is not False),
                            "remark": user.remark, "tags": user.tags}
                registry.setdefault("users", {})[user_id] = metadata
                registry.setdefault("expiredUsers", {}).pop(user_id, None)
                for auth in user.auth:
                    inbound = manager._find_inbound(data, _tags()[auth.protocol])
                    if auth.protocol == "socks":
                        if manager._auth_identifier_exists(data, auth.username):
                            raise manager.SingboxConfigError("target SOCKS username conflict; replication refused")
                        metadata["socksUsername"] = auth.username
                        inbound["users"].append({"username": auth.username, "password": auth.credential})
                    else:
                        credential_key = "password" if auth.protocol == "trojan" else "uuid"
                        if any(entry.get(credential_key) == auth.credential for entry in inbound["users"]):
                            raise manager.SingboxConfigError("target protocol credential conflict; replication refused")
                        entry = {"name": manager._auth_name(user_id), credential_key: auth.credential}
                        if auth.protocol == "vless" and auth.flow:
                            entry["flow"] = auth.flow
                        inbound["users"].append(entry)
                if user.proxy:
                    proxy = user.proxy.model_dump()
                    manager._save_proxy_metadata(registry, user_id, proxy)
                    manager._set_proxy_binding(data, registry, user_id, proxy)
                else:
                    manager._set_direct_binding(data, registry, user_id)
                usage = store["users"].setdefault(user_id, {})
                if user.trafficOrigins is None and (user.upload or user.download):
                    raise ReplicationConflict("TRAFFIC_ORIGIN_REQUIRED")
                try:
                    if user.trafficOrigins is not None:
                        origins = validate_origins(user.trafficOrigins)
                        if user.upload + user.download != sum(v["upload"] + v["download"] for v in origins.values()):
                            raise QuotaEvidenceRejected("TRAFFIC_ORIGIN_TOTAL_MISMATCH")
                    if user.trafficEpoch is not None and (
                            user.trafficEpoch.get("cycleStart") != user.trafficCycleStart
                            or (user.trafficEpoch.get("manualResetAt") or 0) != user.manualTrafficResetAt):
                        raise QuotaEvidenceRejected("TRAFFIC_EPOCH_MISMATCH")
                    import_origins(usage, user.trafficOrigins or {}, str(config.node.id),
                                   user.trafficCycleStart, user.manualTrafficResetAt, user.trafficEpoch)
                except QuotaEvidenceRejected as error:
                    raise ReplicationConflict(str(error)) from None
                usage["replicationCycle"] = metadata["expiresAt"]
                limited = bool(user.trafficLimitBytes and usage["upload"] + usage["download"]
                               + peer_used_bytes(usage, user.trafficLimitBytes) >= user.trafficLimitBytes)
                auth_names = sorted(manager._user_auth_names(registry, user_id))
                if metadata["accessEnabled"] is False:
                    metadata[manager.ACCESS_AUTH_USERS_KEY] = auth_names
                    metadata[manager.ACCESS_BLOCKED_KEY] = True
                    enforcement_rules.append({"auth_user": auth_names, "action": "reject"})
                if limited:
                    metadata[manager.ENFORCEMENT_TRAFFIC_KEY] = True
                    metadata[manager.ENFORCEMENT_AUTH_USERS_KEY] = auth_names
                    enforcement_rules.append({"auth_user": auth_names, "action": "reject"})
            data.setdefault("route", {}).setdefault("rules", [])[0:0] = enforcement_rules
            for user_id in removed:
                store["users"].pop(user_id, None)
            if request.generation is not None:
                registry.setdefault("replicationVersions", {})[request.groupKey] = {
                    "generation": request.generation, "digest": digest}
            # Persist counters before enabling credentials. Failed config reloads
            # restore the prior counters while collection remains locked.
            if store != original_store:
                from singbox.runtime_client import enabled as runtime_enabled
                if runtime_enabled():
                    import runtime_publication
                    runtime_publication.stage_related(traffic.TRAFFIC_PATH, store)
                else:
                    with traffic.traffic_lock:
                        traffic._write_store(store)
            return len(desired)

        try:
            import runtime_publication
            with runtime_publication.related_transaction(), manager.without_restart():
                count = manager.mutate_config(apply)
        except runtime_publication.RuntimeRecoveryRequired:
            # The durable journal owns both config and counters until reconciliation.
            raise
        except Exception:
            with traffic.traffic_lock:
                if store_existed:
                    traffic._write_store(original_store)
                else:
                    traffic.TRAFFIC_PATH.unlink(missing_ok=True)
            raise
        return {"success": True, "userCount": count, "removedCount": len(removed)}
