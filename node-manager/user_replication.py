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
from singbox import manager
from ha_template import export_template, apply_template


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
        users = []
        for user_id in sorted(manager._discover_user_ids(data, registry)):
            metadata = manager._registry_user(registry, user_id)
            if manager._as_utc(metadata.get("expiresAt")) is None:
                raise manager.SingboxConfigError("missing expiration; repair historical data before replication")
            outbound = next((item for item in data.get("outbounds", [])
                             if item.get("tag") == manager.USER_OUTBOUND_PREFIX + user_id), None)
            if any(manager._is_user_proxy_outbound_tag(str(item.get("tag") or ""), user_id)
                   and item.get("tag") != manager.USER_OUTBOUND_PREFIX + user_id
                   for item in data.get("outbounds", [])):
                raise manager.SingboxConfigError("multi-proxy users require a separate migration; replication refused")
            proxy = None
            portable_outbound_fields = {"type", "tag", "server", "server_port", "username", "password"}
            if outbound and (set(outbound) - portable_outbound_fields
                             or (outbound.get("type") == "direct" and set(outbound) - {"type", "tag"})):
                raise manager.SingboxConfigError("custom outbound options require a separate migration; replication refused")
            if outbound and outbound.get("type") in {"socks", "socks5"}:
                proxy = {"server": outbound["server"], "port": outbound["server_port"],
                         "username": outbound.get("username"), "password": outbound.get("password")}
                proxy.update({key: metadata.get(key) for key in
                              ("sourceIp", "countryCode", "countryName", "provinceName", "cityName")})
            elif outbound and outbound.get("type") != "direct":
                raise manager.SingboxConfigError("unsupported outbound; replication refused")
            usage = store["users"].get(user_id, {})
            users.append(PortableUser(
                userId=user_id, auth=_auth(data, registry, user_id), proxy=proxy,
                createdAt=metadata.get("createdAt"), expiresAt=metadata["expiresAt"],
                trafficLimitBytes=metadata.get("trafficLimitBytes"), maxSourceIps=metadata.get("maxSourceIps"),
                maxConnections=metadata.get("maxConnections"),
                upload=int(usage.get("upload") or 0), download=int(usage.get("download") or 0),
                remark=metadata.get("remark"), tags=metadata.get("tags") or [],
            ).model_dump(mode="json"))
        if len(users) > 10000:
            raise manager.SingboxConfigError("replication supports at most 10000 users per group")
        snapshot = {"version": 1, "users": users}
        if shared_config:
            snapshot["sharedConfig"] = export_template(data)
        return snapshot


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
                cycle = metadata["expiresAt"]
                previous_cycle = previous_metadata.get(user_id, {}).get("expiresAt")
                same_cycle = usage.get("replicationCycle") == cycle or previous_cycle == cycle
                usage["upload"] = max(int(usage.get("upload") or 0), user.upload) if same_cycle else user.upload
                usage["download"] = max(int(usage.get("download") or 0), user.download) if same_cycle else user.download
                usage["replicationCycle"] = cycle
                limited = bool(user.trafficLimitBytes and usage["upload"] + usage["download"] >= user.trafficLimitBytes)
                auth_names = sorted({auth.username if auth.protocol == "socks" else manager._auth_name(user_id)
                                     for auth in user.auth})
                if limited:
                    metadata[manager.ENFORCEMENT_TRAFFIC_KEY] = True
                    metadata[manager.ENFORCEMENT_AUTH_USERS_KEY] = auth_names
                    enforcement_rules.append({"auth_user": auth_names, "action": "reject"})
                else:
                    blocked = previous_metadata.get(user_id, {}).get(manager.ENFORCEMENT_SOURCE_CIDRS_KEY)
                    if blocked and same_cycle:
                        metadata[manager.ENFORCEMENT_SOURCE_CIDRS_KEY] = blocked
                        metadata[manager.ENFORCEMENT_AUTH_USERS_KEY] = auth_names
                        enforcement_rules.append({"auth_user": auth_names, "source_ip_cidr": blocked, "action": "reject"})
            data.setdefault("route", {}).setdefault("rules", [])[0:0] = enforcement_rules
            for user_id in removed:
                store["users"].pop(user_id, None)
            if request.generation is not None:
                registry.setdefault("replicationVersions", {})[request.groupKey] = {
                    "generation": request.generation, "digest": digest}
            # Persist counters before enabling credentials. Failed config reloads
            # restore the prior counters while collection remains locked.
            if store != original_store:
                with traffic.traffic_lock:
                    traffic._write_store(store)
            return len(desired)

        try:
            count = manager.mutate_config(apply)
        except Exception:
            with traffic.traffic_lock:
                if store_existed:
                    traffic._write_store(original_store)
                else:
                    traffic.TRAFFIC_PATH.unlink(missing_ok=True)
            raise
        return {"success": True, "userCount": count, "removedCount": len(removed)}
