"""Coherent local read-only capture, including users legacy export cannot encode."""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from monitor import traffic
from singbox import manager
from ha_template import export_template
from user_replication import _auth, _tags
from replication_safety import ReplicationSafety, PERMISSION_READ, SafetyError


def capture_local(safety: ReplicationSafety, *, group_key, permissions=frozenset()):
    safety._permit(permissions, PERMISSION_READ)
    # Same lock order as replication and traffic collection. No counters sampled.
    with traffic.collection_lock:
        with manager._config_lock():
            data, registry = manager.read_config(), manager.read_registry()
            store = traffic.get_traffic_store_snapshot()
            if len(registry.get("users", {})) > safety.policy.max_users:
                raise SafetyError("INPUT_TOO_LARGE")
            user_ids = manager._discover_user_ids(data, registry) | set(registry.get("users", {}))
            if len(user_ids) > safety.policy.max_users:
                raise SafetyError("INPUT_TOO_LARGE")
            users, errors = [], []
            for user_id in sorted(user_ids):
                metadata = manager._registry_user(registry, user_id)
                issues = []
                try:
                    auth = _auth(data, registry, user_id)
                except manager.SingboxConfigError:
                    auth = []
                    issues.append("AMBIGUOUS_AUTH")
                outbounds = [item for item in data.get("outbounds", [])
                             if manager._is_user_proxy_outbound_tag(str(item.get("tag") or ""), user_id)]
                proxy = None
                if len(outbounds) > 1:
                    issues.append("MULTI_PROXY")
                for index, outbound in enumerate(outbounds):
                    if outbound.get("tag") != manager.USER_OUTBOUND_PREFIX + user_id:
                        issues.append("MULTI_PROXY")
                    if outbound.get("type") in ("socks", "socks5"):
                        if index == 0:
                            proxy = {"server": outbound.get("server"), "port": outbound.get("server_port"),
                                     "username": outbound.get("username"), "password": outbound.get("password")}
                        supported = {"type", "tag", "server", "server_port", "username", "password"}
                    elif outbound.get("type") == "direct":
                        supported = {"type", "tag"}
                    else:
                        supported = set()
                        issues.append("UNSUPPORTED_OUTBOUND")
                    if set(outbound) - supported:
                        issues.append("CUSTOM_OUTBOUND")
                if not outbounds:
                    issues.append("MISSING_BINDING")
                usage = store.get("users", {}).get(user_id, {})
                user = {"userId": user_id, "auth": auth, "proxy": proxy,
                        "createdAt": metadata.get("createdAt"), "expiresAt": metadata.get("expiresAt"),
                        "serializationIssues": sorted(set(issues))}
                user.update({key: copy.deepcopy(metadata.get(key)) for key in
                             ("trafficLimitBytes", "maxSourceIps", "maxConnections", "remark", "tags")})
                user.update({key: usage.get(key, 0) for key in ("upload", "download")})
                users.append(user)
            known_names = set()
            for user_id in user_ids:
                known_names.update(manager._user_auth_names(registry, user_id))
            protocol_counts = {}
            orphan_count = 0
            managed_tags = _tags()
            for inbound in data.get("inbounds", []):
                if inbound.get("users") and inbound.get("tag") not in managed_tags.values():
                    errors.append("UNSUPPORTED_PROTOCOL_AUTH")
                if any(inbound.get("tag") == tag and inbound.get("type") != protocol
                       for protocol, tag in managed_tags.items()):
                    errors.append("PROTOCOL_TAG_TYPE_CONFLICT")
            for protocol, tag in _tags().items():
                entries = [entry for inbound in data.get("inbounds", []) if inbound.get("tag") == tag
                           for entry in inbound.get("users", [])]
                protocol_counts[protocol] = len(entries)
                orphan_count += sum(entry.get("name", entry.get("username")) not in known_names for entry in entries)
            if orphan_count:
                errors.append("UNREGISTERED_PROTOCOL_AUTH")
            try:
                shared = export_template(data)
            except manager.SingboxConfigError:
                shared = None
                errors.append("UNSUPPORTED_SHARED_CONFIG")
            version = registry.get("replicationVersions", {}).get(group_key, {})
            return {"version": 2, "users": users, "sharedConfig": shared,
                    "generation": version.get("generation"), "errors": sorted(set(errors)),
                    "capture": {"capturedAt": datetime.now(timezone.utc).isoformat(),
                                "schema": "local-config-registry-traffic.v1",
                                "sourceVersion": "replication-reconciliation.v1",
                                "registrySchema": registry.get("version"),
                                "protocolCounts": protocol_counts,
                                "registryCount": len(registry.get("users", {})),
                                "archivedCount": len(registry.get("expiredUsers", {})),
                                "unregisteredAuthCount": orphan_count,
                                "stateDigest": safety._seal({"config": data, "registry": registry}),
                                "trafficDigest": safety._seal(store),
                                "expirationCleanupEnabled": manager.EXPIRATION_ENABLED}}
