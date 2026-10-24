"""Linear-time, read-only replication inspection. Diagnostics never contain secrets."""
from __future__ import annotations

import hashlib
import json

from config import config
from singbox import manager
from ha_template import export_template


class ReplicationConflict(manager.SingboxConfigError):
    def __init__(self, code):
        self.public_code = code
        super().__init__(code)


def capture(data, registry, shared_config=False):
    ids = manager._discover_user_ids(data, registry)
    if len(ids) > 10000:
        raise ReplicationConflict("TOO_MANY_USERS")
    tags = {"vless": config.singbox.vless_tag, "vmess": config.singbox.vmess_tag,
            "trojan": config.singbox.trojan_tag, "socks": config.singbox.socks_tag}
    auth_index = {}
    errors = set()
    if len(set(tags.values())) != len(tags):
        errors.add("DUPLICATE_MANAGED_INBOUND")
    for protocol, tag in tags.items():
        inbounds = [item for item in data.get("inbounds", []) if item.get("tag") == tag]
        if len(inbounds) > 1:
            errors.add("DUPLICATE_MANAGED_INBOUND")
        index = {}
        for inbound in inbounds:
            for entry in inbound.get("users", []):
                for name in {entry.get("name"), entry.get("username")} - {None, ""}:
                    index.setdefault(name, []).append(entry)
        auth_index[protocol] = index
    outbounds = {}
    multiple = set()
    for outbound in data.get("outbounds", []):
        tag = str(outbound.get("tag") or "")
        outbounds.setdefault(tag, []).append(outbound)
        if not tag.startswith(manager.USER_OUTBOUND_PREFIX):
            continue
        tail = tag[len(manager.USER_OUTBOUND_PREFIX):]
        while "-" in tail:
            tail, suffix = tail.rsplit("-", 1)
            if not suffix.isdigit():
                break
            if tail in ids:
                multiple.add(tail)
    users = []
    for user_id in sorted(ids):
        metadata = manager._registry_user(registry, user_id)
        names = manager._user_auth_names(registry, user_id)
        issues = set()
        auth = []
        for protocol, index in auth_index.items():
            matches = {id(entry): entry for name in names for entry in index.get(name, [])}
            if len(matches) > 1:
                issues.add("AMBIGUOUS_AUTH")
                continue
            if matches:
                entry = next(iter(matches.values()))
                auth.append({"protocol": protocol,
                    "credential": entry.get("uuid") if protocol in {"vless", "vmess"} else entry.get("password"),
                    "username": entry.get("username") if protocol == "socks" else None,
                    "flow": entry.get("flow") if protocol == "vless" else None})
        if not auth or any(not item["credential"] for item in auth):
            issues.add("MISSING_AUTH")
        matches = outbounds.get(manager.USER_OUTBOUND_PREFIX + user_id, [])
        if len(matches) > 1:
            issues.add("AMBIGUOUS_PROXY")
        if user_id in multiple:
            issues.add("MULTI_PROXY_UNSUPPORTED")
        outbound = matches[0] if len(matches) == 1 else None
        proxy = None
        if outbound:
            allowed = {"type", "tag", "server", "server_port", "username", "password"}
            if set(outbound) - allowed or (outbound.get("type") == "direct" and set(outbound) - {"type", "tag"}):
                issues.add("CUSTOM_OUTBOUND_UNSUPPORTED")
            if outbound.get("type") in {"socks", "socks5"}:
                proxy = {"server": outbound.get("server"), "port": outbound.get("server_port"),
                    "username": outbound.get("username"), "password": outbound.get("password")}
                proxy.update({key: metadata.get(key) for key in
                    ("sourceIp", "countryCode", "countryName", "provinceName", "cityName")})
            elif outbound.get("type") != "direct":
                issues.add("UNSUPPORTED_OUTBOUND")
        else:
            issues.add("MISSING_OUTBOUND")
        row = {key: metadata.get(key) for key in ("createdAt", "expiresAt", "trafficLimitBytes",
            "maxSourceIps", "maxConnections", "remark")}
        row.update(userId=user_id, auth=auth, proxy=proxy, tags=metadata.get("tags") or [],
            directConfirmed=bool(outbound and outbound.get("type") == "direct"),
            accessEnabled=metadata.get("accessEnabled") is not False, serializationIssues=sorted(issues))
        users.append(row)
    result = {"version": 2, "users": users, "errors": sorted(errors)}
    if shared_config:
        try:
            result["sharedConfig"] = export_template(data)
        except manager.SingboxConfigError:
            result["errors"].append("UNSUPPORTED_SHARED_CONFIG")
    result["revision"] = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result


def inspect_users(shared_config=False):
    # No traffic collection, expiration processing, registry writes, or reload.
    with manager._config_lock():
        data, registry = manager.read_config(), manager.read_registry()
    return capture(data, registry, shared_config)
