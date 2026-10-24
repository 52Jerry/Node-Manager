"""Read-only, redacted proof that an existing residential owner can be adopted."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from auth import verify_token
from config import config
from singbox import manager
import wireguard

router = APIRouter()


class AdoptionCheck(BaseModel):
    subscriptionId: int = Field(gt=0)
    resourceId: int = Field(gt=0)
    accessProfileId: int = Field(gt=0)
    nodeUserId: str = Field(pattern=r"^res-[0-9a-f]{32}$")
    previousNodeUserId: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    uuidSha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proxySha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expiresAt: datetime


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _owner_present(data: dict, registry: dict, discovered: set, user_id: str) -> bool:
    return (user_id in discovered or manager._user_exists(data, registry, user_id)
            or any(manager._is_user_proxy_outbound_tag(str(o.get("tag") or ""), user_id)
                   for o in data.get("outbounds", [])))


def evaluate(request: AdoptionCheck, data: dict, registry: dict, runtime: dict) -> dict:
    target = request.nodeUserId
    users = registry.get("users", {})
    user = manager._registry_user(registry, target)
    names = manager._user_auth_names(registry, target)
    discovered = manager._discover_user_ids(data, registry)
    target_tag = manager.USER_OUTBOUND_PREFIX + target
    outbounds = [o for o in data.get("outbounds", [])
                 if manager._is_user_proxy_outbound_tag(str(o.get("tag") or ""), target)]
    outbound = outbounds[0] if len(outbounds) == 1 else {}
    identity = [str(outbound.get("server") or ""), outbound.get("server_port"),
                outbound.get("username"), outbound.get("password")]
    proxy_complete = (len(outbounds) == 1 and outbound.get("tag") == target_tag
                      and outbound.get("type") == "socks"
                      and all(isinstance(outbound.get(k), str) and outbound[k].strip()
                              for k in ("server", "username", "password"))
                      and isinstance(outbound.get("server_port"), int)
                      and not isinstance(outbound.get("server_port"), bool)
                      and 1 <= outbound["server_port"] <= 65535)
    proxy_unique = False
    if proxy_complete:
        canonical = manager._proxy_identity(*identity)
        proxy_unique = True
        for other in data.get("outbounds", []):
            if other is outbound or other.get("type") not in {"socks", "socks5"}:
                continue
            try:
                if canonical == manager._proxy_identity(str(other.get("server") or ""),
                        other.get("server_port"), other.get("username"), other.get("password")):
                    proxy_unique = False
            except (TypeError, ValueError):
                continue

    managed = {config.singbox.vless_tag: "vless", config.singbox.vmess_tag: "vmess",
               config.singbox.socks_tag: "socks", config.singbox.trojan_tag: "trojan"}
    uuid_values = set()
    auth_shared = False
    owned_auth_names = set()
    seen_tags = set()
    for inbound in data.get("inbounds", []):
        tag = inbound.get("tag")
        owned_count = 0
        for auth in inbound.get("users", []):
            ours = auth.get("name") in names or auth.get("username") in names
            credential = str(auth.get("uuid") or "").lower()
            if ours:
                owned_count += 1
                owned_auth_names.update(v for v in (auth.get("name"), auth.get("username")) if v in names)
                if tag not in managed or inbound.get("type") != managed.get(tag):
                    auth_shared = True
                if inbound.get("type") in {"vless", "vmess"}:
                    if credential:
                        uuid_values.add(credential)
                    else:
                        auth_shared = True
                elif credential:
                    auth_shared = True
                if inbound.get("type") == "trojan" and _sha(str(auth.get("password") or "").lower()) != request.uuidSha256:
                    auth_shared = True
                if inbound.get("type") == "socks" and not str(auth.get("password") or ""):
                    auth_shared = True
            elif ((credential and _sha(credential) == request.uuidSha256)
                  or (inbound.get("type") == "trojan"
                      and _sha(str(auth.get("password") or "").lower()) == request.uuidSha256)):
                auth_shared = True
        if owned_count:
            if owned_count != 1 or tag in seen_tags:
                auth_shared = True
            seen_tags.add(tag)
    if any(other != target and names.intersection(manager._user_auth_names(registry, other))
           for other in discovered):
        auth_shared = True

    rules = data.get("route", {}).get("rules", [])
    owned_rules = [r for r in rules if r.get("outbound") == target_tag]
    routes_owned = bool(owned_rules) and all(
        isinstance(r.get("auth_user"), list) and bool(r["auth_user"])
        and set(r["auth_user"]).issubset(names) and not r.get("rules") for r in owned_rules)
    routed_names = {n for r in owned_rules for n in r.get("auth_user", [])}
    routes_owned = routes_owned and owned_auth_names.issubset(routed_names)
    for rule in rules:
        if set(rule.get("auth_user") or []).intersection(names) and rule.get("outbound") != target_tag:
            routes_owned = False
        if rule.get("rules"):
            # Generated owner routes are flat; ambiguous nested ownership is refused.
            rendered = json.dumps(rule, separators=(",", ":"))
            if target_tag in rendered or any(name in rendered for name in names):
                routes_owned = False
    if data.get("route", {}).get("final") == target_tag or any(
            target_tag in o.get("outbounds", []) or o.get("detour") == target_tag
            for o in data.get("outbounds", [])):
        routes_owned = False

    now = datetime.now(timezone.utc)
    expected_expiry = manager._as_utc(request.expiresAt)
    user_expiry = manager._as_utc(user.get("expiresAt"))
    eligible = False
    try:
        wireguard._binding_from_snapshot(target, expected_expiry, registry,
                                         wireguard._outbounds_by_tag(data), now)
        eligible = not user.get("accessBlocked")
    except (wireguard.WireguardError, ValueError, TypeError, KeyError, manager.SingboxConfigError):
        pass
    checks = {
        "targetPresent": target in discovered and bool(user),
        "previousOwnerAbsentOrTarget": request.previousNodeUserId == target or not _owner_present(
            data, registry, discovered, request.previousNodeUserId),
        "canonicalTargetAbsent": not _owner_present(data, registry, discovered, "primary-" + str(request.accessProfileId)),
        "scopeMatches": all(user.get(k) in (None, "") or str(user[k]) == str(v) for k, v in (
            ("resourceId", request.resourceId), ("userIpResourceId", request.resourceId),
            ("subscriptionId", request.subscriptionId), ("accessProfileId", request.accessProfileId))),
        "proxyComplete": bool(proxy_complete),
        "proxyUnique": proxy_unique,
        "proxyMatches": bool(proxy_complete) and _sha(json.dumps(
            identity, ensure_ascii=False, separators=(",", ":"))) == request.proxySha256,
        "uuidMatches": len(uuid_values) == 1 and _sha(next(iter(uuid_values))) == request.uuidSha256,
        "authenticationUnique": not auth_shared,
        "routesOwned": routes_owned,
        "entitlementCurrent": expected_expiry is not None and expected_expiry > now
            and user_expiry is not None and user_expiry >= expected_expiry,
        "targetEligible": eligible,
        "runtimeReady": runtime.get("success") is True and runtime.get("routingReady") is True
            and runtime.get("runtimeReason") is None and runtime.get("recoveryReason") is None
            and bool(runtime.get("serverPublicKey")),
    }
    return {"ready": all(checks.values()), "checks": checks,
            "subscriptionId": request.subscriptionId, "resourceId": request.resourceId,
            "accessProfileId": request.accessProfileId, "nodeUserId": target,
            "previousNodeUserId": request.previousNodeUserId,
            "serverPublicKey": runtime.get("serverPublicKey")}


@router.post("/api/wireguard/owner-adoption/check", tags=["wireguard"])
def check_owner_adoption(request: AdoptionCheck, response: Response, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    try:
        with manager._config_lock():
            data, registry = manager.read_config(), manager.read_registry()
        runtime = wireguard.status()
        result = evaluate(request, data, registry, runtime)
        with manager._config_lock():
            unchanged = data == manager.read_config() and registry == manager.read_registry()
        result["checks"]["snapshotUnchanged"] = unchanged
        result["ready"] = result["ready"] and unchanged
        return result
    except (OSError, ValueError, TypeError, KeyError, manager.SingboxConfigError, wireguard.WireguardError):
        raise HTTPException(status_code=503, detail="owner adoption proof unavailable") from None
