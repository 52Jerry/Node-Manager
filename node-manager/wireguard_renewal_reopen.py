"""Read-only proof for the single, create-only renewal reopen of subscription 2359."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from auth import verify_token
from singbox import manager
import wireguard
import wireguard_owner_adoption as adoption

router = APIRouter()
CHECK_NAMES = (
    "scopeExact", "previousOwnerAbsent", "canonicalStateConsistent", "registryScopeMatches",
    "proxyMatches", "proxyUnique", "uuidMatches", "authenticationUnique", "routesOwned",
    "entitlementCurrent", "targetEligible", "wireguardStateCompatible", "runtimeReady",
    "snapshotUnchanged",
)
PREVIOUS = "3hlW0nxdIqHa"
TARGET = "primary-2359"
PEER_ID = "sub-2359-node-6"


class ReopenCheck(BaseModel):
    subscriptionId: int = Field(gt=0)
    resourceId: int = Field(gt=0)
    accessProfileId: int = Field(gt=0)
    previousNodeUserId: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    targetUserId: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    uuidSha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proxySha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expiresAt: datetime


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _references(value, names: set[str], prefix: str) -> bool:
    if isinstance(value, dict):
        return any(_references(v, names, prefix) for v in value.values())
    if isinstance(value, list):
        return any(_references(v, names, prefix) for v in value)
    return isinstance(value, str) and (value in names or value == prefix)


def _owner_absence(data: dict, registry: dict, runtime: dict, owner: str) -> dict:
    names = manager._user_auth_names(registry, owner)
    return {
        "registry": owner not in registry.get("users", {}) and owner not in registry.get("expiredUsers", {}),
        "auth": not manager._user_exists(data, registry, owner),
        "outbound": not any(manager._is_user_proxy_outbound_tag(str(o.get("tag") or ""), owner)
                            for o in data.get("outbounds", []))
            and not _references(data.get("outbounds", []), names, manager.USER_OUTBOUND_PREFIX + owner),
        "routes": not _references(data.get("route", {}), names, manager.USER_OUTBOUND_PREFIX + owner),
        "wireguard": not any(p.get("nodeUserId") == owner for p in runtime.get("peers", [])),
    }


def _required_authentication_exact(data: dict, names: set[str], uuid_sha: str) -> bool:
    required = ((adoption.config.singbox.vless_tag, "vless"),
                (adoption.config.singbox.vmess_tag, "vmess"),
                (adoption.config.singbox.socks_tag, "socks"))
    for tag, protocol in required:
        inbounds = [i for i in data.get("inbounds", []) if i.get("tag") == tag]
        if len(inbounds) != 1 or inbounds[0].get("type") != protocol:
            return False
        owned = [a for a in inbounds[0].get("users", [])
                 if a.get("name") in names or a.get("username") in names]
        if len(owned) != 1:
            return False
        auth = owned[0]
        if protocol == "socks":
            if auth.get("username") != TARGET or _sha(str(auth.get("password") or "")) != uuid_sha:
                return False
        elif (auth.get("name") != manager._auth_name(TARGET)
              or _sha(str(auth.get("uuid") or "").lower()) != uuid_sha):
            return False
    return True


def evaluate(request: ReopenCheck, data: dict, registry: dict, runtime: dict) -> dict:
    scope_exact = (request.subscriptionId == 2359 and request.resourceId == 2363
                   and request.accessProfileId == 2359 and request.previousNodeUserId == PREVIOUS
                   and request.targetUserId == TARGET)
    old_absence = _owner_absence(data, registry, runtime, PREVIOUS)
    target_absence = _owner_absence(data, registry, runtime, TARGET)
    # A phase selects the candidate branch; ready and every check must also pass.
    phase = "ABSENT" if all(target_absence.values()) else "EXISTING_EXACT"
    checks = {name: False for name in CHECK_NAMES}
    checks.update(scopeExact=scope_exact, previousOwnerAbsent=all(old_absence.values()),
                  runtimeReady=runtime.get("success") is True and runtime.get("routingReady") is True
                    and runtime.get("runtimeReason") is None and runtime.get("recoveryReason") is None
                    and bool(runtime.get("serverPublicKey")), snapshotUnchanged=True)
    expected_expiry = manager._as_utc(request.expiresAt)
    current = expected_expiry is not None and expected_expiry > datetime.now(timezone.utc)
    exact_outbounds = []
    for outbound in data.get("outbounds", []):
        if outbound.get("type") not in {"socks", "socks5"}:
            continue
        identity = [str(outbound.get("server") or ""), outbound.get("server_port"),
                    outbound.get("username"), outbound.get("password")]
        identities = [identity]
        try:
            identities.append(manager._proxy_identity(*identity))
        except (ValueError, TypeError):
            pass
        if any(_sha(json.dumps(value, ensure_ascii=False, separators=(",", ":"))) == request.proxySha256
               for value in identities):
            exact_outbounds.append(outbound)
    uuid_unused = not any(
        (auth.get("uuid") and _sha(str(auth["uuid"]).lower()) == request.uuidSha256)
        or (inbound.get("type") == "trojan"
            and _sha(str(auth.get("password") or "").lower()) == request.uuidSha256)
        for inbound in data.get("inbounds", []) for auth in inbound.get("users", []))
    relevant_peers = [p for p in runtime.get("peers", [])
                      if p.get("nodeUserId") == TARGET or p.get("peerId") == PEER_ID]
    if phase == "ABSENT":
        names = manager._user_auth_names(registry, TARGET)
        aliases_unused = not any(names.intersection(manager._user_auth_names(registry, other))
                                 for other in manager._discover_user_ids(data, registry))
        checks.update(
            canonicalStateConsistent=all(target_absence.values()), registryScopeMatches=target_absence["registry"],
            proxyMatches=not exact_outbounds, proxyUnique=not exact_outbounds,
            uuidMatches=uuid_unused, authenticationUnique=uuid_unused and target_absence["auth"] and aliases_unused,
            routesOwned=target_absence["routes"], entitlementCurrent=current,
            targetEligible=all(target_absence.values()) and current,
            wireguardStateCompatible=not relevant_peers and old_absence["wireguard"])
    else:
        # Reuse the frozen proof's authentication, proxy and route logic in memory.
        # Its public res-* request model is intentionally not used for this canonical scope.
        existing_request = SimpleNamespace(
            subscriptionId=request.subscriptionId, resourceId=request.resourceId,
            accessProfileId=request.accessProfileId, nodeUserId=TARGET,
            previousNodeUserId=PREVIOUS, uuidSha256=request.uuidSha256,
            proxySha256=request.proxySha256, expiresAt=request.expiresAt)
        proof = adoption.evaluate(existing_request, data, registry, runtime)["checks"]
        names = manager._user_auth_names(registry, TARGET)
        required_auth_exact = _required_authentication_exact(data, names, request.uuidSha256)
        checks.update(
            canonicalStateConsistent=proof["targetPresent"] and proof["proxyComplete"] and required_auth_exact,
            registryScopeMatches=proof["scopeMatches"] and TARGET not in registry.get("expiredUsers", {}),
            proxyMatches=proof["proxyMatches"], proxyUnique=proof["proxyUnique"],
            uuidMatches=proof["uuidMatches"], authenticationUnique=proof["authenticationUnique"] and required_auth_exact,
            routesOwned=proof["routesOwned"], entitlementCurrent=proof["entitlementCurrent"],
            targetEligible=proof["targetEligible"],
            wireguardStateCompatible=old_absence["wireguard"]
                and all(p.get("nodeUserId") == TARGET for p in relevant_peers))
    return {"phase": phase, "ready": all(checks.values()), "checks": checks,
            "subscriptionId": request.subscriptionId, "resourceId": request.resourceId,
            "accessProfileId": request.accessProfileId, "previousNodeUserId": request.previousNodeUserId,
            "targetUserId": request.targetUserId, "serverPublicKey": runtime.get("serverPublicKey")}


@router.post("/api/wireguard/renewal-reopen/check", tags=["wireguard"])
def check_renewal_reopen(request: ReopenCheck, response: Response, _token: str = Depends(verify_token)):
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
        raise HTTPException(status_code=503, detail="renewal reopen proof unavailable") from None
