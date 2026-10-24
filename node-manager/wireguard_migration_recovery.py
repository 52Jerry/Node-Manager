"""Read-only, credential-redacted proof for completing historical WG migration."""
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


class RecoveryCheck(BaseModel):
    subscriptionId: int = Field(gt=0)
    resourceId: int = Field(gt=0)
    accessProfileId: int = Field(gt=0)
    peerId: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    uuidSha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proxySha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expiresAt: datetime


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def evaluate(request: RecoveryCheck, data: dict, registry: dict, runtime: dict) -> dict:
    target = "primary-" + str(request.accessProfileId)
    users = registry.get("users", {})
    user = users.get(target) or {}
    proof = user.get("residentialOwnershipMigration") or {}
    proof = proof if isinstance(proof, dict) else {}
    source = proof.get("sourceUserId")
    names = manager._user_auth_names(registry, target)
    discovered = manager._discover_user_ids(data, registry)
    outbounds = [o for o in data.get("outbounds", [])
                 if manager._is_user_proxy_outbound_tag(str(o.get("tag") or ""), target)]
    outbound = outbounds[0] if len(outbounds) == 1 else {}
    identity = [str(outbound.get("server") or ""), outbound.get("server_port"),
                outbound.get("username"), outbound.get("password")]
    uuid_values = set()
    auth_shared = False
    managed_tags = {config.singbox.vless_tag, config.singbox.vmess_tag,
                    config.singbox.socks_tag, config.singbox.trojan_tag}
    for inbound in data.get("inbounds", []):
        for auth in inbound.get("users", []):
            ours = auth.get("name") in names or auth.get("username") in names
            credential = str(auth.get("uuid") or "").lower()
            if ours:
                if inbound.get("tag") not in managed_tags:
                    auth_shared = True
                if credential:
                    uuid_values.add(credential)
                if inbound.get("tag") == config.singbox.trojan_tag and _sha(str(auth.get("password") or "").lower()) != request.uuidSha256:
                    auth_shared = True
            elif credential and _sha(credential) == request.uuidSha256:
                auth_shared = True
            elif inbound.get("type") == "trojan" and _sha(str(auth.get("password") or "").lower()) == request.uuidSha256:
                auth_shared = True
    if any(other != target and names.intersection(manager._user_auth_names(registry, other))
           for other in users):
        auth_shared = True
    target_tag = manager.USER_OUTBOUND_PREFIX + target
    owned_rules = [r for r in data.get("route", {}).get("rules", []) if r.get("outbound") == target_tag]
    routes_owned = bool(owned_rules) and all(r.get("auth_user") and set(r["auth_user"]).issubset(names)
                                           for r in owned_rules)
    routes_owned = routes_owned and not any(target_tag in o.get("outbounds", [])
                                            for o in data.get("outbounds", []))
    selected = [p for p in runtime.get("peers", []) if p.get("peerId") == request.peerId]
    old = selected[0] if len(selected) == 1 else {}
    now = datetime.now(timezone.utc)
    expected_expiry = manager._as_utc(request.expiresAt)
    user_expiry = manager._as_utc(user.get("expiresAt"))
    proof_fingerprints = set()
    proxy_unique = False
    try:
        canonical_identity = manager._proxy_identity(str(outbound.get("server") or ""),
                outbound.get("server_port"), outbound.get("username"), outbound.get("password"))
        if len(uuid_values) == 1:
            proof_expiries = [user_expiry]
            # Expiry sync may shorten the current entitlement after migration.
            # The same source peer retains the exact original migration expiry.
            # Historical proof does not change the current entitlement checks.
            if old and isinstance(source, str) and source and old.get("nodeUserId") == source:
                proof_expiries.append(manager._as_utc(old.get("expiresAt")))
            for proof_expiry in proof_expiries:
                if proof_expiry is not None:
                    proof_fingerprints.add(_sha(json.dumps(
                        [canonical_identity, next(iter(uuid_values)), manager._iso(proof_expiry)],
                        separators=(",", ":"), ensure_ascii=True)))
        manager._assert_proxy_available(data, target, {"server": outbound.get("server"),
                "port": outbound.get("server_port"), "username": outbound.get("username"),
                "password": outbound.get("password")})
        proxy_unique = True
    except (ValueError, TypeError, KeyError, manager.SingboxConfigError):
        pass
    eligible = False
    try:
        wireguard._binding_from_snapshot(target, expected_expiry, registry,
                                         wireguard._outbounds_by_tag(data), now)
        eligible = True
    except (wireguard.WireguardError, ValueError, TypeError, KeyError, manager.SingboxConfigError):
        pass
    checks = {
        "targetPresent": target in discovered and bool(user),
        "sourceAbsent": isinstance(source, str) and bool(source) and source != target and source not in discovered,
        "proofMatches": all(str(proof.get(k)) == str(v) for k, v in (
            ("resourceId", request.resourceId), ("subscriptionId", request.subscriptionId),
            ("accessProfileId", request.accessProfileId))) and bool(proof.get("fingerprint")),
        "proofFingerprintMatches": isinstance(proof.get("fingerprint"), str)
            and proof["fingerprint"] in proof_fingerprints,
        "proxyUnique": proxy_unique,
        "proxyMatches": len(outbounds) == 1 and outbound.get("tag") == target_tag
            and outbound.get("type") in {"socks", "socks5"}
            and _sha(json.dumps(identity, ensure_ascii=False, separators=(",", ":"))) == request.proxySha256,
        "uuidMatches": len(uuid_values) == 1 and _sha(next(iter(uuid_values))) == request.uuidSha256,
        "authenticationUnique": not auth_shared,
        "routesOwned": routes_owned,
        "entitlementCurrent": expected_expiry is not None and expected_expiry > now
            and user_expiry is not None and user_expiry >= expected_expiry,
        "targetEligible": eligible,
        "oldPeerMatchesSource": bool(old) and old.get("nodeUserId") == source,
        "oldPeerRecoverable": (old.get("status") == "BLOCKED" and old.get("stateReason") == "NODE_USER_MISSING")
            or old.get("status") == "REVOKED",
        "runtimeReady": runtime.get("success") is True and runtime.get("routingReady") is True
            and runtime.get("runtimeReason") is None and runtime.get("recoveryReason") is None,
        "oldIdentityUnique": bool(old) and not any(p.get("peerId") != request.peerId and (
            p.get("publicKey") == old.get("publicKey") or p.get("address") == old.get("address"))
            for p in runtime.get("peers", [])),
    }
    return {"ready": all(checks.values()), "checks": checks, "sourceUserId": source,
            "targetUserId": target, "resourceId": request.resourceId,
            "subscriptionId": request.subscriptionId, "accessProfileId": request.accessProfileId,
            "serverPublicKey": runtime.get("serverPublicKey"),
            "oldPeer": {k: old.get(k) for k in ("peerId", "publicKey", "address", "nodeUserId",
                         "status", "stateReason", "kernelPresent", "allowedIps", "expiresAt")}}


@router.post("/api/wireguard/migration-recovery/check", tags=["wireguard"])
def check_migration(request: RecoveryCheck, response: Response, _token: str = Depends(verify_token)):
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
        raise HTTPException(status_code=503, detail="migration recovery proof unavailable") from None
