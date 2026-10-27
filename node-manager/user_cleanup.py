"""Expired-user retirement: node-side SOCKS verification, DB backup acknowledgement,
and compare-and-remove under the same native configuration lock. No timers run here.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from auth import verify_token
from singbox import manager

router = APIRouter(prefix="/api/users/cleanup", tags=["user-cleanup"], dependencies=[Depends(verify_token)])
_proof_key = secrets.token_bytes(32)  # Restart invalidates outstanding removal proofs.
_targets = (("www.cloudflare.com", "/cdn-cgi/trace"), ("www.gstatic.com", "/generate_204"))
_snapshot_read_lock = threading.Lock()
_snapshot_read_cache = None
_peer_read_lock = threading.Lock()
_peer_read_cache = None


@router.get("/inventory")
def inventory(response: Response):
    # One native collection rather than repeating the full registry/traffic scan per 100-row page.
    # The normal public pagination limit remains unchanged.
    from main import get_users
    response.headers["Cache-Control"] = "no-store, private"
    return get_users(page=1, pageSize=100000, keyword=None, sort="userIdAsc", _token="internal-authorized")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProbeRequest(StrictModel):
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    archiveId: int = Field(gt=0)


class DetachItem(ProbeRequest):
    userId: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    proof: str = Field(min_length=1, max_length=2048)


class DetachRequest(StrictModel):
    items: list[DetachItem] = Field(min_length=1, max_length=200)


def _id(user_id):
    import re
    if not isinstance(user_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user_id):
        raise HTTPException(422, "invalid userId")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _configuration(data, registry, user_id, peers=None):
    _id(user_id)
    if not manager._user_exists(data, registry, user_id):
        raise HTTPException(409, "USER_ABSENT")
    metadata = copy.deepcopy(manager._registry_user(registry, user_id))
    expiry = manager._as_utc(metadata.get("expiresAt"))
    if expiry is None or datetime.now(timezone.utc) < expiry + timedelta(hours=24):
        raise HTTPException(409, "EXPIRY_NOT_ELIGIBLE")
    names = manager._user_auth_names(registry, user_id)
    for other_id in registry.get("users", {}):
        if other_id != user_id and names & manager._user_auth_names(registry, other_id):
            raise HTTPException(409, "SHARED_CREDENTIAL_REQUIRES_REVIEW")
    outbound_tag = manager.USER_OUTBOUND_PREFIX + user_id
    outbounds = [copy.deepcopy(item) for item in data.get("outbounds", [])
                 if manager._is_user_proxy_outbound_tag(str(item.get("tag") or ""), user_id)]
    # A direct/multi-proxy/shared route cannot be unambiguously tested as one SOCKS IP.
    if len(outbounds) != 1 or outbounds[0].get("tag") != outbound_tag or outbounds[0].get("type") not in {"socks", "socks5"}:
        raise HTTPException(409, "PROXY_REQUIRES_REVIEW")
    auth = []
    for inbound in data.get("inbounds", []):
        entries = [copy.deepcopy(u) for u in inbound.get("users", [])
                   if u.get("name") in names or u.get("username") in names]
        if entries:
            auth.append({"tag": inbound.get("tag"), "type": inbound.get("type"), "users": entries})
    rules = []
    for rule in data.get("route", {}).get("rules", []):
        owners = rule.get("auth_user", [])
        if isinstance(owners, str):
            owners = [owners]
        if rule.get("outbound") == outbound_tag or set(owners) & names:
            if set(owners) - names:
                raise HTTPException(409, "SHARED_ROUTE_REQUIRES_REVIEW")
            rules.append(copy.deepcopy(rule))
    for other in data.get("outbounds", []):
        if other.get("tag") != outbound_tag and (outbound_tag == other.get("detour") or outbound_tag in (other.get("outbounds") or [])):
            raise HTTPException(409, "SHARED_OUTBOUND_REQUIRES_REVIEW")
    owned_peers = []
    for peer in (peers or {}).values():
        if peer.get("nodeUserId") != user_id:
            continue
        peer_expiry = manager._as_utc(peer.get("expiresAt"))
        if peer.get("status") != "REVOKED" and (peer_expiry is None or datetime.now(timezone.utc) < peer_expiry + timedelta(hours=24)):
            raise HTTPException(409, "WIREGUARD_EXPIRY_REQUIRES_REVIEW")
        owned_peers.append({key: peer[key] for key in ("peerId", "publicKey", "address", "nodeUserId", "expiresAt")})
    return {"version": 1, "userId": user_id, "metadata": metadata,
            "inbounds": auth, "outbounds": outbounds, "rules": rules,
            "wireguardPeers": sorted(owned_peers, key=lambda peer: peer["peerId"])}


@contextmanager
def _wireguard_state():
    from config import config
    if not config.wireguard.enabled:
        yield None, {"peers": {}}
        return
    import wireguard
    # All mutations follow the existing WG -> sing-box lock order.
    with wireguard._locked():
        yield wireguard, wireguard._read()


def _fingerprint(snapshot):
    return hashlib.sha256(_canonical(snapshot).encode()).hexdigest()


def _read_wireguard_peers():
    global _peer_read_cache
    from config import config
    if not config.wireguard.enabled:
        return {}
    import wireguard
    # The registry is replaced atomically. Reads need not join the long-running
    # WG reconciliation lock; detach still takes that lock and checks the proof.
    try:
        stat = wireguard.REGISTRY_PATH.stat()
        version = (stat.st_ino, stat.st_size, stat.st_mtime_ns)
    except FileNotFoundError:
        version = None
    key = (str(wireguard.REGISTRY_PATH), config.wireguard.interface, version)
    with _peer_read_lock:
        if _peer_read_cache is not None and _peer_read_cache[0] == key:
            return _peer_read_cache[1]
        # Full peer validation is CPU-bound. Reuse it only for this exact atomic
        # file version; the snapshot still verifies versions after reading and
        # detach independently reads fresh peers under the native WG lock.
        peers = wireguard._read()["peers"]
        _peer_read_cache = (key, peers)
        return peers


def _snapshot_version():
    from config import config
    paths = [manager.CONFIG_PATH, manager.REGISTRY_PATH]
    if config.wireguard.enabled:
        import wireguard
        paths.append(wireguard.REGISTRY_PATH)
    versions = []
    for path in paths:
        try:
            stat = path.stat()
            versions.append((stat.st_ino, stat.st_size, stat.st_mtime_ns))
        except FileNotFoundError:
            versions.append(None)
    return tuple(versions)


def _read_snapshot_configuration(version):
    global _snapshot_read_cache
    key = (str(manager.CONFIG_PATH), str(manager.REGISTRY_PATH), version[:2])
    with _snapshot_read_lock:
        if _snapshot_read_cache is not None and _snapshot_read_cache[0] == key:
            return _snapshot_read_cache[1]
        # _configuration only reads these inputs and copies owned output fields.
        # Cache one version in memory; any atomic config/registry replacement
        # invalidates it. The caller still checks all versions after reading.
        value = (manager.read_config(), manager.read_registry())
        _snapshot_read_cache = (key, value)
        return value


def snapshot(user_id):
    reason = "CONFIGURATION_CHANGED_RECHECK_REQUIRED"
    for _ in range(3):
        # All three files are atomically replaced. Optimistic readers must not
        # queue behind network publication while holding up the management API.
        # A snapshot is not a removal decision: probe and detach revalidate its
        # full fingerprint, and detach retains the native WG/config locks.
        before = _snapshot_version()
        data, registry = _read_snapshot_configuration(before)
        peers = _read_wireguard_peers()
        configuration = _configuration(data, registry, user_id, peers)
        if peers != _read_wireguard_peers():
            reason = "WIREGUARD_STATE_CHANGED_RECHECK_REQUIRED"
            continue
        if before != _snapshot_version():
            reason = "CONFIGURATION_CHANGED_RECHECK_REQUIRED"
            continue
        return {"snapshot": configuration, "fingerprint": _fingerprint(configuration),
                "expiresAt": configuration["metadata"]["expiresAt"],
                "sourceIp": configuration["metadata"].get("sourceIp") or configuration["outbounds"][0].get("server")}
    raise HTTPException(409, reason)


def _read_exact(sock, count):
    value = bytearray()
    while len(value) < count:
        part = sock.recv(count - len(value))
        if not part:
            raise OSError("incomplete proxy response")
        value.extend(part)
    return bytes(value)


def _probe_once(proxy, target):
    """Only explicit proxy endpoint refusal/auth rejection proves INVALID.
    Destination errors, timeouts, DNS/TLS failures and malformed replies are UNKNOWN.
    """
    host, path = target
    deadline = time.monotonic() + 8
    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        return min(4, left)
    def read(sock, count):
        sock.settimeout(remaining())
        return _read_exact(sock, count)
    try:
        sock = socket.create_connection((proxy["server"], int(proxy["server_port"])), timeout=4)
    except ConnectionRefusedError:
        return "INVALID", "PROXY_CONNECTION_REFUSED"
    except (OSError, ValueError, KeyError, TypeError):
        return "UNKNOWN", "PROXY_UNREACHABLE_OR_TIMEOUT"
    try:
        with sock:
            sock.settimeout(4)
            username = str(proxy.get("username") or "").encode()
            password = str(proxy.get("password") or "").encode()
            if len(username) > 255 or len(password) > 255:
                return "UNKNOWN", "CREDENTIAL_FORMAT_REQUIRES_REVIEW"
            method = 2 if username else 0
            sock.sendall(bytes((5, 1, method)))
            greeting = read(sock, 2)
            if greeting[0] != 5 or greeting[1] != method:
                return "UNKNOWN", "AUTH_METHOD_REQUIRES_REVIEW"
            if method == 2:
                sock.sendall(bytes((1, len(username))) + username + bytes((len(password),)) + password)
                auth = read(sock, 2)
                if auth[0] != 1:
                    return "UNKNOWN", "INVALID_AUTH_RESPONSE"
                if auth[1] != 0:
                    return "INVALID", "PROXY_AUTH_REJECTED"
            encoded_host = host.encode("ascii")
            sock.sendall(bytes((5, 1, 0, 3, len(encoded_host))) + encoded_host + (443).to_bytes(2, "big"))
            reply = read(sock, 4)
            if reply[:3] != bytes((5, 0, 0)):
                return "UNKNOWN", "DESTINATION_CONNECT_FAILED"
            if reply[3] == 1:
                read(sock, 6)
            elif reply[3] == 4:
                read(sock, 18)
            elif reply[3] == 3:
                read(sock, read(sock, 1)[0] + 2)
            else:
                return "UNKNOWN", "INVALID_SOCKS_RESPONSE"
            sock.settimeout(remaining())
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(("HEAD " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").encode("ascii"))
                header = tls.recv(256).split(b"\r\n", 1)[0].split(b" ")
                if len(header) >= 2 and header[0] in {b"HTTP/1.0", b"HTTP/1.1"} and header[1] in {b"200", b"204"}:
                    return "VALID", "SOCKS_TLS_HTTP_OK"
                return "UNKNOWN", "DESTINATION_RESPONSE_REQUIRES_REVIEW"
    except (OSError, ValueError, KeyError, TypeError):
        return "UNKNOWN", "PROBE_INCOMPLETE_OR_TIMEOUT"


def _proof(payload):
    encoded = base64.urlsafe_b64encode(_canonical(payload).encode()).decode().rstrip("=")
    return encoded + "." + hmac.new(_proof_key, encoded.encode(), hashlib.sha256).hexdigest()


def _verify_proof(item):
    try:
        encoded, signature = item.proof.split(".")
        if not hmac.compare_digest(signature, hmac.new(_proof_key, encoded.encode(), hashlib.sha256).hexdigest()):
            raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if (payload.get("userId") != item.userId or payload.get("fingerprint") != item.fingerprint
                or payload.get("archiveId") != item.archiveId or payload.get("outcome") != "INVALID"
                or not 0 <= time.time() - payload["at"] <= 600):
            raise ValueError()
        return payload
    except (ValueError, KeyError, TypeError):
        raise HTTPException(409, "FRESH_INVALID_PROBE_REQUIRED") from None


def probe(user_id, request):
    current = snapshot(user_id)
    if current["fingerprint"] != request.fingerprint:
        raise HTTPException(409, "USER_CHANGED")
    results = []
    for target in _targets:
        results.append(_probe_once(current["snapshot"]["outbounds"][0], target))
        if results[-1][0] == "VALID":
            break
    if snapshot(user_id)["fingerprint"] != request.fingerprint:
        raise HTTPException(409, "USER_CHANGED_DURING_PROBE")
    if any(result[0] == "VALID" for result in results):
        outcome, reason = "VALID", "SOCKS_TLS_HTTP_OK"
    elif len(results) == 2 and results[0] == results[1] and results[0][0] == "INVALID":
        outcome, reason = results[0]
    else:
        outcome, reason = "UNKNOWN", "PROBE_NOT_CONCLUSIVE"
    payload = {"userId": user_id, "fingerprint": request.fingerprint, "archiveId": request.archiveId,
               "outcome": outcome, "at": int(time.time())}
    return {"outcome": outcome, "reason": reason, "attempts": len(results),
            "checkedAt": datetime.now(timezone.utc).isoformat(), "proof": _proof(payload) if outcome == "INVALID" else None}


def detach(items):
    if len({item.userId for item in items}) != len(items):
        raise HTTPException(422, "DUPLICATE_USER")
    for item in items:
        _verify_proof(item)

    peer_state = {}
    def apply(data, registry):
        # Validate the entire batch before changing even the in-memory candidate.
        snapshots = {}
        for item in items:
            current = _configuration(data, registry, item.userId, peer_state)
            if _fingerprint(current) != item.fingerprint:
                raise HTTPException(409, "USER_CHANGED_BEFORE_REMOVAL")
            snapshots[item.userId] = current
        for item in items:
            names = manager._user_auth_names(registry, item.userId)
            tags = {outbound["tag"] for outbound in snapshots[item.userId]["outbounds"]}
            for inbound in data.get("inbounds", []):
                inbound["users"] = [u for u in inbound.get("users", [])
                                    if u.get("name") not in names and u.get("username") not in names]
            data["outbounds"] = [outbound for outbound in data.get("outbounds", []) if outbound.get("tag") not in tags]
            metadata = manager._registry_user(registry, item.userId)
            manager._remove_expiration_rule(data, metadata)
            manager._remove_managed_enforcement_rules(data.setdefault("route", {}).setdefault("rules", []), metadata)
            manager._remove_access_rule(data, metadata)
            rules = data["route"]["rules"]
            rules[:] = [rule for rule in rules if rule.get("outbound") not in tags
                        and not (set([rule["auth_user"]] if isinstance(rule.get("auth_user"), str) else rule.get("auth_user", [])) & names)]
            # The complete record is already encrypted in the website database.
            # Keep a small node tombstone to prevent ensure_user_outbounds resurrection.
            registry.setdefault("expiredUsers", {})[item.userId] = {
                "userId": item.userId, "expiresAt": snapshots[item.userId]["metadata"]["expiresAt"],
                "archivedAt": datetime.now(timezone.utc).isoformat(), "status": "ARCHIVED",
                "databaseArchiveId": item.archiveId, "fingerprint": item.fingerprint}
            registry.setdefault("users", {}).pop(item.userId, None)
        return {"success": True, "removed": [item.userId for item in items], "databaseHistoryPreserved": True}

    with _wireguard_state() as (wireguard, state):
        peer_state = state["peers"]
        result = manager.mutate_config(apply)  # Exactly one configuration apply per batch; traffic history is retained.
        if wireguard:
            owned_users = {item.userId for item in items}
            peers = [peer for peer in state["peers"].values() if peer["nodeUserId"] in owned_users]
            for peer in peers:
                wireguard._set_state(peer, "REVOKED", "EXPIRED_INVALID_SOCKS_ARCHIVED")
            if peers:
                wireguard._write(state)  # Retain identity tombstones; remove only their kernel/gateway routes.
                for peer in peers:
                    wireguard._remove(peer)
                wireguard._sync_routes(state["peers"])
    return result


def reject_unguarded_expired_deletion(user_id):
    """Legacy delete endpoints must not bypass the probe/DB archive workflow."""
    with manager._config_lock():
        registry = manager.read_registry()
        expiry = manager._as_utc(manager._registry_user(registry, user_id).get("expiresAt"))
    if expiry is not None and datetime.now(timezone.utc) >= expiry + timedelta(hours=24):
        raise HTTPException(409, "EXPIRED_USER_REQUIRES_DATABASE_ARCHIVE_AND_SOCKS_PROBE")


@router.get("/{user_id}/snapshot")
def get_snapshot(user_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store, private"
    return snapshot(user_id)


@router.post("/{user_id}/probe")
def post_probe(user_id: str, request: ProbeRequest, response: Response):
    response.headers["Cache-Control"] = "no-store, private"
    return probe(user_id, request)


@router.post("/detach")
def post_detach(request: DetachRequest, response: Response):
    response.headers["Cache-Control"] = "no-store, private"
    return detach(request.items)
