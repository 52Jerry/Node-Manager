"""Durable peer ownership and verified kernel reconciliation; no TUN/routing setup."""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from config import config
from singbox import manager

try:
    import fcntl
except ImportError:
    fcntl = None

REGISTRY_PATH = Path(os.environ.get("NODE_MANAGER_WIREGUARD_REGISTRY", "/var/lib/node-manager/wireguard-peers.json"))
LOCK_PATH = Path(os.environ.get("NODE_MANAGER_WIREGUARD_LOCK", "/run/lock/node-manager-wireguard.lock"))
BATCH_APPLY_LIMIT = 4000
_mutex = threading.Lock()
_stop = threading.Event()
_thread = None
_recovery_error = None
logger = logging.getLogger(__name__)


class WireguardError(RuntimeError):
    def __init__(self, message, code="WIREGUARD_OPERATION_FAILED"):
        super().__init__(message)
        self.code = code


class WireguardRecoveryPending(WireguardError):
    """A retryable operational failure, not a change of peer ownership."""


def _now():
    return datetime.now(timezone.utc)


def _require_enabled():
    if not config.wireguard.enabled:
        raise WireguardError("wireguard peer management is disabled")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", config.wireguard.interface):
        raise WireguardError("invalid WireGuard interface")


def _identity(value, name="peerId"):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value):
        raise WireguardError("invalid " + name)
    return value


def _key(value):
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
            raise ValueError()
        return value
    except (ValueError, TypeError):
        raise WireguardError("invalid WireGuard public key") from None


def _address(value):
    try:
        parsed = ipaddress.ip_interface(value)
        if parsed.version != 4 or parsed.network.prefixlen != 32 or str(parsed) != value:
            raise ValueError()
        if parsed.ip.is_unspecified or parsed.ip.is_multicast or parsed.ip.is_loopback:
            raise ValueError()
        return str(parsed)
    except (ValueError, TypeError):
        raise WireguardError("address must be one IPv4 /32") from None


def _date(value):
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        raise WireguardError("expiresAt must include a timezone") from None


@contextmanager
def _locked():
    with _mutex:
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOCK_PATH.open("a", encoding="ascii") as handle:
            if fcntl:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read():
    if not REGISTRY_PATH.exists():
        return {"version": 1, "interface": config.wireguard.interface, "peers": {}}
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        if data.get("version") != 1 or data.get("interface") != config.wireguard.interface or not isinstance(data.get("peers"), dict):
            raise ValueError()
        addresses, keys, active_users = set(), set(), set()
        for peer_id, peer in data["peers"].items():
            if peer["peerId"] != _identity(peer_id) or peer["status"] not in {"ACTIVE", "APPLYING", "REVOKED", "EXPIRED", "BLOCKED", "FAILED"}:
                raise ValueError()
            address, key, user = _address(peer["address"]), _key(peer["publicKey"]), _identity(peer["nodeUserId"], "nodeUserId")
            if peer["allowedIps"] != [address] or not peer.get("exitFingerprint"):
                raise ValueError()
            _date(peer["expiresAt"])
            if address in addresses or key in keys:
                raise ValueError()
            if peer["status"] in {"ACTIVE", "APPLYING"}:
                if user in active_users:
                    raise ValueError()
                active_users.add(user)
            addresses.add(address); keys.add(key)
        return data
    except (OSError, ValueError, KeyError, TypeError, WireguardError):
        raise WireguardError("WireGuard registry invalid or unreadable") from None


def _write(data):
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, name = tempfile.mkstemp(prefix="wireguard.", suffix=".json", dir=REGISTRY_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o600)
        os.replace(name, REGISTRY_PATH)
        if os.name != "nt":
            directory = os.open(REGISTRY_PATH.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def _invoke(args):
    try:
        result = subprocess.run([config.wireguard.command, *args], capture_output=True, text=True, timeout=15, check=False)
        if result.returncode:
            raise WireguardError("WireGuard command failed")
        return result.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        raise WireguardError("WireGuard command unavailable") from None


def _kernel():
    # Separate machine-readable commands avoid reading private/preshared keys.
    values = _invoke(["show", config.wireguard.interface, "allowed-ips"])
    peers = {}
    for line in values.splitlines():
        parts = line.split()
        if len(parts) < 2:
            raise WireguardError("invalid WireGuard status")
        peers[parts[0]] = [part for field in parts[1:] for part in field.split(",") if part != "(none)"]
    return peers


def _interface_addresses():
    """Return only canonical IPv4 interface addresses; never expose wg config or keys."""
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", config.wireguard.interface],
            capture_output=True, text=True, timeout=15, check=False)
        if result.returncode:
            raise WireguardError("WireGuard interface address unavailable")
        addresses = set()
        for line in (result.stdout or "").splitlines():
            fields = line.split()
            if "inet" not in fields:
                continue
            index = fields.index("inet")
            if index + 1 >= len(fields):
                continue
            try:
                address = ipaddress.ip_interface(fields[index + 1])
                if address.version == 4:
                    addresses.add(str(address))
            except ValueError:
                continue
        return sorted(addresses)
    except (OSError, subprocess.TimeoutExpired):
        raise WireguardError("WireGuard interface address unavailable") from None


def _binding(node_user_id, expires_at):
    try:
        data, registry = _read_binding_snapshot()
        return _binding_from_snapshot(
            node_user_id, expires_at, registry, _outbounds_by_tag(data), _now()
        )
    except (OSError, ValueError, TypeError, manager.SingboxConfigError):
        raise WireguardError("node user or residential binding unavailable") from None


def _read_binding_snapshot():
    """Read matching sing-box config and registry versions under a short lock."""
    with manager._config_lock():
        return manager.read_config(), manager.read_registry()


def _validate_current_bindings(peers, source_config, user_registry, now=None):
    """Reject an activation if its user or residential SOCKS binding changed."""
    now = now or _now()
    outbounds_by_tag = _outbounds_by_tag(source_config)
    for peer in peers:
        if peer.get("status") not in {"ACTIVE", "APPLYING"}:
            continue
        current = _binding_from_snapshot(
            peer["nodeUserId"], _date(peer["expiresAt"]), user_registry,
            outbounds_by_tag, now,
        )
        if current != peer.get("exitFingerprint"):
            raise WireguardError("residential binding changed during WireGuard synchronization")


def _outbounds_by_tag(data):
    outbounds = {}
    for outbound in data.get("outbounds", []):
        if isinstance(outbound, dict) and outbound.get("tag"):
            outbounds.setdefault(str(outbound["tag"]), outbound)
    return outbounds


def _binding_from_snapshot(node_user_id, expires_at, registry, outbounds_by_tag, now):
    user = registry.get("users", {}).get(node_user_id)
    if not isinstance(user, dict):
        raise WireguardError("node user missing", "NODE_USER_MISSING")
    user_expires_at = _date(user.get("expiresAt"))
    if user_expires_at <= now:
        raise WireguardError("node user expired", "NODE_USER_EXPIRED")
    if expires_at > user_expires_at:
        raise WireguardError("peer exceeds node user expiration", "PEER_EXCEEDS_ENTITLEMENT")
    if user.get("accessEnabled") is False:
        raise WireguardError("node user access disabled", "NODE_USER_ACCESS_DISABLED")
    if user.get("expirationBlocked"):
        raise WireguardError("node user expiration blocked", "NODE_USER_EXPIRATION_BLOCKED")
    if user.get("enforcementTrafficBlocked"):
        raise WireguardError("node user traffic blocked", "NODE_USER_TRAFFIC_BLOCKED")
    binding = _resolve_exit_binding(node_user_id, outbounds_by_tag)
    return _binding_fingerprint(binding["identity"])


def _valid_socks_member(outbound, allow_detour=False):
    if (not isinstance(outbound, dict) or outbound.get("type") != "socks"
            or not isinstance(outbound.get("server"), str) or not outbound["server"].strip()
            or not isinstance(outbound.get("server_port"), int)
            or isinstance(outbound.get("server_port"), bool)
            or not 1 <= outbound["server_port"] <= 65535
            or (not allow_detour and outbound.get("detour"))):
        raise WireguardError("residential SOCKS outbound required")


def _binding_fingerprint(identity):
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def _resolve_exit_binding(node_user_id, outbounds_by_tag):
    """Resolve one direct SOCKS or a urltest aggregate and its SOCKS members."""
    root = outbounds_by_tag.get(manager.USER_OUTBOUND_PREFIX + node_user_id)
    if not isinstance(root, dict):
        raise WireguardError("residential SOCKS outbound required")
    if root.get("type") == "socks":
        _valid_socks_member(root, allow_detour=True)
        identity = {k: root.get(k) for k in (
            "type", "server", "server_port", "version", "username", "password", "detour")}
        return {"kind": "socks", "root": root, "members": [], "identity": identity}
    if root.get("type") != "urltest":
        raise WireguardError("residential SOCKS outbound required")

    member_tags = root.get("outbounds")
    settings = {key: value for key, value in root.items()
                if key not in {"type", "tag", "outbounds"}}
    allowed_settings = {
        "url", "interval", "tolerance", "idle_timeout",
        "interrupt_exist_connections", "interrupt_exist_connections_on_first",
    }
    if (not isinstance(member_tags, list) or len(member_tags) < 2
            or not all(isinstance(tag, str) and tag for tag in member_tags)
            or len(set(member_tags)) != len(member_tags)
            or set(settings) - allowed_settings):
        raise WireguardError("invalid residential urltest outbound")
    if "url" in settings and (not isinstance(settings["url"], str) or not settings["url"].strip()):
        raise WireguardError("invalid residential urltest outbound")
    if "interval" in settings and (not isinstance(settings["interval"], str) or not settings["interval"].strip()):
        raise WireguardError("invalid residential urltest outbound")
    if "tolerance" in settings and (not isinstance(settings["tolerance"], int)
                                    or isinstance(settings["tolerance"], bool)
                                    or settings["tolerance"] < 0):
        raise WireguardError("invalid residential urltest outbound")

    members = []
    member_identities = []
    for tag in member_tags:
        member = outbounds_by_tag.get(tag)
        _valid_socks_member(member)
        members.append(member)
        member_identities.append({key: value for key, value in member.items() if key != "tag"})
    identity = {"type": "urltest", "settings": settings, "members": member_identities}
    return {"kind": "urltest", "root": root, "members": members, "identity": identity}


class _KernelAddressIndex:
    """IPv4 prefix trie for checking peer addresses against one kernel snapshot."""

    def __init__(self, kernel):
        self.root = {}
        for public_key, networks in kernel.items():
            for value in networks:
                network = ipaddress.ip_network(value, strict=False)
                if network.version != 4:
                    continue
                node = self.root
                address = int(network.network_address)
                for bit_index in range(network.prefixlen):
                    bit = (address >> (31 - bit_index)) & 1
                    node = node.setdefault(bit, {})
                node.setdefault(None, set()).add(public_key)

    def conflicts(self, address, public_key):
        value = int(ipaddress.ip_address(address.split("/")[0]))
        node = self.root
        for depth in range(33):
            if any(owner != public_key for owner in node.get(None, ())):
                return True
            if depth == 32:
                return False
            node = node.get((value >> (31 - depth)) & 1)
            if node is None:
                return False
        return False


def _conflicts(data, peer, kernel):
    for other_id, other in data["peers"].items():
        if other_id == peer["peerId"]:
            continue
        if any(other[field] == peer[field] for field in ("publicKey", "address")):
            raise WireguardError("peer identity already owned")
        if other["nodeUserId"] == peer["nodeUserId"] and (
                other["status"] in {"ACTIVE", "APPLYING"} or other["publicKey"] in kernel):
            raise WireguardError("peer identity already owned")
    for key, networks in kernel.items():
        if key == peer["publicKey"]:
            continue
        for network in networks:
            parsed = ipaddress.ip_network(network, strict=False)
            if parsed.version == 4 and ipaddress.ip_address(peer["address"].split("/")[0]) in parsed:
                raise WireguardError("tunnel address already owned by kernel peer")


def _remove(peer):
    if peer["publicKey"] in _kernel():
        _invoke(["set", config.wireguard.interface, "peer", peer["publicKey"], "remove"])
    if peer["publicKey"] in _kernel():
        raise WireguardError("peer removal could not be verified")


def _install(peer):
    if _kernel().get(peer["publicKey"]) != [peer["address"]]:
        _invoke(["set", config.wireguard.interface, "peer", peer["publicKey"], "allowed-ips", peer["address"]])
    if _kernel().get(peer["publicKey"]) != [peer["address"]]:
        raise WireguardError("peer installation could not be verified")


def _receipt(peer, server_public_key=None):
    return {"success": True, "interface": config.wireguard.interface,
            "serverPublicKey": server_public_key or _key(_invoke(["show", config.wireguard.interface, "public-key"]).strip()),
            **{key: peer[key] for key in ("peerId", "publicKey", "address", "allowedIps", "nodeUserId", "expiresAt", "status")}}


def _runtime_ready():
    try:
        from wireguard_routes import runtime_ready
        return bool(runtime_ready())
    except Exception as error:
        logger.error("WireGuard runtime check failed errorType=%s", type(error).__name__)
        return False


def _runtime_failure_reason():
    from wireguard_routes import runtime_failure_reason
    return runtime_failure_reason() or "GATEWAY_RUNTIME_NOT_READY"


def _sync_routes(peers, source_config=None, user_registry=None):
    try:
        from wireguard_routes import sync_routes
        if source_config is None or user_registry is None:
            source_config, user_registry = _read_binding_snapshot()
        sync_routes(peers, source_config, user_registry)
    except Exception as error:
        logger.error("WireGuard route synchronization failed errorType=%s reason=%s",
                     type(error).__name__, getattr(error, "code", "ROUTE_SYNC_FAILED"))
        raise WireguardError("WireGuard residential routes could not be applied", "ROUTE_SYNC_FAILED") from None


def _quarantine_inactive(data):
    """Deny non-active sources without deleting their kernel identities."""
    from wireguard_routes import quarantine_sources
    inactive = [p["address"] for p in data["peers"].values()
                if p["status"] not in {"ACTIVE", "APPLYING"}]
    if inactive:
        quarantine_sources(data["peers"], inactive)


def _binding_reason(peer, source_config, user_registry, now):
    try:
        fingerprint = _binding_from_snapshot(
            peer["nodeUserId"], _date(peer["expiresAt"]), user_registry,
            source_config, now)
        if fingerprint != peer["exitFingerprint"]:
            return "RESIDENTIAL_BINDING_CHANGED"
    except WireguardError as error:
        return error.code if error.code != "WIREGUARD_OPERATION_FAILED" else "RESIDENTIAL_BINDING_INVALID"
    return None


def _set_state(peer, state, reason=None):
    changed = peer.get("status") != state or peer.get("stateReason") != reason
    peer["status"] = state
    if reason:
        peer["stateReason"] = reason
    else:
        peer.pop("stateReason", None)
    if changed:
        logger.info("WireGuard peer state peerId=%s status=%s reason=%s",
                    peer["peerId"], state, reason or "VERIFIED")
    return changed


def _can_adopt_kernel_peer(peer, kernel):
    return (config.wireguard.allow_legacy_peer_adoption
            and kernel.get(peer["publicKey"]) == [peer["address"]])


def apply_peer(peer_id, public_key, address, allowed_ips, node_user_id, expires_at):
    _require_enabled()
    peer = {"peerId": _identity(peer_id), "publicKey": _key(public_key), "address": _address(address),
            "nodeUserId": _identity(node_user_id, "nodeUserId"), "expiresAt": _date(expires_at).isoformat(),
            "allowedIps": allowed_ips, "status": "APPLYING"}
    if allowed_ips != [address]:
        raise WireguardError("allowedIps must equal the single peer address")
    if _date(expires_at) <= _now():
        raise WireguardError("expiresAt must be in the future")
    with _locked():
        _require_enabled()
        if peer["publicKey"] == _key(_invoke(["show", config.wireguard.interface, "public-key"]).strip()):
            raise WireguardError("peer public key cannot equal server key")
        if not _runtime_ready():
            raise WireguardError("dedicated WireGuard residential gateway is not ready")
        data = _read()
        existing = data["peers"].get(peer_id)
        if existing and (existing["status"] == "REVOKED" or any(existing[field] != peer[field] for field in ("publicKey", "address", "nodeUserId"))):
            raise WireguardError("peer identity is immutable or revoked")
        peer["exitFingerprint"] = _binding(node_user_id, _date(expires_at))
        if existing and existing["exitFingerprint"] != peer["exitFingerprint"]:
            raise WireguardError("residential binding changed; explicit migration required")
        kernel = _kernel()
        if not existing and public_key in kernel and not _can_adopt_kernel_peer(peer, kernel):
            raise WireguardError("unmanaged peer cannot be adopted")
        _conflicts(data, peer, kernel)
        previous = copy.deepcopy(existing)
        if existing and existing["status"] == "ACTIVE":
            # Refreshing the same identity must not temporarily revoke a working tunnel.
            peer["status"] = "ACTIVE"
        data["peers"][peer_id] = peer
        _write(data)  # Durable intent before touching the interface.
        try:
            _sync_routes(data["peers"])
            _install(peer)
            current_config, current_registry = _read_binding_snapshot()
            _validate_current_bindings([peer], current_config, current_registry)
            peer["status"] = "ACTIVE"
            _write(data)
        except Exception as error:
            _fail_apply_batch(data, [peer], {peer_id: previous}, error)
            raise WireguardError("peer application failed; existing kernel identity retained") from None
        return _receipt(peer)


def _normalize_apply_batch(items):
    if not isinstance(items, list) or not items or len(items) > BATCH_APPLY_LIMIT:
        raise WireguardError(f"batch must contain between 1 and {BATCH_APPLY_LIMIT} peers")
    normalized = []
    seen = {"peerId": set(), "publicKey": set(), "address": set(), "nodeUserId": set()}
    now = _now()
    for item in items:
        if not isinstance(item, dict):
            raise WireguardError("invalid WireGuard batch item")
        peer_id = _identity(item.get("peerId"))
        public_key = _key(item.get("publicKey"))
        address = _address(item.get("address"))
        node_user_id = _identity(item.get("nodeUserId"), "nodeUserId")
        allowed_ips = item.get("allowedIps")
        expires_at = _date(item.get("expiresAt"))
        if allowed_ips != [address]:
            raise WireguardError("allowedIps must equal the single peer address")
        if expires_at <= now:
            raise WireguardError("expiresAt must be in the future")
        values = {"peerId": peer_id, "publicKey": public_key, "address": address, "nodeUserId": node_user_id}
        for field, value in values.items():
            if value in seen[field]:
                raise WireguardError("duplicate identity in WireGuard batch")
            seen[field].add(value)
        normalized.append({
            **values,
            "allowedIps": [address],
            "expiresAt": expires_at.isoformat(),
            "_expiresAt": expires_at,
        })
    return normalized


def _validate_apply_batch(data, kernel, batch, server_public_key, user_registry,
                          outbounds_by_tag, now):
    owners = {field: {peer[field]: peer_id for peer_id, peer in data["peers"].items()}
              for field in ("publicKey", "address")}
    user_owners = {}
    for peer_id, existing_peer in data["peers"].items():
        user_owners.setdefault(existing_peer["nodeUserId"], []).append((peer_id, existing_peer))
    kernel_index = _KernelAddressIndex(kernel)
    for peer in batch:
        if peer["_expiresAt"] <= now:
            raise WireguardError("expiresAt must be in the future")
        existing = data["peers"].get(peer["peerId"])
        if peer["publicKey"] == server_public_key:
            raise WireguardError("peer public key cannot equal server key")
        if existing and (existing["status"] == "REVOKED" or any(
                existing[field] != peer[field] for field in ("publicKey", "address", "nodeUserId"))):
            raise WireguardError("peer identity is immutable or revoked")
        for field in ("publicKey", "address"):
            owner = owners[field].get(peer[field])
            if owner is not None and owner != peer["peerId"]:
                raise WireguardError("peer identity already owned")
        previous_peers = [owner for owner_id, owner in user_owners.get(peer["nodeUserId"], [])
                          if owner_id != peer["peerId"]]
        if any(owner["status"] in {"ACTIVE", "APPLYING"} or owner["publicKey"] in kernel
               for owner in previous_peers):
            raise WireguardError("peer identity already owned")
        if (existing is None and peer["publicKey"] in kernel
                and not _can_adopt_kernel_peer(peer, kernel)):
            raise WireguardError("unmanaged peer cannot be adopted")
        if kernel_index.conflicts(peer["address"], peer["publicKey"]):
            raise WireguardError("tunnel address already owned by kernel peer")
        peer["exitFingerprint"] = _binding_from_snapshot(
            peer["nodeUserId"], peer["_expiresAt"], user_registry,
            outbounds_by_tag, now
        )
        if existing and existing.get("exitFingerprint") != peer["exitFingerprint"]:
            raise WireguardError("residential binding changed; explicit migration required")


def _fail_apply_batch(data, batch, previous, error):
    """Roll back refreshed records; quarantine new intents, retaining kernel peers."""
    global _recovery_error
    logger.error("WireGuard apply failed errorType=%s reason=%s kernelRemoval=false",
                 type(error).__name__, getattr(error, "code", "APPLY_FAILED"))
    for item in batch:
        peer_id = item["peerId"]
        old = previous.get(peer_id)
        if old and old["status"] == "ACTIVE":
            data["peers"][peer_id] = copy.deepcopy(old)
        else:
            _set_state(data["peers"][peer_id], "FAILED", "APPLY_FAILED")
    # A concurrent entitlement/binding change affects only its own records.
    try:
        source_config, user_registry = _read_binding_snapshot()
        _refresh_peer_bindings(data, source_config, user_registry)
    except Exception as binding_error:
        source_config = user_registry = None
        _recovery_error = "BINDING_SNAPSHOT_UNAVAILABLE"
        logger.error("WireGuard apply rollback snapshot unavailable errorType=%s",
                     type(binding_error).__name__)
    try:
        _write(data)
    except OSError:
        logger.error("WireGuard batch failure state could not be persisted")
    try:
        _quarantine_inactive(data)
        if source_config is not None and user_registry is not None:
            _sync_routes(data["peers"], source_config, user_registry)
    except Exception as cleanup_error:
        _recovery_error = "APPLY_ROUTE_RECOVERY_PENDING"
        logger.error("WireGuard apply cleanup needs retry errorType=%s kernelRemoval=false",
                     type(cleanup_error).__name__)


def apply_peers(items):
    """Apply a validated peer batch with one route sync and one kernel readback.

    Returns {"success": True, "peers": [peer receipts]} only after every peer
    is present with the requested /32. New intents use APPLYING; a refresh of
    an already ACTIVE identity keeps its state and kernel session throughout.
    """
    _require_enabled()
    batch = _normalize_apply_batch(items)
    with _locked():
        _require_enabled()
        now = _now()
        data = _read()
        kernel = _kernel()
        server_public_key = _key(_invoke(["show", config.wireguard.interface, "public-key"]).strip())
        if not _runtime_ready():
            raise WireguardError("dedicated WireGuard residential gateway is not ready")
        try:
            manager.recover_wireguard_user_metadata({
                peer["nodeUserId"]: peer["_expiresAt"] for peer in batch
            })
        except manager.SingboxConfigError as exc:
            raise WireguardError(str(exc)) from None
        source_config, user_registry = _read_binding_snapshot()
        outbounds_by_tag = _outbounds_by_tag(source_config)
        _validate_apply_batch(data, kernel, batch, server_public_key, user_registry,
                              outbounds_by_tag, now)
        if any(peer["_expiresAt"] <= _now() for peer in batch):
            raise WireguardError("expiresAt must be in the future")

        previous = {peer["peerId"]: copy.deepcopy(data["peers"].get(peer["peerId"])) for peer in batch}
        for peer in batch:
            record = {key: value for key, value in peer.items() if not key.startswith("_")}
            old = previous[peer["peerId"]]
            record["status"] = "ACTIVE" if old and old["status"] == "ACTIVE" else "APPLYING"
            data["peers"][peer["peerId"]] = record
        _write(data)
        try:
            _sync_routes(data["peers"], source_config, user_registry)
            for peer in batch:
                if kernel.get(peer["publicKey"]) == [peer["address"]]:
                    continue
                _invoke(["set", config.wireguard.interface, "peer", peer["publicKey"],
                         "allowed-ips", peer["address"]])
            verified = _kernel()
            if any(verified.get(peer["publicKey"]) != [peer["address"]] for peer in batch):
                raise WireguardError("batch peer installation could not be verified")
            current_config, current_registry = _read_binding_snapshot()
            _validate_current_bindings(
                (data["peers"][peer["peerId"]] for peer in batch),
                current_config, current_registry,
            )
            for peer in batch:
                data["peers"][peer["peerId"]]["status"] = "ACTIVE"
            _write(data)
        except Exception as error:
            _fail_apply_batch(data, batch, previous, error)
            raise WireguardError("WireGuard batch application failed; existing kernel identities retained") from None

        receipts = []
        for peer in batch:
            receipts.append(_receipt(data["peers"][peer["peerId"]], server_public_key))
        return {"success": True, "peers": receipts}


def revoke_peer(peer_id, public_key):
    _require_enabled()
    _identity(peer_id); _key(public_key)
    with _locked():
        _require_enabled()
        data = _read()
        peer = data["peers"].get(peer_id)
        if peer is None:
            if public_key in _kernel() or any(p["publicKey"] == public_key for p in data["peers"].values()):
                raise WireguardError("peer ownership is unknown")
            return {"success": True, "peerId": peer_id, "publicKey": public_key, "status": "REVOKED", "interface": config.wireguard.interface}
        if peer["publicKey"] != public_key:
            raise WireguardError("peer public key mismatch")
        _set_state(peer, "REVOKED", "PEER_REVOKED")
        _write(data)  # Persist tombstone first, so restart cannot resurrect it.
        removal_error = None
        try:
            _remove(peer)
        except WireguardError as exc:
            removal_error = exc
        try:
            _sync_routes(data["peers"])
        except WireguardError as exc:
            removal_error = removal_error or exc
        if removal_error:
            raise WireguardError("peer revoke could not be fully verified") from None
        return _receipt(peer)


def _refresh_peer_bindings(data, source_config, user_registry, recover=False):
    """Change only peers whose own entitlement or residential identity is invalid."""
    now = _now()
    outbounds = _outbounds_by_tag(source_config)
    active_users = {p["nodeUserId"]: p["peerId"] for p in data["peers"].values()
                    if p["status"] in {"ACTIVE", "APPLYING"}}
    changed = False
    for peer in data["peers"].values():
        if peer["status"] == "REVOKED":
            continue
        if _date(peer["expiresAt"]) <= now:
            changed |= _set_state(peer, "EXPIRED", "PEER_EXPIRED")
            continue
        if peer["status"] not in {"ACTIVE", "BLOCKED", "APPLYING"}:
            continue
        reason = _binding_reason(peer, outbounds, user_registry, now)
        if reason:
            changed |= _set_state(peer, "BLOCKED", reason)
        elif recover and peer["status"] == "BLOCKED" and peer.get("stateReason") in {
                "KERNEL_INSTALL_FAILED", "KERNEL_ADDRESS_CONFLICT"}:
            # Only operational failures are retried automatically. Other blocked
            # identities still require an explicitly validated apply/migration.
            if active_users.get(peer["nodeUserId"], peer["peerId"]) == peer["peerId"]:
                changed |= _set_state(peer, "ACTIVE")
                active_users[peer["nodeUserId"]] = peer["peerId"]
            else:
                changed |= _set_state(peer, "BLOCKED", "NODE_USER_PEER_CONFLICT")
    return changed


def _remove_terminal_peers(data, kernel):
    """Explicit revocation and expiration are the only automatic kernel removals."""
    changed = False
    for peer in data["peers"].values():
        if peer["status"] not in {"REVOKED", "EXPIRED"} or peer["publicKey"] not in kernel:
            continue
        _invoke(["set", config.wireguard.interface, "peer", peer["publicKey"], "remove"])
        changed = True
    if changed:
        kernel = _kernel()
        if any(p["status"] in {"REVOKED", "EXPIRED"} and p["publicKey"] in kernel
               for p in data["peers"].values()):
            raise WireguardRecoveryPending("terminal peer removal could not be verified", "TERMINAL_REMOVAL_PENDING")
    return kernel


def reconcile():
    global _recovery_error
    if not config.wireguard.enabled:
        return
    with _locked():
        _require_enabled()
        data = _read()
        kernel = _kernel()
        changed = False
        for peer in data["peers"].values():
            if peer["status"] == "REVOKED":
                continue
            if _date(peer["expiresAt"]) <= _now():
                changed |= _set_state(peer, "EXPIRED", "PEER_EXPIRED")
            elif peer["status"] == "APPLYING":
                changed |= _set_state(peer, "FAILED", "APPLY_INTERRUPTED")
        if changed:
            _write(data)
        # Revocation/expiration enforcement must not depend on proxy health.
        kernel = _remove_terminal_peers(data, kernel)
        try:
            source_config, user_registry = _read_binding_snapshot()
        except Exception as error:
            _fail_closed(data, "BINDING_SNAPSHOT_UNAVAILABLE", error)
            raise WireguardRecoveryPending("binding snapshot unavailable; retry pending", "BINDING_SNAPSHOT_UNAVAILABLE") from None
        changed = _refresh_peer_bindings(data, source_config, user_registry, recover=True)
        kernel_index = _KernelAddressIndex(kernel)
        for peer in data["peers"].values():
            if peer["status"] == "ACTIVE" and kernel_index.conflicts(peer["address"], peer["publicKey"]):
                changed |= _set_state(peer, "BLOCKED", "KERNEL_ADDRESS_CONFLICT")
        if changed:
            _write(data)
        kernel = _remove_terminal_peers(data, kernel)
        try:
            if any(p["status"] == "ACTIVE" for p in data["peers"].values()) and not _runtime_ready():
                reason = _runtime_failure_reason()
                # Route sync can start an exited active generation. Requiring its
                # listeners first would prevent that recovery from ever running.
                if reason != "ACTIVE_GENERATION_UNREADY":
                    raise WireguardError("dedicated gateway runtime is not ready", reason)
            if data["peers"]:
                _sync_routes(data["peers"], source_config, user_registry)
        except Exception as error:
            _fail_closed(data, getattr(error, "code", "ROUTE_SYNC_FAILED"), error)
            raise WireguardRecoveryPending("residential route recovery pending; kernel peers retained", _recovery_error) from None

        active = [p for p in data["peers"].values() if p["status"] == "ACTIVE"]
        kernel_changed = False
        failed = False
        for peer in active:
            if kernel.get(peer["publicKey"]) == [peer["address"]]:
                continue
            try:
                _invoke(["set", config.wireguard.interface, "peer", peer["publicKey"], "allowed-ips", peer["address"]])
                kernel_changed = True
            except WireguardError as error:
                failed = True
                _set_state(peer, "BLOCKED", "KERNEL_INSTALL_FAILED")
                logger.error("WireGuard kernel install pending peerId=%s errorType=%s",
                             peer["peerId"], type(error).__name__)
        try:
            verified = _kernel() if kernel_changed else kernel
            for peer in active:
                if peer["status"] == "ACTIVE" and verified.get(peer["publicKey"]) != [peer["address"]]:
                    failed = True
                    _set_state(peer, "BLOCKED", "KERNEL_INSTALL_FAILED")
            current_config, current_registry = _read_binding_snapshot()
        except Exception as error:
            _write(data)
            _fail_closed(data, "RECOVERY_READBACK_UNAVAILABLE", error)
            raise WireguardRecoveryPending("recovery readback unavailable; kernel peers retained", "RECOVERY_READBACK_UNAVAILABLE") from None
        late_change = _refresh_peer_bindings(data, current_config, current_registry)
        if failed or late_change:
            _write(data)
            try:
                _quarantine_inactive(data)
                _sync_routes(data["peers"], current_config, current_registry)
                _remove_terminal_peers(data, verified)
            except Exception as error:
                _fail_closed(data, "PEER_ISOLATION_PENDING", error)
                raise WireguardRecoveryPending("peer route isolation pending", "PEER_ISOLATION_PENDING") from None
        _recovery_error = None
        if failed or late_change:
            raise WireguardRecoveryPending("individual peer recovery pending; other peers retained", "PEER_RECOVERY_PENDING")


def _fail_closed(data, reason, error):
    """Keep last valid peer identities; fail delivery and isolate invalid sources."""
    global _recovery_error
    _recovery_error = reason
    logger.error("WireGuard recovery pending reason=%s errorType=%s kernelRemoval=false retrySeconds=15",
                 reason, type(error).__name__)
    try:
        if reason in {"POLICY_RULE_MISSING", "POLICY_ROUTE_MISSING", "TPROXY_JUMP_MISSING",
                      "INPUT_JUMP_MISSING", "FORWARD_JUMP_MISSING"}:
            from wireguard_routes import quarantine_sources
            quarantine_sources(data["peers"], [p["address"] for p in data["peers"].values()])
        else:
            _quarantine_inactive(data)
    except Exception as isolation_error:
        _recovery_error = "PEER_ISOLATION_PENDING"
        logger.error("WireGuard source isolation pending errorType=%s kernelRemoval=false",
                     type(isolation_error).__name__)


def status():
    _require_enabled()
    with _locked():
        data, kernel = _read(), _kernel()
        public_key = _key(_invoke(["show", config.wireguard.interface, "public-key"]).strip())
        try:
            runtime_ready = bool(_runtime_ready())
            routing_ready = runtime_ready and _recovery_error is None
        except Exception:
            runtime_ready = routing_ready = False
        handshakes = {f[0]: int(f[1]) for line in _invoke(["show", config.wireguard.interface, "latest-handshakes"]).splitlines() if len(f := line.split()) == 2}
        transfer = {f[0]: (int(f[1]), int(f[2])) for line in _invoke(["show", config.wireguard.interface, "transfer"]).splitlines() if len(f := line.split()) == 3}
        peers = [{**{k: p[k] for k in ("peerId", "publicKey", "address", "allowedIps", "nodeUserId", "expiresAt", "status")},
                  "stateReason": p.get("stateReason"),
                  "kernelPresent": kernel.get(p["publicKey"]) == [p["address"]],
                  "latestHandshake": handshakes.get(p["publicKey"], 0),
                  "receiveBytes": transfer.get(p["publicKey"], (0, 0))[0],
                  "transmitBytes": transfer.get(p["publicKey"], (0, 0))[1]} for p in data["peers"].values()]
        return {"success": True, "interface": config.wireguard.interface, "serverPublicKey": public_key,
                "interfaceAddresses": _interface_addresses(),
                "routingReady": routing_ready, "recoveryReason": _recovery_error,
                "runtimeReason": None if runtime_ready else _runtime_failure_reason(), "peers": peers,
                "occupiedAddresses": sorted({a for values in kernel.values() for a in values}),
                "trafficSource": "wireguard kernel cumulative counters; reset when peer or interface resets; not billing"}


def _delivery_versions():
    """Atomic-replace registries let readers detect concurrent writer commits."""
    versions = []
    for path in (REGISTRY_PATH, manager.CONFIG_PATH, manager.REGISTRY_PATH):
        try:
            stat = path.stat()
            versions.append((stat.st_dev, stat.st_ino, stat.st_size,
                             stat.st_mtime_ns, stat.st_ctime_ns))
        except FileNotFoundError:
            versions.append(None)
    return tuple(versions)


def peer_delivery_status(peer_id, node_user_id, include_runtime=True):
    """Fresh, read-only delivery check without the long reconciliation lock.

    Writers atomically replace the peer registry before revocation/activation.
    Validate the entire registry, read live kernel/binding state, then reject a
    mixed generation. No cached authorization and no route/peer mutation.
    """
    _require_enabled()
    peer_id = _identity(peer_id)
    node_user_id = _identity(node_user_id, "nodeUserId")
    for _ in range(2):
        before = _delivery_versions()
        recovery_reason = _recovery_error
        data = _read()
        peer = data["peers"].get(peer_id)
        public_key = _key(_invoke(["show", config.wireguard.interface, "public-key"]).strip())
        kernel = _kernel()
        runtime_ready = bool(_runtime_ready()) if include_runtime else False
        runtime_reason = (_runtime_failure_reason()
                          if include_runtime and not runtime_ready else None)
        access = False
        selected = []
        if peer is not None and peer["nodeUserId"] == node_user_id:
            source, users = _read_binding_snapshot()
            try:
                fingerprint = _binding_from_snapshot(
                    node_user_id, _date(peer["expiresAt"]), users,
                    _outbounds_by_tag(source), _now())
                access = fingerprint == peer["exitFingerprint"]
            except (WireguardError, ValueError, TypeError, KeyError):
                access = False
            selected.append({
                **{key: peer[key] for key in (
                    "peerId", "publicKey", "address", "allowedIps",
                    "nodeUserId", "expiresAt", "status")},
                "stateReason": peer.get("stateReason"),
                "kernelPresent": kernel.get(peer["publicKey"]) == [peer["address"]],
            })
        if before != _delivery_versions() or recovery_reason != _recovery_error:
            continue
        access = bool(access and peer["status"] == "ACTIVE"
                      and _date(peer["expiresAt"]) > _now()) if selected else False
        return {
            "success": True, "interface": config.wireguard.interface,
            "serverPublicKey": public_key, "peers": selected,
            "runtimeChecked": bool(include_runtime),
            "routingReady": runtime_ready and recovery_reason is None,
            "recoveryReason": recovery_reason, "runtimeReason": runtime_reason,
            "accessByUser": {node_user_id: access},
        }
    raise WireguardError("WireGuard state changed during delivery check; retry", "DELIVERY_SNAPSHOT_CHANGED")


def wireguard_access_snapshot():
    """Return whether each discovered node user is eligible for WireGuard now.

    This is a read-only projection of the same binding, expiry, access and
    residential SOCKS checks used by the peer apply path. It intentionally
    excludes credentials and peer material.
    """
    _require_enabled()
    with _locked():
        source_config, user_registry = _read_binding_snapshot()
        outbounds_by_tag = _outbounds_by_tag(source_config)
        now = _now()
        result = {}
        for user_id in sorted(manager._discover_user_ids(source_config, user_registry)):
            user = user_registry.get("users", {}).get(user_id)
            if not isinstance(user, dict):
                result[user_id] = False
                continue
            try:
                expires_at = _date(user.get("expiresAt"))
                _binding_from_snapshot(
                    user_id, expires_at, user_registry, outbounds_by_tag, now
                )
            except (WireguardError, OSError, ValueError, TypeError, KeyError,
                    manager.SingboxConfigError):
                result[user_id] = False
            else:
                result[user_id] = True
        return result


def start_reconciler():
    global _thread
    if not config.wireguard.enabled or (_thread and _thread.is_alive()):
        return
    # Temporary proxy/read failures must not prevent the retry worker starting.
    # Invalid registries and invalid configuration still fail startup explicitly.
    try:
        reconcile()
    except WireguardRecoveryPending as error:
        logger.error("WireGuard startup recovery pending reason=%s retrySeconds=15", error.code)
    _stop.clear()
    def loop():
        while not _stop.wait(15):
            try:
                reconcile()
            except Exception as error:
                logger.error("WireGuard reconciliation pending reason=%s errorType=%s retrySeconds=15",
                             getattr(error, "code", "RECONCILIATION_FAILED"), type(error).__name__)
    _thread = threading.Thread(target=loop, name="wireguard-reconcile", daemon=True)
    _thread.start()


def stop_reconciler():
    _stop.set()
    if _thread:
        _thread.join(timeout=1)
