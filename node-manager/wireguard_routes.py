"""Isolated fail-closed WireGuard residential egress through a separate sing-box."""
from __future__ import annotations

import copy
import ipaddress
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import config
from singbox import manager
from wireguard import WireguardError, _binding_fingerprint, _resolve_exit_binding

CONFIG_PATH = Path(os.environ.get("NODE_MANAGER_WIREGUARD_PROXY_CONFIG", "/etc/niusu-wireguard/singbox.json"))
SINGBOX = os.environ.get("NODE_MANAGER_WIREGUARD_SINGBOX", "/usr/bin/sing-box")
SERVICE = "niusu-wireguard-proxy.service"
PORT = 61037
MARK = "0x178/0xffffffff"
OUTPUT_CHAIN = "NIUSU_WG_REUSE_OUT"
OUTPUT_CHAIN_MARKER = Path("/var/lib/niusu-wireguard/reuse-output-owned")
HOTLOAD_CHAIN = "NIUSU_WG_HOT"
HOTLOAD_CHAIN_MARKER = Path("/var/lib/niusu-wireguard/hotload-chain-owned")
logger = logging.getLogger(__name__)
_last_runtime_error = None


class GatewayCommandError(RuntimeError):
    def __init__(self, command, returncode):
        super().__init__("WireGuard gateway command failed")
        self.code = "GATEWAY_" + Path(command).name.upper().replace("-", "_") + "_EXIT_" + str(returncode)


def _valid_source(value: str) -> str:
    address = ipaddress.ip_interface(value)
    if address.version != 4 or address.network.prefixlen != 32:
        raise ValueError("WireGuard source must be IPv4 /32")
    return str(address)


def build_config(peers: dict[str, dict[str, Any]], source_config: dict[str, Any],
                 user_registry: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Build a standalone config; every destination without an eligible SOCKS is rejected."""
    now = now or datetime.now(timezone.utc)
    outbounds = source_config.get("outbounds", [])
    outbounds_by_tag: dict[str, dict[str, Any]] = {}
    for outbound in outbounds:
        if isinstance(outbound, dict) and outbound.get("tag"):
            outbounds_by_tag.setdefault(str(outbound["tag"]), outbound)
    users = user_registry.get("users", {})
    result_outbounds: list[dict[str, Any]] = [{"type": "block", "tag": "wg-reject"}]
    used_tags = {"wg-reject"}
    rules: list[dict[str, Any]] = [
        {"inbound": ["wg-tproxy"], "ip_is_private": True, "outbound": "wg-reject"}
    ]

    for peer_id, peer in sorted(peers.items()):
        if peer.get("status") not in {"ACTIVE", "APPLYING"}:
            continue
        source = _valid_source(peer["address"])
        expiration = manager._as_utc(peer.get("expiresAt"))
        user_id = peer.get("nodeUserId")
        user = users.get(user_id) if isinstance(user_id, str) else None
        if (not expiration or expiration <= now or not isinstance(user, dict)
                or user.get("accessEnabled") is False
                or manager._expiration_status(user, now) != "ACTIVE"
                or user.get("expirationBlocked") or user.get("enforcementTrafficBlocked")):
            continue
        try:
            binding = _resolve_exit_binding(user_id, outbounds_by_tag)
        except WireguardError:
            continue
        if peer.get("exitFingerprint") != _binding_fingerprint(binding["identity"]):
            continue
        route_tag = _reserve_tag("wg-egress-" + str(peer_id), used_tags)
        if binding["kind"] == "socks":
            result_outbounds.append({**copy.deepcopy(binding["root"]), "tag": route_tag})
        else:
            member_tags = []
            for index, member in enumerate(binding["members"]):
                member_tag = _reserve_tag(f"wg-egress-upstream-{peer_id}-{index}", used_tags)
                member_tags.append(member_tag)
                result_outbounds.append({**copy.deepcopy(member), "tag": member_tag})
            aggregate = {key: copy.deepcopy(value) for key, value in binding["root"].items()
                         if key not in {"type", "tag", "outbounds"}}
            result_outbounds.append({"type": "urltest", "tag": route_tag,
                                     "outbounds": member_tags, **aggregate})
        rules.append({"inbound": ["wg-tproxy"], "source_ip_cidr": [source], "outbound": route_tag})

    # Missing, expired, or changed bindings all hit this deny rule.
    rules.append({"inbound": ["wg-tproxy"], "outbound": "wg-reject"})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{"type": "tproxy", "tag": "wg-tproxy", "listen": "0.0.0.0", "listen_port": PORT}],
        "outbounds": result_outbounds,
        "route": {"final": "wg-reject", "rules": rules},
    }


def _reserve_tag(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 1
    while candidate in used:
        candidate = f"{base}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _run(args: list[str], timeout: int = 15) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise GatewayCommandError(args[0], result.returncode)
    return result.stdout


def _atomic_write(data: dict[str, Any]) -> None:
    _atomic_write_bytes(json.dumps(data, separators=(",", ":")).encode("utf-8"))


def _atomic_write_bytes(content: bytes) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, tmp = tempfile.mkstemp(prefix="singbox.", suffix=".json", dir=CONFIG_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content.decode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_PATH)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _iptables(*args: str) -> None:
    _run(["iptables", "-w", "5", *args])


def _iptables_restore(batch: str) -> None:
    command = ["iptables-restore", "-w", "5", "--noflush"]
    for extra in (["--test"], []):
        result = subprocess.run(
            [*command, *extra],
            input=batch,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("WireGuard gateway firewall batch was rejected")


def _eligible_sources(rendered: dict[str, Any]) -> list[str]:
    return sorted({
        rule["source_ip_cidr"][0]
        for rule in rendered["route"]["rules"]
        if rule.get("source_ip_cidr")
    })


def _can_reuse_loaded_config(loaded: dict[str, Any], desired: dict[str, Any],
                            peers: dict[str, dict[str, Any]]) -> bool:
    """Keep loaded routes for denied peers, provided every live route is exact.

    Expiration/revocation is enforced by the current kernel peers and firewall,
    not by deleting an inert outbound from the shared process. Never reuse a
    missing or changed live route, or retain an address no longer owned here.
    """
    try:
        def split(data):
            body = copy.deepcopy(data)
            outbounds = body.pop("outbounds")
            rules = body["route"].pop("rules")
            if len(rules) < 2 or "source_ip_cidr" in rules[0] or "source_ip_cidr" in rules[-1]:
                raise ValueError("missing boundary deny rules")
            by_tag = {}
            for outbound in outbounds:
                tag = outbound["tag"]
                if tag in by_tag:
                    raise ValueError("duplicate outbound")
                by_tag[tag] = outbound
            sources, fixed = {}, []
            for rule in rules:
                if "source_ip_cidr" not in rule:
                    fixed.append(rule)
                    continue
                values = rule["source_ip_cidr"]
                if (not isinstance(values, list) or len(values) != 1
                        or rule.get("inbound") != ["wg-tproxy"]
                        or not str(rule.get("outbound", "")).startswith("wg-egress-")):
                    raise ValueError("unexpected source route")
                source = _valid_source(values[0])
                if source in sources:
                    raise ValueError("duplicate source route")
                sources[source] = rule
            if len(fixed) != 2:
                raise ValueError("unexpected fixed rules")
            return body, fixed, sources, by_tag

        old_body, old_fixed, old_sources, old_outbounds = split(loaded)
        new_body, new_fixed, new_sources, new_outbounds = split(desired)
        owned_sources = {_valid_source(peer["address"]) for peer in peers.values()}
        if old_body != new_body or old_fixed != new_fixed:
            return False
        if not set(old_sources).issubset(owned_sources):
            return False
        if any(old_sources.get(source) != rule for source, rule in new_sources.items()):
            return False
        if any(old_outbounds.get(tag) != outbound for tag, outbound in new_outbounds.items()):
            return False
        if any(tag != "wg-reject" and not tag.startswith("wg-egress-")
               for tag in old_outbounds):
            return False
        return True
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _managed_sources(peers: dict[str, dict[str, Any]], source_config: dict[str, Any] | None = None,
                     user_registry: dict[str, Any] | None = None) -> tuple[list[str], list[str]]:
    """Return all owned addresses and the currently eligible source addresses."""
    source_config = source_config if source_config is not None else manager.read_config()
    user_registry = user_registry if user_registry is not None else manager.read_registry()
    all_sources: set[str] = set()
    for peer in peers.values():
        all_sources.add(_valid_source(peer["address"]))
    rendered = build_config(peers, source_config, user_registry)
    return sorted(all_sources), _eligible_sources(rendered)


def _ensure_output_chain() -> None:
    """Own only this chain; never replace unrelated OUTPUT rules."""
    try:
        _run(["iptables", "-w", "5", "-S", OUTPUT_CHAIN])
    except GatewayCommandError:
        _iptables("-N", OUTPUT_CHAIN)
        OUTPUT_CHAIN_MARKER.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        OUTPUT_CHAIN_MARKER.write_text(OUTPUT_CHAIN + "\n", encoding="ascii")
        os.chmod(OUTPUT_CHAIN_MARKER, 0o600)
    if (not OUTPUT_CHAIN_MARKER.exists()
            or OUTPUT_CHAIN_MARKER.read_text(encoding="ascii").strip() != OUTPUT_CHAIN):
        raise RuntimeError("WireGuard output chain ownership could not be verified")
    try:
        _run(["iptables", "-w", "5", "-C", "OUTPUT", "-o", "wg0", "-j", OUTPUT_CHAIN])
    except GatewayCommandError:
        _iptables("-I", "OUTPUT", "1", "-o", "wg0", "-j", OUTPUT_CHAIN)


def _ensure_hotload_chain() -> None:
    try:
        _run(["iptables", "-w", "5", "-t", "mangle", "-S", HOTLOAD_CHAIN])
    except GatewayCommandError:
        _iptables("-t", "mangle", "-N", HOTLOAD_CHAIN)
        HOTLOAD_CHAIN_MARKER.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        HOTLOAD_CHAIN_MARKER.write_text(HOTLOAD_CHAIN + "\n", encoding="ascii")
        os.chmod(HOTLOAD_CHAIN_MARKER, 0o600)
    if (not HOTLOAD_CHAIN_MARKER.exists()
            or HOTLOAD_CHAIN_MARKER.read_text(encoding="ascii").strip() != HOTLOAD_CHAIN):
        raise RuntimeError("WireGuard hotload chain ownership could not be verified")


def _hotload_generation_rules(state: dict[str, Any]) -> list[list[str]]:
    """Pin each connection to its original generation; change only new connections."""
    ports = [generation["port"] for generation in state["generations"]]
    active_port = state["activePort"]
    if (not ports or PORT not in ports or len(ports) != len(set(ports))
            or type(active_port) is not int or active_port not in ports
            or any(type(port) is not int or not PORT <= port < PORT + 8 for port in ports)):
        raise RuntimeError("WireGuard hotload generation ownership is invalid")
    mask = "0xff000000"

    def connection_mark(port):
        return f"{hex((port - PORT + 1) << 24)}/{mask}"

    rules: list[list[str]] = []
    # Existing unmarked TCP and replied UDP sessions predate the first hotload.
    # Keep them on the original listener instead of moving their socket state.
    for proto in ("tcp", "udp"):
        rules.append(["-i", "wg0", "-p", proto, "-m", "connmark", "--mark", f"0x0/{mask}",
                      "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
                      "-j", "CONNMARK", "--set-xmark", connection_mark(PORT)])
    rules.append(["-i", "wg0", "-m", "connmark", "--mark", f"0x0/{mask}",
                  "-j", "CONNMARK", "--set-xmark", connection_mark(active_port)])
    for port in sorted(ports):
        for proto in ("tcp", "udp"):
            rules.append(["-i", "wg0", "-p", proto, "-m", "connmark", "--mark", connection_mark(port),
                          "-j", "TPROXY", "--on-port", str(port), "--tproxy-mark", MARK])
    return rules


def _hotload_prerouting_rules(active_sources: list[str], state: dict[str, Any]) -> list[list[str]]:
    _hotload_generation_rules(state)  # Reject an invalid plan before changing chains.
    return [["-i", "wg0", "-s", _valid_source(source), "-j", HOTLOAD_CHAIN]
            for source in active_sources]


def _canonical_firewall_rule(rule: list[str]) -> list[str]:
    """Compare generated rules despite iptables' harmless display defaults."""
    remaining = list(rule)
    prefix: list[str] = []
    for flag in ("-s", "-d", "-i", "-o", "-p"):
        if flag in remaining:
            index = remaining.index(flag)
            prefix.extend(remaining[index:index + 2])
            del remaining[index:index + 2]
    normalized = prefix + remaining
    if "--on-ip" in normalized:
        index = normalized.index("--on-ip")
        if normalized[index + 1:index + 2] == ["0.0.0.0"]:
            del normalized[index:index + 2]
    for index, token in enumerate(normalized[:-1]):
        if token in {"--mark", "--tproxy-mark"} and normalized[index + 1].endswith("/0xffffffff"):
            normalized[index + 1] = normalized[index + 1].split("/", 1)[0]
    return normalized


def _sync_firewall(peers: dict[str, dict[str, Any]], source_config: dict[str, Any] | None = None,
                   user_registry: dict[str, Any] | None = None,
                   active_sources: list[str] | None = None,
                   hotload_state: dict[str, Any] | None = None) -> None:
    """Block managed addresses first, then install TPROXY rules only for eligible peers."""
    if active_sources is None:
        all_sources, active_sources = _managed_sources(peers, source_config, user_registry)
    else:
        all_sources = sorted({_valid_source(peer["address"]) for peer in peers.values()})
        active_sources = sorted(set(active_sources))
    _ensure_output_chain()
    in_rules: list[list[str]] = []
    fwd_rules: list[list[str]] = []
    pre_rules: list[list[str]] = []

    for source in active_sources:
        # TPROXY keeps the original destination port (for example 443 or 53).
        # The local sing-box listener port is not present on the INPUT packet.
        in_rules.append(["-i", "wg0", "-s", source, "-m", "mark", "--mark", MARK,
                         "-j", "ACCEPT"])
    for source in all_sources:
        in_rules.append(["-s", source, "-j", "DROP"])
        fwd_rules.append(["-s", source, "-j", "DROP"])
    in_rules.append(["-j", "RETURN"])
    fwd_rules.append(["-j", "RETURN"])

    if hotload_state is None:
        from wireguard_hotload import read_state
        hotload_state = read_state(required=False)
    if hotload_state is not None:
        _ensure_hotload_chain()
        pre_rules = _hotload_prerouting_rules(active_sources, hotload_state)
    else:
        for source in active_sources:
            for proto in ("tcp", "udp"):
                pre_rules.append(["-i", "wg0", "-s", source, "-p", proto, "-j", "TPROXY",
                                  "--on-port", str(PORT), "--tproxy-mark", MARK])
    pre_rules.append(["-j", "RETURN"])

    desired = {
        ("filter", "NIUSU_WGM_IN"): in_rules,
        ("filter", "NIUSU_WGM_FWD"): fwd_rules,
        # Retaining the shared process also retains its UDP associations. Deny
        # downstream packets to inactive peers, including existing associations.
        ("filter", OUTPUT_CHAIN): [
            ["-d", source, "-j", "DROP"]
            for source in sorted(set(all_sources) - set(active_sources))
        ] + [["-j", "RETURN"]],
        ("mangle", "NIUSU_WGM_PRE"): pre_rules,
    }
    if hotload_state is not None:
        desired[("mangle", HOTLOAD_CHAIN)] = _hotload_generation_rules(hotload_state) + [["-j", "RETURN"]]
    changed: set[tuple[str, str]] = set()
    for (table, chain), rules in desired.items():
        current = [line.split(f"-A {chain} ", 1)[1].split()
                   for line in _run(["iptables", "-w", "5", "-t", table, "-S", chain]).splitlines()
                   if line.startswith(f"-A {chain}")]
        if ([_canonical_firewall_rule(rule) for rule in current]
                != [_canonical_firewall_rule(rule) for rule in rules]):
            changed.add((table, chain))
    if not changed:
        return

    # Restore filter chains before mangle so managed sources are denied before
    # interception rules are changed. --noflush leaves all unrelated chains intact.
    batch: list[str] = []
    for table in ("filter", "mangle"):
        chains = [chain for candidate_table, chain in desired
                  if candidate_table == table and (table, chain) in changed]
        if not chains:
            continue
        batch.append(f"*{table}")
        for chain in chains:
            batch.append(f"-F {chain}")
            batch.extend(f"-A {chain} {' '.join(rule)}" for rule in desired[(table, chain)])
        batch.append("COMMIT")
    _iptables_restore("\n".join(batch) + "\n")


def quarantine_sources(peers: dict[str, dict[str, Any]], denied_sources: list[str]) -> None:
    """Remove only these sources from current firewall grants; do not restart the proxy."""
    denied = {_valid_source(source) for source in denied_sources}
    if not denied:
        return
    current = _run(["iptables", "-w", "5", "-t", "filter", "-S", "NIUSU_WGM_IN"])
    allowed = set()
    for line in current.splitlines():
        fields = line.split()
        if (fields[:2] == ["-A", "NIUSU_WGM_IN"] and "-s" in fields
                and fields[-2:] == ["-j", "ACCEPT"]):
            allowed.add(_valid_source(fields[fields.index("-s") + 1]))
    _sync_firewall(peers, active_sources=sorted(allowed - denied))
    # A missing entry jump must not bypass the deny rules for retained peers.
    for chain, managed in (("INPUT", "NIUSU_WGM_IN"), ("FORWARD", "NIUSU_WGM_FWD")):
        current = _run(["iptables", "-w", "5", "-S", chain])
        if not any(line.split()[-2:] == ["-j", managed] for line in current.splitlines()):
            _iptables("-I", chain, "1", "-i", "wg0", "-j", managed)


def _record_runtime_error(reason):
    global _last_runtime_error
    if reason != _last_runtime_error and reason is not None:
        logger.error("WireGuard runtime unavailable reason=%s", reason)
    _last_runtime_error = reason


def runtime_failure_reason():
    return _last_runtime_error


def _valid_runtime() -> bool:
    try:
        rules = _run(["ip", "-4", "rule", "show"])
        routes = _run(["ip", "-4", "route", "show", "table", "178"])
        # Readers also acquire the xtables lock. Match the bounded wait used by
        # writers so brief contention is not mistaken for a broken gateway.
        mangle = _run(["iptables", "-w", "5", "-t", "mangle", "-S", "PREROUTING"])
        filt_in = _run(["iptables", "-w", "5", "-S", "INPUT"])
        filt_fwd = _run(["iptables", "-w", "5", "-S", "FORWARD"])
        active = _run(["systemctl", "is-active", SERVICE]).strip() == "active"
        mark_ready = ("fwmark 0x178/0xffffffff" in rules or "fwmark 0x178 " in rules)
        checks = ((mark_ready, "POLICY_RULE_MISSING"),
                  ("local default dev lo" in routes, "POLICY_ROUTE_MISSING"),
                  ("NIUSU_WGM_PRE" in mangle, "TPROXY_JUMP_MISSING"),
                  ("NIUSU_WGM_IN" in filt_in, "INPUT_JUMP_MISSING"),
                  ("NIUSU_WGM_FWD" in filt_fwd, "FORWARD_JUMP_MISSING"),
                  (active, "PROXY_SERVICE_INACTIVE"))
        reason = next((reason for ready, reason in checks if not ready), None)
        _record_runtime_error(reason)
        return reason is None
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        _record_runtime_error(getattr(error, "code", "RUNTIME_" + type(error).__name__.upper()))
        return False


def runtime_ready() -> bool:
    if not _valid_runtime():
        return False
    try:
        from wireguard_hotload import _ready, read_state
        state = read_state(required=False)
        port = state["activePort"] if state is not None else PORT
        if not _ready(port):
            _record_runtime_error("ACTIVE_GENERATION_UNREADY" if port != PORT else "PROXY_LISTENER_UNREADY")
            return False
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        _record_runtime_error("HOTLOAD_STATE_UNAVAILABLE")
        return False
    return True


def sync_routes(peers: dict[str, dict[str, Any]], source_config: dict[str, Any] | None = None,
                user_registry: dict[str, Any] | None = None) -> None:
    """Keep all managed source addresses blocked unless config and runtime are ready."""
    if not _valid_runtime():
        raise RuntimeError("dedicated WireGuard gateway runtime is not ready")
    source_config = source_config if source_config is not None else manager.read_config()
    user_registry = user_registry if user_registry is not None else manager.read_registry()
    rendered = build_config(peers, source_config, user_registry)
    from wireguard_hotload import read_state, sync_routes as hotload_sync
    # Once generations exist, their active config is the authority. The base
    # config intentionally stays immutable so its established flows can drain.
    if read_state(required=False) is not None:
        hotload_sync(peers, rendered, source_config, user_registry)
        return
    old = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    loaded = None
    if old is not None:
        try:
            loaded = json.loads(old.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    if loaded == rendered or (
            isinstance(loaded, dict) and _can_reuse_loaded_config(loaded, rendered, peers)):
        _sync_firewall(peers, source_config, user_registry, _eligible_sources(rendered))
        return
    # Candidate validation and readiness happen before promotion. No HUP/restart
    # fallback: a rejected update must leave the existing shared process intact.
    hotload_sync(peers, rendered, source_config, user_registry)

