"""Bounded TCP generations. No production changes occur without an explicit spec.

The original instance is protected because it also owns the legacy WG TPROXY
listener. This module never sends HUP, flushes conntrack, or stops that instance.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


class RolloutError(RuntimeError):
    pass


class CapacityError(RolloutError):
    pass


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
        if os.name != "nt":
            d = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(d)
            finally:
                os.close(d)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def api(endpoint, path, method="GET"):
    # Endpoints come from the root-owned generation journal, never API input.
    port = endpoint["apiPort"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise RolloutError("invalid_api_endpoint")
    headers = {}
    if endpoint.get("apiSecret"):
        headers["Authorization"] = "Bearer " + endpoint["apiSecret"]
    request = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path), headers=headers, method=method
    )
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            request, timeout=4
        ) as response:
            body = response.read(64 * 1024 * 1024 + 1)
            if len(body) > 64 * 1024 * 1024:
                raise RolloutError("metrics_snapshot_too_large")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        if method == "DELETE" and exc.code == 404:
            return {}
        raise RolloutError("instance_api_http_error") from None
    except (OSError, ValueError) as exc:
        raise RolloutError("instance_api_unavailable") from None


MAX_GENERATIONS = 32


def endpoints(state):
    values = [state["baseline"]] + list(state.get("generations", []))
    if len(values) > MAX_GENERATIONS + 1 or len({x["id"] for x in values}) != len(values):
        raise RolloutError("invalid_generation_journal")
    return values


def merged_connections(state, fetch=api):
    result = {"connections": [], "uploadTotal": 0, "downloadTotal": 0}
    seen = set()
    values = endpoints(state)
    with ThreadPoolExecutor(max_workers=len(values)) as pool:
        jobs = [(e, pool.submit(fetch, e, "/connections")) for e in values]
        for endpoint, job in jobs:
            snap = job.result()
            if not isinstance(snap, dict) or not isinstance(
                snap.get("connections"), list
            ):
                raise RolloutError("invalid_connection_snapshot")
            for key in ("uploadTotal", "downloadTotal"):
                number = snap.get(key)
                if type(number) is not int or not 0 <= number <= 2**63 - 1:
                    raise RolloutError("invalid_native_counter")
                initial = endpoint.get("nativeStart", {}).get(key, 0)
                if type(initial) is not int or number < initial:
                    raise RolloutError("instance_native_counter_reset")
                carry = endpoint.get("nativeCarry", {}).get(key, 0)
                if type(carry) is not int or carry < 0:
                    raise RolloutError("invalid_instance_counter_carry")
                result[key] += number - initial + carry
            for item in snap["connections"]:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("id"), str)
                    or not item["id"]
                ):
                    raise RolloutError("unidentified_connection")
                item = copy.deepcopy(item)
                # Preserve IDs of connections already accounted before adoption.
                if endpoint["id"] != "baseline":
                    item["id"] = "rr:" + endpoint["id"] + ":" + item["id"]
                if item["id"] in seen:
                    raise RolloutError("duplicate_connection_identity")
                seen.add(item["id"])
                result["connections"].append(item)
    for key in ("uploadTotal", "downloadTotal"):
        retained = state.get("retiredTotals", {}).get(key, 0)
        if type(retained) is not int or retained < 0:
            raise RolloutError("invalid_retired_counter")
        result[key] += retained
        if result[key] > 2**63 - 1:
            raise RolloutError("counter_overflow")
    return result


def close_connection(state, connection_id, fetch=api):
    target = state["baseline"]
    raw = connection_id
    if connection_id.startswith("rr:"):
        parts = connection_id.split(":", 2)
        if len(parts) != 3:
            raise RolloutError("invalid_connection_identity")
        target = next(
            (e for e in state.get("generations", []) if e["id"] == parts[1]), None
        )
        if target is None:
            raise RolloutError("connection_generation_not_found")
        raw = parts[2]
    fetch(target, "/connections/" + urllib.parse.quote(raw, safe=""), "DELETE")
    return True


def user_fingerprints(config, managed_tags):
    """Auth and per-user routes/outbounds, for detecting obsolete old sessions."""
    users = {}
    for inbound in config.get("inbounds", []):
        if inbound.get("tag") not in managed_tags:
            continue
        for user in inbound.get("users", []):
            name = user.get("name") or user.get("username")
            if not isinstance(name, str) or not name:
                raise RolloutError("managed_user_missing_identity")
            users.setdefault(name, {"auth": [], "rules": [], "outbounds": []})[
                "auth"
            ].append([inbound["tag"], user])
    outbounds = {o.get("tag"): o for o in config.get("outbounds", [])}
    for rule in config.get("route", {}).get("rules", []):
        names = rule.get("auth_user", [])
        if isinstance(names, str):
            names = [names]
        for name in names:
            if name in users:
                users[name]["rules"].append(rule)
                if rule.get("outbound") in outbounds:
                    users[name]["outbounds"].append(outbounds[rule["outbound"]])
    return {name: digest(value) for name, value in users.items()}


def unmanaged_projection(config, managed_tags):
    """WG's independent configuration may not silently become stale."""
    unmanaged = [
        i for i in config.get("inbounds", []) if i.get("tag") not in managed_tags
    ]
    tags = {i.get("tag") for i in unmanaged}
    rules = []
    outbound_tags = set()
    for rule in config.get("route", {}).get("rules", []):
        inbound = rule.get("inbound", [])
        if isinstance(inbound, str):
            inbound = [inbound]
        if tags.intersection(inbound):
            rules.append(rule)
            if rule.get("outbound"):
                outbound_tags.add(rule["outbound"])
    return {
        "inbounds": unmanaged,
        "rules": rules,
        "outbounds": [
            o for o in config.get("outbounds", []) if o.get("tag") in outbound_tags
        ],
    }


def build_candidate(config, mappings, api_port, isolated=False):
    result = copy.deepcopy(config)
    if not mappings or len({m["candidatePort"] for m in mappings}) != len(mappings):
        raise RolloutError("invalid_port_mapping")
    by_tag = {m["tag"]: m for m in mappings}
    if len(by_tag) != len(mappings):
        raise RolloutError("duplicate_inbound_tag")
    inbounds = []
    found = set()
    for inbound in result.get("inbounds", []):
        mapping = by_tag.get(inbound.get("tag"))
        if mapping is None:
            continue
        if inbound.get("type") not in {"vless", "vmess", "socks", "trojan"}:
            raise RolloutError("unsupported_managed_protocol")
        if inbound.get("listen_port") != mapping["publicPort"]:
            raise RolloutError("canonical_port_changed")
        for key in ("publicPort", "candidatePort"):
            if type(mapping[key]) is not int or not 1024 <= mapping[key] <= 65535:
                raise RolloutError("invalid_port")
        inbound["listen"] = "127.0.0.1" if isolated else "0.0.0.0"
        inbound["listen_port"] = mapping["candidatePort"]
        # This rollout owns TCP only. UDP and legacy WG stay on baseline.
        inbounds.append(inbound)
        found.add(inbound["tag"])
    if found != set(by_tag):
        raise RolloutError("managed_inbound_missing")
    result["inbounds"] = inbounds
    experiments = result.get("experimental", {})
    if set(experiments) - {"clash_api"}:
        raise RolloutError("unsupported_experimental_listener")
    clash = experiments.get("clash_api")
    if not isinstance(clash, dict):
        raise RolloutError("clash_metrics_required")
    clash["external_controller"] = "127.0.0.1:%d" % api_port
    return result


def readiness(endpoint, ports, expected_proxy_tags, fetch=api, connect=None):
    for port in ports:
        if connect is None:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass
        else:
            connect(port)
    proxies = fetch(endpoint, "/proxies")
    if not isinstance(proxies, dict) or not isinstance(proxies.get("proxies"), dict):
        raise RolloutError("candidate_proxy_inventory_unavailable")
    if not set(expected_proxy_tags).issubset(proxies["proxies"]):
        raise RolloutError("candidate_route_inventory_incomplete")
    # Real VLESS/VMess/SOCKS handshakes are performed by the probe command too.
    fetch(endpoint, "/connections")


def routing_restore(mappings):
    """One atomic replacement of the owned NAT chain; established flows bypass NAT."""
    lines = ["*nat", ":NIUSU_SB_ACTIVE - [0:0]", "-F NIUSU_SB_ACTIVE"]
    for item in mappings:
        lines.append(
            "-A NIUSU_SB_ACTIVE -p tcp --dport %d -j REDIRECT --to-ports %d"
            % (item["publicPort"], item["candidatePort"])
        )
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def guard_restore(all_mappings):
    """Only remapped original business ports and loopback can reach private slots."""
    lines = [
        "*filter",
        ":NIUSU_SB_GUARD - [0:0]",
        "-F NIUSU_SB_GUARD",
        "-A NIUSU_SB_GUARD -i lo -j ACCEPT",
    ]
    for item in all_mappings:
        lines.append(
            "-A NIUSU_SB_GUARD -p tcp --dport %d -m conntrack --ctstate DNAT --ctorigdstport %d -j ACCEPT"
            % (item["candidatePort"], item["publicPort"])
        )
    lines.extend(["-A NIUSU_SB_GUARD -j DROP", "COMMIT"])
    return "\n".join(lines) + "\n"


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def read_state(spec):
    state = json.loads(Path(spec["statePath"]).read_text())
    if state.get("bootId") != boot_id():
        raise RolloutError("bootstrap_required_after_host_reboot")
    if state.get("phase") not in {"steady", "prepared"}:
        raise RolloutError("rollout_recovery_required")
    return state


def retirement_intent(state, fetch=api):
    """Never terminate a legacy/WG process or an instance with live API sessions."""
    result = copy.deepcopy(state)
    for endpoint in list(result.get("generations", [])):
        if endpoint["id"] == result["activeId"]:
            continue
        snap = fetch(endpoint, "/connections")
        if not isinstance(snap.get("connections"), list):
            raise RolloutError("drain_state_unknown")
        if snap["connections"]:
            continue
        # A second read after quiescence is required by the caller before stop.
        again = fetch(endpoint, "/connections")
        if again.get("connections") != []:
            continue
        for key in ("uploadTotal", "downloadTotal"):
            value = again.get(key)
            if type(value) is not int or value < 0:
                raise RolloutError("drain_counter_unknown")
            result.setdefault("retiredTotals", {}).setdefault(key, 0)
            initial = endpoint.get("nativeStart", {}).get(key, 0)
            if value < initial:
                raise RolloutError("drain_counter_reset")
            result["retiredTotals"][key] += value - initial
        result["phase"] = "retiring"
        result["retiringEndpoint"] = endpoint
        result["generations"].remove(endpoint)
        return result
    return result


def choose_slot(state, slots, available_bytes, reserve_bytes, candidate_budget):
    if available_bytes < reserve_bytes + candidate_budget:
        raise CapacityError("insufficient_memory_keep_existing_instances")
    used = {e["slot"] for e in state.get("generations", [])}
    for slot in slots:
        if slot["name"] not in used:
            return slot
    raise CapacityError("draining_slots_busy_keep_existing_connections")


def validate_transition(state, proposed, managed_tags):
    if digest(unmanaged_projection(proposed, managed_tags)) != state["unmanagedDigest"]:
        raise RolloutError("unmanaged_wg_or_udp_change_requires_separate_publication")
    # Unscoped global routing changes can affect draining sessions, so they
    # require an explicit future migration rather than silent mixed semantics.
    global_rules = [
        r for r in proposed.get("route", {}).get("rules", []) if not r.get("auth_user")
    ]
    if (
        digest({"rules": global_rules, "final": proposed.get("route", {}).get("final")})
        != state["globalRouteDigest"]
    ):
        raise RolloutError("global_routing_change_requires_explicit_migration")


def changed_names(old, new):
    return {name for name, fingerprint in old.items() if new.get(name) != fingerprint}


def matching_connection(item, names, outbound_prefix="node-manager-out:"):
    metadata = item.get("metadata") or {}
    aliases = {
        str(metadata.get(k))
        for k in ("inboundUser", "inbound_user", "authUser", "auth_user", "user")
        if metadata.get(k)
    }
    aliases.update(
        str(item[k])
        for k in ("inboundUser", "inbound_user", "authUser", "auth_user", "user")
        if item.get(k)
    )
    if aliases.intersection(names):
        return True
    ids = {n[len("node-manager:") :] for n in names if n.startswith("node-manager:")}
    return bool(
        {outbound_prefix + user for user in ids}.intersection(item.get("chains") or [])
    )
