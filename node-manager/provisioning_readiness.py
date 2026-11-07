"""Read-only protocol admission checks. Never enable, reload or repair listeners."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from contextvars import ContextVar
from pathlib import Path
import re
import shlex
import subprocess
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from auth import verify_token
from config import config
from singbox import manager

router = APIRouter()
PROTOCOLS = {"vless", "vmess", "socks", "trojan"}
MAX_FILE = 16 << 20
OBSERVATION_SECONDS = 3.5
_deadline = ContextVar("provisioning_observation_deadline", default=None)
_REASONS = frozenset({
    "METADATA_TOO_LARGE", "OBSERVATION_TIMEOUT", "OBSERVATION_UNAVAILABLE",
    "PROCESS_IDENTITY_UNKNOWN", "PROCESS_IDENTITY_UNVERIFIED", "PROCESS_CHANGED",
    "UNEXPECTED_LISTENER_PROCESS", "LISTENER_OWNER_UNVERIFIED", "CONFIG_CHANGED",
    "PUBLICATION_INBOUND_MISMATCH", "PUBLICATION_NOT_STEADY", "PUBLICATION_ROUTE_MISMATCH",
    "PUBLICATION_IDENTITY_UNKNOWN", "UNOWNED_GENERATION", "INVALID_GENERATION_IDENTITY",
    "GENERATION_PROCESS_CHANGED", "PUBLICATION_HOOK_MISSING", "GENERATION_CONFIG_CHANGED",
    "GENERATION_INBOUND_MISSING", "LISTENER_OBSERVATION_TIMEOUT", "PROCESS_OBSERVATION_TIMEOUT",
    "PUBLICATION_OBSERVATION_TIMEOUT", "LISTENER_OBSERVATION_UNAVAILABLE",
    "PROCESS_OBSERVATION_UNAVAILABLE", "PUBLICATION_OBSERVATION_UNAVAILABLE",
})


class ObservationUnknown(RuntimeError):
    def __init__(self, reason):
        reason = str(reason).upper()
        self.reason = reason if reason in _REASONS else "CONFIG_OR_RUNTIME_UNVERIFIED"
        super().__init__(self.reason)


def _remaining():
    deadline = _deadline.get()
    remaining = OBSERVATION_SECONDS if deadline is None else deadline - time.monotonic()
    if remaining <= 0:
        raise ObservationUnknown("observation_timeout")
    return remaining


def _read(path: Path, watched: dict | None = None) -> bytes:
    _remaining()
    with path.open("rb") as handle:
        value = handle.read(MAX_FILE + 1)
    if len(value) > MAX_FILE:
        raise ObservationUnknown("metadata_too_large")
    if watched is not None:
        if path in watched and watched[path] != value:
            raise ObservationUnknown("config_changed")
        watched[path] = value
    return value


def _run(command: list[str]) -> str:
    category = {"ss": "LISTENER", "systemctl": "PROCESS", "iptables": "PUBLICATION"}.get(command[0], "OBSERVATION")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=min(1, _remaining()))
    except subprocess.TimeoutExpired:
        raise ObservationUnknown(category + "_OBSERVATION_TIMEOUT") from None
    except OSError:
        raise ObservationUnknown(category + "_OBSERVATION_UNAVAILABLE") from None
    if result.returncode:
        raise ObservationUnknown(category + "_OBSERVATION_UNAVAILABLE")
    return result.stdout


def _pid(unit: str) -> int:
    value = _run(["systemctl", "show", unit, "-p", "MainPID", "--value"]).strip()
    if not value.isdigit():
        raise ObservationUnknown("process_identity_unknown")
    return int(value)


def _identity(pid: int) -> int:
    try:
        path = Path("/proc") / str(pid)
        executable = Path(os.readlink(path / "exe")).name
        if executable.endswith(" (deleted)"):
            executable = executable[:-10]
        if not executable.startswith(("sing-box", "singbox")):
            raise ObservationUnknown("unexpected_listener_process")
        return int((path / "stat").read_text().rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        raise ObservationUnknown("process_identity_unverified") from None


def _listeners(ports) -> list[dict]:
    rows = []
    # -p scans every process's descriptors. Ask the kernel only for the target
    # listening ports, then prove their inodes against the expected core below.
    expression = "( " + " or ".join("sport = :" + str(port) for port in sorted(set(ports))) + " )"
    for line in _run(["ss", "-H", "-lntue", expression]).splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] not in {"tcp", "udp"}:
            continue
        match = re.search(r":(\d+)$", parts[4])
        if match:
            inode = re.search(r"\bino:(\d+)\b", line)
            rows.append({"network": parts[0], "port": int(match[1]),
                         "address": parts[4].rsplit(":", 1)[0].strip("[]"),
                         "inode": int(inode.group(1)) if inode else 0})
    return rows


def _owned_sockets(pid: int, inodes: set[int]) -> dict[int, str]:
    """Find only the required sockets in the expected process, never all /proc."""
    found = {}
    try:
        with os.scandir(Path("/proc") / str(pid) / "fd") as descriptors:
            for descriptor in descriptors:
                _remaining()
                try:
                    target = os.readlink(descriptor.path)
                except FileNotFoundError:
                    continue  # An unrelated connection can close during the scan.
                match = re.fullmatch(r"socket:\[(\d+)\]", target)
                if match and int(match.group(1)) in inodes:
                    found[int(match.group(1))] = descriptor.path
                    if len(found) == len(inodes):
                        break
    except OSError:
        raise ObservationUnknown("listener_owner_unverified") from None
    return found


def _verify_descriptors(found):
    # A socket closed/replaced during observation cannot supply a READY proof.
    for inode, descriptor in found.items():
        _remaining()
        try:
            if os.readlink(descriptor) != "socket:[" + str(inode) + "]":
                raise ObservationUnknown("listener_owner_unverified")
        except OSError:
            raise ObservationUnknown("listener_owner_unverified") from None


def _generation(inbound: dict, pid: int, watched: dict) -> tuple[int, int, str]:
    """Resolve the published VLESS listener rather than an old draining slot."""
    spec_path = os.environ.get("NODE_MANAGER_VLESS_PUBLICATION_SPEC")
    if inbound.get("type") != "vless" or not spec_path:
        return inbound["listen_port"], pid, inbound.get("listen") or "::"
    spec = json.loads(_read(Path(spec_path), watched))
    if spec.get("enabled") is not True:
        return inbound["listen_port"], pid, inbound.get("listen") or "::"
    if spec.get("vlessTag") != inbound.get("tag"):
        raise ObservationUnknown("publication_inbound_mismatch")
    state = json.loads(_read(Path(spec["statePath"]), watched))
    if state.get("phase") != "steady" or state.get("bootId") != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        raise ObservationUnknown("publication_not_steady")
    rules = [shlex.split(line) for line in _run(["iptables", "-w", "1", "-t", "nat", "-S"]).splitlines() if line.startswith("-A ")]
    active_rules = [row for row in rules if row[1] == "NIUSU_VLESS_ACTIVE"]
    if state.get("activeId") == "baseline":
        if active_rules:
            raise ObservationUnknown("publication_route_mismatch")
        return inbound["listen_port"], pid, inbound.get("listen") or "::"
    active = [row for row in state.get("generations", []) if row.get("id") == state.get("activeId")]
    if len(active) != 1 or len(active_rules) != 1:
        raise ObservationUnknown("publication_identity_unknown")
    generation = active[0]
    unit = generation.get("unit", "")
    if not re.fullmatch(r"niusu-vless-gen-[0-9a-f]{12}\.service", unit):
        raise ObservationUnknown("unowned_generation")
    owner, port = generation.get("pid"), generation.get("port")
    if type(owner) is not int or owner <= 0 or type(port) is not int or not 1 <= port <= 65535:
        raise ObservationUnknown("invalid_generation_identity")
    if _pid(unit) != owner or _identity(owner) != generation.get("startTicks"):
        raise ObservationUnknown("generation_process_changed")
    route = active_rules[0]
    def option(row, key):
        return row[row.index(key) + 1] if key in row and row.index(key) + 1 < len(row) else None
    if (option(route, "-p") != "tcp" or option(route, "--dport") != str(inbound["listen_port"])
            or option(route, "-j") != "REDIRECT" or option(route, "--to-ports") != str(port)):
        raise ObservationUnknown("publication_route_mismatch")
    for hook in ["PREROUTING", "OUTPUT"]:
        if not any(row[1] == hook and option(row, "-j") == "NIUSU_VLESS_ACTIVE"
                   and option(row, "--dport") == str(inbound["listen_port"]) for row in rules):
            raise ObservationUnknown("publication_hook_missing")
    value = json.loads(_read(Path(generation["configPath"]), watched))
    fingerprint = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if fingerprint != generation.get("configHash"):
        raise ObservationUnknown("generation_config_changed")
    matches = [row for row in value.get("inbounds", []) if row.get("tag") == inbound.get("tag")
               and row.get("type") == "vless" and row.get("listen_port") == port]
    if len(matches) != 1:
        raise ObservationUnknown("generation_inbound_missing")
    return port, owner, matches[0].get("listen") or "::"


def evaluate(data: dict, protocols: list[str], watched: dict) -> dict:
    tags = {name: getattr(config.singbox, name + "_tag", name) for name in PROTOCOLS}
    requested = []
    for name in protocols:
        matches = [row for row in data.get("inbounds", []) if row.get("tag") == tags[name]]
        if not matches:
            return {"state": "DISABLED", "reason": "INBOUND_NOT_CONFIGURED"}
        if len(matches) != 1 or matches[0].get("type") != name:
            return {"state": "UNKNOWN", "reason": "INBOUND_IDENTITY_INVALID"}
        inbound = matches[0]
        port = inbound.get("listen_port")
        if type(port) is not int or not 1 <= port <= 65535:
            return {"state": "UNKNOWN", "reason": "LISTENER_CONFIGURATION_UNKNOWN"}
        requested.append(inbound)
    pid = _pid(config.singbox.service)
    identities = {pid: _identity(pid)} if pid else {}
    resolved = []
    for inbound in requested:
        port, owner, listen = _generation(inbound, pid, watched)
        if not owner:
            return {"state": "UNAVAILABLE", "reason": "SERVICE_NOT_RUNNING"}
        if owner not in identities:
            identities[owner] = _identity(owner)
        resolved.append((inbound, port, owner, listen))
    listeners = _listeners([port for _, port, _, _ in resolved])
    required = {}
    for inbound, port, owner, listen in resolved:
        transport = inbound.get("transport") or {}
        network = "udp" if transport.get("type") == "quic" else "tcp"
        address = str(listen).strip("[]")
        addresses = {"::", "*"} if address == "::" else {"0.0.0.0", "*", "::"} if address == "0.0.0.0" else {address}
        rows = [row for row in listeners if row["network"] == network and row["port"] == port
                and row["address"] in addresses]
        if not rows:
            return {"state": "UNAVAILABLE", "reason": "INBOUND_NOT_LISTENING"}
        # Every matching listener must be owned by this core. A second socket
        # on the same address/port (SO_REUSEPORT) must not hide a foreign owner.
        if any(type(row.get("inode")) is not int or row["inode"] <= 0 for row in rows):
            return {"state": "UNKNOWN", "reason": "LISTENER_OWNER_UNVERIFIED"}
        required.setdefault(owner, set()).update(row["inode"] for row in rows)
    descriptors = {}
    for owner, inodes in required.items():
        found = _owned_sockets(owner, inodes)
        if set(found) != inodes:
            return {"state": "UNKNOWN", "reason": "LISTENER_OWNER_UNVERIFIED"}
        descriptors[owner] = found
    # Resolve publication metadata/routes again before granting readiness. The
    # active generation and its systemd PID must still be the observed pair.
    if _pid(config.singbox.service) != pid:
        raise ObservationUnknown("process_changed")
    for inbound, port, owner, listen in resolved:
        if _generation(inbound, pid, watched) != (port, owner, listen):
            raise ObservationUnknown("generation_process_changed")
    if any(_identity(owner) != identity for owner, identity in identities.items()):
        raise ObservationUnknown("process_changed")
    for found in descriptors.values():
        _verify_descriptors(found)
    _remaining()
    return {"state": "READY", "reason": "LOCAL_LISTENERS_VERIFIED"}


def readiness(protocols: list[str], expected: dict | None = None) -> dict:
    protocols = sorted(set(protocols))
    if not protocols or any(name not in PROTOCOLS for name in protocols):
        raise ValueError("unsupported protocol selection")
    watched = {}
    token = _deadline.set(time.monotonic() + OBSERVATION_SECONDS)
    try:
        data = json.loads(_read(manager.CONFIG_PATH, watched))
        if expected is not None and data != expected:
            raise ObservationUnknown("config_changed")
        result = evaluate(data, protocols, watched)
        if any(_read(path) != value for path, value in watched.items()):
            raise ObservationUnknown("config_changed")
        _remaining()
    except ObservationUnknown as error:
        result = {"state": "UNKNOWN", "reason": error.reason}
    except subprocess.TimeoutExpired:
        result = {"state": "UNKNOWN", "reason": "OBSERVATION_TIMEOUT"}
    except OSError:
        result = {"state": "UNKNOWN", "reason": "METADATA_UNAVAILABLE"}
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, subprocess.SubprocessError):
        result = {"state": "UNKNOWN", "reason": "CONFIG_OR_RUNTIME_UNVERIFIED"}
    finally:
        _deadline.reset(token)
    # No credentials, process IDs, listener ports or full configuration are exposed.
    return {"version": 1, "createGuard": "require_readiness" in inspect.signature(manager.create_user).parameters,
            "protocols": protocols, **result}


def assert_user_provisioning_allowed(data: dict, protocols: list[str]) -> None:
    result = readiness(protocols, expected=data)
    if result["state"] != "READY":
        raise manager.SingboxConfigError("PROVISIONING_" + result["state"])


@router.get("/api/singbox/provisioning-readiness", tags=["sing-box"])
def provisioning_readiness(response: Response, protocols: str = Query(..., max_length=64),
                           _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    values = [value.strip().lower() for value in protocols.split(",")]
    if not values or any(value not in PROTOCOLS for value in values):
        raise HTTPException(422, "unsupported protocol selection")
    return readiness(values)
