"""Read-only protocol admission checks. Never enable, reload or repair listeners."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from auth import verify_token
from config import config
from singbox import manager

router = APIRouter()
PROTOCOLS = {"vless", "vmess", "socks", "trojan"}
MAX_FILE = 16 << 20


class ObservationUnknown(RuntimeError):
    pass


def _read(path: Path, watched: dict | None = None) -> bytes:
    with path.open("rb") as handle:
        value = handle.read(MAX_FILE + 1)
    if len(value) > MAX_FILE:
        raise ObservationUnknown("metadata_too_large")
    if watched is not None:
        watched[path] = value
    return value


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=1)
    if result.returncode:
        raise ObservationUnknown("observation_unavailable")
    return result.stdout


def _pid(unit: str) -> int:
    value = _run(["systemctl", "show", unit, "-p", "MainPID", "--value"]).strip()
    if not value.isdigit():
        raise ObservationUnknown("process_identity_unknown")
    return int(value)


def _identity(pid: int) -> int:
    path = Path("/proc") / str(pid)
    executable = Path(os.readlink(path / "exe")).name.removesuffix(" (deleted)")
    if not executable.startswith(("sing-box", "singbox")):
        raise ObservationUnknown("unexpected_listener_process")
    return int((path / "stat").read_text().rsplit(")", 1)[1].split()[19])


def _listeners() -> list[dict]:
    rows = []
    for line in _run(["ss", "-H", "-lntup"]).splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] not in {"tcp", "udp"}:
            continue
        match = re.search(r":(\d+)$", parts[4])
        if match:
            rows.append({"network": parts[0], "port": int(match[1]),
                         "address": parts[4].rsplit(":", 1)[0].strip("[]"),
                         "pids": {int(pid) for pid in re.findall(r"pid=(\d+)", line)}})
    return rows


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
    pid = _pid("sing-box")
    if pid:
        _identity(pid)
    listeners = _listeners()
    for inbound in requested:
        port, owner, listen = _generation(inbound, pid, watched)
        if not owner:
            return {"state": "UNAVAILABLE", "reason": "SERVICE_NOT_RUNNING"}
        transport = inbound.get("transport") or {}
        network = "udp" if transport.get("type") == "quic" else "tcp"
        address = str(listen).strip("[]")
        addresses = {"::", "*"} if address == "::" else {"0.0.0.0", "*", "::"} if address == "0.0.0.0" else {address}
        rows = [row for row in listeners if row["network"] == network and row["port"] == port
                and row["address"] in addresses]
        if not rows:
            return {"state": "UNAVAILABLE", "reason": "INBOUND_NOT_LISTENING"}
        if not any(row["pids"] == {owner} for row in rows):
            return {"state": "UNKNOWN", "reason": "LISTENER_OWNER_UNVERIFIED"}
    return {"state": "READY", "reason": "LOCAL_LISTENERS_VERIFIED"}


def readiness(protocols: list[str], expected: dict | None = None) -> dict:
    protocols = sorted(set(protocols))
    if not protocols or any(name not in PROTOCOLS for name in protocols):
        raise ValueError("unsupported protocol selection")
    watched = {}
    try:
        data = json.loads(_read(manager.CONFIG_PATH, watched))
        if expected is not None and data != expected:
            raise ObservationUnknown("config_changed")
        result = evaluate(data, protocols, watched)
        if any(_read(path) != value for path, value in watched.items()):
            raise ObservationUnknown("config_changed")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError,
            subprocess.SubprocessError, ObservationUnknown):
        result = {"state": "UNKNOWN", "reason": "CONFIG_OR_RUNTIME_UNVERIFIED"}
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
