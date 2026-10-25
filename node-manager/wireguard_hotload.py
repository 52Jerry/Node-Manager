"""Bounded, connection-aware hot switching for the WireGuard TPROXY proxy."""
from __future__ import annotations

import copy
import hashlib
import importlib
import ipaddress
import json
import math
import os
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


BASE_PORT = 61037
SLOT_COUNT = 10
PORT_LIMIT = BASE_PORT + SLOT_COUNT
COOKIE_MASK = 0xFF000000
COOKIE_MASK_TEXT = "0xff000000"
BASE_COOKIE = 1
TEMPLATE_UNIT = "niusu-wireguard-proxy@.service"
STATE_PATH = Path(os.environ.get(
    "NODE_MANAGER_WIREGUARD_HOTLOAD_STATE_PATH",
    os.environ.get("NODE_MANAGER_WIREGUARD_HOTLOAD_STATE", "/var/lib/niusu-wireguard/hotload-state.json"),
))
MIN_DRAIN_SECONDS = 60
_SYNC_LOCK = threading.RLock()


class HotloadPendingError(RuntimeError):
    """The current proxy stays available, but this update needs a later retry."""

    code = "WIREGUARD_HOTLOAD_PENDING"


def _routes():
    return importlib.import_module("wireguard_routes")


def _run(args: list[str], timeout: float = 15) -> str:
    return _routes()._run(args, timeout=timeout)


def _owned_port(port: Any) -> bool:
    return type(port) is int and BASE_PORT <= port < PORT_LIMIT


def _validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        raise ValueError("WireGuard hotload state has an unsupported schema")
    if not _owned_port(value.get("activePort")):
        raise ValueError("WireGuard hotload active port is not owned")
    generations = value.get("generations")
    if not isinstance(generations, list) or not 1 <= len(generations) <= SLOT_COUNT:
        raise ValueError("WireGuard hotload generation count is invalid")

    ports: set[int] = set()
    clean_generations = []
    for generation in generations:
        if not isinstance(generation, dict) or not _owned_port(generation.get("port")):
            raise ValueError("WireGuard hotload generation port is not owned")
        port = generation["port"]
        created_at = generation.get("createdAt")
        digest = generation.get("sha256")
        if (port in ports or isinstance(created_at, bool)
                or not isinstance(created_at, (int, float)) or not math.isfinite(created_at)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("WireGuard hotload generation metadata is invalid")
        ports.add(port)
        clean_generations.append({**generation, "createdAt": float(created_at)})

    if BASE_PORT not in ports or value["activePort"] not in ports:
        raise ValueError("WireGuard hotload state is missing its base or active generation")
    legacy_marked = value.get("legacyMarked", False)
    if type(legacy_marked) is not bool:
        raise ValueError("WireGuard hotload legacy mark status is invalid")
    if not legacy_marked and value["activePort"] != BASE_PORT:
        raise ValueError("WireGuard hotload cannot promote before legacy flows are marked")
    return {**value, "generations": clean_generations, "legacyMarked": legacy_marked}


def read_state(required: bool = False) -> dict[str, Any] | None:
    path = Path(STATE_PATH)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if required:
            raise HotloadPendingError("WireGuard hotload state is missing") from None
        return None
    except OSError as error:
        raise HotloadPendingError("WireGuard hotload state cannot be read") from error
    try:
        return _validate_state(json.loads(raw))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise HotloadPendingError("WireGuard hotload state is invalid; it was not reset") from error


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        Path(temporary).unlink(missing_ok=True)


def _write_state(state: dict[str, Any]) -> None:
    normalized = _validate_state(state)
    body = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    _atomic_write(Path(STATE_PATH), body)


def _generation_path(config_path: Path, port: int) -> Path:
    if port == BASE_PORT:
        return config_path
    return config_path.parent / "generations" / f"{port}.json"


def _canonical_config(config: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(config)
    inbounds = normalized.get("inbounds")
    if not isinstance(inbounds, list):
        raise ValueError("WireGuard candidate has no inbounds")
    target = [item for item in inbounds if isinstance(item, dict)
              and item.get("tag") == "wg-tproxy" and item.get("type") == "tproxy"]
    if len(target) != 1:
        raise ValueError("WireGuard candidate must have one managed TPROXY inbound")
    target[0]["listen_port"] = BASE_PORT
    return normalized


def _config_for_port(config: dict[str, Any], port: int) -> dict[str, Any]:
    if not _owned_port(port):
        raise ValueError("WireGuard generation port is not owned")
    configured = copy.deepcopy(config)
    target = [item for item in configured.get("inbounds", []) if isinstance(item, dict)
              and item.get("tag") == "wg-tproxy" and item.get("type") == "tproxy"]
    if len(target) != 1:
        raise ValueError("WireGuard candidate must have one managed TPROXY inbound")
    target[0]["listen_port"] = port
    return configured


def _config_hash(config: dict[str, Any]) -> str:
    body = json.dumps(_canonical_config(config), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _load_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HotloadPendingError("WireGuard generation config is missing or invalid") from error
    if not isinstance(value, dict):
        raise HotloadPendingError("WireGuard generation config is invalid")
    return value


def _generation(state: dict[str, Any], port: int) -> dict[str, Any]:
    return next(item for item in state["generations"] if item["port"] == port)


def _verify_generation_file(config_path: Path, generation: dict[str, Any]) -> dict[str, Any]:
    config = _load_config(_generation_path(config_path, generation["port"]))
    if _config_hash(config) != generation["sha256"]:
        raise HotloadPendingError("WireGuard generation config does not match its state hash")
    return config


def _generation_record(port: int, config: dict[str, Any], created_at: float | None = None) -> dict[str, Any]:
    return {
        "port": port,
        "createdAt": time.time() if created_at is None else float(created_at),
        "sha256": _config_hash(config),
    }


def _service(port: int) -> str:
    if not _owned_port(port):
        raise ValueError("WireGuard generation port is not owned")
    if port == BASE_PORT:
        return "niusu-wireguard-proxy.service"
    return f"niusu-wireguard-proxy@{port}.service"


def _ensure_template() -> None:
    try:
        output = _run(["systemctl", "cat", TEMPLATE_UNIT], timeout=15)
    except Exception as error:
        raise HotloadPendingError("WireGuard hotload systemd template is not installed") from error
    if not output.strip():
        raise HotloadPendingError("WireGuard hotload systemd template is not installed")


def _conntrack_entries() -> list[dict[str, Any]]:
    output = _run(["conntrack", "-L", "-f", "ipv4", "-o", "extended"], timeout=30)
    entries = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or (stripped.startswith("conntrack ") and "flow entries" in stripped):
            continue
        source = re.search(r"(?:^|\s)src=([^\s]+)", stripped)
        mark = re.search(r"(?:^|\s)mark=([^\s]+)", stripped)
        if not source or not mark:
            raise HotloadPendingError("conntrack output could not be verified safely")
        try:
            raw_mark = mark.group(1)
            mark_value = int(raw_mark, 16 if raw_mark.lower().startswith("0x") else 10)
            source_ip = ipaddress.ip_address(source.group(1))
        except ValueError as error:
            raise HotloadPendingError("conntrack output contains an invalid address or mark") from error
        if source_ip.version != 4:
            continue
        entries.append({"source": source_ip, "mark": mark_value})
    return entries


def _check_initial_mark_ownership(allowed_base_sources: set[ipaddress.IPv4Address] | None = None) -> None:
    try:
        entries = _conntrack_entries()
    except Exception as error:
        raise HotloadPendingError("conntrack is unavailable; hotload ownership was not initialized") from error
    base_mark = BASE_COOKIE << 24
    if any(entry["mark"] & COOKIE_MASK
           and not (allowed_base_sources is not None
                    and entry["source"] in allowed_base_sources
                    and entry["mark"] & COOKIE_MASK == base_mark)
           for entry in entries):
        raise HotloadPendingError("conntrack high mark bits are already in use")


def _check_raw_notrack() -> None:
    try:
        rules = _run(["iptables", "-w", "5", "-t", "raw", "-S"], timeout=15)
    except Exception as error:
        raise HotloadPendingError("raw-table NOTRACK rules could not be checked") from error
    if re.search(r"\bNOTRACK\b|--notrack\b", rules, flags=re.IGNORECASE):
        raise HotloadPendingError("raw-table NOTRACK rules prevent safe connection migration")


def _contains_native_notrack(value: Any) -> bool:
    if isinstance(value, dict):
        return any(str(key).lower() == "notrack" or _contains_native_notrack(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_native_notrack(item) for item in value)
    return False


def _contains_ct_mark_key(value: Any) -> bool:
    if isinstance(value, dict):
        ct = value.get("ct")
        if isinstance(ct, dict) and str(ct.get("key", "")).lower() == "mark":
            return True
        return any(_contains_ct_mark_key(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_ct_mark_key(item) for item in value)
    return False


def _contains_native_ct_mark_write(value: Any) -> bool:
    if isinstance(value, dict):
        mangle = value.get("mangle")
        if isinstance(mangle, dict) and _contains_ct_mark_key(mangle.get("key")):
            return True
        return any(_contains_native_ct_mark_write(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_native_ct_mark_write(item) for item in value)
    return False


def _check_nft_ownership() -> None:
    try:
        ruleset = json.loads(_run(["nft", "-j", "list", "ruleset"], timeout=15))
    except Exception as error:
        raise HotloadPendingError("native nftables ownership could not be checked") from error
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
        raise HotloadPendingError("native nftables ruleset could not be verified")
    if _contains_native_notrack(ruleset):
        raise HotloadPendingError("native nftables NOTRACK rules prevent safe connection migration")
    if _contains_native_ct_mark_write(ruleset):
        raise HotloadPendingError("native nftables rules may overwrite conntrack mark ownership")


def _check_mangle_mark_ownership() -> None:
    try:
        rules = _run(["iptables", "-w", "5", "-t", "mangle", "-S"], timeout=15)
    except Exception as error:
        raise HotloadPendingError("mangle connection-mark rules could not be checked") from error

    owned_chains = {"NIUSU_WGM_PRE", "NIUSU_WG_HOT"}
    for line in rules.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[0] != "-A" or fields[1] in owned_chains:
            continue
        target = None
        if "-j" in fields:
            jump = fields.index("-j")
            if jump + 1 < len(fields):
                target = fields[jump + 1].upper()
        if target != "CONNMARK":
            continue
        if any(option in fields for option in ("--save-mark", "--restore-mark", "--nfmask", "--ctmask")):
            raise HotloadPendingError("another mangle chain may overwrite conntrack mark ownership")
        for option in ("--set-mark", "--set-xmark"):
            if option not in fields:
                continue
            index = fields.index(option)
            if index + 1 >= len(fields):
                raise HotloadPendingError("an mangle conntrack mark rule could not be parsed")
            mark = fields[index + 1].split("/", 1)
            try:
                mark_value = int(mark[0], 0)
                mask = int(mark[1], 0) if len(mark) == 2 else 0xFFFFFFFF
            except ValueError as error:
                raise HotloadPendingError("an mangle conntrack mark rule could not be parsed") from error
            if mask & COOKIE_MASK or mark_value & COOKIE_MASK:
                raise HotloadPendingError("another mangle chain uses the reserved conntrack mark bits")
        if not any(option in fields for option in ("--set-mark", "--set-xmark")):
            raise HotloadPendingError("an unrecognized mangle CONNMARK rule may overwrite owned bits")


def _migrate_legacy(peers: dict[str, dict[str, Any]], routes) -> None:
    owned = {ipaddress.ip_address(routes._valid_source(peer["address"]).split("/")[0])
             for peer in peers.values()}
    if not owned:
        return
    try:
        before = _conntrack_entries()
    except Exception as error:
        raise HotloadPendingError("conntrack entries could not be read for legacy migration") from error
    base_mark = BASE_COOKIE << 24
    existing_sources = {entry["source"] for entry in before
                        if entry["source"] in owned and entry["mark"] & COOKIE_MASK != base_mark}
    networks = list(ipaddress.collapse_addresses(ipaddress.ip_network(f"{address}/32") for address in owned))
    for network in networks:
        if not any(address in network for address in existing_sources):
            continue
        # conntrack-tools applies MARK as (old & ~mask) XOR value in -U mode,
        # so the low mark bits used by unrelated routing remain untouched.
        try:
            _run(["conntrack", "-U", "-f", "ipv4", "--orig-src", str(network), "--mark",
                  f"0x{BASE_COOKIE << 24:08x}/{COOKIE_MASK_TEXT}"], timeout=30)
        except Exception as error:
            # conntrack returns 1 when every matching flow already changed or expired.
            # Verify that exact network afresh instead of treating a harmless race as
            # a permanent hotload failure. Never accept another mark or unreadable state.
            if getattr(error, "code", None) == "GATEWAY_CONNTRACK_EXIT_1":
                try:
                    current = _conntrack_entries()
                    if not any(entry["source"] in network
                               and entry["mark"] & COOKIE_MASK != base_mark for entry in current):
                        continue
                except Exception:
                    pass
            raise HotloadPendingError("an existing WireGuard flow could not be assigned to the base generation") from error

    try:
        after = _conntrack_entries()
    except Exception as error:
        raise HotloadPendingError("legacy WireGuard flow marks could not be verified") from error
    if any(entry["source"] in owned and entry["mark"] & COOKIE_MASK != BASE_COOKIE << 24
           for entry in after):
        raise HotloadPendingError("some existing WireGuard flows are not pinned to the base generation")


def _ready(port: int, timeout: float = 2.0) -> bool:
    service = _service(port)
    deadline = time.monotonic() + max(0.0, timeout)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        raw_pid = _run(["systemctl", "show", service, "--property=MainPID", "--value"],
                       timeout=remaining / 2).strip()
        pid = int(raw_pid)
        if pid <= 0:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        listeners = _run(["ss", "-H", "-lntup"], timeout=remaining)
    except (Exception, ValueError):
        return False
    protocols = set()
    for line in listeners.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0].lower() not in {"tcp", "udp"}:
            continue
        if fields[4].rsplit(":", 1)[-1] != str(port):
            continue
        if re.search(rf"\bpid={pid}\b", line):
            protocols.add(fields[0].lower())
    return protocols == {"tcp", "udp"}


def _wait_ready(port: int, timeout: float = 10.0, interval: float = 0.1,
                max_attempts: int = 100) -> bool:
    deadline = time.monotonic() + timeout
    for attempt in range(max_attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if _ready(port, timeout=min(2.0, remaining)):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0 or attempt + 1 >= max_attempts:
            break
        active = _active_unit(port, timeout=min(0.5, remaining))
        if active is False:
            return False
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
    return False


def _active_unit(port: int, timeout: float = 15) -> bool | None:
    try:
        state = _run(["systemctl", "show", _service(port), "--property=ActiveState", "--value"],
                     timeout=timeout).strip()
        if state in {"inactive", "failed"}:
            return False
        if state == "active":
            return True
        return None
    except Exception:
        return None


def _ensure_active_generation_ready(port: int) -> None:
    if port == BASE_PORT or _wait_ready(port, timeout=2.0, max_attempts=20):
        return
    active = _active_unit(port, timeout=1.0)
    if active is None:
        raise HotloadPendingError("active WireGuard generation health could not be checked")
    if active:
        raise HotloadPendingError("active WireGuard generation is not ready; its process was left running")
    try:
        _run(["systemctl", "start", _service(port)], timeout=30)
    except Exception as error:
        raise HotloadPendingError("active WireGuard generation service could not be recovered") from error
    if not _wait_ready(port):
        raise HotloadPendingError("active WireGuard generation did not recover its TCP and UDP listeners")


def _save_generation(config_path: Path, port: int, config: dict[str, Any]) -> Path:
    path = _generation_path(config_path, port)
    content = json.dumps(_config_for_port(config, port), separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8") + b"\n"
    _atomic_write(path, content)
    return path


def _stop_unprepared(config_path: Path, port: int) -> None:
    """A not-yet-routed candidate may be stopped only before it enters persisted state."""
    try:
        _run(["systemctl", "stop", _service(port)], timeout=30)
        active_state = _run(["systemctl", "show", _service(port), "--property=ActiveState", "--value"],
                            timeout=15).strip()
        if active_state in {"inactive", "failed"}:
            _generation_path(config_path, port).unlink(missing_ok=True)
    except Exception:
        pass


def _conntrack_empty(port: int) -> bool:
    mark = f"0x{(port - BASE_PORT + 1) << 24:08x}/{COOKIE_MASK_TEXT}"
    try:
        output = _run(["conntrack", "-L", "-f", "ipv4", "--mark", mark], timeout=30)
    except Exception:
        return False
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return True
    return all(re.fullmatch(r"(?:conntrack\s+[^:]+:\s*)?0 flow entries have been shown\.?", line)
               for line in lines)


def _endpoint_port(endpoint: str) -> int | None:
    try:
        return int(endpoint.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None


def _wildcard_peer(endpoint: str) -> bool:
    host, separator, port = endpoint.rpartition(":")
    return bool(separator and port == "*" and host in {"*", "0.0.0.0", "::", "[::]"})


def _process_drained(port: int) -> bool:
    try:
        output = _run(["systemctl", "show", _service(port), "--property=ActiveState", "--property=MainPID"],
                      timeout=2).splitlines()
        properties = {}
        for line in output:
            name, separator, value = line.partition("=")
            if not separator:
                return False
            properties[name] = value
        if not {"ActiveState", "MainPID"}.issubset(properties):
            return False
        active_state = properties["ActiveState"].strip()
        raw_pid = properties["MainPID"].strip()
        pid = int(raw_pid)
    except (Exception, ValueError):
        return False
    if active_state in {"inactive", "failed"}:
        return pid == 0
    if active_state != "active" or pid <= 0:
        return False
    try:
        sockets = _run(["ss", "-H", "-ntup"], timeout=5)
    except Exception:
        return False

    for line in sockets.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0].lower() not in {"tcp", "udp"}:
            continue
        pids = {int(value) for value in re.findall(r"\bpid=(\d+)\b", line)}
        local_port = _endpoint_port(fields[4])
        if pid not in pids:
            if local_port == port:
                return False
            continue
        protocol, socket_state, peer = fields[0].lower(), fields[1].upper(), fields[5]
        wildcard_peer = _wildcard_peer(peer)
        if not (local_port == port and wildcard_peer
                and ((protocol == "tcp" and socket_state == "LISTEN")
                     or (protocol == "udp" and socket_state == "UNCONN"))):
            return False
    return True


def _retire_inactive(state: dict[str, Any], config_path: Path) -> dict[str, Any]:
    path = Path(STATE_PATH)
    try:
        persisted_at = path.stat().st_mtime
    except OSError:
        return state
    if time.time() - persisted_at < MIN_DRAIN_SECONDS:
        return state

    for generation in list(state["generations"]):
        port = generation["port"]
        if (port in {BASE_PORT, state["activePort"]} or not _conntrack_empty(port)
                or not _process_drained(port)):
            continue
        try:
            _run(["systemctl", "stop", _service(port)], timeout=30)
            active_state = _run(["systemctl", "show", _service(port), "--property=ActiveState", "--value"],
                                timeout=15).strip()
        except Exception:
            continue
        if active_state not in {"inactive", "failed"}:
            continue

        reduced = copy.deepcopy(state)
        reduced["generations"] = [item for item in reduced["generations"] if item["port"] != port]
        try:
            _write_state(reduced)
        except Exception:
            continue
        _generation_path(config_path, port).unlink(missing_ok=True)
        state = reduced
    return state


def _initial_state(routes, rendered: dict[str, Any], peers: dict[str, dict[str, Any]],
                   source_config: dict[str, Any], user_registry: dict[str, Any]) -> dict[str, Any]:
    config_path = Path(routes.CONFIG_PATH)
    base_config = _load_config(config_path)
    base_record = _generation_record(BASE_PORT, base_config)
    _ensure_template()
    _check_initial_mark_ownership()
    _check_raw_notrack()
    _check_nft_ownership()
    _check_mangle_mark_ownership()
    state = {"version": 1, "activePort": BASE_PORT, "legacyMarked": False,
             "generations": [base_record]}
    _write_state(state)

    old_sources = set(routes._eligible_sources(base_config))
    desired_sources = set(routes._eligible_sources(rendered))
    routes._sync_firewall(peers, source_config, user_registry,
                          active_sources=sorted(old_sources & desired_sources), hotload_state=state)
    _migrate_legacy(peers, routes)
    state["legacyMarked"] = True
    _write_state(state)
    return state


def _active_config(routes, state: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    config_path = Path(routes.CONFIG_PATH)
    generation = _generation(state, state["activePort"])
    loaded = _verify_generation_file(config_path, generation)
    return _generation_path(config_path, state["activePort"]), loaded


def _candidate_for_hash(state: dict[str, Any], config_path: Path, digest: str) -> int | None:
    for generation in state["generations"]:
        if generation["port"] == state["activePort"] or generation["sha256"] != digest:
            continue
        try:
            _verify_generation_file(config_path, generation)
        except HotloadPendingError:
            continue
        if _ready(generation["port"]):
            return generation["port"]
    return None


def _allocate_port(state: dict[str, Any]) -> int | None:
    tracked = {generation["port"] for generation in state["generations"]}
    for port in range(BASE_PORT + 1, PORT_LIMIT):
        if port in tracked:
            continue
        active = _active_unit(port)
        if active is False:
            return port
    return None


def _rollback_firewall(routes, peers, source_config, user_registry, old_state,
                       old_sources: set[str], desired_sources: set[str]) -> None:
    routes._sync_firewall(
        peers,
        source_config,
        user_registry,
        active_sources=sorted(old_sources & desired_sources),
        hotload_state=old_state,
    )


def _promote(routes, peers, rendered, source_config, user_registry,
             state: dict[str, Any], active_config: dict[str, Any], port: int) -> dict[str, Any]:
    old_state = copy.deepcopy(state)
    old_sources = set(routes._eligible_sources(active_config))
    desired_sources = set(routes._eligible_sources(rendered))
    promoted = copy.deepcopy(state)
    promoted["activePort"] = port
    try:
        routes._sync_firewall(peers, source_config, user_registry,
                              active_sources=sorted(desired_sources), hotload_state=promoted)
    except Exception as firewall_error:
        try:
            _rollback_firewall(routes, peers, source_config, user_registry, old_state,
                               old_sources, desired_sources)
        except Exception as rollback_error:
            raise HotloadPendingError(
                "WireGuard route switch failed; old flows and the prepared generation remain recorded"
            ) from rollback_error
        raise HotloadPendingError("WireGuard route switch failed; the previous legal routes were restored") from firewall_error

    try:
        _write_state(promoted)
    except Exception as state_error:
        try:
            _write_state(old_state)
        except Exception:
            pass
        try:
            _rollback_firewall(routes, peers, source_config, user_registry, old_state,
                               old_sources, desired_sources)
        except Exception as rollback_error:
            raise HotloadPendingError(
                "WireGuard active state commit failed; candidate and possible marked flows remain recorded"
            ) from rollback_error
        raise HotloadPendingError("WireGuard active state commit failed; previous routes were restored") from state_error
    return promoted


def _start_new_candidate(routes, state, rendered, config_path) -> int:
    digest = _config_hash(rendered)
    port = _allocate_port(state)
    if port is None:
        raise HotloadPendingError("all ten WireGuard hotload slots are occupied or not safely reclaimable")

    path = _save_generation(config_path, port, rendered)
    try:
        _run([routes.SINGBOX, "check", "-c", str(path)], timeout=30)
        _run(["systemctl", "start", _service(port)], timeout=60)
        if not _wait_ready(port):
            raise HotloadPendingError("WireGuard candidate did not expose TCP and UDP listeners from its MainPID")
    except Exception as error:
        _stop_unprepared(config_path, port)
        if isinstance(error, HotloadPendingError):
            raise
        raise HotloadPendingError("WireGuard candidate validation or startup failed") from error

    prepared = copy.deepcopy(state)
    prepared["generations"].append(_generation_record(port, rendered))
    try:
        _write_state(prepared)
    except Exception as error:
        # It has not been routed yet; nevertheless do not stop a process whose
        # state persistence had an ambiguous result.
        raise HotloadPendingError("WireGuard candidate is ready but its generation state could not be persisted") from error
    return port


def sync_routes(peers: dict[str, dict[str, Any]], rendered: dict[str, Any],
                source_config: dict[str, Any], user_registry: dict[str, Any]) -> None:
    """Start and promote a validated generation without reloading the base process."""
    routes = _routes()
    config_path = Path(routes.CONFIG_PATH)
    normalized_desired = _canonical_config(rendered)

    with _SYNC_LOCK:
        state = read_state(required=False)
        if state is None:
            base_config = _load_config(config_path)
            canonical_base = _canonical_config(base_config)
            reusable = (canonical_base == normalized_desired
                        or routes._can_reuse_loaded_config(canonical_base, normalized_desired, peers))
            if reusable:
                routes._sync_firewall(peers, source_config, user_registry,
                                      routes._eligible_sources(rendered))
                return
            state = _initial_state(routes, rendered, peers, source_config, user_registry)

        if not state["legacyMarked"]:
            if state["activePort"] != BASE_PORT:
                raise HotloadPendingError("legacy WireGuard flows must be pinned before promotion")
            _, base_config = _active_config(routes, state)
            old_sources = set(routes._eligible_sources(base_config))
            desired_sources = set(routes._eligible_sources(rendered))
            owned_sources = {
                ipaddress.ip_address(routes._valid_source(peer["address"]).split("/")[0])
                for peer in peers.values()
            }
            _check_initial_mark_ownership(owned_sources)
            _check_raw_notrack()
            _check_nft_ownership()
            _check_mangle_mark_ownership()
            routes._sync_firewall(peers, source_config, user_registry,
                                  active_sources=sorted(old_sources & desired_sources), hotload_state=state)
            _migrate_legacy(peers, routes)
            state["legacyMarked"] = True
            _write_state(state)

        _, active_config = _active_config(routes, state)
        if state["activePort"] != BASE_PORT:
            _ensure_active_generation_ready(state["activePort"])
        canonical_active = _canonical_config(active_config)
        if (canonical_active == normalized_desired
                or routes._can_reuse_loaded_config(canonical_active, normalized_desired, peers)):
            routes._sync_firewall(peers, source_config, user_registry,
                                  routes._eligible_sources(rendered), hotload_state=state)
            state = _retire_inactive(state, config_path)
            return

        digest = _config_hash(rendered)
        state = _retire_inactive(state, config_path)
        candidate_port = _candidate_for_hash(state, config_path, digest)
        if candidate_port is None:
            _ensure_template()
            candidate_port = _start_new_candidate(routes, state, rendered, config_path)
            state = read_state(required=True)
        _promote(routes, peers, rendered, source_config, user_registry, state,
                 active_config, candidate_port)
        _retire_inactive(read_state(required=True), config_path)
