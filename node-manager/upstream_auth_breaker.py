"""Durable policy and bounded, redacted observations for SOCKS auth protection.

This store never edits proxy users, billing, access policy or routing. A manual
probe only asks an already reporting core to admit its next single probe.
"""
from __future__ import annotations

from contextlib import contextmanager
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import time


DEFAULTS = {"enabled": True, "threshold": 3, "windowSeconds": 30,
            "cooldownSeconds": 300, "maxCooldownSeconds": 1800}
FIELDS = tuple(DEFAULTS)
POLICY_LIMIT = 65536
STATE_LIMIT = 4 * 1024 * 1024
MAX_CORES = 256
MAX_CIRCUITS = 8192
FRESH_SECONDS = 20
PROBE_TTL_SECONDS = 3600
_lock = threading.RLock()
_identifier = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class BreakerError(Exception):
    def __init__(self, code: str, status: int = 409):
        self.code, self.status = code, status
        super().__init__(code)


def policy_path() -> Path:
    return Path(os.environ.get("NIUSU_UPSTREAM_AUTH_BREAKER_CONFIG")
                or "/var/lib/node-manager/upstream-auth-breaker.json")


def state_directory() -> Path:
    return Path(os.environ.get("NIUSU_UPSTREAM_AUTH_BREAKER_STATE_DIR")
                or "/var/lib/node-manager/upstream-auth-breaker-state")


def _integer(value, low=0, high=2**53 - 1):
    return type(value) is int and low <= value <= high


def _number(value, low=0, high=2**53 - 1):
    return type(value) in (int, float) and math.isfinite(value) and low <= value <= high


def validate_settings(value: dict) -> dict:
    if not isinstance(value, dict) or type(value.get("enabled")) is not bool:
        raise BreakerError("BREAKER_POLICY_INVALID", 422)
    limits = {"threshold": (1, 100), "windowSeconds": (1, 3600),
              "cooldownSeconds": (1, 86400), "maxCooldownSeconds": (1, 86400)}
    for name, (low, high) in limits.items():
        if not _integer(value.get(name), low, high):
            raise BreakerError("BREAKER_POLICY_INVALID", 422)
    if value["maxCooldownSeconds"] < value["cooldownSeconds"]:
        raise BreakerError("BREAKER_COOLDOWN_INVALID", 422)
    return {name: value[name] for name in FIELDS}


def _read_json(path: Path, limit: int):
    """No symlinks, devices, unbounded payloads or raw parser exception output."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        if path.is_symlink():
            raise BreakerError("BREAKER_UNSAFE_FILE", 503)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise BreakerError("BREAKER_UNSAFE_FILE", 503)
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                raw = handle.read(limit + 1)
            if len(raw) > limit:
                raise BreakerError("BREAKER_UNSAFE_FILE", 503)
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise BreakerError("BREAKER_INVALID_FILE", 503)
            return value
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        return None
    except BreakerError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise BreakerError("BREAKER_FILE_UNAVAILABLE", 503) from None


def _policy_document():
    value = _read_json(policy_path(), POLICY_LIMIT)
    if value is None:
        return {"schemaVersion": 1, "revision": 0, **DEFAULTS, "probeRequests": []}, False
    try:
        if type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1 or not _integer(value.get("revision")):
            raise BreakerError("BREAKER_POLICY_INVALID", 503)
        settings = validate_settings(value)
        probes = value.get("probeRequests", [])
        if not isinstance(probes, list) or len(probes) > 128:
            raise BreakerError("BREAKER_POLICY_INVALID", 503)
        for probe in probes:
            if (not isinstance(probe, dict) or not _identifier.fullmatch(str(probe.get("id", "")))
                    or not _identifier.fullmatch(str(probe.get("requestId", "")))
                    or not _number(probe.get("requestedAtUnix"))):
                raise BreakerError("BREAKER_POLICY_INVALID", 503)
        document = {"schemaVersion": 1, "revision": value["revision"], **settings,
                    "probeRequests": probes}
        if "controllerRevision" in value:
            if value.get("controllerId") != "website" or not _integer(value["controllerRevision"]):
                raise BreakerError("BREAKER_POLICY_INVALID", 503)
            document.update(controllerId="website", controllerRevision=value["controllerRevision"],
                            controllerPayload=validate_settings(value.get("controllerPayload")))
        return document, True
    except (BreakerError, TypeError):
        raise BreakerError("BREAKER_POLICY_INVALID", 503) from None


@contextmanager
def _exclusive():
    with _lock:
        path = policy_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = path.with_name(path.name + ".lock")
        if lock_path.is_symlink():
            raise BreakerError("BREAKER_UNSAFE_FILE", 503)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise BreakerError("BREAKER_UNSAFE_FILE", 503)
            if os.name == "nt":
                import msvcrt
                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)


def _write(document):
    destination = policy_path()
    if destination.is_symlink():
        raise BreakerError("BREAKER_UNSAFE_FILE", 503)
    encoded = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode()
    if len(encoded) > POLICY_LIMIT:
        raise BreakerError("BREAKER_POLICY_TOO_LARGE", 409)
    reader_group = os.environ.get("NIUSU_UPSTREAM_AUTH_BREAKER_READER_GROUP", "")
    reader_gid = None
    if reader_group:
        try:
            import grp
            reader_gid = grp.getgrnam(reader_group).gr_gid
        except (ImportError, KeyError, OSError):
            raise BreakerError("BREAKER_READER_GROUP_UNAVAILABLE", 503) from None
    descriptor, temporary = tempfile.mkstemp(prefix="." + destination.name + ".", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if reader_gid is not None:
                os.fchown(handle.fileno(), -1, reader_gid)
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o640 if reader_gid is not None else 0o600)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        if os.name != "nt":
            directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError:
        raise BreakerError("BREAKER_POLICY_WRITE_FAILED", 503) from None
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _live_cores(proc: Path | None = None) -> dict[int, dict]:
    result = {}
    proc = proc or Path("/proc")
    if not proc.is_dir():
        return result
    try:
        directories = list(proc.iterdir())
    except OSError:
        return result
    for directory in directories:
        if not directory.name.isdigit():
            continue
        try:
            args = (directory / "cmdline").read_bytes().split(b"\0")
            argv_name = Path(os.fsdecode(args[0])).name
            executable = Path(os.readlink(directory / "exe").removesuffix(" (deleted)")).name
            if not any(name == "sing-box" or name.startswith("sing-box-") for name in (argv_name, executable)):
                continue
            if b"run" not in args:
                continue
            if not any(item in (b"-c", b"--config") for item in args):
                continue
            raw_stat = (directory / "stat").read_text()
            fields = raw_stat[raw_stat.rfind(")") + 2:].split()
            result[int(directory.name)] = {"processStartTicks": int(fields[19])}
        except (OSError, ValueError, IndexError):
            continue
    return result


def _safe_server(value):
    if not isinstance(value, str) or len(value) > 253 or not value:
        return None
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value):
            return value
    return None


def _public_circuit(raw):
    if not isinstance(raw, dict) or not _identifier.fullmatch(str(raw.get("id", ""))):
        return None
    server = _safe_server(raw.get("server"))
    if not server or not _integer(raw.get("port"), 1, 65535) or raw.get("state") not in ("CLOSED", "OPEN", "HALF_OPEN"):
        return None
    result = {"id": raw["id"], "server": server, "port": raw["port"], "state": raw["state"]}
    for name in ("consecutiveFailures", "totalAuthFailures", "suppressed", "inFlightAuthentication"):
        value = raw.get(name, 0)
        if not _integer(value):
            return None
        result[name] = value
    for name in ("firstFailureAtUnix", "openedAtUnix", "lastFailureAtUnix", "lastSuccessAtUnix", "nextProbeAtUnix"):
        value = raw.get(name, 0)
        if not _number(value):
            return None
        result[name] = value
    return result


def inspect() -> dict:
    policy, configured = _policy_document()
    public_policy = {name: policy[name] for name in ("schemaVersion", "revision", *FIELDS)}
    for name in ("controllerId", "controllerRevision"):
        if name in policy:
            public_policy[name] = policy[name]
    live = _live_cores()
    reports, errors = {}, []
    directory = state_directory()
    if directory.is_symlink():
        errors.append("BREAKER_STATE_DIRECTORY_UNSAFE")
        paths = []
    else:
        try:
            paths = sorted(directory.iterdir(), key=lambda item: item.name) if directory.exists() else []
        except OSError:
            paths = []
            errors.append("BREAKER_STATE_DIRECTORY_UNAVAILABLE")
    candidates = [path for path in paths if re.fullmatch(r"[1-9][0-9]{0,9}\.json", path.name)]
    candidates.sort(key=lambda path: (int(path.stem) not in live, path.name))
    if len(candidates) > MAX_CORES:
        errors.append("BREAKER_TOO_MANY_CORE_REPORTS")
    for path in candidates[:MAX_CORES]:
        try:
            raw = _read_json(path, STATE_LIMIT)
            pid = int(path.stem)
            if raw is None or raw.get("schemaVersion") != 1 or raw.get("pid") != pid:
                raise BreakerError("BREAKER_STATE_INVALID", 503)
            for name in ("processStartedAtUnix", "observedAtUnix"):
                if not _number(raw.get(name)):
                    raise BreakerError("BREAKER_STATE_INVALID", 503)
            if not _integer(raw.get("policyRevision")) or type(raw.get("enabled")) is not bool:
                raise BreakerError("BREAKER_STATE_INVALID", 503)
            circuits = raw.get("circuits", [])
            if not isinstance(circuits, list) or len(circuits) > MAX_CIRCUITS:
                raise BreakerError("BREAKER_STATE_INVALID", 503)
            safe_circuits = [_public_circuit(row) for row in circuits]
            if any(row is None for row in safe_circuits):
                raise BreakerError("BREAKER_STATE_INVALID", 503)
            identity = live.get(pid)
            tick_match = identity is not None and raw.get("processStartTicks") == identity.get("processStartTicks")
            # Heartbeats can advance while several state files are read.
            # Compare with the time after reading this report, not the time
            # at the beginning of the whole inspection.
            age = time.time() - raw["observedAtUnix"]
            fresh = tick_match and 0 <= age <= FRESH_SECONDS
            instance = raw.get("instanceId", "")
            if not isinstance(instance, str) or not _identifier.fullmatch(instance):
                raise BreakerError("BREAKER_STATE_INVALID", 503)
            policy_error = raw.get("policyError", "")
            if policy_error not in ("", "BREAKER_POLICY_INVALID", "BREAKER_POLICY_UNAVAILABLE", "BREAKER_POLICY_READ_FAILED"):
                policy_error = "BREAKER_POLICY_UNAVAILABLE"
            reports[pid] = {"pid": pid, "instanceId": instance,
                            "processStartTicks": raw.get("processStartTicks"),
                            "processStartedAtUnix": raw["processStartedAtUnix"],
                            "observedAtUnix": raw["observedAtUnix"], "policyRevision": raw["policyRevision"],
                            "enabled": raw["enabled"], "stale": not fresh, "processAlive": identity is not None,
                            "reported": True, "identityMatched": tick_match, "circuits": safe_circuits,
                            "policyError": policy_error}
            for name in ("policyReadAtUnix", "trackedCircuits"):
                if _number(raw.get(name)):
                    reports[pid][name] = raw[name]
            if type(raw.get("diagnosticsTruncated")) is bool:
                reports[pid]["diagnosticsTruncated"] = raw["diagnosticsTruncated"]
            if _integer(raw.get("omittedCircuits")):
                reports[pid]["omittedCircuits"] = raw["omittedCircuits"]
        except BreakerError as error:
            errors.append(error.code)
    for pid in live:
        if pid not in reports:
            reports[pid] = {"pid": pid, "reported": False, "stale": True, "processAlive": True,
                            "identityMatched": False, "circuits": []}
            errors.append("BREAKER_CORE_UNREPORTED")
    cores = [reports[pid] for pid in sorted(reports)]
    active = [row for row in cores if row["processAlive"]]
    for core in active:
        if core["reported"] and core["stale"]:
            errors.append("BREAKER_CORE_STALE")
        if core["reported"] and (core["policyRevision"] != policy["revision"] or core["enabled"] != policy["enabled"]):
            errors.append("BREAKER_POLICY_PENDING")
        if core.get("policyError"):
            errors.append("BREAKER_CORE_POLICY_ERROR")
    applied = bool(active) and not errors and all(
        row["reported"] and not row["stale"] and row["policyRevision"] == policy["revision"]
        and row["enabled"] == policy["enabled"] and not row.get("policyError") for row in active)
    return {"policy": public_policy, "configured": configured,
            "policySource": "FILE" if configured else "DEFAULT", "cores": cores,
            "allReportedCoresApplied": applied, "applicationConfirmed": applied,
            "status": "APPLIED" if applied else ("PENDING" if active else "UNREPORTED"),
            "stateErrors": sorted(set(errors)), "observedAtUnix": time.time()}


def update(settings: dict, expected_revision: int, controller_id=None, controller_revision=None):
    settings = validate_settings(settings)
    if not _integer(expected_revision):
        raise BreakerError("BREAKER_REVISION_INVALID", 422)
    if (controller_id is None) != (controller_revision is None):
        raise BreakerError("BREAKER_CONTROLLER_INVALID", 422)
    if controller_id is not None and (controller_id != "website" or not _integer(controller_revision)):
        raise BreakerError("BREAKER_CONTROLLER_INVALID", 422)
    try:
        with _exclusive():
            document, _ = _policy_document()
            same_settings = all(document[name] == settings[name] for name in FIELDS)
            if controller_id:
                old_revision = document.get("controllerRevision", -1)
                if controller_revision < old_revision:
                    raise BreakerError("BREAKER_CONTROLLER_STALE")
                if controller_revision == old_revision:
                    if document.get("controllerPayload") != settings:
                        raise BreakerError("BREAKER_CONTROLLER_CONFLICT")
                    if same_settings:
                        return inspect()
            if document["revision"] != expected_revision:
                raise BreakerError("BREAKER_POLICY_CONFLICT")
            document.update(settings)
            document["revision"] += 1
            if controller_id:
                document.update(controllerId=controller_id, controllerRevision=controller_revision,
                                controllerPayload=settings)
            document["probeRequests"] = [row for row in document["probeRequests"]
                                         if time.time() - row["requestedAtUnix"] < PROBE_TTL_SECONDS]
            _write(document)
    except OSError:
        raise BreakerError("BREAKER_POLICY_WRITE_FAILED", 503) from None
    return inspect()


def request_probe(circuit_id: str, request_id: str):
    if not _identifier.fullmatch(circuit_id) or not _identifier.fullmatch(request_id):
        raise BreakerError("BREAKER_PROBE_INVALID", 422)
    try:
        with _exclusive():
            document, _ = _policy_document()
            previous = next((row for row in document["probeRequests"] if row["requestId"] == request_id), None)
            if previous:
                if previous["id"] != circuit_id:
                    raise BreakerError("BREAKER_PROBE_CONFLICT")
            else:
                if not document["enabled"]:
                    raise BreakerError("BREAKER_DISABLED")
                snapshot = inspect()
                candidates = [row for core in snapshot["cores"] if not core["stale"]
                              and core.get("policyRevision") == document["revision"] and not core.get("policyError")
                              for row in core["circuits"] if row["id"] == circuit_id]
                if not candidates:
                    raise BreakerError("BREAKER_CIRCUIT_NOT_CURRENT", 404)
                if any(row["state"] != "OPEN" for row in candidates):
                    raise BreakerError("BREAKER_CIRCUIT_NOT_OPEN")
                probes = [row for row in document["probeRequests"]
                          if time.time() - row["requestedAtUnix"] < PROBE_TTL_SECONDS]
                if len(probes) >= 128:
                    raise BreakerError("BREAKER_PROBE_QUEUE_FULL", 429)
                probes.append({"id": circuit_id, "requestId": request_id, "requestedAtUnix": int(time.time())})
                document["probeRequests"] = probes
                document["revision"] += 1
                _write(document)
            return {"accepted": True, "requestId": request_id, "circuitId": circuit_id,
                    "policyRevision": document["revision"], "probeRequested": True,
                    "applicationConfirmed": False}
    except OSError:
        raise BreakerError("BREAKER_POLICY_WRITE_FAILED", 503) from None
