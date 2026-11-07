"""Bounded process-local publication diagnostics; no payloads or credentials."""
from __future__ import annotations

from functools import wraps
from contextvars import ContextVar
from contextlib import contextmanager
import threading
import time

_lock = threading.Lock()
_phases = {}
_rejections = {}
operation = ContextVar('runtime_operation_diagnostic', default=None)
PHASES = frozenset({"mutation", "prepare", "file_bundle", "native_apply", "receipt", "publication",
                    "collector_sample", "collector_native", "collector_connections",
                    "collector_projection", "collector_enforcement", "traffic_persistence"})


@contextmanager
def measure(phase):
    if phase not in PHASES:
        raise ValueError("unknown diagnostic phase")
    start = time.monotonic()
    succeeded = False
    try:
        yield
        succeeded = True
    finally:
        elapsed = (time.monotonic() - start) * 1000
        observed = operation.get()
        if observed is not None:
            phases = observed.setdefault('phaseTimesMs', {})
            phases[phase] = round(phases.get(phase, 0.) + elapsed, 2)
            if not succeeded:
                observed.setdefault('failedPhase', phase)
        with _lock:
            row = _phases.setdefault(phase, {"calls": 0, "failures": 0, "totalMs": 0., "maxMs": 0., "lastMs": 0.})
            row["calls"] += 1
            row["failures"] += int(not succeeded)
            row["totalMs"] += elapsed
            row["maxMs"] = max(row["maxMs"], elapsed)
            row["lastMs"] = elapsed


def timed(phase):
    if phase not in PHASES:
        raise ValueError("unknown diagnostic phase")

    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            with measure(phase):
                return function(*args, **kwargs)
        return wrapped
    return decorate


def rejection_category(error):
    # Exceptions can contain usernames, UUIDs or passwords. Retain ONLY a fixed
    # category; never store str(error) or exception objects in diagnostic state.
    message = str(error)
    code = "POLICY_REJECTED"
    for prefix, category in (
        ("user already exists:", "USER_ALREADY_EXISTS"),
        ("SOCKS username already exists", "AUTH_NAME_CONFLICT"),
        ("user version changed;", "USER_VERSION_CONFLICT"),
        ("PROVISIONING_", "LISTENER_READINESS_REJECTED"),
        ("queued user expiration", "EXPIRATION_REJECTED"),
        ("EXPIRED_USER_REQUIRES_", "ARCHIVE_REQUIRED"),
        ("user not found", "USER_NOT_FOUND"),
        ("当前已有这条住宅IP的连接了", "RESIDENTIAL_PROXY_CONFLICT"),
        ("runtime authentication name belongs to", "HISTORICAL_OWNER_CONFLICT"),
        ("proxy loop:", "PROXY_LOOP_REJECTED"),
    ):
        if message.startswith(prefix):
            code = category
            break
    return code


def rejection(error):
    code = rejection_category(error)
    with _lock:
        _rejections[code] = _rejections.get(code, 0) + 1


def snapshot():
    with _lock:
        return {"scope": "process-lifetime", "phases": {
            key: {**row, "meanMs": round(row["totalMs"] / row["calls"], 2),
                  "lastMs": round(row["lastMs"], 2), "maxMs": round(row["maxMs"], 2),
                  "totalMs": round(row["totalMs"], 2)} for key, row in _phases.items()},
            "mutationRejections": dict(_rejections)}
