from __future__ import annotations

import atexit
import math
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import psutil

from singbox.manager import is_singbox_running, singbox_api


def get_cpu_usage() -> float:
    # A one-second blocking sample made every heartbeat and manual refresh
    # visibly slow. A short sample is sufficient for the dashboard metric.
    return psutil.cpu_percent(interval=0.1)


def get_memory_usage() -> float:
    memory = psutil.virtual_memory()
    return memory.percent

def _measure_system_connections() -> int:
    """Read host socket counts in the sampler, never in a request handler."""
    if sys.platform.startswith("linux"):
        try:
            total = 0
            for name in ("tcp", "tcp6", "udp", "udp6", "unix"):
                try:
                    with (Path("/proc/net") / name).open(encoding="ascii") as table:
                        next(table, None)
                        total += sum(1 for line in table if line.strip())
                except FileNotFoundError:
                    if name not in ("tcp6", "udp6"):
                        raise
            return total
        except OSError:
            pass
    return len(psutil.net_connections())


def get_system_connections() -> int:
    # Retain this standalone helper's historical API. The background sampler
    # uses the strict measurement above so an error never becomes a healthy 0.
    try:
        return _measure_system_connections()
    except Exception:
        return 0


def get_proxy_connections() -> int:
    # The background collector already samples the merged baseline/VLESS
    # connection set. Reading its snapshot keeps heartbeats responsive when
    # many rolling generations would make a fresh API merge expensive.
    try:
        from monitor.traffic import _read_store

        # The collector writes the file atomically. Avoid its in-process lock:
        # a large persistence pass can hold that lock longer than the control
        # plane's heartbeat timeout.
        store = _read_store()
        if store.get("collectedAt") is not None:
            return sum(1 for item in store.get("connections", {}).values()
                       if item.get("online", True))
    except (OSError, ValueError):
        pass
    snapshot = singbox_api.get_connections()
    connections = snapshot.get("connections") if isinstance(snapshot, dict) else None
    return len(connections) if isinstance(connections, list) else 0


STATUS_SAMPLE_INTERVAL_SECONDS = 3.0
STATUS_STALE_AFTER_SECONDS = 9.0
SYSTEM_CONNECTION_SAMPLE_INTERVAL_SECONDS = 30.0
_METRIC_NAMES = ("singbox", "cpu", "memory", "connections", "systemConnections")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _observation_time(value: object, now: datetime) -> datetime | None:
    """Untrusted/old stores must not freshen a value with an invalid clock."""
    if not isinstance(value, str) or not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            return None
        stamp = stamp.astimezone(timezone.utc)
        return stamp if stamp <= now else None
    except (TypeError, ValueError, OverflowError):
        return None


def _reason(value: object, default: str | None = None) -> str | None:
    # Project diagnostic codes, never arbitrary exception text or store data.
    return value if (isinstance(value, str) and len(value) <= 128
                     and re.fullmatch(r"[a-z][a-z0-9_:.-]*", value)) else default


class _StatusSampler:
    """One bounded dashboard snapshot and one non-overlapping sampling worker.

    This cache is only for observability. Quota, authorization and runtime
    mutation paths must continue reading their authoritative state directly.
    """

    def __init__(
        self,
        interval: float = STATUS_SAMPLE_INTERVAL_SECONDS,
        stale_after: float = STATUS_STALE_AFTER_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        system_interval: float = SYSTEM_CONNECTION_SAMPLE_INTERVAL_SECONDS,
        wall_clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.interval = interval
        self.stale_after = stale_after
        self.system_interval = system_interval
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._values = self._empty_values()
        self._sample_time: str | None = None
        self._sample_monotonic: float | None = None
        self._system_sample_time: str | None = None
        self._system_sample_monotonic: float | None = None
        self._unavailable = ["singbox", "cpu", "memory", "connections", "systemConnections"]
        self._error: str | None = "sample_pending"
        self._metric_samples = self._empty_metric_samples()
        self._last_successful_time: str | None = None
        self._attempt_time: str | None = None
        self._connections_epoch: float | None = None
        self._enforcement_available: bool | None = None
        self._enforcement_reason: str | None = None

    def _empty_metric_samples(self) -> dict:
        return {field: {"sampledAt": None, "at": None, "initialAge": 0.0,
                        "maxAge": (self.system_interval + self.stale_after
                                   if field == "systemConnections" else self.stale_after),
                        "available": False, "reason": "sample_pending"}
                for field in _METRIC_NAMES}

    @staticmethod
    def _empty_values() -> dict:
        # Legacy response models require numbers. A negative sentinel cannot
        # be mistaken for measured zero while the first sample is pending.
        return {"singbox": "unknown", "cpu": -1.0, "memory": -1.0,
                "connections": -1, "systemConnections": -1,
                "connectionsCollectedAt": None}

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop = threading.Event()
            self._thread = threading.Thread(
                target=self._loop, args=(self._stop,),
                name="node-manager-status", daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            self._stop.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=timeout)

    def reset(self) -> None:
        self.stop()
        with self._lock:
            self._values = self._empty_values()
            self._sample_time = None
            self._sample_monotonic = None
            self._system_sample_time = None
            self._system_sample_monotonic = None
            self._unavailable = ["singbox", "cpu", "memory", "connections", "systemConnections"]
            self._error = "sample_pending"
            self._metric_samples = self._empty_metric_samples()
            self._last_successful_time = None
            self._attempt_time = None
            self._connections_epoch = None
            self._enforcement_available = None
            self._enforcement_reason = None

    def _sample_once(self, stop: threading.Event) -> None:
        values = {}
        metric_updates = {}

        def measured(field: str, value: object) -> None:
            values[field] = value
            metric_updates[field] = {"sampledAt": self._wall_clock().isoformat(),
                                     "at": self._clock(), "initialAge": 0.0,
                                     "available": True, "reason": None}

        def failed(field: str, reason: str = "sample_failed") -> None:
            # Keep the original successful value and its timestamp together.
            metric_updates[field] = {"available": False, "reason": reason}
        measurements = (
            ("singbox", lambda: "running" if is_singbox_running() else "stopped"),
            ("cpu", get_cpu_usage),
            ("memory", get_memory_usage),
        )
        for field, measure in measurements:
            if stop.is_set():
                return
            try:
                measured(field, measure())
            except Exception:
                failed(field)
        # Walking /proc/net can be expensive on busy hosts. It is only a
        # dashboard metric, so sample it less often than CPU/service health.
        # Failed attempts do not move this success timestamp: the next normal
        # worker cycle retries instead of waiting another 30 seconds.
        system_sample_time = None
        system_sample_monotonic = None
        with self._lock:
            previous_system_time = self._system_sample_monotonic
        if previous_system_time is None or self._clock() - previous_system_time >= self.system_interval:
            if stop.is_set():
                return
            try:
                measured("systemConnections", _measure_system_connections())
                system_sample_monotonic = self._clock()
                system_sample_time = metric_updates["systemConnections"]["sampledAt"]
            except Exception:
                failed("systemConnections")
        if stop.is_set():
            return
        connection_epoch = None
        try:
            from monitor.traffic import get_proxy_connection_count_snapshot

            traffic = get_proxy_connection_count_snapshot()
            count = traffic.get("connections")
            collected_at = traffic.get("collectedAt")
            wall_now = self._wall_clock()
            stamp = _observation_time(collected_at, wall_now)
            observed = (type(count) is int and count >= 0
                        and stamp is not None
                        and traffic.get("observationAvailable", True) is True)
            with self._lock:
                previous_epoch = self._connections_epoch
            epoch = stamp.timestamp() if stamp is not None else None
            if not observed:
                failed("connections", "connection_observation_invalid")
            elif previous_epoch is not None and epoch < previous_epoch:
                failed("connections", "connection_observation_out_of_order")
            else:
                telemetry_available = traffic.get("telemetryAvailable", traffic.get("available")) is True
                # A newer stale observation is still the latest known count.
                # Equal unavailable reads may update health, not rewrite the
                # value associated with an already accepted observation.
                if previous_epoch is None or epoch > previous_epoch or telemetry_available:
                    values["connections"] = count
                    values["connectionsCollectedAt"] = collected_at
                age = (wall_now - stamp).total_seconds()
                reported_age = traffic.get("stalenessSeconds")
                if (type(reported_age) in (int, float) and math.isfinite(reported_age)
                        and reported_age >= 0):
                    age = max(age, reported_age)
                max_age = traffic.get("staleAfterSeconds", self.stale_after)
                if type(max_age) not in (int, float) or not math.isfinite(max_age) or max_age <= 0:
                    max_age = self.stale_after
                metric_updates["connections"] = {
                    "sampledAt": collected_at, "at": self._clock(), "initialAge": age,
                    "maxAge": max_age, "available": telemetry_available,
                    "reason": _reason(traffic.get("unavailableReason"),
                                      None if telemetry_available else "proxy_connection_sample_unavailable"),
                }
                connection_epoch = epoch
            enforcement_available = traffic.get("enforcementAvailable")
            enforcement_reason = _reason(traffic.get("enforcementReason"))
        except Exception:
            failed("connections", "proxy_connection_sample_unavailable")
            enforcement_available = None
            enforcement_reason = None
        with self._lock:
            if stop.is_set():
                return
            if connection_epoch is not None:
                self._connections_epoch = connection_epoch
            self._values.update(values)
            for field, update in metric_updates.items():
                self._metric_samples[field].update(update)
            self._attempt_time = self._wall_clock().isoformat()
            self._enforcement_available = (enforcement_available
                                          if type(enforcement_available) is bool else None)
            self._enforcement_reason = enforcement_reason
            if system_sample_monotonic is not None:
                self._system_sample_monotonic = system_sample_monotonic
                self._system_sample_time = system_sample_time
            samples = self._read_metric_samples(self._clock())
            self._unavailable = [field for field in _METRIC_NAMES if not samples[field]["available"]]
            self._error = ("sample_unavailable:" + ",".join(self._unavailable)
                           if self._unavailable else None)
            known = [item for item in self._metric_samples.values() if item["at"] is not None]
            if known:
                latest = max(known, key=lambda item: item["at"] - item["initialAge"])
                self._sample_monotonic = latest["at"] - latest["initialAge"]
                self._sample_time = latest["sampledAt"]
            if not self._unavailable:
                self._last_successful_time = self._attempt_time

    def _read_metric_samples(self, now: float) -> dict:
        result = {}
        for field, state in self._metric_samples.items():
            age = (state["initialAge"] + max(0.0, now - state["at"])
                   if state["at"] is not None else None)
            stale = age is None or age > state["maxAge"]
            available = state["available"] and not stale
            result[field] = {
                "sampledAt": state["sampledAt"], "sampleAgeSeconds": age,
                "stale": stale, "available": available,
                "unavailableReason": (None if available else state["reason"] or
                                      ("sample_stale" if stale else "sample_unavailable")),
            }
        return result

    def _loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self._sample_once(stop)
            if stop.wait(self.interval):
                break

    def read(self, node_id: str) -> dict:
        with self._lock:
            now = self._clock()
            age = (max(0.0, now - self._sample_monotonic)
                   if self._sample_monotonic is not None else None)
            samples = self._read_metric_samples(now)
            unavailable = [field for field in _METRIC_NAMES if not samples[field]["available"]]
            stale = bool(unavailable)
            system_age = (max(0.0, now - self._system_sample_monotonic)
                          if self._system_sample_monotonic is not None else None)
            system_stale = (system_age is None
                            or system_age > self.system_interval + self.stale_after
                            or not samples["systemConnections"]["available"])
            return {
                "node": node_id,
                **self._values,
                "sampledAt": self._sample_time,
                "sampleAgeSeconds": age,
                "sampleStale": stale,
                "sampleAvailable": not stale,
                "sampleError": self._error or ("sample_stale" if stale else None),
                "metricsUnavailable": unavailable,
                # sampledAt is the newest successful observation, not proof
                # that all metrics share a timestamp or are fresh together.
                "sampleAttemptedAt": self._attempt_time,
                "lastSuccessfulSampledAt": self._last_successful_time,
                "metricSamples": samples,
                "connectionsSampleAgeSeconds": samples["connections"]["sampleAgeSeconds"],
                "connectionsStale": samples["connections"]["stale"],
                "connectionsAvailable": samples["connections"]["available"],
                "connectionsUnavailableReason": samples["connections"]["unavailableReason"],
                "enforcementAvailable": self._enforcement_available,
                "enforcementReason": self._enforcement_reason,
                "systemConnectionsSampledAt": self._system_sample_time,
                "systemConnectionsSampleAgeSeconds": system_age,
                "systemConnectionsSampleIntervalSeconds": self.system_interval,
                "systemConnectionsStale": system_stale,
            }


_status_sampler = _StatusSampler()


def start_status_sampler() -> None:
    _status_sampler.start()


def stop_status_sampler() -> None:
    _status_sampler.stop()


def reset_status_sampler() -> None:
    """Stop and clear the observability snapshot; useful for isolated tests."""
    _status_sampler.reset()


def get_node_status(node_id: str) -> dict:
    # Starting a worker is cheap; the request never performs the slow sample.
    start_status_sampler()
    return _status_sampler.read(node_id)


atexit.register(stop_status_sampler)
