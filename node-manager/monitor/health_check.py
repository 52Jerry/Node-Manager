"""Background health checker for upstream SOCKS outbounds.

Periodically TCP-probes every SOCKS outbound's upstream server.
Dead outbounds are logged as warnings for manual review — no auto-deletion.
"""
from __future__ import annotations

import concurrent.futures
from collections import OrderedDict
import logging
import socket
import threading
from typing import Any

from config import config
from singbox.manager import (
    USER_OUTBOUND_PREFIX,
    read_config,
)

logger = logging.getLogger(__name__)

stop_event = threading.Event()
collector_thread: threading.Thread | None = None

# Track consecutive failures per outbound tag
_failure_counts: dict[str, int] = {}
_lock = threading.Lock()

# Keep one unresolved record per tag, bounded even during a prolonged outage.
# The most recently confirmed failures remain available for manual review.
MAX_DEAD_OUTBOUNDS = 1000
_dead_outbounds: OrderedDict[str, dict[str, Any]] = OrderedDict()


def _extract_outbounds() -> list[dict[str, Any]] | None:
    """Return all socks outbounds with their tag, server, and port."""
    try:
        data = read_config()
    except Exception:
        logger.exception("could not read sing-box config")
        # A read failure does not prove that configured outbounds were deleted.
        return None

    result = []
    for ob in data.get("outbounds", []):
        if ob.get("type") != "socks":
            continue
        tag = ob.get("tag", "")
        if not tag.startswith(USER_OUTBOUND_PREFIX):
            continue
        server = ob.get("server", "")
        port = ob.get("server_port", 0)
        if server and port:
            result.append({"tag": tag, "server": server, "port": int(port)})
    return result


def _check_tcp(host: str, port: int, timeout: float = 5.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.gaierror, socket.timeout):
        return False


def _user_id_from_tag(tag: str) -> str:
    """Extract user ID from outbound tag like 'node-manager-out:AbC123'."""
    if tag.startswith(USER_OUTBOUND_PREFIX):
        return tag[len(USER_OUTBOUND_PREFIX):]
    return tag


def _prune_removed_outbounds(active_tags: set[str]) -> None:
    """Drop state for removed outbounds after a successful configuration read."""
    with _lock:
        for tag in list(_failure_counts):
            if tag not in active_tags:
                _failure_counts.pop(tag, None)
        for tag in list(_dead_outbounds):
            if tag not in active_tags:
                _dead_outbounds.pop(tag, None)


def _record_probe_result(ob: dict[str, Any], ok: bool, fail_threshold: int) -> dict[str, Any] | None:
    """Update bounded review state; callers perform network I/O outside the lock."""
    tag = ob["tag"]
    with _lock:
        if ok:
            _failure_counts.pop(tag, None)
            _dead_outbounds.pop(tag, None)
            return None

        failures = _failure_counts.get(tag, 0) + 1
        _failure_counts[tag] = failures
        if failures < fail_threshold:
            return None

        dead_info = {
            "userId": _user_id_from_tag(tag),
            "tag": tag,
            "server": ob["server"],
            "port": ob["port"],
            "failCount": failures,
        }
        newly_dead = tag not in _dead_outbounds
        _dead_outbounds[tag] = dead_info
        _dead_outbounds.move_to_end(tag)
        while len(_dead_outbounds) > MAX_DEAD_OUTBOUNDS:
            _dead_outbounds.popitem(last=False)
        # Preserve the original consecutive-failure threshold cycle, while
        # retaining only one unresolved record instead of appending duplicates.
        _failure_counts.pop(tag, None)
        return dict(dead_info) if newly_dead else None


def _health_check_loop(interval: int, fail_threshold: int, tcp_timeout: float, batch_size: int) -> None:
    """Main loop: every ``interval`` seconds, probe all outbounds."""
    logger.info("health checker started: interval=%ds, fail_threshold=%d, tcp_timeout=%.1fs",
                interval, fail_threshold, tcp_timeout)

    # Reuse worker threads across batches and rounds rather than repeatedly
    # creating thousands of short-lived workers on a large node. Submission
    # remains bounded to one batch; the context cleans up on normal/error exit.
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(batch_size, 50), thread_name_prefix="health-probe"
    ) as pool:
        while not stop_event.is_set():
            outbounds = _extract_outbounds()
            if outbounds is None:
                if stop_event.wait(interval):
                    break
                continue

            _prune_removed_outbounds({ob["tag"] for ob in outbounds})
            if not outbounds:
                logger.debug("no socks outbounds to check")
                if stop_event.wait(interval):
                    break
                continue

            logger.info("checking %d upstream outbounds", len(outbounds))

            newly_dead: list[dict[str, Any]] = []
            checked = 0
            alive = 0
            failed = 0

            for start in range(0, len(outbounds), batch_size):
                if stop_event.is_set():
                    break

                batch = outbounds[start:start + batch_size]
                future_map = {
                    pool.submit(_check_tcp, ob["server"], ob["port"], tcp_timeout): ob
                    for ob in batch
                }
                for future in concurrent.futures.as_completed(future_map):
                    ob = future_map[future]
                    ok = future.result()
                    if ok:
                        alive += 1
                    else:
                        failed += 1
                    dead_info = _record_probe_result(ob, ok, fail_threshold)
                    if dead_info is not None:
                        newly_dead.append(dead_info)

                    checked += 1

            with _lock:
                total_dead = len(_dead_outbounds)

            # Log warnings for newly dead outbounds
            if newly_dead:
                logger.warning("=" * 60)
                logger.warning("DEAD OUTBOUNDS DETECTED: %d new", len(newly_dead))
                for d in newly_dead:
                    logger.warning(
                        "  [DEAD] user=%s server=%s:%d tag=%s fail_count=%d",
                        d["userId"], d["server"], d["port"], d["tag"], d["failCount"],
                    )
                logger.warning("Manual action required: review and delete via node-manager API")
                logger.warning("Dead outbounds list (total %d):", total_dead)
                logger.warning("=" * 60)

            logger.info("health check complete: checked=%d, alive=%d, failed=%d, newly_dead=%d, total_dead=%d",
                        checked, alive, failed, len(newly_dead), total_dead)

            if stop_event.wait(interval):
                break

    logger.info("health checker stopped")


def get_dead_outbounds() -> list[dict[str, Any]]:
    """Return bounded unresolved failures for heartbeat reporting."""
    with _lock:
        return [dict(item) for item in _dead_outbounds.values()]


def clear_dead_outbounds() -> None:
    """Clear the dead outbound list after manual cleanup."""
    with _lock:
        _dead_outbounds.clear()


def start_health_checker() -> None:
    """Start the background health checker thread."""
    global collector_thread

    interval = config.monitoring.health_check_interval_seconds
    if interval <= 0:
        logger.info("health checker disabled (interval=0)")
        return

    fail_threshold = config.monitoring.health_check_fail_threshold
    tcp_timeout = config.monitoring.health_check_tcp_timeout_seconds
    batch_size = config.monitoring.health_check_batch_size

    collector_thread = threading.Thread(
        target=_health_check_loop,
        args=(interval, fail_threshold, tcp_timeout, batch_size),
        daemon=True,
        name="health-checker",
    )
    collector_thread.start()


def stop_health_checker() -> None:
    """Signal stop; in-flight probes/DNS may outlive the bounded join below."""
    stop_event.set()
    if collector_thread is not None:
        collector_thread.join(timeout=10)
