"""Background health checker for upstream SOCKS outbounds.

Periodically TCP-probes every SOCKS outbound's upstream server.
Dead outbounds are logged as warnings for manual review — no auto-deletion.
"""
from __future__ import annotations

import concurrent.futures
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

# Record of all dead outbounds (for manual review)
_dead_outbounds: list[dict[str, Any]] = []


def _extract_outbounds() -> list[dict[str, Any]]:
    """Return all socks outbounds with their tag, server, and port."""
    try:
        data = read_config()
    except Exception:
        logger.exception("could not read sing-box config")
        return []

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


def _health_check_loop(interval: int, fail_threshold: int, tcp_timeout: float, batch_size: int) -> None:
    """Main loop: every ``interval`` seconds, probe all outbounds."""
    logger.info("health checker started: interval=%ds, fail_threshold=%d, tcp_timeout=%.1fs",
                interval, fail_threshold, tcp_timeout)

    while not stop_event.is_set():
        outbounds = _extract_outbounds()
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(batch_size, 50)) as pool:
                future_map = {
                    pool.submit(_check_tcp, ob["server"], ob["port"], tcp_timeout): ob
                    for ob in batch
                }
                for future in concurrent.futures.as_completed(future_map):
                    ob = future_map[future]
                    ok = future.result()
                    tag = ob["tag"]
                    user_id = _user_id_from_tag(tag)

                    with _lock:
                        if ok:
                            _failure_counts.pop(tag, None)
                            alive += 1
                        else:
                            _failure_counts[tag] = _failure_counts.get(tag, 0) + 1
                            failed += 1
                            if _failure_counts[tag] >= fail_threshold:
                                dead_info = {
                                    "userId": user_id,
                                    "tag": tag,
                                    "server": ob["server"],
                                    "port": ob["port"],
                                    "failCount": _failure_counts[tag],
                                }
                                newly_dead.append(dead_info)
                                _dead_outbounds.append(dead_info)
                                _failure_counts.pop(tag, None)

                    checked += 1

        # Log warnings for newly dead outbounds
        if newly_dead:
            logger.warning("=" * 60)
            logger.warning("DEAD OUTBOUNDS DETECTED: %d new", len(newly_dead))
            for d in newly_dead:
                logger.warning(
                    "  [DEAD] user=%s server=%s:%d tag=%s fail_count=%d",
                    d["user_id"], d["server"], d["port"], d["tag"], d["fail_count"],
                )
            logger.warning("Manual action required: review and delete via node-manager API")
            logger.warning("Dead outbounds list (total %d):", len(_dead_outbounds))
            logger.warning("=" * 60)

        logger.info("health check complete: checked=%d, alive=%d, failed=%d, newly_dead=%d, total_dead=%d",
                    checked, alive, failed, len(newly_dead), len(_dead_outbounds))

        if stop_event.wait(interval):
            break

    logger.info("health checker stopped")


def get_dead_outbounds() -> list[dict[str, Any]]:
    """Return list of all dead outbounds for heartbeat reporting."""
    with _lock:
        return list(_dead_outbounds)


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
    """Signal the health checker to stop."""
    stop_event.set()
    if collector_thread is not None:
        collector_thread.join(timeout=10)
