"""Bound repetitive polling diagnostics without buffering logs or customer data."""
from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from typing import Callable

# Exact templates only: authentication, changes and other unknown failures pass through.
POLLING_MESSAGES = {
    "singbox.api": frozenset({
        "VLESS generation API unavailable: %s",
        "Failed to get proxies: HTTP %s",
        "Sing-box proxy metrics are not available: %s",
        "Failed to get connections: HTTP %s",
        "Sing-box connection metrics are not available: %s",
    }),
    "monitor.traffic": frozenset({
        "traffic telemetry unavailable; retaining prior enforcement, review required",
        "could not synchronize sing-box user enforcement rules",
        "traffic collection failed; no new enforcement applied",
        "traffic collection failed",
    }),
    "monitor.health_check": frozenset({"could not read sing-box config"}),
}


class PollingLogFilter(logging.Filter):
    def __init__(self, interval: float = 60, clock: Callable[[], float] = time.monotonic):
        super().__init__()
        if interval <= 0:
            raise ValueError("positive polling log interval required")
        self.interval = interval
        self.clock = clock
        self._windows: OrderedDict[tuple[str, str, int], tuple[float, int]] = OrderedDict()
        self._lock = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        if (record.levelno < logging.WARNING or not isinstance(record.msg, str)
                or record.msg not in POLLING_MESSAGES.get(record.name, ())):
            return True
        key = (record.name, record.msg, record.levelno)
        now = self.clock()
        suppressed = 0
        with self._lock:
            previous = self._windows.get(key)
            if previous is not None:
                started, suppressed = previous
                if now - started < self.interval:
                    self._windows[key] = (started, suppressed + 1)
                    return False
            self._windows[key] = (now, 0)
            self._windows.move_to_end(key)
            while len(self._windows) > 128:
                self._windows.popitem(last=False)
        if suppressed:
            # Format only emitted records. Keep exc_info on the first and periodic report.
            record.msg = record.getMessage() + f" (repeated polling failures suppressed: {suppressed})"
            record.args = ()
        return True


def configure_background_logging() -> None:
    limiter = PollingLogFilter()
    for name in POLLING_MESSAGES:
        logger = logging.getLogger(name)
        if not any(isinstance(item, PollingLogFilter) for item in logger.filters):
            logger.addFilter(limiter)
    # Successful HTTP client requests otherwise emit a line for every heartbeat/poll.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
