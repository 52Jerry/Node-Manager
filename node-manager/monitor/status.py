from __future__ import annotations

import sys
from pathlib import Path

import psutil

from singbox.manager import is_singbox_running, singbox_api


def get_cpu_usage() -> float:
    # A one-second blocking sample made every heartbeat and manual refresh
    # visibly slow. A short sample is sufficient for the dashboard metric.
    return psutil.cpu_percent(interval=0.1)


def get_memory_usage() -> float:
    memory = psutil.virtual_memory()
    return memory.percent

def get_system_connections() -> int:
    try:
        if sys.platform.startswith("linux"):
            try:
                # Count kernel entries without resolving every address and process.
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
        connections = psutil.net_connections()
        return len(connections)
    except Exception:
        return 0


def get_proxy_connections() -> int:
    snapshot = singbox_api.get_connections()
    connections = snapshot.get("connections") if isinstance(snapshot, dict) else None
    return len(connections) if isinstance(connections, list) else 0


def get_node_status(node_id: str) -> dict:
    return {
        "node": node_id,
        "singbox": "running" if is_singbox_running() else "stopped",
        "cpu": get_cpu_usage(),
        "memory": get_memory_usage(),
        "connections": get_proxy_connections(),
        "systemConnections": get_system_connections(),
    }
