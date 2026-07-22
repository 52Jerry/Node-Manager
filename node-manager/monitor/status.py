import psutil

from singbox.manager import is_singbox_running, singbox_api


def get_cpu_usage() -> float:
    return psutil.cpu_percent(interval=1)


def get_memory_usage() -> float:
    memory = psutil.virtual_memory()
    return memory.percent

def get_system_connections() -> int:
    try:
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
