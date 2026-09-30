"""Local runtime readiness; does not claim to validate an external entry line."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from singbox import manager
from ha_template import export_template
import socket


def tcp_reachable(port, host):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


class ReadinessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    groupKey: str = Field(pattern=r"^[A-Za-z0-9-]{1,64}$")
    generation: int = Field(gt=0)


def readiness(request: ReadinessRequest):
    with manager._config_lock():
        data, registry = manager.read_config(), manager.read_registry()
        current = registry.get("replicationVersions", {}).get(request.groupKey, {}).get("generation")
        matches = registry.get("sharedProtocolOwner") == request.groupKey and current == request.generation
        template = export_template(data)
    running = manager.is_singbox_running()
    ports = []
    for options in template.values():
        inbound = next(item for item in data["inbounds"]
                       if item.get("type") == options["type"] and item.get("listen_port") == options["listen_port"])
        address = str(inbound.get("listen") or "::")
        host = "::1" if address == "::" else "127.0.0.1" if address == "0.0.0.0" else address
        ports.append({"port": options["listen_port"],
                      "reachable": tcp_reachable(options["listen_port"], host)})
    return {"ready": bool(matches and running and all(port["reachable"] for port in ports)),
            "generationMatches": matches, "singboxRunning": running, "ports": ports,
            "scope": "local-runtime"}
