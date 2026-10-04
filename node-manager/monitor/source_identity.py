from __future__ import annotations

import ipaddress
from typing import Any

from config import config


PRIVATE_SOURCE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
))


def normalize_ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(str(value).strip().strip("[]"))
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return address.compressed.lower()
    except ValueError:
        return None


def source_ip_diagnostics(connections: list[dict[str, Any]] | None) -> dict[str, Any]:
    if connections is None:
        return {"sourceIpVisibility": "unavailable", "suspectedRelaySourceIps": [],
                "missingSourceConnections": None}
    relay_networks = tuple(ipaddress.ip_network(item.strip(), strict=False)
                           for item in config.monitoring.relay_source_cidrs.split(",")
                           if item.strip())
    suspicious = set()
    missing = 0
    for connection in connections:
        source = normalize_ip(connection.get("sourceIp"))
        if source is None:
            missing += 1
            continue
        address = ipaddress.ip_address(source)
        if (address.is_loopback or address.is_link_local or address.is_unspecified
                or address.is_multicast
                or any(address in network for network in PRIVATE_SOURCE_NETWORKS + relay_networks)):
            suspicious.add(source)
    # A public observed IP is not proof of a unique physical device or absence of NAT.
    visibility = ("relay_detected" if suspicious else "missing" if missing
                  else "observed" if connections else "idle")
    return {"sourceIpVisibility": visibility, "suspectedRelaySourceIps": sorted(suspicious),
            "missingSourceConnections": missing}
