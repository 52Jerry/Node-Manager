"""Resolve provenance only while ASGI client still represents the socket peer."""
from __future__ import annotations

import ipaddress
from typing import Iterable

MAX_HEADER_BYTES = 2048
MAX_HOPS = 16


def address(value: str):
    if not value or "%" in value:
        raise ValueError("invalid IP literal")
    result = ipaddress.ip_address(value.strip())
    return result.ipv4_mapped if isinstance(result, ipaddress.IPv6Address) and result.ipv4_mapped else result


def networks(raw: str) -> list:
    result = []
    for item in raw.split(","):
        if item.strip():
            network = ipaddress.ip_network(item.strip(), strict=False)
            if network.prefixlen == 0:
                raise ValueError("trusting all proxy peers is forbidden")
            result.append(network)
    return result


def resolve(peer: str | None, headers: Iterable[str], trusted: Iterable) -> str | None:
    try:
        current = address(peer)
    except (ValueError, TypeError, AttributeError):
        return None
    trusted = tuple(trusted)

    def is_trusted(ip):
        return any(ip.version == net.version and ip in net for net in trusted)

    if not is_trusted(current):
        return str(current)
    values = list(headers)
    # Duplicate fields and malformed chains are rejected, never partially parsed.
    if not values:
        return str(current)
    if len(values) != 1 or len(values[0].encode("utf-8")) > MAX_HEADER_BYTES:
        return None
    parts = values[0].split(",")
    if len(parts) > MAX_HOPS:
        return None
    try:
        chain = [address(part) for part in parts]
    except ValueError:
        return None
    for hop in reversed(chain):
        if not is_trusted(current):
            break
        current = hop
    return str(current)
