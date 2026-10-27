"""Prove a retired standard-SOCKS5 generation has only orphan UDP associations.

RFC 1928 section 6 ties a UDP association to its TCP control connection. This
proof accepts neither arbitrary idle UDP nor a generation with any TCP session.
All observations are local, bounded, reset on uncertainty, and do not stop units.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import subprocess
from pathlib import Path


def socks_hosts(config: dict) -> frozenset[str]:
    if not isinstance(config, dict) or set(config) - {"log", "inbounds", "outbounds", "route"}:
        raise ValueError("unsupported generation config")
    inbounds = config.get("inbounds")
    if (not isinstance(inbounds, list) or len(inbounds) != 1
            or inbounds[0].get("type") != "tproxy" or inbounds[0].get("tag") != "wg-tproxy"):
        raise ValueError("unsupported generation inbound")
    hosts = set()
    for outbound in config.get("outbounds", []):
        if outbound.get("type") in {"block", "urltest"}:
            continue
        if (outbound.get("type") != "socks" or outbound.get("version", "5") != "5"
                or outbound.get("udp_over_tcp") not in (None, False)
                or outbound.get("detour") or outbound.get("netns")):
            raise ValueError("only standard direct SOCKS5 relays are eligible")
        address = ipaddress.ip_address(outbound["server"])
        if address.version != 4 or not address.is_global:
            raise ValueError("relay must be a public literal IPv4 address")
        hosts.add(str(address))
    if not hosts:
        raise ValueError("no standard SOCKS5 relays")
    return frozenset(hosts)


def _endpoint(value: str) -> tuple[str, int | None]:
    host, _, port = value.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, None if port == "*" else int(port)


def residual_udp_fingerprint(text: str, port: int, pid: int, hosts: frozenset[str],
                             inet_inodes: set[str], transparent_inodes: frozenset[str] = frozenset()) -> str:
    """Reject live TCP, client-side UDP, queued packets, missing owners and shared FDs."""
    seen = set()
    residual = []
    relays = 0
    lines = []
    for line in text.splitlines():
        if line.strip().startswith('inet-sockopt:') and lines:
            lines[-1] += ' ' + line.strip()
        else:
            lines.append(line)
    for line in lines:
        fields = line.split()
        if len(fields) < 6 or fields[0] not in {"tcp", "udp"}:
            raise ValueError("unparseable socket observation")
        owners = {int(value) for value in re.findall(r"\bpid=(\d+)\b", line)}
        local_host, local_port = _endpoint(fields[4])
        if pid not in owners:
            if local_port == port:
                raise ValueError("listener ownership is uncertain")
            continue
        if owners != {pid}:
            raise ValueError("socket has another owner")
        inode = re.search(r"\bino:(\d+)\b", line)
        if not inode or inode[1] in seen:
            raise ValueError("socket inode is unavailable or duplicated")
        seen.add(inode[1])
        remote_host, remote_port = _endpoint(fields[5])
        listener = (local_port == port and remote_port is None and remote_host in {"*", "0.0.0.0", "::"}
                    and ((fields[0] == "tcp" and fields[1] == "LISTEN")
                         or (fields[0] == "udp" and fields[1] == "UNCONN")))
        if listener:
            continue
        # TPROXY replies keep a transparent socket bound to the original destination.
        # It belongs to the same orphan association, not another listening service.
        reply = (fields[0] == "udp" and fields[1] == "UNCONN" and fields[2:4] == ["0", "0"]
                 and remote_port is None and remote_host in {"*", "0.0.0.0"}
                 and ipaddress.ip_address(local_host).version == 4
                 and ipaddress.ip_address(local_host).is_global
                 and (inode[1] in transparent_inodes
                      or re.search(r'inet-sockopt:\s*\([^)]*\btransparent\b', line)))
        if reply:
            residual.append((inode[1], fields[4], fields[5]))
            continue
        if (fields[0] != "udp" or fields[1] != "ESTAB" or fields[2:4] != ["0", "0"]
                or remote_host not in hosts or remote_port is None or not 1 <= remote_port <= 65535
                or ipaddress.ip_address(local_host).version != 4):
            raise ValueError("generation still has live or unverified connections")
        residual.append((inode[1], fields[4], fields[5]))
        relays += 1
    if not residual or not relays or seen != inet_inodes:
        raise ValueError("complete socket ownership could not be proven")
    return hashlib.sha256(json.dumps(sorted(residual)).encode()).hexdigest()


def process_identity(pid: int, proc: Path = Path("/proc")) -> tuple[str, set[str]]:
    """Cross-check ss against process FDs and all namespace INET socket tables."""
    stat = (proc / str(pid) / "stat").read_text()
    start_ticks = stat.rsplit(")", 1)[1].split()[19]
    owned = set()
    for fd in (proc / str(pid) / "fd").iterdir():
        target = str(fd.readlink())
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            owned.add(match[1])
    inet = set()
    for table in ("tcp", "tcp6", "udp", "udp6", "raw", "raw6"):
        for line in (proc / str(pid) / "net" / table).read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise ValueError("incomplete INET socket table")
            if fields[9] in owned:
                inet.add(fields[9])
    if not inet:
        raise ValueError("no verifiable process socket ownership")
    return start_ticks, inet


def tproxy_reply_inodes(pid: int, sockets: str, proc: Path = Path("/proc")) -> frozenset[str]:
    """Identify nonlocal reply binds only for an already-verified single-TPROXY config.

    Older production kernels lack pidfd_getfd and ss --inet-sockopt. Use complete
    FD ownership, the process network namespace, and actual interface addresses;
    an ordinary socket bound to a local interface is never an exception.
    """
    if (proc / str(pid) / "ns/net").readlink() != (proc / "self/ns/net").readlink():
        raise ValueError("process network namespace differs")
    result = subprocess.run(["ip", "-o", "-4", "address", "show"], capture_output=True,
                            text=True, timeout=5, check=True)
    local = set(re.findall(r"\binet\s+([0-9.]+)/\d+", result.stdout))
    if not local:
        raise ValueError("local interface ownership is unavailable")
    replies = set()
    for line in sockets.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[:4] != ["udp", "UNCONN", "0", "0"]:
            continue
        if pid not in {int(v) for v in re.findall(r"\bpid=(\d+)\b", line)}:
            continue
        host, port = _endpoint(fields[4]); remote, remote_port = _endpoint(fields[5])
        inode = re.search(r"\bino:(\d+)\b", line)
        if (inode and host not in local and ipaddress.ip_address(host).version == 4
                and ipaddress.ip_address(host).is_global and port is not None and 1 <= port <= 65535
                and remote in {"0.0.0.0", "*"} and remote_port is None):
            replies.add(inode[1])
    return frozenset(replies)


class OrphanUdpWindow:
    def __init__(self, minimum_seconds: float = 60, clock=time.monotonic):
        self.minimum_seconds = minimum_seconds
        self.clock = clock
        self.observations: dict[int, tuple[tuple, float]] = {}

    def forget(self, port: int) -> None:
        self.observations.pop(port, None)

    def observe(self, port: int, pid: int, start_ticks: str, config_digest: str,
                sockets: str, hosts: frozenset[str], inet_inodes: set[str],
                transparent_inodes: frozenset[str] = frozenset()) -> bool:
        try:
            fingerprint = residual_udp_fingerprint(sockets, port, pid, hosts, inet_inodes, transparent_inodes)
        except Exception:
            self.forget(port)
            return False
        identity = (pid, start_ticks, config_digest, fingerprint)
        now = self.clock()
        previous = self.observations.get(port)
        if previous is None or previous[0] != identity or now < previous[1]:
            if len(self.observations) >= 10 and port not in self.observations:
                self.observations.clear()
            self.observations[port] = (identity, now)
            return False
        return now - previous[1] >= self.minimum_seconds
