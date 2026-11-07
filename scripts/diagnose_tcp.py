#!/usr/bin/env python3
"""Passive Linux TCP samples, grouped by leg. No probes or configuration writes."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time

LISTEN_PORTS = {20168, 20169, 5001, 24168, 22168, 21169, 15002, 20166}
PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def classify(local, peer, role):
    peer_ip = ipaddress.ip_address(peer.rsplit(":", 1)[0].strip("[]"))
    local_port = int(local.rsplit(":", 1)[1])
    if local_port == 22 or peer.endswith(":22") or peer_ip.is_loopback:
        return None
    if any(peer_ip.version == network.version and peer_ip in network for network in PRIVATE):
        return "entry-to-hk" if local_port in LISTEN_PORTS or int(peer.rsplit(":", 1)[1]) in LISTEN_PORTS else None
    if local_port in LISTEN_PORTS:
        return "user-to-entry" if role == "entry" else "public-client-to-hk"
    return "hk-to-residential" if role == "hk" else "other-public-outbound"


def read_sockets(role):
    raw = subprocess.run(["ss", "-tinH", "state", "established"], check=True,
                         capture_output=True, text=True, timeout=8).stdout
    rows, header = {}, None
    for line in raw.splitlines():
        fields = line.split()
        if fields and fields[0].isdigit() and len(fields) >= 4:
            header = fields[:4]
            continue
        if header is None or "rtt:" not in line:
            continue
        local, peer = header[2:4]
        try:
            group = classify(local, peer, role)
        except ValueError:
            group = None
        if group:
            values = {name: float(value) for name, value in re.findall(
                r"\b(segs_out|bytes_retrans|bytes_sent|rtt):([\d.]+)", line)}
            retrans = re.search(r"\bretrans:\d+/(\d+)", line)
            rows[(local, peer)] = {"group": group, "retrans": int(retrans[1]) if retrans else 0,
                                   **values}
        header = None
    return rows


def host_tcp():
    result = {}
    for name in ("snmp", "netstat"):
        lines = (Path("/proc/net") / name).read_text().splitlines()
        for index in range(0, len(lines) - 1, 2):
            for key, value in zip(lines[index].split()[1:], lines[index + 1].split()[1:]):
                if key in {"OutSegs", "RetransSegs", "TCPTimeouts", "TCPMemoryPressures", "TCPRcvQDrop", "ListenDrops"}:
                    result[key] = int(value)
    return result


def summarize(before, after):
    groups = {}
    for key, row in after.items():
        group = groups.setdefault(row["group"], {"observedSockets": 0, "survivingSockets": 0,
                                               "retransSegments": 0, "sentSegments": 0, "rttMs": []})
        group["observedSockets"] += 1
        group["rttMs"].append(row.get("rtt", 0))
        old = before.get(key)
        # Exclude churn or reused tuples with reset lifetime counters.
        if old is None or any(row.get(field, 0) < old.get(field, 0) for field in ("retrans", "segs_out", "bytes_sent")):
            continue
        group["survivingSockets"] += 1
        group["retransSegments"] += row["retrans"] - old["retrans"]
        group["sentSegments"] += int(row.get("segs_out", 0) - old.get("segs_out", 0))
    for group in groups.values():
        rtts = sorted(group.pop("rttMs"))
        group["rttP50Ms"] = rtts[len(rtts) // 2]
        group["rttP95Ms"] = rtts[min(len(rtts) - 1, int(len(rtts) * .95))]
        group["retransToSentPct"] = round(100 * group["retransSegments"] / group["sentSegments"], 3) if group["sentSegments"] else None
    return groups


def measure(role, interval=10, samples=3):
    result = {"role": role, "passiveOnly": True, "samples": [],
              "limits": ["TCP segment ratios are not packet loss rates", "leg counters include only surviving sampled connections",
                         "WireGuard UDP loss and short-lived TCP connections require separate evidence"]}
    before, tcp = read_sockets(role), host_tcp()
    for _ in range(samples):
        start = time.monotonic()
        time.sleep(interval)
        after, latest = read_sockets(role), host_tcp()
        result["samples"].append({"seconds": round(time.monotonic() - start, 2),
                                  "hostTcpDelta": {key: latest[key] - value for key, value in tcp.items()},
                                  "legs": summarize(before, after)})
        before, tcp = after, latest
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("entry", "hk"), required=True)
    parser.add_argument("--interval", type=int, choices=range(1, 61), default=10)
    parser.add_argument("--samples", type=int, choices=range(1, 7), default=3)
    args = parser.parse_args()
    print(json.dumps(measure(args.role, args.interval, args.samples)))
