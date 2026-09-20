"""AI-B 节点网络探针：B6 检查所需的底层命令封装（纯标准库）。

设计约束：
  - 只依赖系统命令（ip/ss/iptables/ping/ufw/nft），缺失时降级为 None/空，
    绝不抛异常，保证在 Windows 开发机与最小化 Linux 节点上都能安全调用；
  - 所有外部命令都带超时，避免排障时把 Node Manager 卡死；
  - 只读：不会修改任何内核参数、规则或配置。
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import subprocess
import sys
from typing import Any, Sequence

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5
IS_LINUX = sys.platform.startswith("linux")


def have(binary: str) -> bool:
    """命令是否存在（Windows 开发环境返回 False，调用方据此降级）。"""
    return shutil.which(binary) is not None


def run(args: Sequence[str], timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str]:
    """执行命令并返回 (returncode, combined_output)；失败返回非 0 与错误文本。"""
    command = list(args)
    if not command:
        return -1, "empty command"
    if not have(command[0]):
        return 127, f"{command[0]}: not available"
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return -1, f"{command[0]}: timeout after {timeout}s"
    except OSError as exc:  # pragma: no cover - 平台相关
        return -1, f"{command[0]}: {exc}"
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output.strip()


# --------------------------------------------------------------------------
# 监听端口
# --------------------------------------------------------------------------

_PORT_RE = re.compile(r":(\d+)\s*$")
_PROC_RE = re.compile(r'users:\(\("([^"]+)"')


def _parse_ss(text: str) -> dict[tuple[str, int], str]:
    result: dict[tuple[str, int], str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        netid = parts[0]
        if netid not in ("tcp", "udp"):
            continue
        local = parts[4]
        match = _PORT_RE.search(local)
        if not match:
            continue
        port = int(match.group(1))
        process = ""
        proc_match = _PROC_RE.search(line)
        if proc_match:
            process = proc_match.group(1)
        result[(netid, port)] = process
    return result


def _parse_netstat(text: str) -> dict[tuple[str, int], str]:
    result: dict[tuple[str, int], str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "tcp6", "udp", "udp6"):
            continue
        family = "tcp" if proto.startswith("tcp") else "udp"
        match = _PORT_RE.search(parts[3])
        if not match:
            continue
        result[(family, int(match.group(1)))] = parts[-1] if len(parts) > 6 else ""
    return result


def listening_map() -> dict[tuple[str, int], str]:
    """返回 {(proto, port): process}；非 Linux 或工具缺失时返回 {}。"""
    code, output = run(["ss", "-lntup"], timeout=6)
    if code == 0 and output:
        parsed = _parse_ss(output)
        if parsed:
            return parsed
    code, output = run(["netstat", "-lntup"], timeout=6)
    if code == 0 and output:
        return _parse_netstat(output)
    return {}


def bind_probe(port: int, protocol: str = "tcp") -> bool:
    """兜底探测：端口已被占用说明有服务在监听。"""
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    try:
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(1)
            sock.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    except Exception:  # pragma: no cover - 防御性
        return False


def is_listening(port: int, protocol: str = "tcp") -> bool:
    listeners = listening_map()
    if listeners:
        return (protocol, port) in listeners
    return bind_probe(port, protocol)


def listener_process(port: int, protocol: str = "tcp") -> str:
    return listening_map().get((protocol, port), "")


def tcp_reachable(port: int, host: str = "127.0.0.1", timeout: float = 2.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# 地址 / 链路 / 路由
# --------------------------------------------------------------------------


def addresses() -> list[dict[str, str]]:
    """返回 [{interface, family, cidr}]。"""
    result: list[dict[str, str]] = []
    for family, flag in (("ipv4", "-4"), ("ipv6", "-6")):
        code, output = run(["ip", "-o", flag, "addr", "show"], timeout=6)
        if code != 0:
            continue
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            cidr = parts[3]
            if family == "ipv6" and cidr.startswith("fe80"):
                continue
            result.append({"interface": parts[1], "family": family, "cidr": cidr})
    return result


def links() -> list[dict[str, Any]]:
    """返回 [{interface, mtu, state}]，只含非 lo 接口。"""
    result: list[dict[str, Any]] = []
    code, output = run(["ip", "-o", "link", "show"], timeout=6)
    if code != 0:
        return result
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[1].rstrip(":")
        if name == "lo":
            continue
        entry: dict[str, Any] = {"interface": name, "mtu": None, "state": None}
        for index, token in enumerate(parts):
            if token == "mtu" and index + 1 < len(parts):
                try:
                    entry["mtu"] = int(parts[index + 1])
                except ValueError:
                    pass
            if token == "state" and index + 1 < len(parts):
                entry["state"] = parts[index + 1]
        result.append(entry)
    return result


def routes(family: int = 4) -> list[str]:
    flag = "-4" if family == 4 else "-6"
    code, output = run(["ip", flag, "route", "show"], timeout=6)
    return output.splitlines() if code == 0 else []


def policy_rules() -> list[str]:
    code, output = run(["ip", "rule", "show"], timeout=6)
    return output.splitlines() if code == 0 else []


def route_get(target: str) -> dict[str, Any]:
    """回程路径查询：返回 dev/src/via，用于判断流量是否从预期接口返回。"""
    entry: dict[str, Any] = {"target": target, "dev": None, "src": None, "via": None}
    code, output = run(["ip", "route", "get", target], timeout=6)
    if code != 0:
        entry["error"] = output
        return entry
    entry["raw"] = output
    parts = output.split()
    for index, token in enumerate(parts):
        if token in ("dev", "src", "via") and index + 1 < len(parts):
            entry[token] = parts[index + 1]
    return entry


def sysctl(name: str) -> str | None:
    code, output = run(["sysctl", "-n", name], timeout=5)
    if code != 0 or not output:
        return None
    return output.strip().splitlines()[0].strip()


def rp_filter() -> dict[str, int | None]:
    """反向路径过滤：回程不对称时 all/接口 rp_filter 会导致丢包。"""
    result: dict[str, int | None] = {}
    for key in ("all", "default"):
        value = sysctl(f"net.ipv4.conf.{key}.rp_filter")
        result[key] = int(value) if value is not None and value.isdigit() else None
    conf_dir = "/proc/sys/net/ipv4/conf"
    if os.path.isdir(conf_dir):
        for name in sorted(os.listdir(conf_dir)):
            if name in ("all", "default"):
                continue
            try:
                with open(os.path.join(conf_dir, name, "rp_filter"), encoding="utf-8") as handle:
                    result[name] = int(handle.read().strip())
            except (OSError, ValueError):
                result[name] = None
    return result


# --------------------------------------------------------------------------
# 转发 / 防火墙 / NAT
# --------------------------------------------------------------------------


def ip_forward(family: str = "ipv4") -> bool:
    key = (
        "net.ipv4.ip_forward"
        if family == "ipv4"
        else "net.ipv6.conf.all.forwarding"
    )
    return sysctl(key) == "1"


def chain_policy(text: str, chain: str) -> str | None:
    match = re.search(rf"Chain {chain} \(policy (\w+)", text)
    return match.group(1) if match else None


def parse_rule_lines(text: str) -> list[dict[str, Any]]:
    """解析 `iptables -vnL` 规则行（含包/字节计数器）。"""
    rules: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Chain", "pkts", "num")):
            continue
        parts = stripped.split(None, 9)
        if len(parts) < 9:
            continue
        try:
            packets = int(parts[0])
            size = int(parts[1])
        except ValueError:
            continue
        rules.append(
            {
                "packets": packets,
                "bytes": size,
                "target": parts[2],
                "proto": parts[3],
                "in": parts[5],
                "out": parts[6],
                "source": parts[7],
                "destination": parts[8],
                "extra": parts[9] if len(parts) > 9 else "",
            }
        )
    return rules


def iptables_chain(table: str, chain: str | None = None) -> tuple[str | None, list[dict[str, Any]], str]:
    """返回 (policy, rules, raw)。工具缺失时 raw 为错误文本。"""
    args = ["iptables", "-t", table, "-vnL"]
    if chain:
        args.append(chain)
    code, output = run(args, timeout=8)
    if code != 0 and not output:
        return None, [], ""
    policy = chain_policy(output, chain) if chain else None
    return policy, parse_rule_lines(output), output


def nat_rules() -> list[dict[str, Any]]:
    """汇总 nat 表规则，并按 target 标记 dnat/snat/masquerade。"""
    rules: list[dict[str, Any]] = []
    for chain in ("PREROUTING", "POSTROUTING", "OUTPUT"):
        _policy, chain_rules, _raw = iptables_chain("nat", chain)
        for rule in chain_rules:
            target = str(rule.get("target", "")).upper()
            if target == "DNAT":
                rule["kind"] = "dnat"
            elif target == "SNAT":
                rule["kind"] = "snat"
            elif target == "MASQUERADE":
                rule["kind"] = "masquerade"
            else:
                rule["kind"] = "other"
            rule["chain"] = chain
            rules.append(rule)
    return rules


def forward_rules() -> dict[str, Any]:
    policy, rules, raw = iptables_chain("filter", "FORWARD")
    return {"policy": policy, "rules": rules, "raw": raw}


def firewall_backend() -> dict[str, Any]:
    """探测本机防火墙实现与状态（只读）。"""
    result: dict[str, Any] = {"ufw": "absent", "nft": False, "iptables": False}
    if have("ufw"):
        code, output = run(["ufw", "status"], timeout=6)
        if code == 0:
            head = output.splitlines()[0].lower() if output else ""
            if "active" in head:
                result["ufw"] = "active"
            elif "inactive" in head:
                result["ufw"] = "inactive"
    result["nft"] = have("nft")
    result["iptables"] = have("iptables")
    if result["iptables"]:
        code, output = run(["iptables", "-S", "INPUT"], timeout=6)
        if code == 0:
            for line in output.splitlines():
                if line.startswith("-P INPUT"):
                    result["inputPolicy"] = line.split()[-1]
                    break
    return result


def ufw_allowed_ports() -> set[tuple[str, int]]:
    """解析 ufw 规则中显式放行的端口。"""
    allowed: set[tuple[str, int]] = set()
    code, output = run(["ufw", "status"], timeout=6)
    if code != 0:
        return allowed
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)(?:/(tcp|udp))?\s+ALLOW", line, re.IGNORECASE)
        if not match:
            continue
        port = int(match.group(1))
        proto = (match.group(2) or "tcp").lower()
        allowed.add((proto, port))
    return allowed


def input_accept_ports() -> set[tuple[str, int]]:
    """从 iptables INPUT 链提取显式 ACCEPT 的端口。"""
    allowed: set[tuple[str, int]] = set()
    _policy, rules, _raw = iptables_chain("filter", "INPUT")
    for rule in rules:
        if str(rule.get("target", "")).upper() not in ("ACCEPT", "RETURN"):
            continue
        extra = str(rule.get("extra", ""))
        match = re.search(r"dpt:(\d+)", extra)
        if not match:
            continue
        port = int(match.group(1))
        proto = str(rule.get("proto", "tcp")).lower()
        if proto in ("tcp", "udp"):
            allowed.add((proto, port))
    return allowed


def conntrack() -> dict[str, int | None]:
    count = sysctl("net.netfilter.nf_conntrack_count")
    maximum = sysctl("net.netfilter.nf_conntrack_max")
    return {
        "count": int(count) if count and count.isdigit() else None,
        "max": int(maximum) if maximum and maximum.isdigit() else None,
    }


# --------------------------------------------------------------------------
# 链路探测
# --------------------------------------------------------------------------


def ping(target: str, count: int = 4, timeout: int = 2, interval: float = 0.2) -> dict[str, Any]:
    """返回 {target, sent, lossPct, avgRttMs, reachable, raw}。"""
    entry: dict[str, Any] = {
        "target": target, "sent": count, "lossPct": None,
        "avgRttMs": None, "reachable": False,
    }
    args = ["ping", "-n", "-c", str(count), "-W", str(timeout), "-i", str(interval), target]
    code, output = run(args, timeout=int(timeout * count + 6))
    entry["raw"] = output
    loss = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", output)
    if loss:
        entry["lossPct"] = float(loss.group(1))
        entry["reachable"] = entry["lossPct"] < 100
    rtt = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output)
    if rtt:
        entry["avgRttMs"] = float(rtt.group(2))
    elif code == 0:
        entry["reachable"] = True
    return entry


def mtu_probe(target: str, sizes: Sequence[int] = (1472, 1400, 1300)) -> list[dict[str, Any]]:
    """用 DF 位探测路径 MTU：payload + 28 = MTU。非 Linux 返回空。"""
    if not IS_LINUX or not have("ping"):
        return []
    results: list[dict[str, Any]] = []
    for size in sizes:
        code, _output = run(
            ["ping", "-n", "-c", "1", "-W", "2", "-M", "do", "-s", str(size), target],
            timeout=8,
        )
        results.append({"target": target, "payload": size, "mtu": size + 28, "ok": code == 0})
    return results
