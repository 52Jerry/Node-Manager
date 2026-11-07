"""Private-network transport; proxy identities are independent of the underlay."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import ipaddress
import re


@dataclass(frozen=True)
class PrivateTransport:
    entry_public: str = "150.242.80.15"
    entry_private: str = "172.16.80.15"
    exit_private: str = "172.16.208.118"
    interface: str = "ens19"

    def __post_init__(self):
        for name in ("entry_public", "entry_private", "exit_private"):
            value = ipaddress.IPv4Address(getattr(self, name))
            if value.is_unspecified or value.is_multicast or value.is_loopback:
                raise ValueError("传输地址必须是明确的服务器 IPv4 地址")
        private = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        if not all(any(ipaddress.IPv4Address(getattr(self, n)) in net for net in private)
                   for n in ("entry_private", "exit_private")):
            raise ValueError("深港传输必须使用 RFC1918 私网地址")
        if self.entry_private == self.exit_private:
            raise ValueError("入口与出口私网地址不能相同")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", self.interface):
            raise ValueError("无效的私网网卡名称")


def migrate_listeners(core: dict, transport: PrivateTransport) -> dict:
    """Change exactly three shared listeners; preserve credentials and all policy."""
    expected = {"vless": 6666, "vmess": 7777, "socks": 9999}
    result = deepcopy(core)
    seen = set()
    for inbound in result.get("inbounds", []):
        kind = inbound.get("type")
        if kind not in expected:
            if str(inbound.get("listen", "")).startswith("10.44."):
                raise ValueError("发现未纳入迁移的旧内网监听，拒绝部分迁移")
            continue
        if kind in seen or inbound.get("listen_port") != expected[kind]:
            raise ValueError("共享核心协议或端口不符合迁移预期")
        if inbound.get("listen") not in ("10.44.0.1", transport.exit_private):
            raise ValueError("共享核心监听地址已改变，需重新核对")
        inbound["listen"] = transport.exit_private
        seen.add(kind)
    if seen != set(expected):
        raise ValueError("共享核心三协议不完整，拒绝迁移")
    return result


def restore_listeners(core: dict, transport: PrivateTransport) -> dict:
    """Rollback only addresses in a fresh config; retain post-cutover purchases."""
    migrate_listeners(core, transport)  # Validate the same three listeners first.
    result = deepcopy(core)
    for inbound in result["inbounds"]:
        if inbound.get("type") in ("vless", "vmess", "socks"):
            inbound["listen"] = "10.44.0.1"
    return result
