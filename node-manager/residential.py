"""住宅 SOCKS 代理配置模块。

负责：
  1. 接收并校验住宅 SOCKS 代理基础信息（IP / 端口 / 认证账号 / 密码）。
  2. 提供标准化的住宅 SOCKS 配置对象，供多协议生成模块复用。
  3. 敏感认证信息的安全约定：本模块只负责校验与建模，不落盘、
     不打印明文；真正的加密存储由 Control Plane 以 AES-GCM 完成。

输入校验规则与《账号登录与批量SOCKS节点开发文档》保持一致：
  - IP：IPv4 四段十进制，每段 0-255；
  - 端口：1-65535；
  - 账号/密码：非空、最长 255 字符、不含空白与控制字符。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable

from protocols import ProtocolData

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAX_CREDENTIAL_LEN = 255


class ResidentialConfigError(ValueError):
    """住宅 SOCKS 配置校验失败。"""


@dataclass(frozen=True)
class ResidentialSocksConfig:
    """一条已校验的住宅 SOCKS 代理基础配置。"""

    ip: str
    port: int
    username: str
    password: str
    source_address: str | None = None  # 实际 SOCKS 接入地址（可为域名）
    country_code: str = "XX"
    country_name: str = ""
    city_name: str = ""

    def to_protocol_data(self, **overrides) -> ProtocolData:
        """转换为多协议生成所需的统一数据源。"""
        base = {
            "ip": self.ip,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city_name": self.city_name,
        }
        base.update(overrides)
        return ProtocolData(**base)


# ---------------------------------------------------------------------------
# 校验函数
# ---------------------------------------------------------------------------

def validate_ip(value: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        raise ResidentialConfigError("IP 地址不能为空")
    if not _IPV4_RE.match(normalized):
        raise ResidentialConfigError(f"IP 地址格式不正确: {normalized}")
    try:
        address = ipaddress.IPv4Address(normalized)
    except ipaddress.AddressValueError as exc:
        raise ResidentialConfigError(f"IP 地址格式不正确: {normalized}") from exc
    return str(address)


def validate_port(value: int | str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ResidentialConfigError("端口必须是数字") from exc
    if port < 1 or port > 65535:
        raise ResidentialConfigError("端口必须在 1-65535 之间")
    return port


def validate_credential(value: str, name: str = "账号") -> str:
    if value is None:
        raise ResidentialConfigError(f"{name}不能为空")
    normalized = value.strip()
    if not normalized:
        raise ResidentialConfigError(f"{name}不能为空")
    if len(normalized) > _MAX_CREDENTIAL_LEN:
        raise ResidentialConfigError(f"{name}不能超过 {_MAX_CREDENTIAL_LEN} 个字符")
    if any(ch.isspace() for ch in normalized):
        raise ResidentialConfigError(f"{name}不能包含空白字符")
    if any(ord(ch) < 32 or ch == "\x7f" for ch in normalized):
        raise ResidentialConfigError(f"{name}不能包含控制字符")
    return normalized


def validate_config(
    ip: str,
    port: int | str,
    username: str,
    password: str,
    source_address: str | None = None,
    country_code: str = "XX",
    country_name: str = "",
    city_name: str = "",
) -> ResidentialSocksConfig:
    """校验并构建住宅 SOCKS 配置。校验失败抛出 ResidentialConfigError。"""
    return ResidentialSocksConfig(
        ip=validate_ip(ip),
        port=validate_port(port),
        username=validate_credential(username, "账号"),
        password=validate_credential(password, "密码"),
        source_address=source_address,
        country_code=country_code or "XX",
        country_name=country_name,
        city_name=city_name,
    )


def validate_batch(lines: Iterable[str]) -> list[ResidentialSocksConfig]:
    """批量校验多行 `IP 端口 账号 密码` 输入，逐行返回配置或抛出错误。"""
    results: list[ResidentialSocksConfig] = []
    for line in lines:
        text = (line or "").strip()
        if not text:
            continue
        columns = text.split()
        if len(columns) != 4:
            raise ResidentialConfigError(f"行格式错误，应为 4 列: {text}")
        results.append(validate_config(columns[0], columns[1], columns[2], columns[3]))
    return results