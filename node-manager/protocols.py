"""多协议代理配置生成模块（对标 IPVelo 五种协议）。

基于同一份住宅 SOCKS 代理数据，生成五种标准化协议链接：
  1. SOCKS5（原始）      socks://user:pass@ip:port#备注
  2. 比特浏览器          ip:port:user:pass
  3. VLESS（加速）       vless://uuid@域名:端口?参数
  4. SOCKS（加速）       socks://b64user:b64pass@域名:端口#备注
  5. VMess（加速）       vmess://base64(JSON)

设计原则：后端只返回一份统一数据，前端/本模块按协议模板本地拼接，
不额外发起 API 请求。加速线路的 SOCKS 认证信息由 username/password
Base64 编码生成，无需单独存储。
"""
from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field
from typing import Any


def _b64(raw: str) -> str:
    """标准 Base64 编码字符串（用于 SOCKS 加速认证与 VMess 配置）。"""
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def _base64url(raw: bytes) -> str:
    """URL-safe Base64 且去除填充（用于 REALITY 公钥）。"""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass
class ProtocolData:
    """五种协议共用的统一数据源。

    与《IPVelo_代理连接信息生成分析文档》11.9 节参数清单对应：
    - 通用参数：ip / port / username / password / 地区
    - 加速共用：acceleration_domain / uuid
    - VLESS 专属、VMess 专属参数
    """

    ip: str
    port: int
    username: str
    password: str
    country_code: str = "XX"
    country_name: str = ""
    city_name: str = ""
    remark: str = ""
    # 加速线路共用
    acceleration_domain: str = "proxy.tkip.xin"
    uuid: str = ""
    acceleration_port_socks: int = 5001
    # VLESS 专属
    vless_port: int = 20168
    vless_encryption: str = "none"
    vless_security: str = "reality"
    vless_sni: str = "www.microsoft.com"
    vless_fp: str = "chrome"
    vless_pbk: str = ""
    vless_sid: str = ""
    vless_spx: str = "%2F"
    vless_type: str = "tcp"
    vless_header_type: str = "none"
    vless_flow: str = "xtls-rprx-vision"
    # VMess 专属
    vmess_port: int = 20169
    vmess_v: str = "2"
    vmess_aid: str = "0"
    vmess_scy: str = "auto"
    vmess_net: str = "tcp"
    vmess_type: str = "none"
    vmess_host: str = ""
    vmess_path: str = ""
    vmess_tls: str = ""
    vmess_sni: str = ""
    vmess_alpn: str = ""
    vmess_fp: str = ""

    def remark_label(self) -> str:
        """生成标准备注：原始地址用 `US-1.2.3.4`，加速线路用 `[US] 1.2.3.4`。"""
        if self.remark:
            return self.remark
        base = self.ip
        if self.city_name:
            return f"{self.city_name}"
        return base

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# 协议生成函数
# ---------------------------------------------------------------------------

def socks5_original(data: ProtocolData) -> str:
    """原始地址 - SOCKS5：socks://user:pass@ip:port#备注"""
    remark = f"{data.country_code}-{data.ip}"
    return f"socks://{data.username}:{data.password}@{data.ip}:{data.port}#{remark}"


def bitbrowser(data: ProtocolData) -> str:
    """原始地址 - 比特浏览器：ip:port:user:pass"""
    return f"{data.ip}:{data.port}:{data.username}:{data.password}"


def vless(data: ProtocolData) -> str:
    """加速线路 - VLESS：vless://uuid@域名:端口?参数#备注"""
    remark = f"[{data.country_code}] {data.ip}"
    return (
        f"vless://{data.uuid}@{data.acceleration_domain}:{data.vless_port}"
        f"?encryption={data.vless_encryption}"
        f"&security={data.vless_security}"
        f"&sni={data.vless_sni}"
        f"&fp={data.vless_fp}"
        f"&pbk={data.vless_pbk}"
        f"&sid={data.vless_sid}"
        f"&spx={data.vless_spx}"
        f"&type={data.vless_type}"
        f"&headerType={data.vless_header_type}"
        f"&flow={data.vless_flow}"
        f"#{_url_encode(remark)}"
    )


def socks_acceleration(data: ProtocolData) -> str:
    """加速线路 - SOCKS：socks://b64user:b64pass@域名:端口#备注"""
    remark = f"[{data.country_code}] {data.ip}"
    return (
        f"socks://{_b64(data.username)}:{_b64(data.password)}"
        f"@{data.acceleration_domain}:{data.acceleration_port_socks}"
        f"#{_url_encode(remark)}"
    )


def vmess(data: ProtocolData) -> str:
    """加速线路 - VMess：vmess://base64(JSON 配置)"""
    config = {
        "v": data.vmess_v,
        "ps": f"[{data.country_code}] {data.ip}",
        "add": data.acceleration_domain,
        "port": str(data.vmess_port),
        "id": data.uuid,
        "aid": data.vmess_aid,
        "scy": data.vmess_scy,
        "net": data.vmess_net,
        "type": data.vmess_type,
        "host": data.vmess_host,
        "path": data.vmess_path,
        "tls": data.vmess_tls,
        "sni": data.vmess_sni,
        "alpn": data.vmess_alpn,
        "fp": data.vmess_fp,
    }
    return f"vmess://{_b64(json.dumps(config, separators=(',', ':')))}"


def _url_encode(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="")


def generate_all(data: ProtocolData) -> dict[str, str]:
    """一次性生成五种协议链接。"""
    return {
        "socks5": socks5_original(data),
        "bitbrowser": bitbrowser(data),
        "vless": vless(data),
        "socksAcceleration": socks_acceleration(data),
        "vmess": vmess(data),
    }


def generate_all_dict(raw: dict[str, Any]) -> dict[str, str]:
    """从字典构造 ProtocolData 并生成五种协议链接。"""
    return generate_all(ProtocolData(**raw))