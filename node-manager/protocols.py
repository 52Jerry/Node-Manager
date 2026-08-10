"""多协议代理配置生成模块（对标 IPVelo 五种协议）。

基于同一份住宅 SOCKS 代理数据，生成五种标准化协议链接：
  1. SOCKS5（原始）      socks://Base64(user:pass)@ip:port#备注
  2. 比特浏览器          ip:port:user:pass
  3. VLESS（加速）       vless://uuid@域名:端口?参数
  4. SOCKS（加速）       socks://Base64(user:pass)@域名:端口#备注
  5. VMess（加速）       vmess://base64(JSON)

设计原则：后端只返回一份统一数据，前端/本模块按协议模板本地拼接，
不额外发起 API 请求。SOCKS URI 的完整 ``username:password`` 使用标准 Base64
编码后放入 ``@`` 前的 userinfo；服务器端仍使用分开的原始用户名和密码认证。
URI 备注和其他参数继续按 URI 规则编码，只有 VMess 的完整 JSON 载荷也使用 Base64。
"""
from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field
from typing import Any


def _b64(raw: str) -> str:
    """Encode a UTF-8 string with standard Base64 (without line breaks)."""
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def _socks_uri_auth(username: str, password: str) -> str:
    """Return the V2Ray/V2RayN SOCKS userinfo representation.

    The sing-box server still receives the username and password as separate
    fields.  Only the share URI uses the client-compatible convention of
    Base64-encoding the complete ``username:password`` pair before ``@``.
    Keeping this conversion at the presentation boundary prevents the encoded
    value from ever being written into the server's authentication config.
    """
    return _b64(f"{username}:{password}")


def _base64url(raw: bytes) -> str:
    """URL-safe Base64 且去除填充（用于 REALITY 公钥）。"""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _uri_host(value: str) -> str:
    """Format an IPv6 host for URI authority syntax without double brackets."""
    raw = str(value or "").strip()
    if ":" in raw and not raw.startswith("["):
        return f"[{raw}]"
    return raw


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
    # Empty means the caller must supply the current node host.  Keeping this
    # unset prevents a fresh installation from emitting a stale deployment
    # domain; callers may provide either an IP address or a DNS name.
    acceleration_domain: str = ""
    # For residential links, ``ip`` remains the exit-IP shown in the remark,
    # while this optional host is the real upstream SOCKS endpoint clients
    # connect to.  Direct links leave it empty.
    endpoint_host: str = ""
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
    """原始地址 - SOCKS5：socks://user:pass@ip:port#备注。

    V2Ray/V2RayN 兼容完整凭据 Base64 userinfo：先编码
    ``username:password``，再放到 URI 的 ``@`` 前。该格式只用于分享链接，
    不改变服务器端 SOCKS 的实际用户名和密码字段。
    """
    remark = f"{data.country_code}-{data.ip}"
    auth = _socks_uri_auth(str(data.username), str(data.password))
    endpoint = data.endpoint_host or data.ip
    return f"socks://{auth}@{_uri_host(endpoint)}:{data.port}#{_url_encode(remark)}"


def bitbrowser(data: ProtocolData) -> str:
    """原始地址 - 比特浏览器：ip:port:user:pass"""
    endpoint = data.endpoint_host or data.ip
    return f"{endpoint}:{data.port}:{data.username}:{data.password}"


def vless(data: ProtocolData) -> str:
    """加速线路 - VLESS：vless://uuid@域名:端口?参数#备注"""
    remark = f"[{data.country_code}] {data.ip}"
    return (
        f"vless://{data.uuid}@{_uri_host(data.acceleration_domain)}:{data.vless_port}"
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
    """加速线路 SOCKS。

    Use the V2Ray/V2RayN-compatible Base64 userinfo form. The complete
    ``username:password`` pair is encoded as one value for the share URI;
    sing-box itself continues to authenticate with the original separate
    username/password fields.
    """
    remark = f"[{data.country_code}] {data.ip}"
    auth = _socks_uri_auth(str(data.username), str(data.password))
    return (
        f"socks://{auth}"
        f"@{_uri_host(data.acceleration_domain)}:{data.acceleration_port_socks}"
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


def protocol_info(
    data: ProtocolData,
    *,
    protocol_id: str = "",
    status: int = 0,
    expire_time: str | None = None,
    include_original: bool = True,
) -> dict[str, Any]:
    """Return the structured fields needed by a client to build links.

    The keys intentionally use the camelCase contract documented in
    ``IPVelo_代理连接信息生成分析文档.md``.  Complete URI strings remain
    available through :func:`generate_all` for older Control Plane versions.
    ``password`` is only the local SOCKS credential supplied to this method;
    an upstream residential proxy password must never be passed here.
    """
    result: dict[str, Any] = {
        "id": protocol_id or data.uuid,
        "ip": data.ip,
        "port": data.port,
        "username": data.username,
        "password": data.password,
        "countryCode": data.country_code,
        "countryName": data.country_name,
        "cityName": data.city_name,
        "status": status,
        "expireTime": expire_time,
        "remark": data.remark_label(),
        "accelerationDomain": data.acceleration_domain,
        "uuid": data.uuid,
        "accelerationPortSocks": data.acceleration_port_socks,
        "vlessPort": data.vless_port,
        "vlessEncryption": data.vless_encryption,
        "vlessSecurity": data.vless_security,
        "vlessSni": data.vless_sni,
        "vlessFp": data.vless_fp,
        "vlessPbk": data.vless_pbk,
        "vlessSid": data.vless_sid,
        "vlessSpx": data.vless_spx,
        "vlessType": data.vless_type,
        "vlessHeaderType": data.vless_header_type,
        "vlessFlow": data.vless_flow,
        "vmessPort": data.vmess_port,
        "vmessV": data.vmess_v,
        "vmessAid": data.vmess_aid,
        "vmessScy": data.vmess_scy,
        "vmessNet": data.vmess_net,
        "vmessType": data.vmess_type,
        "vmessHost": data.vmess_host,
        "vmessPath": data.vmess_path,
        "vmessTls": data.vmess_tls,
        "vmessSni": data.vmess_sni,
        "vmessAlpn": data.vmess_alpn,
        "vmessFp": data.vmess_fp,
    }
    if include_original:
        result["rawPort"] = data.port
        result["rawProtocol"] = "socks5"
    else:
        # Direct users only expose the three acceleration protocols.
        result.pop("rawPort", None)
        result.pop("rawProtocol", None)
    return result


def generate_all_dict(raw: dict[str, Any]) -> dict[str, str]:
    """从字典构造 ProtocolData 并生成五种协议链接。"""
    return generate_all(ProtocolData(**raw))
