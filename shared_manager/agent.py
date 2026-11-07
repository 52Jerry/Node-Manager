from __future__ import annotations

import hmac
import ipaddress
import os
import socket
from urllib.parse import urlsplit
import httpx

from .settings import Settings


class AgentError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


class Agent:
    def __init__(self, settings: Settings, transport=None):
        self.denied_hosts = {host.strip().strip("[]").lower() for host in os.environ.get("SHARED_UPSTREAM_DENY_HOSTS", "").split(",") if host.strip()}
        self.denied_hosts.add(urlsplit(settings.agent_url).hostname.lower())
        self.client = httpx.Client(base_url=settings.agent_url, headers={"Authorization": "Bearer " + settings.agent_token},
                                   timeout=httpx.Timeout(75, connect=5), follow_redirects=False, trust_env=False, transport=transport)

    def close(self):
        self.client.close()

    def request(self, method: str, path: str, *, missing_user_id: str | None = None, **kwargs):
        try:
            response = self.client.request(method, path, **kwargs)
        except httpx.RequestError:
            raise AgentError(503, "节点暂时无法连接，请稍后重试；不会重复创建账号") from None
        if response.status_code == 404:
            return None
        # Legacy Node Manager maps a missing user to 409 instead of 404.
        # Recognize only this exact identity-specific error; suspended/expired
        # users also return 409 and must never be recreated.
        if response.status_code == 409 and missing_user_id is not None:
            try:
                if response.json().get("detail") == "user not found: " + missing_user_id:
                    return None
            except (ValueError, AttributeError):
                pass
        if response.status_code == 429:
            raise AgentError(429, "节点正在处理其他任务，请稍后重试")
        if response.status_code >= 500:
            raise AgentError(503, "节点正在处理或暂不可用，请稍后检查结果")
        if response.status_code in {400, 409, 422}:
            raise AgentError(409, "节点尚未就绪，或账号已受限、到期；请联系管理员")
        if not 200 <= response.status_code < 300:
            raise AgentError(502, "节点配置异常，请联系管理员")
        try:
            return response.json()
        except ValueError:
            raise AgentError(502, "节点返回格式异常") from None

    @staticmethod
    def verify(result: dict, allocation: dict):
        expected = allocation["request"]
        socks = result.get("socks") or {}
        values = [(result.get("userId"), expected["userId"]), (result.get("uuid"), expected["uuid"]),
                  (socks.get("username"), expected["socksUsername"]), (socks.get("password"), expected["socksPassword"])]
        if any(not isinstance(a, str) or not hmac.compare_digest(a.encode(), b.encode()) for a, b in values):
            raise AgentError(409, "节点账号身份不一致，请联系管理员核对")
        return result

    def connections(self, allocation: dict, create: bool = False):
        path = "/api/user/" + allocation["node_user_id"] + "/connections"
        result = self.request("GET", path, missing_user_id=allocation["node_user_id"])
        if result is None and create and not allocation["ready"]:
            try:
                created = self.request("POST", "/api/user/create", json=allocation["request"],
                                       headers={"Idempotency-Key": allocation["idempotency_key"]})
                if created is None:
                    raise AgentError(502, "节点未提供创建接口")
            except AgentError as exc:
                # A concurrent click may have completed the same persisted identity.
                if exc.status != 409:
                    raise
                result = self.request("GET", path, missing_user_id=allocation["node_user_id"])
                if result is None:
                    raise exc
            if result is None:
                result = self.request("GET", path, missing_user_id=allocation["node_user_id"])
        if result is None:
            if allocation["ready"]:
                raise AgentError(409, "连接账号已被移除，请联系管理员")
            raise AgentError(503, "连接尚未生成完成，请稍后再次点击检查")
        if not isinstance(result, dict):
            raise AgentError(502, "节点返回格式异常")
        return self.verify(result, allocation)

    def public_upstream(self, server: str, port: int, username: str, password: str):
        """Pin a globally routable address; never dial an untrusted DNS name."""
        server = server.strip().strip("[]").rstrip(".").lower()
        if not server or any(char in server for char in "/\\@%#? \t\r\n"):
            raise AgentError(422, "请填写 SOCKS5 服务器域名或公网 IP，不包含协议或路径")
        if len(username.encode()) > 255 or len(password.encode()) > 255 or bool(username) != bool(password):
            raise AgentError(422, "SOCKS5 用户名和密码须同时填写或同时留空，且各不超过 255 字节")
        if server in self.denied_hosts:
            raise AgentError(422, "该地址不能作为上游代理")
        try:
            address = ipaddress.ip_address(server)
            addresses = [address]
        except ValueError:
            if ":" in server or len(server) > 253 or any(not part or len(part) > 63 for part in server.split(".")):
                raise AgentError(422, "上游服务器地址无效") from None
            try:
                addresses = sorted({ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(server, port, type=socket.SOCK_STREAM)}, key=lambda a: (a.version, int(a)))
            except (OSError, ValueError):
                raise AgentError(422, "上游域名暂时无法解析，请核对地址") from None
        addresses = [address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address for address in addresses]
        if not addresses or any(not address.is_global or address.is_multicast or str(address) in self.denied_hosts for address in addresses):
            raise AgentError(422, "上游代理必须使用可访问的公网地址，不能指向节点或内网")
        return {"mode": "socks5", "server": server, "resolvedServer": str(addresses[0]),
                "port": port, "username": username, "password": password}

    def upstream_matches(self, allocation, desired):
        # Ownership is proven before reading or mutating the privileged proxy API.
        self.connections(allocation)
        result = self.request("GET", "/api/user/" + allocation["node_user_id"] + "/proxy")
        if not isinstance(result, dict) or result.get("userId") != allocation["node_user_id"]:
            raise AgentError(502, "节点出口信息不可用")
        if desired["mode"] == "direct":
            return result.get("proxyBound") is False
        if not result.get("proxyBound"):
            return False
        values = [(result.get("server"), desired["resolvedServer"]), (result.get("username") or "", desired["username"]),
                  (result.get("password") or "", desired["password"])]
        return result.get("port") == desired["port"] and all(isinstance(a, str) and hmac.compare_digest(a.encode(), b.encode()) for a, b in values)

    def apply_upstream(self, allocation, operation):
        desired = operation["payload"]
        if self.upstream_matches(allocation, desired):
            return
        key = "shared-route:" + operation["operation_id"]
        if desired["mode"] == "direct":
            result = self.request("POST", "/api/user/" + allocation["node_user_id"] + "/direct",
                                  json={"expectedUuid": allocation["request"]["uuid"], "expectedSocksUsername": allocation["request"]["socksUsername"]},
                                  headers={"Idempotency-Key": key})
        else:
            result = self.request("POST", "/api/user/bind-proxy", json={"userId": allocation["node_user_id"],
                                  "syncSocksCredentials": False, "proxy": {"type": "socks5", "server": desired["resolvedServer"],
                                  "port": desired["port"], "username": desired["username"], "password": desired["password"]}},
                                  headers={"Idempotency-Key": key})
        if result is None:
            raise AgentError(502, "节点尚未支持此出口操作")
        if not self.upstream_matches(allocation, desired):
            raise AgentError(503, "出口变更尚未确认，请稍后使用相同配置重试")

    def traffic(self, allocation):
        result = self.request("GET", "/api/user/" + allocation["node_user_id"] + "/traffic")
        if not isinstance(result, dict) or result.get("userId") != allocation["node_user_id"]:
            raise AgentError(503, "节点流量数据暂不可用")
        return result

    def update_traffic_limit(self, allocation, traffic_limit_bytes: int):
        """Set an absolute quota without resetting usage or credentials."""
        self.connections(allocation)
        result = self.request("PATCH", "/api/user/" + allocation["node_user_id"] + "/policy",
                              json={"trafficLimitBytes": traffic_limit_bytes})
        if result is None:
            raise AgentError(502, "连接暂不支持修改流量额度")
        proof = self.traffic(allocation)
        observed = proof.get("trafficLimitBytes")
        if type(observed) is not int or observed != traffic_limit_bytes:
            raise AgentError(503, "流量额度修改尚未确认，请使用相同额度重试")
        return proof
