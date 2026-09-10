from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator
import re

_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


UserProtocol = Literal["vless", "vmess", "socks"]


class ProxyConfig(BaseModel):
    type: Literal["socks5", "socks"] = "socks5"
    server: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=255)


class ProxyDescriptor(ProxyConfig):
    """上游代理完整描述。

    与 ``ProxyConfig`` 相比增加 ``sourceIp``，表示该代理出口/入口的真实对外 IP，
    用于生成原始链接（SOCKS5 / BitBrowser）和展示出口信息。
    """

    sourceIp: str | None = Field(default=None, max_length=255)
    sourceAddress: str | None = Field(default=None, max_length=255)
    countryCode: str = Field(default="XX", max_length=8)
    countryName: str = ""
    cityName: str = ""


class ResidentialSocksRequest(BaseModel):
    """住宅 SOCKS 代理配置生成请求（对标 IPVelo 五协议）。"""
    ip: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    countryCode: str = Field(default="XX", min_length=0, max_length=8)
    countryName: str = ""
    cityName: str = ""
    uuid: str = Field(default="", max_length=64)
    accelerationDomain: str | None = Field(default=None, max_length=255)

    @field_validator("uuid")
    @classmethod
    def uuid_must_be_valid(cls, value: str) -> str:
        if value and not _UUID_PATTERN.match(value):
            raise ValueError("uuid must be a valid UUID v4 string")
        return value


class ResidentialProtocolsResponse(BaseModel):
    success: bool
    ip: str
    port: int
    protocolsAll: dict[str, str]
    protocolInfo: dict[str, Any] = Field(default_factory=dict)


class CreateUserRequest(BaseModel):
    userId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    protocols: list[UserProtocol] = Field(
        default_factory=lambda: ["vless", "vmess", "socks"],
        min_length=1,
    )
    socksUsername: str | None = Field(default=None, min_length=1, max_length=255)
    socksPassword: str | None = Field(default=None, min_length=1, max_length=255)
    # Keep residential metadata (sourceIp/sourceAddress/country) when the
    # request comes from Control Plane.  ProxyConfig would silently discard
    # those extra fields during Pydantic validation.
    proxy: ProxyDescriptor | None = None
    trafficLimitBytes: int | None = Field(default=None, ge=0)
    maxSourceIps: int | None = Field(default=None, ge=0, le=1000)

    @field_validator("protocols")
    @classmethod
    def protocols_must_be_unique(cls, value: list[UserProtocol]) -> list[UserProtocol]:
        if len(value) != len(set(value)):
            raise ValueError("protocols must not contain duplicates")
        return value

    @model_validator(mode="after")
    def socks_credentials_require_socks_protocol(self):
        if (self.socksUsername is not None or self.socksPassword is not None) and "socks" not in self.protocols:
            raise ValueError("socksUsername and socksPassword require the socks protocol")
        return self


class UpdateUserPolicyRequest(BaseModel):
    trafficLimitBytes: int | None = Field(default=None, ge=0)
    maxSourceIps: int | None = Field(default=None, ge=0, le=1000)

    @model_validator(mode="after")
    def at_least_one_policy_is_required(self):
        if not self.model_fields_set:
            raise ValueError("at least one policy field is required")
        return self


class BindProxyRequest(BaseModel):
    userId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    proxy: ProxyDescriptor


class ProxyMetadataUpdateRequest(BaseModel):
    sourceIp: str | None = Field(default=None, max_length=255)
    sourceAddress: str | None = Field(default=None, max_length=255)
    sourcePort: int | None = Field(default=None, ge=1, le=65535)
    countryCode: str | None = Field(default=None, max_length=8)
    countryName: str | None = Field(default=None, max_length=255)
    cityName: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def at_least_one_metadata_field_is_required(self):
        if not self.model_fields_set:
            raise ValueError("at least one proxy metadata field is required")
        return self


class SocksConnection(BaseModel):
    host: str
    port: int
    username: str
    password: str


class CreateUserResponse(BaseModel):
    success: bool = True
    userId: str
    uuid: str
    protocols: list[UserProtocol]
    # 五协议统一输出。使用默认空字典兼容旧版 Node Manager 响应和无 SOCKS 用户。
    protocolsAll: dict[str, str] = Field(default_factory=dict)
    vless: str | None = None
    vmess: str | None = None
    socks: SocksConnection | None = None
    proxyBound: bool = False
    protocolInfo: dict[str, Any] = Field(default_factory=dict)


class UserConnectionResponse(CreateUserResponse):
    createdAt: datetime | None = None


class ProxyDetailsResponse(BaseModel):
    userId: str
    proxyBound: bool
    server: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    sourceIp: str | None = None
    sourceAddress: str | None = None
    sourcePort: int | None = None
    countryCode: str | None = None
    countryName: str | None = None
    cityName: str | None = None
    protocolInfo: dict[str, Any] = Field(default_factory=dict)


class OperationResponse(BaseModel):
    success: bool
    userId: str | None = None
    message: str | None = None


class NodeStatusResponse(BaseModel):
    node: str
    name: str
    host: str
    singbox: str
    cpu: float
    memory: float
    connections: int
    systemConnections: int
    api_available: bool


class TrafficResponse(BaseModel):
    userId: str
    upload: int = 0
    download: int = 0
    total: int = 0
    available: bool = False
    source: str = "clash-api-sampled"
    collectedAt: datetime | None = None
    trafficLimitBytes: int | None = None
    maxSourceIps: int | None = None
    activeSourceIps: list[str] = Field(default_factory=list)
    status: Literal["active", "traffic_limited", "device_limited"] = "active"


class ReloadResponse(BaseModel):
    success: bool


class UserSummary(BaseModel):
    userId: str
    protocols: list[UserProtocol]
    socksUsername: str | None = None
    proxyBound: bool
    proxyServer: str | None = None
    upload: int = 0
    download: int = 0
    total: int = 0
    trafficLimitBytes: int | None = None
    maxSourceIps: int | None = None
    activeSourceIps: list[str] = Field(default_factory=list)
    status: Literal["active", "traffic_limited", "device_limited"] = "active"
    createdAt: datetime | None = None


class UserListResponse(BaseModel):
    items: list[UserSummary]
    page: int
    pageSize: int
    total: int


class NodeSummary(BaseModel):
    nodeId: str
    name: str
    host: str
    domain: str | None = None
    managerVersion: str
    singboxVersion: str
    status: Literal["online", "offline"]
    singbox: str
    cpu: float
    memory: float
    connections: int
    systemConnections: int
    userCount: int
    apiAvailable: bool
    lastHeartbeatAt: datetime


class NodeListResponse(BaseModel):
    items: list[NodeSummary]
    page: int
    pageSize: int
    total: int


class AgentInfoResponse(BaseModel):
    agent: str = "node-manager"
    apiVersion: str
    managerVersion: str
    nodeId: str
    capabilities: list[str]
    controlPlaneResponsibilities: list[str]
    idempotencyHeader: str = "Idempotency-Key"
    heartbeatEndpoint: str = "/api/agent/heartbeat"


class TrafficTotals(BaseModel):
    upload: int = 0
    download: int = 0
    total: int = 0
    available: bool = False
    source: str = "clash-api-sampled"
    collectedAt: datetime | None = None


class DeadOutboundInfo(BaseModel):
    """死掉的上游代理信息，用于心跳上报到控制中心。"""
    userId: str
    server: str
    port: int
    tag: str
    failCount: int


class AgentHeartbeatResponse(BaseModel):
    nodeId: str
    name: str
    host: str
    status: Literal["online", "degraded", "offline"]
    managerVersion: str
    singboxVersion: str
    singbox: str
    apiAvailable: bool
    cpu: float
    memory: float
    connections: int
    systemConnections: int
    userCount: int
    socksPort: int | None = Field(default=None, ge=1, le=65535)
    traffic: TrafficTotals
    deadOutbounds: list[DeadOutboundInfo] = Field(default_factory=list)
    reportedAt: datetime
