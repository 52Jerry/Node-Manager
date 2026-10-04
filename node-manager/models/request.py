from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator
import re

_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


UserProtocol = Literal["vless", "vmess", "socks", "trojan"]


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
    provinceName: str = ""
    cityName: str = ""


class ResidentialSocksRequest(BaseModel):
    """住宅 SOCKS 代理配置生成请求（对标 IPVelo 五协议）。"""
    ip: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    username: str = Field(default="")
    password: str = Field(default="")
    countryCode: str = Field(default="XX", min_length=0, max_length=8)
    countryName: str = ""
    provinceName: str = ""
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
    # B1: Control Plane 可指定 UUID，确保多节点共享同一 UUID（主备/负载均衡场景）。
    # 留空时 Node Manager 仍随机生成，保持向后兼容。
    uuid: str = Field(default="", max_length=64)
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
    expiresAt: datetime | None = None

    @field_validator("uuid")
    @classmethod
    def uuid_must_be_valid(cls, value: str) -> str:
        if value and not _UUID_PATTERN.match(value):
            raise ValueError("uuid must be a valid UUID v4 string")
        return value

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

    @field_validator("expiresAt")
    @classmethod
    def expiration_must_be_in_the_future(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            if normalized <= datetime.now(timezone.utc):
                raise ValueError("expiresAt must be in the future")
        return value


class UpdateUserPolicyRequest(BaseModel):
    trafficLimitBytes: int | None = Field(default=None, ge=0)
    maxSourceIps: int | None = Field(default=None, ge=0, le=1000)
    maxConnections: int | None = Field(default=None, ge=0, le=100000)

    @model_validator(mode="after")
    def at_least_one_policy_is_required(self):
        if not self.model_fields_set:
            raise ValueError("at least one policy field is required")
        return self


class ApplyDefaultTrafficLimitRequest(BaseModel):
    trafficLimitBytes: int = Field(ge=0, le=1073741824000000)


class RenewUserRequest(BaseModel):
    expiresAt: datetime
    trafficLimitBytes: int | None = Field(default=None, ge=0)
    maxSourceIps: int | None = Field(default=None, ge=0, le=1000)
    resetTraffic: bool = True

    @field_validator("expiresAt")
    @classmethod
    def expiration_must_be_in_the_future(cls, value: datetime) -> datetime:
        normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if normalized <= datetime.now(timezone.utc):
            raise ValueError("expiresAt must be in the future")
        return value


class BindProxyRequest(BaseModel):
    userId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    proxy: ProxyDescriptor
    syncSocksCredentials: bool = False
    uuid: str = Field(default="", max_length=64)

    @field_validator("uuid")
    @classmethod
    def uuid_must_be_valid(cls, value: str) -> str:
        if value and not _UUID_PATTERN.match(value):
            raise ValueError("uuid must be a valid UUID v4 string")
        return value


class BindMultipleProxiesRequest(BaseModel):
    """负载均衡：为一个用户绑定多个上游住宅 SOCKS 出口。

    mode:
      - selector: sing-box selector outbound，支持手动切换默认出口
      - urltest:  sing-box urltest outbound，自动探测延迟最低的出口
    """

    userId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    proxies: list[ProxyDescriptor] = Field(min_length=2, max_length=16)
    mode: Literal["selector", "urltest"] = "urltest"
    healthCheckUrl: str = Field(
        default="https://www.gstatic.com/generate_204", max_length=512
    )
    interval: str = Field(default="3m", max_length=8)
    tolerance: int = Field(default=50, ge=0, le=1000)

    @field_validator("interval")
    @classmethod
    def interval_must_look_like_duration(cls, value: str) -> str:
        if not value or not value[-1].isalpha():
            raise ValueError("interval must be a duration like '3m' or '30s'")
        return value


class ProxyMetadataUpdateRequest(BaseModel):
    sourceIp: str | None = Field(default=None, max_length=255)
    sourceAddress: str | None = Field(default=None, max_length=255)
    sourcePort: int | None = Field(default=None, ge=1, le=65535)
    countryCode: str | None = Field(default=None, max_length=8)
    countryName: str | None = Field(default=None, max_length=255)
    provinceName: str | None = Field(default=None, max_length=255)
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
    # 六协议统一输出。使用默认空字典兼容旧版 Node Manager 响应和无 SOCKS 用户。
    protocolsAll: dict[str, str] = Field(default_factory=dict)
    vless: str | None = None
    vmess: str | None = None
    trojan: str | None = None
    socks: SocksConnection | None = None
    proxyBound: bool = False
    protocolInfo: dict[str, Any] = Field(default_factory=dict)


class UserConnectionResponse(CreateUserResponse):
    createdAt: datetime | None = None
    expiresAt: datetime | None = None
    expirationStatus: Literal["ACTIVE", "EXPIRED"] = "ACTIVE"


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
    provinceName: str | None = None
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


class OnlineConnection(BaseModel):
    id: str
    deviceId: str | None = None
    credentialId: str | None = None
    sourceIp: str | None = None
    sourcePort: int | None = None
    destinationIp: str | None = None
    destinationPort: int | None = None
    host: str | None = None
    network: str | None = None
    protocol: str | None = None
    startedAt: datetime | None = None
    upload: int = 0
    download: int = 0


class TrafficResponse(BaseModel):
    userId: str
    upload: int = 0
    download: int = 0
    total: int = 0
    available: bool = False
    source: str = "clash-api-sampled"
    collectedAt: datetime | None = None
    onlineConnections: list[OnlineConnection] | None = None
    sourceIpActiveWindowSeconds: float | None = None
    trafficLimitBytes: int | None = None
    maxSourceIps: int | None = None
    maxConnections: int | None = None
    connectionLimitSupported: bool = True
    activeSourceIps: list[str] = Field(default_factory=list)
    status: Literal["active", "traffic_limited", "device_limited", "connection_limited"] = "active"


class ReloadResponse(BaseModel):
    success: bool


class UserSummary(BaseModel):
    userId: str
    protocols: list[UserProtocol]
    socksUsername: str | None = None
    proxyBound: bool
    proxyServer: str | None = None
    sourceIp: str | None = None
    countryCode: str | None = None
    countryName: str | None = None
    provinceName: str | None = None
    cityName: str | None = None
    upload: int = 0
    download: int = 0
    total: int = 0
    trafficLimitBytes: int | None = None
    maxSourceIps: int | None = None
    activeSourceIps: list[str] = Field(default_factory=list)
    status: Literal["active", "traffic_limited", "device_limited", "connection_limited"] = "active"
    createdAt: datetime | None = None
    expiresAt: datetime | None = None
    expirationStatus: Literal["ACTIVE", "EXPIRED"] = "ACTIVE"


class UserListResponse(BaseModel):
    items: list[UserSummary]
    page: int
    pageSize: int
    total: int


class BatchDeleteUsersRequest(BaseModel):
    userIds: list[str] = Field(min_length=1, max_length=100)

    @field_validator("userIds")
    @classmethod
    def user_ids_must_be_valid_and_unique(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 64 or not re.fullmatch(r"[A-Za-z0-9._-]+", item) for item in normalized):
            raise ValueError("userIds contains an invalid user id")
        return list(dict.fromkeys(normalized))


class BatchDeleteUserFailure(BaseModel):
    userId: str
    error: str


class BatchDeleteUsersResponse(BaseModel):
    success: bool
    deleted: list[str] = Field(default_factory=list)
    failed: list[BatchDeleteUserFailure] = Field(default_factory=list)


class UpdateUserExpirationRequest(BaseModel):
    expiresAt: datetime

    @field_validator("expiresAt")
    @classmethod
    def expiration_must_be_in_the_future(cls, value: datetime) -> datetime:
        normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if normalized <= datetime.now(timezone.utc):
            raise ValueError("expiresAt must be in the future")
        return value


class RestoreUserRequest(UpdateUserExpirationRequest):
    pass


class ExpectedExpirationProxy(BaseModel):
    server: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class SyncUserExpirationRequest(BaseModel):
    expiresAt: datetime
    snapshotStartedAt: datetime | None = None
    expectedExpiresAt: datetime | None
    expectedProxy: ExpectedExpirationProxy

    @field_validator("expiresAt", "expectedExpiresAt", "snapshotStartedAt")
    @classmethod
    def synchronization_dates_require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("synchronization dates must include a timezone")
        return value


class BatchExpirationSyncItem(SyncUserExpirationRequest):
    userId: str = Field(min_length=1, max_length=64)


class BatchExpirationSyncRequest(BaseModel):
    items: list[BatchExpirationSyncItem] = Field(min_length=1, max_length=100)


class ExpiredUserSummary(BaseModel):
    userId: str
    createdAt: datetime | None = None
    expiresAt: datetime | None = None
    expiredAt: datetime | None = None
    archivedAt: datetime | None = None
    status: Literal["EXPIRED", "ARCHIVED"]
    protocols: list[UserProtocol] = Field(default_factory=list)


class ExpiredUserListResponse(BaseModel):
    items: list[ExpiredUserSummary]
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
