from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


UserProtocol = Literal["vless", "vmess", "socks"]


class ProxyConfig(BaseModel):
    type: Literal["socks5", "socks"] = "socks5"
    server: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=255)


class CreateUserRequest(BaseModel):
    userId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    protocols: list[UserProtocol] = Field(
        default_factory=lambda: ["vless", "vmess", "socks"],
        min_length=1,
    )
    socksUsername: str | None = Field(default=None, min_length=1, max_length=255)
    socksPassword: str | None = Field(default=None, min_length=1, max_length=255)
    proxy: ProxyConfig | None = None

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


class BindProxyRequest(BaseModel):
    userId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    proxy: ProxyConfig


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
    vless: str | None = None
    vmess: str | None = None
    socks: SocksConnection | None = None
    proxyBound: bool = False


class UserConnectionResponse(CreateUserResponse):
    createdAt: datetime | None = None


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
    status: Literal["active"] = "active"
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
    traffic: TrafficTotals
    reportedAt: datetime
