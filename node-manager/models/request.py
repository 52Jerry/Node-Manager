from typing import Literal

from pydantic import BaseModel, Field, field_validator


UserProtocol = Literal["vless", "vmess", "socks"]


class CreateUserRequest(BaseModel):
    userId: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    protocols: list[UserProtocol] = Field(
        default_factory=lambda: ["vless", "vmess", "socks"],
        min_length=1,
    )

    @field_validator("protocols")
    @classmethod
    def protocols_must_be_unique(cls, value: list[UserProtocol]) -> list[UserProtocol]:
        if len(value) != len(set(value)):
            raise ValueError("protocols must not contain duplicates")
        return value


class ProxyConfig(BaseModel):
    type: Literal["socks5", "socks"] = "socks5"
    server: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=255)


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
    api_available: bool


class TrafficResponse(BaseModel):
    userId: str
    upload: int = 0
    download: int = 0
    total: int = 0


class ReloadResponse(BaseModel):
    success: bool
