from pydantic import BaseModel
from typing import List, Optional

class CreateUserRequest(BaseModel):
    userId: str
    protocols: List[str]

class ProxyConfig(BaseModel):
    type: str
    server: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

class BindProxyRequest(BaseModel):
    userId: str
    proxy: ProxyConfig

class CreateUserResponse(BaseModel):
    userId: str
    uuid: str
    vless: Optional[str] = None
    vmess: Optional[str] = None
    socks: Optional[dict] = None

class NodeStatusResponse(BaseModel):
    node: str
    singbox: str
    cpu: float
    memory: float
    connections: int

class TrafficResponse(BaseModel):
    userId: str
    upload: int
    download: int
    total: int

class ReloadResponse(BaseModel):
    success: bool
