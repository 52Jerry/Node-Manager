from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    secret: str
    agent_token: str
    origin: str
    database: Path = Path(".shared-manager/accounts.json")
    agent_url: str = "http://127.0.0.1:8089"
    site_name: str = "共享节点"
    node_name: str = "共享节点"
    registration_enabled: bool = True
    max_accounts: int = 1000
    registration_daily_attempts: int = 100
    lifetime_days: int = 30
    traffic_limit_bytes: int = 300 * 1024**3
    max_source_ips: int = 3
    session_seconds: int = 43200

    def __post_init__(self):
        if len(self.secret) < 32 or len(self.agent_token) < 16:
            raise ValueError("SHARED_SECRET 至少 32 字符，SHARED_AGENT_TOKEN 至少 16 字符")
        for name, value in (("SHARED_ORIGIN", self.origin), ("SHARED_AGENT_URL", self.agent_url)):
            parts = urlsplit(value)
            if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}:
                raise ValueError(name + " 必须是无路径的 HTTP(S) 地址")
        parts = urlsplit(self.origin)
        if parts.scheme == "http" and parts.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("公网登录入口必须使用 HTTPS；HTTP 仅用于本机预览")
        for name in ("max_accounts", "registration_daily_attempts", "lifetime_days", "traffic_limit_bytes", "max_source_ips", "session_seconds"):
            if getattr(self, name) <= 0:
                raise ValueError(name + " 必须大于 0")
        if self.max_source_ips > 1000:
            raise ValueError("max_source_ips 不能超过 1000")

    @property
    def secure_cookies(self):
        return self.origin.startswith("https://")

    @classmethod
    def from_env(cls):
        return cls(secret=os.environ.get("SHARED_SECRET", ""),
                   agent_token=os.environ.get("SHARED_AGENT_TOKEN", ""),
                   origin=os.environ.get("SHARED_ORIGIN", "http://127.0.0.1:8090").rstrip("/"),
                   database=Path(os.environ.get("SHARED_DATABASE", ".shared-manager/accounts.json")),
                   agent_url=os.environ.get("SHARED_AGENT_URL", "http://127.0.0.1:8089").rstrip("/"),
                   site_name=os.environ.get("SHARED_SITE_NAME", "共享节点"),
                   node_name=os.environ.get("SHARED_NODE_NAME", "共享节点"),
                   registration_enabled=os.environ.get("SHARED_REGISTRATION_ENABLED", "true").lower() == "true",
                   max_accounts=int(os.environ.get("SHARED_MAX_ACCOUNTS", "1000")),
                   registration_daily_attempts=int(os.environ.get("SHARED_REGISTRATION_DAILY_ATTEMPTS", "100")),
                   lifetime_days=int(os.environ.get("SHARED_LIFETIME_DAYS", "30")),
                   traffic_limit_bytes=int(os.environ.get("SHARED_TRAFFIC_LIMIT_BYTES", str(300 * 1024**3))),
                   max_source_ips=int(os.environ.get("SHARED_MAX_SOURCE_IPS", "3")))
