from __future__ import annotations

import ipaddress
import logging
from typing import Iterable

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from config import config

logger = logging.getLogger(__name__)
security = HTTPBearer()


def _allowed_cidrs() -> list[str]:
    """Return the configured control-plane IP allowlist (empty = disabled)."""
    raw = getattr(config.security, "allowed_cidrs", "") or ""
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def _client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def _ip_in_allowlist(client_ip: str | None, cidrs: Iterable[str]) -> bool:
    if not client_ip:
        return False
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for entry in cidrs:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False


def verify_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    # NOTE: keep the bare Request annotation. FastAPI only injects the request
    # object for Request; Optional[Request] is parsed as a normal model field
    # and raises FastAPIError at route registration, breaking app import.
    token = credentials.credentials
    if token != config.security.token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    # B1: 可选 IP 白名单加固。未配置 allowed_cidrs 时退化为纯 Token 校验，
    # 保持向后兼容；配置后仅允许指定 CIDR 的 Control Plane 调用。
    cidrs = _allowed_cidrs()
    if cidrs:
        client_ip = _client_ip(request)
        if not _ip_in_allowlist(client_ip, cidrs):
            logger.warning(
                "rejected node-manager request from unauthorized ip: %s",
                client_ip,
            )
            raise HTTPException(status_code=403, detail="IP not allowed")
    return token
