from __future__ import annotations

import logging
import os
import socket
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from auth import verify_token
from config import config
from idempotency import IdempotencyConflict, execute_idempotent
from models.request import (
    AgentHeartbeatResponse,
    AgentInfoResponse,
    BindMultipleProxiesRequest,
    BindProxyRequest,
    CreateUserRequest,
    CreateUserResponse,
    NodeListResponse,
    NodeStatusResponse,
    OperationResponse,
    ProxyDetailsResponse,
    ProxyMetadataUpdateRequest,
    ReloadResponse,
    ResidentialProtocolsResponse,
    ResidentialSocksRequest,
    TrafficResponse,
    UpdateUserExpirationRequest,
    UpdateUserPolicyRequest,
    RestoreUserRequest,
    ExpiredUserListResponse,
    UserConnectionResponse,
    UserListResponse,
)
from protocols import ProtocolData, generate_all, protocol_info
from residential import ResidentialConfigError, validate_config
from revision import (
    apply_desired_revision,
    get_revision_state,
    rollback_to_last_known_good,
)
from monitor.status import get_node_status
from monitor.traffic import (
    collect_traffic,
    delete_user_traffic,
    get_traffic_totals,
    get_user_traffic,
    get_traffic_store_snapshot,
    start_traffic_collector,
    stop_traffic_collector,
)
from network_check import run_network_check
from monitor.health_check import (
    start_health_checker,
    stop_health_checker,
    get_dead_outbounds,
)
from singbox.manager import (
    SingboxConfigError,
    bind_proxy,
    bind_multiple_proxies,
    build_protocol_info,
    create_user,
    delete_user,
    ensure_user_outbounds,
    migrate_legacy_socks_usernames,
    get_user_connection,
    get_user_proxy,
    get_user_policies,
    update_proxy_metadata,
    update_user_policy,
    get_socks_inbound_port,
    is_api_available,
    list_users,
    list_expired_users,
    migrate_user_expirations,
    process_user_expirations,
    restore_user,
    start_expiration_scheduler,
    stop_expiration_scheduler,
    update_user_expiration,
    reload_singbox,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = FastAPI(
    title="Python Node Manager API",
    version="1.4.11",
    description="Single-node sing-box agent API for a Spring Boot multi-node control plane.",
)

static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.exception_handler(SingboxConfigError)
async def singbox_error_handler(_request: Request, exc: SingboxConfigError):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(IdempotencyConflict)
async def idempotency_error_handler(_request: Request, exc: IdempotencyConflict):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.on_event("startup")
def startup_tasks():
    try:
        migrated_expirations = migrate_user_expirations()
        if migrated_expirations:
            logging.getLogger(__name__).info("backfilled expiration for %s existing users", migrated_expirations)
        migrated_socks = migrate_legacy_socks_usernames()
        if migrated_socks:
            logging.getLogger(__name__).info("migrated %s legacy SOCKS usernames", migrated_socks)
        migrated = ensure_user_outbounds()
        if migrated:
            logging.getLogger(__name__).info("added traffic outbounds for %s existing users", migrated)
    except Exception:
        logging.getLogger(__name__).exception("could not migrate existing user traffic outbounds")
    start_traffic_collector()
    start_health_checker()
    start_expiration_scheduler()


@app.on_event("shutdown")
def shutdown_tasks():
    stop_expiration_scheduler()
    stop_health_checker()
    stop_traffic_collector()


@app.get("/", include_in_schema=False)
def root():
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}


@app.get("/api/node/status", response_model=NodeStatusResponse, tags=["node"])
def get_status(_token: str = Depends(verify_token)):
    status = get_node_status(config.node.id)
    return {
        **status,
        "name": config.node.name,
        "host": config.node.host,
        "api_available": is_api_available(),
    }


@app.get("/api/node/network-check", tags=["node"])
def network_check_endpoint(_token: str = Depends(verify_token)):
    """B6: 节点网络前置检查。

    检查项：
      - 端口监听（VLESS/VMess/Trojan/SOCKS/Manager/Clash API）
      - 防火墙放行（ufw/iptables）
      - IP 转发（DNAT 依赖 net.ipv4.ip_forward=1）
      - MTU（避免大包分片导致代理卡顿，建议 ≥1280）
      - TCP 本地连通性（端口握手探测）

    用于节点上线前自检与排障，所有命令均带超时避免卡死。
    在非 Linux 开发环境退化为仅报告不可用，不抛异常。
    """
    return run_network_check().to_dict()


@app.post("/api/user/create", response_model=CreateUserResponse, tags=["users"])
def create_user_endpoint(
    request: CreateUserRequest,
    response: Response,
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key", min_length=1, max_length=128
    ),
    _token: str = Depends(verify_token),
):
    payload = request.model_dump(mode="json")
    result, replayed = execute_idempotent(
        idempotency_key,
        "create-user",
        payload,
        lambda: create_user(
            request.userId,
            list(request.protocols),
            user_uuid=request.uuid or None,
            socks_username=request.socksUsername,
            socks_password=request.socksPassword,
            proxy=request.proxy.model_dump() if request.proxy else None,
            traffic_limit_bytes=request.trafficLimitBytes,
            max_source_ips=request.maxSourceIps,
            expires_at=request.expiresAt,
        ),
    )
    response.headers["Idempotency-Replayed"] = str(replayed).lower()
    return result


@app.post(
    "/api/residential/protocols",
    response_model=ResidentialProtocolsResponse,
    tags=["residential"],
)
def generate_residential_protocols(
    request: ResidentialSocksRequest,
    response: Response,
    _token: str = Depends(verify_token),
):
    """住宅 SOCKS 代理配置模块：校验输入并生成五种协议模板。

    该接口本身接收完整的住宅 SOCKS 参数，因此返回五种标准化协议。
    节点用户创建/连接接口则按是否绑定住宅出口动态返回三种或五种协议。
    """
    try:
        cfg = validate_config(
            request.ip,
            request.port,
            request.username,
            request.password,
            country_code=request.countryCode,
            country_name=request.countryName,
            city_name=request.cityName,
        )
    except ResidentialConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # 直接调用该生成接口时也必须得到可用的 VLESS/VMess UUID。
    # 显式传入的 UUID 保持兼容；未传时由服务端一次生成并复用于两种协议。
    effective_uuid = request.uuid or str(uuid.uuid4())
    data = cfg.to_protocol_data(
        uuid=effective_uuid,
        acceleration_domain=(
            request.accelerationDomain
            or config.node.acceleration_domain
            or config.node.host
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    return {
        "success": True,
        "ip": data.ip,
        "port": data.port,
        "protocolInfo": protocol_info(
            data,
            protocol_id=effective_uuid,
            include_original=True,
        ),
        "protocolsAll": generate_all(data),
    }


@app.get("/api/users", response_model=UserListResponse, tags=["users"])
def get_users(
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=20, ge=1, le=100),
    keyword: str | None = Query(default=None, max_length=64),
    sort: Literal["createdAsc", "createdDesc", "userIdAsc", "userIdDesc"] = Query(
        default="createdDesc"
    ),
    _token: str = Depends(verify_token),
):
    items = list_users()
    if keyword:
        normalized = keyword.casefold()
        items = [
            item
            for item in items
            if normalized in item["userId"].casefold()
            or normalized in (item.get("socksUsername") or "").casefold()
        ]
    items = _sort_users(items, sort)
    total = len(items)
    start = (page - 1) * pageSize
    page_items = items[start:start + pageSize]
    # Traffic is sampled by the background collector. Do not block every user
    # list request on a live sing-box /connections call.
    traffic_available = None
    policies = get_user_policies()
    traffic_store = get_traffic_store_snapshot()
    for item in page_items:
        traffic = get_user_traffic(
            item["userId"],
            refresh=False,
            available=traffic_available,
            policy=policies.get(item["userId"], {}),
            store=traffic_store,
        )
        item.update(
            upload=traffic["upload"],
            download=traffic["download"],
            total=traffic["total"],
            trafficLimitBytes=traffic["trafficLimitBytes"],
            maxSourceIps=traffic["maxSourceIps"],
            activeSourceIps=traffic["activeSourceIps"],
            status=traffic["status"],
        )
    return {"items": page_items, "page": page, "pageSize": pageSize, "total": total}


def _sort_users(items: list[dict], sort: str) -> list[dict]:
    """Sort before pagination so large nodes do not require control-plane scans."""
    if sort in {"userIdAsc", "userIdDesc"}:
        return sorted(
            items,
            key=lambda item: str(item.get("userId") or "").casefold(),
            reverse=sort == "userIdDesc",
        )

    def created_key(item: dict) -> tuple[bool, float, str]:
        value = item.get("createdAt")
        timestamp = 0.0
        has_timestamp = False
        if value:
            try:
                timestamp = datetime.fromisoformat(
                    str(value).replace("Z", "+00:00")
                ).timestamp()
                has_timestamp = True
            except (TypeError, ValueError, OverflowError):
                pass
        # Missing legacy timestamps stay at the end and remain deterministic.
        normalized_timestamp = timestamp if sort == "createdAsc" else -timestamp
        return (not has_timestamp, normalized_timestamp, str(item.get("userId") or "").casefold())

    return sorted(items, key=created_key)


@app.get(
    "/api/user/{userId}/connections",
    response_model=UserConnectionResponse,
    tags=["users"],
)
def get_user_connections(
    userId: str,
    response: Response,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    response.headers["Cache-Control"] = "no-store"
    return get_user_connection(userId)


@app.get(
    "/api/user/{userId}/proxy",
    response_model=ProxyDetailsResponse,
    tags=["users"],
)
def get_user_proxy_endpoint(
    userId: str,
    response: Response,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    response.headers["Cache-Control"] = "no-store"
    return get_user_proxy(userId)


@app.post("/api/user/bind-proxy", response_model=OperationResponse, tags=["users"])
def bind_proxy_endpoint(
    request: BindProxyRequest,
    response: Response,
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key", min_length=1, max_length=128
    ),
    _token: str = Depends(verify_token),
):
    result, replayed = execute_idempotent(
        idempotency_key,
        "bind-proxy",
        request.model_dump(mode="json"),
        lambda: bind_proxy(request.userId, request.proxy.model_dump()),
    )
    response.headers["Idempotency-Replayed"] = str(replayed).lower()
    return result


@app.post("/api/user/bind-proxies", tags=["users"])
def bind_multiple_proxies_endpoint(
    request: BindMultipleProxiesRequest,
    response: Response,
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key", min_length=1, max_length=128
    ),
    _token: str = Depends(verify_token),
):
    """负载均衡：为一个用户绑定多个上游 SOCKS 出口（selector/urltest 聚合）。"""
    payload = request.model_dump(mode="json")
    result, replayed = execute_idempotent(
        idempotency_key,
        "bind-proxies",
        payload,
        lambda: bind_multiple_proxies(
            request.userId,
            [proxy.model_dump() for proxy in request.proxies],
            mode=request.mode,
            health_check_url=request.healthCheckUrl,
            interval=request.interval,
            tolerance=request.tolerance,
        ),
    )
    response.headers["Idempotency-Replayed"] = str(replayed).lower()
    return result


@app.patch(
    "/api/user/{userId}/proxy-metadata",
    response_model=OperationResponse,
    tags=["users"],
)
def update_proxy_metadata_endpoint(
    userId: str,
    request: ProxyMetadataUpdateRequest,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    return update_proxy_metadata(userId, request.model_dump(exclude_unset=True))


@app.delete("/api/user/delete/{userId}", response_model=OperationResponse, tags=["users"])
def delete_user_endpoint(
    userId: str,
    response: Response,
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key", min_length=1, max_length=128
    ),
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    def perform_delete():
        result = delete_user(userId)
        try:
            delete_user_traffic(userId)
        except Exception:
            logging.getLogger(__name__).exception(
                "could not delete traffic history for user %s", userId
            )
        return result

    result, replayed = execute_idempotent(
        idempotency_key,
        "delete-user",
        {"userId": userId},
        perform_delete,
    )
    response.headers["Idempotency-Replayed"] = str(replayed).lower()
    return result


@app.get("/api/user/{userId}/traffic", response_model=TrafficResponse, tags=["users"])
def get_user_traffic_endpoint(userId: str, _token: str = Depends(verify_token)):
    return get_user_traffic(userId)


@app.patch("/api/user/{userId}/policy", tags=["users"])
def update_user_policy_endpoint(
    userId: str,
    request: UpdateUserPolicyRequest,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    return update_user_policy(userId, request.model_dump(exclude_unset=True))


@app.get("/api/users/expired", response_model=ExpiredUserListResponse, tags=["users"])
def get_expired_users(_token: str = Depends(verify_token)):
    process_user_expirations()
    items = list_expired_users()
    return {"items": items, "total": len(items)}


@app.patch("/api/user/{userId}/expiration", tags=["users"])
def update_user_expiration_endpoint(
    userId: str,
    request: UpdateUserExpirationRequest,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    return update_user_expiration(userId, request.expiresAt)


@app.post("/api/user/{userId}/restore", tags=["users"])
def restore_user_endpoint(
    userId: str,
    request: RestoreUserRequest,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    return restore_user(userId, request.expiresAt)


@app.post("/api/singbox/reload", response_model=ReloadResponse, tags=["sing-box"])
def singbox_reload(_token: str = Depends(verify_token)):
    return ReloadResponse(success=reload_singbox())


class DesiredRevisionRequest(BaseModel):
    """B2: Control Plane 推送的期望配置载荷。"""

    config: dict = Field(default_factory=dict)
    registry: dict = Field(default_factory=dict)
    revisionId: str = Field(min_length=1, max_length=128)
    # B5: 显式声明允许删除用户，对照删除审计
    allowUserDeletion: bool = False


@app.get("/api/agent/revision/state", tags=["revision"])
def get_revision_state_endpoint(_token: str = Depends(verify_token)):
    """B2: 返回当前节点 revision 状态，供 Control Plane 拉取。"""
    return get_revision_state()


@app.post("/api/agent/revision/apply", tags=["revision"])
def apply_revision_endpoint(
    request: DesiredRevisionRequest,
    response: Response,
    x_revision_signature: str = Header(default="", alias="X-Revision-Signature"),
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key", min_length=1, max_length=128
    ),
    _token: str = Depends(verify_token),
):
    """B2+B3+B4+B5: 应用带签名的期望配置，含用户集合缩减保护，失败自动回滚。"""
    payload = request.model_dump(mode="json")
    result, replayed = execute_idempotent(
        idempotency_key,
        "apply-revision",
        payload,
        lambda: apply_desired_revision(
            request.config,
            request.registry,
            x_revision_signature,
            request.revisionId,
            allow_user_deletion=request.allowUserDeletion,
        ),
    )
    response.headers["Idempotency-Replayed"] = str(replayed).lower()
    return result


@app.post("/api/agent/revision/rollback", tags=["revision"])
def rollback_revision_endpoint(_token: str = Depends(verify_token)):
    """B4: 显式回滚到上一个已知良好配置。"""
    return rollback_to_last_known_good()


@app.get("/api/singbox/api/status", tags=["sing-box"])
def api_status(_token: str = Depends(verify_token)):
    return {"available": is_api_available(), "usage": "metrics-only"}


@app.get("/api/agent/info", response_model=AgentInfoResponse, tags=["agent"])
def get_agent_info(_token: str = Depends(verify_token)):
    return {
        "apiVersion": "v1",
        "managerVersion": _manager_version(),
        "nodeId": config.node.id,
        "capabilities": [
            "user.create",
            "user.create.uuid",
            "user.delete",
            "user.list",
            "user.connections",
            "proxy.bind",
            "proxy.bind.multiple",
            "proxy.metadata.update",
            "traffic.sampled",
            "traffic.quota",
            "user.source-ip-limit",
            "user.policy.update",
            "user.expiration.update",
            "user.expiration.restore",
            "user.expiration.archive",
            "node.heartbeat",
            "request.idempotency",
            "revision.desired",
            "revision.apply",
            "revision.rollback",
            "network.check",
        ],
        "controlPlaneResponsibilities": [
            "node-registry",
            "heartbeat-scheduling",
            "offline-detection",
            "global-user-allocation",
            "billing-and-business-data",
        ],
    }


@app.get(
    "/api/agent/heartbeat", response_model=AgentHeartbeatResponse, tags=["agent"]
)
def get_agent_heartbeat(_token: str = Depends(verify_token)):
    current = get_node_status(config.node.id)
    api_available = is_api_available()
    status = "online" if current["singbox"] == "running" and api_available else "degraded"
    if current["singbox"] != "running":
        status = "offline"
    return {
        "nodeId": config.node.id,
        "name": config.node.name,
        "host": config.node.host,
        "status": status,
        "managerVersion": _manager_version(),
        "singboxVersion": _singbox_version(),
        "singbox": current["singbox"],
        "apiAvailable": api_available,
        "cpu": current["cpu"],
        "memory": current["memory"],
        "connections": current["connections"],
        "systemConnections": current["systemConnections"],
        "userCount": len(list_users()),
        "socksPort": get_socks_inbound_port(),
        # The collector samples traffic in the background. Avoid an extra
        # synchronous sing-box request on every control-plane heartbeat.
        "traffic": get_traffic_totals(refresh=False),
        "deadOutbounds": get_dead_outbounds(),
        "reportedAt": datetime.now(timezone.utc),
    }


def _manager_version() -> str:
    version_path = Path(__file__).with_name("VERSION")
    return version_path.read_text(encoding="utf-8").strip() if version_path.exists() else app.version


def _singbox_version() -> str:
    try:
        result = subprocess.run(
            ["sing-box", "version"], capture_output=True, text=True, timeout=5, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"
    first_line = (result.stdout or result.stderr).splitlines()[0] if (result.stdout or result.stderr) else ""
    parts = first_line.split()
    return parts[-1] if parts else "unknown"


def _node_domain() -> str | None:
    try:
        socket.inet_pton(socket.AF_INET, config.node.host)
        return None
    except OSError:
        return config.node.host


@app.get("/api/nodes", response_model=NodeListResponse, tags=["node"])
def get_nodes(
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=20, ge=1, le=100),
    status: Literal["online", "offline"] | None = Query(default=None),
    _token: str = Depends(verify_token),
):
    current = get_node_status(config.node.id)
    node_status = "online" if current["singbox"] == "running" else "offline"
    node = {
        "nodeId": config.node.id,
        "name": config.node.name,
        "host": config.node.host,
        "domain": _node_domain(),
        "managerVersion": _manager_version(),
        "singboxVersion": _singbox_version(),
        "status": node_status,
        "singbox": current["singbox"],
        "cpu": current["cpu"],
        "memory": current["memory"],
        "connections": current["connections"],
        "systemConnections": current["systemConnections"],
        "userCount": len(list_users()),
        "apiAvailable": is_api_available(),
        "lastHeartbeatAt": datetime.now(timezone.utc),
    }
    items = [] if status and status != node_status else [node]
    total = len(items)
    start = (page - 1) * pageSize
    return {"items": items[start:start + pageSize], "page": page, "pageSize": pageSize, "total": total}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=config.server.port)
