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
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from auth import verify_token
from config import config
from idempotency import (IdempotencyConflict, execute_idempotent,
                         execute_reconciling_idempotent)
from models.request import (
    AgentHeartbeatResponse,
    AgentInfoResponse,
    BatchDeleteUsersRequest,
    BatchDeleteUsersResponse,
    BindMultipleProxiesRequest,
    BindProxyRequest,
    CreateUserRequest,
    MigrateResidentialOwnershipRequest,
    CreateUserResponse,
    NodeListResponse,
    NodeStatusResponse,
    OperationResponse,
    ProxyDetailsResponse,
    ProxyMetadataUpdateRequest,
    ReloadResponse,
    RenewUserRequest,
    ResetTrafficRequest,
    ResidentialProtocolsResponse,
    ResidentialSocksRequest,
    TrafficResponse,
    UpdateUserExpirationRequest,
    SyncUserExpirationRequest,
    BatchExpirationSyncRequest,
    UpdateUserPolicyRequest,
    UserAccessRequest,
    ApplyDefaultTrafficLimitRequest,
    RestoreUserRequest,
    ExpiredUserListResponse,
    UserConnectionResponse,
    UserListResponse,
    WireguardPeerApplyRequest,
    WireguardPeerApplyBatchRequest,
    WireguardPeerApplyBatchResponse,
    WireguardPeerRevokeRequest,
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
    reset_user_traffic,
)
from network_check import run_network_check
from monitor.traffic_reset import reset_traffic
from user_replication import ReplicationRequest, export_users, apply_users
from replication_snapshot import inspect_users, ReplicationConflict
from ha_readiness import ReadinessRequest, readiness
from wireguard import (WireguardError, apply_peer, apply_peers, revoke_peer, status as wireguard_status,
                       wireguard_access_snapshot, start_reconciler, stop_reconciler)
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
    migrate_residential_ownership,
    get_user_connection,
    get_user_access_snapshot,
    get_user_proxy,
    set_user_access,
    UserAccessConnectionError,
    get_user_policies,
    update_proxy_metadata,
    update_user_policy,
    apply_default_traffic_limit,
    get_socks_inbound_port,
    is_api_available,
    list_users,
    list_expired_users,
    migrate_user_expirations,
    process_user_expirations,
    renew_user,
    restore_user,
    start_expiration_scheduler,
    stop_expiration_scheduler,
    update_user_expiration,
    sync_user_expiration,
    sync_user_expirations,
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

from wireguard_migration_recovery import router as wireguard_migration_recovery_router
app.include_router(wireguard_migration_recovery_router)

from wireguard_owner_adoption import router as wireguard_owner_adoption_router
app.include_router(wireguard_owner_adoption_router)

from wireguard_renewal_reopen import router as wireguard_renewal_reopen_router
app.include_router(wireguard_renewal_reopen_router)

from user_cleanup import router as user_cleanup_router, reject_unguarded_expired_deletion
app.include_router(user_cleanup_router)

from shared_quota_routes import router as shared_quota_router
app.include_router(shared_quota_router)

static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.exception_handler(SingboxConfigError)
async def singbox_error_handler(_request: Request, exc: SingboxConfigError):
    if _request.url.path.startswith("/api/users/replication"):
        return JSONResponse(status_code=409, headers={"Cache-Control": "no-store"}, content={
            "detail": "replication configuration conflict or runtime validation failed",
            "code": exc.public_code if isinstance(exc, ReplicationConflict) else "REPLICATION_CONFLICT"})
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(UserAccessConnectionError)
async def user_access_connection_error_handler(_request: Request, exc: UserAccessConnectionError):
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.exception_handler(IdempotencyConflict)
async def idempotency_error_handler(_request: Request, exc: IdempotencyConflict):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    if request.url.path == "/api/user/migrate-residential-ownership":
        return JSONResponse(status_code=422, content={"detail": "invalid residential ownership migration request"})
    if request.url.path.startswith(("/api/users/replication", "/api/wireguard")):
        # These payloads contain credentials or peer keys; never echo them.
        detail = (
            "invalid WireGuard request"
            if request.url.path.startswith("/api/wireguard")
            else "invalid replication payload"
        )
        return JSONResponse(status_code=422, content={"detail": detail})
    return await request_validation_exception_handler(request, exc)


@app.on_event("startup")
def startup_tasks():
    try:
        migrated_expirations = migrate_user_expirations()
        if migrated_expirations:
            logging.getLogger(__name__).info("registered metadata for %s existing users without inferring expiration", migrated_expirations)
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
    start_reconciler()


@app.on_event("shutdown")
def shutdown_tasks():
    stop_reconciler()
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


@app.post("/api/wireguard/peer/apply", tags=["wireguard"])
def wireguard_peer_apply(
    request: WireguardPeerApplyRequest,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", min_length=1, max_length=128),
    _token: str = Depends(verify_token),
):
    try:
        # Peer operations reconcile live state; an old cache receipt cannot
        # prove that a kernel peer survived a restart or has been removed.
        result = apply_peer(request.peerId, request.publicKey, request.address,
                            request.allowedIps, request.nodeUserId, request.expiresAt)
    except (WireguardError, OSError) as exc:
        if isinstance(exc, OSError):
            raise HTTPException(status_code=503, detail="WireGuard state persistence failed") from None
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Idempotency-Replayed"] = "false"
    return result


@app.post(
    "/api/wireguard/peers/apply",
    response_model=WireguardPeerApplyBatchResponse,
    tags=["wireguard"],
)
def wireguard_peers_apply(
    request: WireguardPeerApplyBatchRequest,
    response: Response,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=1, max_length=128),
    _token: str = Depends(verify_token),
):
    payload = request.model_dump(mode="json")
    try:
        result, replayed = execute_reconciling_idempotent(
            idempotency_key,
            "wireguard-apply-batch",
            payload,
            lambda: apply_peers(payload["peers"]),
        )
    except IdempotencyConflict:
        raise
    except WireguardError as exc:
        detail = str(exc)
        unavailable = {
            "wireguard peer management is disabled",
            "WireGuard registry invalid or unreadable",
            "WireGuard command failed",
            "WireGuard command unavailable",
            "invalid WireGuard status",
            "node user or residential binding unavailable",
            "dedicated WireGuard residential gateway is not ready",
            "WireGuard residential routes could not be applied",
            "WireGuard batch application failed; peers disabled",
            "WireGuard batch cleanup could not be verified",
            "WireGuard batch cleanup left peers present",
        }
        status_code = 503 if detail in unavailable else 409
        raise HTTPException(status_code=status_code, detail=detail) from None
    except OSError:
        raise HTTPException(
            status_code=503,
            detail="WireGuard batch or idempotency state could not be persisted; retry with the same key",
        ) from None
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="WireGuard batch apply failed; inspect peer status and retry with the same key",
        ) from None
    response.headers["Cache-Control"] = "no-store"
    response.headers["Idempotency-Replayed"] = str(replayed).lower()
    return result


@app.post("/api/wireguard/peer/revoke", tags=["wireguard"])
def wireguard_peer_revoke(
    request: WireguardPeerRevokeRequest,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", min_length=1, max_length=128),
    _token: str = Depends(verify_token),
):
    try:
        result = revoke_peer(request.peerId, request.publicKey)
    except (WireguardError, OSError) as exc:
        if isinstance(exc, OSError):
            raise HTTPException(status_code=503, detail="WireGuard state persistence failed") from None
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Idempotency-Replayed"] = "false"
    return result


@app.get("/api/wireguard/status", tags=["wireguard"])
def wireguard_peer_status(response: Response, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    try:
        return wireguard_status()
    except WireguardError as exc:
        raise HTTPException(status_code=503 if exc.code == "DELIVERY_SNAPSHOT_CHANGED" else 409, detail=str(exc)) from exc


@app.get("/api/wireguard/peer-status", tags=["wireguard"])
def wireguard_delivery_status_endpoint(
    response: Response,
    peerId: str = Query(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"),
    nodeUserId: str = Query(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"),
    includeRuntime: bool = Query(default=True),
    _token: str = Depends(verify_token),
):
    from wireguard import peer_delivery_status
    response.headers["Cache-Control"] = "no-store"
    try:
        return peer_delivery_status(peerId, nodeUserId, includeRuntime)
    except WireguardError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/wireguard/access-snapshot", tags=["wireguard"])
def wireguard_access_snapshot_endpoint(response: Response, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    try:
        return wireguard_access_snapshot()
    except WireguardError as exc:
        raise HTTPException(status_code=503 if exc.code == "DELIVERY_SNAPSHOT_CHANGED" else 409, detail=str(exc)) from exc


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
            province_name=request.provinceName,
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
            or config.node.random_acceleration_domain()
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


@app.get("/api/users/replication", tags=["users"])
def export_replication(response: Response, sharedConfig: bool = False, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    return export_users(shared_config=sharedConfig)


@app.get("/api/users/replication/inspection", tags=["users"])
def inspect_replication(response: Response, sharedConfig: bool = False, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    return inspect_users(shared_config=sharedConfig)


@app.get("/api/users/history-snapshot", tags=["users"])
def export_history_snapshot(response: Response, _token: str = Depends(verify_token)):
    from singbox.manager import get_history_user_snapshot
    response.headers["Cache-Control"] = "no-store"
    return get_history_user_snapshot()


@app.get("/api/users/access-snapshot", tags=["users"])
def export_user_access_snapshot(response: Response, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    return get_user_access_snapshot()


@app.post("/api/users/replication", tags=["users"])
def apply_replication(request: ReplicationRequest, _token: str = Depends(verify_token)):
    return apply_users(request)


@app.post("/api/users/replication/readiness", tags=["users"])
def replication_readiness(request: ReadinessRequest, response: Response, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    return readiness(request)


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
    # Traffic is sampled by the background collector. Do not block every user
    # list request on a live sing-box /connections call.
    traffic_available = None
    policies = get_user_policies()
    traffic_store = get_traffic_store_snapshot()
    for item in items:
        traffic = get_user_traffic(
            item["userId"],
            refresh=False,
            available=traffic_available,
            policy=policies.get(item["userId"], {}),
            store=traffic_store,
            include_online=False,
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
        if item.get("accessEnabled") is False:
            item["status"] = "suspended"
    if keyword:
        normalized = keyword.casefold()
        items = [
            item
            for item in items
            if normalized in _user_search_text(item)
        ]
    items = _sort_users(items, sort)
    total = len(items)
    start = (page - 1) * pageSize
    page_items = items[start:start + pageSize]
    return {"items": page_items, "page": page, "pageSize": pageSize, "total": total}


def _user_search_text(item: dict) -> str:
    values = [
        item.get("userId"),
        item.get("socksUsername"),
        item.get("proxyServer"),
        item.get("sourceIp"),
        item.get("countryCode"),
        item.get("countryName"),
        item.get("provinceName"),
        item.get("cityName"),
        *(item.get("activeSourceIps") or []),
    ]
    return " ".join(str(value) for value in values if value).casefold()


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


@app.patch("/api/user/{userId}/access", tags=["users"])
def update_user_access_endpoint(
    userId: str,
    request: UserAccessRequest,
    response: Response,
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key", min_length=1, max_length=128
    ),
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    if not idempotency_key:
        raise HTTPException(status_code=428, detail="Idempotency-Key is required")
    result, replayed = execute_idempotent(
        idempotency_key,
        "user-access",
        {"userId": userId, **request.model_dump(mode="json")},
        lambda: set_user_access(userId, request.enabled),
    )
    response.headers["Idempotency-Replayed"] = str(replayed).lower()
    return result


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


@app.post("/api/user/migrate-residential-ownership", tags=["users"])
def migrate_residential_ownership_endpoint(
    request: MigrateResidentialOwnershipRequest,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", min_length=1, max_length=128),
    _token: str = Depends(verify_token),
):
    if not idempotency_key:
        raise HTTPException(status_code=428, detail="Idempotency-Key is required")
    result, replayed = execute_reconciling_idempotent(
        idempotency_key, "migrate-residential-ownership", request.model_dump(mode="json"),
        lambda: migrate_residential_ownership(request.model_dump()),
    )
    response.headers["Idempotency-Replayed"] = str(replayed).lower()
    response.headers["Cache-Control"] = "no-store"
    return result


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
        lambda: bind_proxy(
            request.userId,
            request.proxy.model_dump(),
            request.syncSocksCredentials,
            request.uuid or None,
        ),
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
        reject_unguarded_expired_deletion(userId)
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


@app.post(
    "/api/users/batch-delete",
    response_model=BatchDeleteUsersResponse,
    tags=["users"],
)
def batch_delete_users_endpoint(
    request: BatchDeleteUsersRequest,
    _token: str = Depends(verify_token),
):
    deleted: list[str] = []
    failed: list[dict[str, str]] = []
    logger = logging.getLogger(__name__)
    for userId in request.userIds:
        try:
            reject_unguarded_expired_deletion(userId)
            delete_user(userId)
            try:
                delete_user_traffic(userId)
            except Exception:
                logger.exception(
                    "could not delete traffic history for batch-deleted user %s",
                    userId,
                )
            deleted.append(userId)
        except Exception as exc:
            logger.warning("could not batch-delete node user %s: %s", userId, exc)
            failed.append({"userId": userId, "error": str(exc)})
    return {
        "success": not failed,
        "deleted": deleted,
        "failed": failed,
    }


@app.get("/api/user/{userId}/traffic", response_model=TrafficResponse, tags=["users"])
def get_user_traffic_endpoint(userId: str, _token: str = Depends(verify_token)):
    return get_user_traffic(userId)


@app.post("/api/user/{userId}/traffic/reset", tags=["users"])
def reset_user_traffic_endpoint(
    userId: str,
    request: ResetTrafficRequest,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    result, _ = execute_idempotent(
        idempotency_key, "traffic-reset:" + userId, request.model_dump(mode="json"),
        lambda: reset_traffic(userId, request.cycleStart),
    )
    return result


@app.patch("/api/user/{userId}/policy", tags=["users"])
def update_user_policy_endpoint(
    userId: str,
    request: UpdateUserPolicyRequest,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    return update_user_policy(userId, request.model_dump(exclude_unset=True))


@app.patch("/api/users/traffic-limit/default", tags=["users"])
def apply_default_traffic_limit_endpoint(
    request: ApplyDefaultTrafficLimitRequest,
    _token: str = Depends(verify_token),
):
    return apply_default_traffic_limit(request.trafficLimitBytes)


@app.post("/api/user/{userId}/renew", tags=["users"])
def renew_user_endpoint(
    userId: str,
    request: RenewUserRequest,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    result = renew_user(
        userId,
        expires_at=request.expiresAt,
        traffic_limit_bytes=request.trafficLimitBytes,
        max_source_ips=request.maxSourceIps,
    )
    if request.resetTraffic and not result.get("expirationPrecisionOnly", False):
        traffic = reset_user_traffic(userId, renewal_key=result["expiresAt"])
        result.update(traffic)
    else:
        result["trafficReset"] = False
    return result


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


@app.patch("/api/user/{userId}/expiration/sync", tags=["users"])
def sync_user_expiration_endpoint(
    userId: str,
    request: SyncUserExpirationRequest,
    _token: str = Depends(verify_token),
):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    return sync_user_expiration(userId, request.expiresAt, request.expectedProxy.model_dump(),
                                request.expectedExpiresAt, request.snapshotStartedAt)


@app.patch("/api/users/expiration/sync", tags=["users"])
def sync_user_expirations_endpoint(request: BatchExpirationSyncRequest, _token: str = Depends(verify_token)):
    return sync_user_expirations([item.model_dump() for item in request.items])


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
            "user.replication.v1",
            "user.replication.inspection.v1",
            "user.replication.preserve.v1",
            "user.replication.ha.v1",
            "user.connections",
            "proxy.bind",
            "proxy.bind.multiple",
            "proxy.metadata.update",
            "traffic.sampled",
            "traffic.quota",
            "traffic.reset",
            "user.source-ip-limit",
            "user.policy.update",
            "users.traffic-limit.default",
            "user.renew",
            "user.expiration.update",
            "user.expiration.sync",
            "user.expiration.restore",
            "user.expiration.archive",
            "node.heartbeat",
            "request.idempotency",
            "wireguard.peer.batch-apply",
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
