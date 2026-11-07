from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import wraps
import hmac
from pathlib import Path
import sqlite3
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .agent import Agent, AgentError
from .admin import create_admin_router
from .settings import Settings
from .store import CapacityError, PendingUpstream, RateLimited, Store
from .presentation import display_links
from .profile_locks import profile_lock
from .profile_provisioning import confirm_initial_proxy

COOKIE = "shared_session"
STATIC = Path(__file__).parent / "static"


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)

    @field_validator("username", mode="before")
    @classmethod
    def trim_username(cls, value):
        # Accept harmless paste/autofill padding; passwords remain byte-for-byte.
        return value.strip() if isinstance(value, str) else value


class UserView(BaseModel):
    username: str
    createdAt: str
    isAdmin: bool = False


class SessionView(BaseModel):
    user: UserView
    csrfToken: str
    connectionState: Literal["EMPTY", "PENDING", "READY"]


class SiteView(BaseModel):
    siteName: str
    nodeName: str
    registrationEnabled: bool
    lifetimeDays: int
    trafficLimitBytes: int
    maxSourceIps: int


class ProtocolLink(BaseModel):
    protocol: Literal["vless", "vmess", "socks"]
    uri: str


class SocksView(BaseModel):
    host: str
    port: int
    username: str
    password: str


class ConnectionView(BaseModel):
    state: Literal["READY"] = "READY"
    expiresAt: str | None
    links: list[ProtocolLink]
    socks: SocksView


class MessageView(BaseModel):
    message: str


class UpstreamRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    server: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=255)


class UpstreamView(BaseModel):
    mode: Literal["direct", "socks5"]
    state: Literal["APPLIED", "PENDING"]
    server: str | None = None
    port: int | None = None
    username: str | None = None
    passwordConfigured: bool = False


class TrafficView(BaseModel):
    upload: int = 0
    download: int = 0
    total: int = 0
    available: bool = False
    collectedAt: str | None = None
    trafficLimitBytes: int
    maxSourceIps: int
    activeSourceIpCount: int = 0
    onlineConnectionCount: int = 0
    status: str = "active"


class PortalBoundary:
    """Bound unauthenticated bodies and enforce the configured browser origin."""
    def __init__(self, app, origin: str):
        self.app, self.origin = app, origin

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        if scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            if headers.get(b"origin", b"").decode("latin1") != self.origin:
                return await JSONResponse({"detail": "请求来源无效，请从本站页面操作"}, status_code=403)(scope, receive, send)
            if headers.get(b"content-type", b"").split(b";")[0].strip().lower() != b"application/json":
                return await JSONResponse({"detail": "需要 JSON 请求"}, status_code=415)(scope, receive, send)
            body = bytearray()
            import asyncio
            while True:
                try:
                    message = await asyncio.wait_for(receive(), 10)
                except asyncio.TimeoutError:
                    return await JSONResponse({"detail": "请求超时"}, status_code=408)(scope, receive, send)
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                limit = 98304 if scope.get("path") in {"/api/me/profiles/import", "/api/me/profiles/import/preview"} else 16384
                if len(body) > limit:
                    return await JSONResponse({"detail": "请求内容过大"}, status_code=413)(scope, receive, send)
                if not message.get("more_body", False):
                    break
            delivered = False
            original_receive = receive
            async def buffered():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await original_receive()
            receive = buffered
        async def secured(message):
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", []),
                    (b"cache-control", b"no-store, private"), (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"), (b"x-frame-options", b"DENY"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]
            await send(message)
        await self.app(scope, receive, secured)


def create_app(settings: Settings | None = None, agent: Agent | None = None):
    settings = settings or Settings.from_env()
    store = Store(settings)
    own_agent = agent is None
    agent = agent or Agent(settings)

    @asynccontextmanager
    async def lifespan(app):
        yield
        if own_agent:
            agent.close()

    app = FastAPI(title="连接管理接口", version="1.1.0", lifespan=lifespan,
                  description="账号、专属连接、住宅代理与订阅管理。")
    app.add_middleware(PortalBoundary, origin=settings.origin)
    app.state.store = store
    app.mount("/assets", StaticFiles(directory=STATIC), name="assets")

    @app.exception_handler(RequestValidationError)
    async def validation(_request, _exc):
        # FastAPI's default validation detail echoes password input.
        if _request.url.path in {"/api/auth/login", "/api/auth/register"}:
            fields = {error["loc"][1] for error in _exc.errors()
                      if len(error.get("loc", ())) >= 2 and error["loc"][0] == "body"}
            if "username" in fields:
                return JSONResponse({"detail": "请输入账号。",
                                     "field": "username"}, status_code=422)
            if "password" in fields:
                return JSONResponse({"detail": "请输入密码。", "field": "password"}, status_code=422)
            return JSONResponse({"detail": "登录或注册信息格式无效，请检查输入。"}, status_code=422)
        return JSONResponse({"detail": "输入格式无效，请检查账号、密码、服务器地址和端口"}, status_code=422)

    @app.exception_handler(RateLimited)
    async def limited(_request, _exc):
        return JSONResponse({"detail": "操作过于频繁，请稍后重试"}, status_code=429, headers={"Retry-After": "900"})

    @app.exception_handler(AgentError)
    async def agent_error(_request, exc):
        return JSONResponse({"detail": exc.message}, status_code=exc.status,
                            headers={"Retry-After": "3"} if exc.status in {429, 503} else None)

    @app.exception_handler(PendingUpstream)
    async def pending_upstream(_request, _exc):
        return JSONResponse({"detail": "上一笔出口变更尚未确认，请先用相同配置重试；不要提交其他出口"}, status_code=409)

    def current_user(request: Request):
        token = request.cookies.get(COOKIE, "")
        user = store.session_user(token)
        if not user:
            raise HTTPException(401, "请先登录")
        return user

    def authorize_write(request: Request, user=Depends(current_user)):
        expected = store.csrf(request.cookies[COOKIE])
        actual = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(actual.encode(), expected.encode()):
            raise HTTPException(403, "会话校验失败，请刷新后重试")
        return user

    def session_view(user, token):
        profiles = store.list_profiles(user["id"], include_deleting=True)
        active = [p for p in profiles if not p["deleting"]]
        return SessionView(user=UserView(username=user["username"], createdAt=datetime.fromtimestamp(user["created_at"], timezone.utc).isoformat(),
                                         isAdmin=bool(user.get("is_admin", False))),
                           csrfToken=store.csrf(token), connectionState="READY" if any(p["ready"] for p in active) else "PENDING" if profiles else "EMPTY")

    app.include_router(create_admin_router(current_user, store))

    def serialize_profile(*, create=False):
        def decorate(function):
            @wraps(function)
            def serialized(*args, **kwargs):
                user = kwargs.get("user")
                if not user:
                    return function(*args, **kwargs)
                allocation = store.allocation(user["id"], create=create)
                if not allocation:
                    return function(*args, **kwargs)
                with profile_lock(user["id"], allocation["id"]):
                    latest = store.get_profile(user["id"], allocation["id"])
                    if not latest or latest["deleting"]:
                        raise HTTPException(409, "连接状态已变化，请刷新后重试")
                    return function(*args, **kwargs)
            return serialized
        return decorate

    def start_session(user, response):
        token = store.create_session(user["id"])
        response.set_cookie(COOKIE, token, httponly=True, secure=settings.secure_cookies,
                            samesite="strict", max_age=settings.session_seconds, path="/")
        return session_view(user, token)

    def source(request):
        return request.client.host if request.client else "unknown"

    def result_view(user, allocation, result):
        confirm_initial_proxy(store, agent, user["id"], allocation)
        try:
            view = ConnectionView(expiresAt=result.get("expiresAt") or allocation["request"]["expiresAt"],
                                  links=display_links(result, allocation.get("name") or "默认连接"),
                                  socks=SocksView(**result["socks"]))
        except (ValueError, TypeError, KeyError):
            raise AgentError(502, "节点连接参数不完整") from None
        if not store.mark_profile_ready(user["id"], allocation["id"]):
            raise HTTPException(409, "连接状态已变化，请刷新后重试")
        return view

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/health", response_model=MessageView)
    def health():
        return {"message": "ok"}

    @app.get("/api/site", response_model=SiteView)
    def site():
        return SiteView(siteName=settings.site_name, nodeName="共享节点",
                        registrationEnabled=settings.registration_enabled, lifetimeDays=settings.lifetime_days,
                        trafficLimitBytes=settings.traffic_limit_bytes, maxSourceIps=settings.max_source_ips)

    @app.post("/api/auth/register", response_model=SessionView, status_code=201)
    def register(body: Credentials, request: Request, response: Response):
        if not settings.registration_enabled:
            raise HTTPException(403, "当前暂停注册")
        store.throttle("register-source", source(request), 5, 900)
        store.throttle("register-global", "all", settings.registration_daily_attempts, 86400)
        try:
            user = store.register(body.username, body.password)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "该账号已注册，请登录或更换账号") from None
        except CapacityError:
            raise HTTPException(409, "当前节点注册名额已满") from None
        return start_session(user, response)

    @app.post("/api/auth/login", response_model=SessionView)
    def login(body: Credentials, request: Request, response: Response):
        store.throttle("login-source", source(request), 30, 900)
        store.throttle("login-account", body.username.lower(), 10, 900)
        user = store.authenticate(body.username, body.password)
        if not user:
            raise HTTPException(401, "账号或密码错误，或账号已停用")
        previous = request.cookies.get(COOKIE)
        if previous:
            store.revoke_session(previous)
        return start_session(user, response)

    @app.get("/api/me", response_model=SessionView)
    def me(request: Request, user=Depends(current_user)):
        return session_view(user, request.cookies[COOKIE])

    @app.post("/api/auth/logout", response_model=MessageView)
    def logout(request: Request, response: Response, user=Depends(authorize_write)):
        store.revoke_session(request.cookies[COOKIE])
        response.delete_cookie(COOKIE, path="/", secure=settings.secure_cookies, httponly=True, samesite="strict")
        return {"message": "已退出登录"}

    @app.get("/api/me/connections", response_model=ConnectionView)
    @serialize_profile()
    def connections(user=Depends(current_user)):
        allocation = store.allocation(user["id"])
        if not allocation:
            raise HTTPException(404, "还没有生成连接")
        return result_view(user, allocation, agent.connections(allocation))

    @app.post("/api/me/connections", response_model=ConnectionView)
    @serialize_profile(create=True)
    def generate(request: Request, user=Depends(authorize_write)):
        store.throttle("generate-account", user["id"], 20, 60)
        allocation = store.allocation(user["id"], create=True)
        return result_view(user, allocation, agent.connections(allocation, create=True))

    def required_allocation(user):
        allocation = store.allocation(user["id"])
        if not allocation or not allocation["ready"]:
            raise HTTPException(409, "请先生成三协议连接，再配置出口")
        return allocation

    def upstream_view(user):
        state = store.upstream(user["id"])
        payload = state["pending"] or state["applied"]
        return UpstreamView(mode=payload["mode"], state="PENDING" if state["pending"] else "APPLIED",
                            server=payload.get("server"), port=payload.get("port"), username=payload.get("username"),
                            passwordConfigured=bool(payload.get("password")))

    @app.get("/api/me/upstream", response_model=UpstreamView)
    @serialize_profile()
    def upstream(user=Depends(current_user)):
        state = store.upstream(user["id"])
        # Readback can settle a lost response without resubmitting any write.
        if state["pending"]:
            allocation = required_allocation(user)
            if agent.upstream_matches(allocation, state["pending"]):
                store.apply_upstream(user["id"], state["pending_id"])
        return upstream_view(user)

    @app.put("/api/me/upstream", response_model=UpstreamView)
    @serialize_profile()
    def set_upstream(body: UpstreamRequest, user=Depends(authorize_write)):
        allocation = required_allocation(user)
        store.throttle("upstream-account", user["id"], 12, 60)
        state = store.upstream(user["id"])
        if state["pending"]:
            # Compare the original requested identity first. A retry keeps its
            # first validated address even if DNS changed in the meantime.
            payload = {"mode": "socks5", "server": body.server.strip().strip("[]").rstrip(".").lower(),
                       "port": body.port, "username": body.username, "password": body.password}
        else:
            payload = agent.public_upstream(body.server, body.port, body.username, body.password)
        operation = store.prepare_upstream(user["id"], payload)
        try:
            agent.apply_upstream(allocation, operation)
        except AgentError as exc:
            if exc.status in {409, 422}:
                store.reject_upstream(user["id"], operation["operation_id"])
            raise
        store.apply_upstream(user["id"], operation["operation_id"])
        return upstream_view(user)

    @app.delete("/api/me/upstream", response_model=UpstreamView)
    @serialize_profile()
    def direct_upstream(user=Depends(authorize_write)):
        allocation = required_allocation(user)
        store.throttle("upstream-account", user["id"], 12, 60)
        operation = store.prepare_upstream(user["id"], {"mode": "direct"})
        try:
            agent.apply_upstream(allocation, operation)
        except AgentError as exc:
            if exc.status in {409, 422}:
                store.reject_upstream(user["id"], operation["operation_id"])
            raise
        store.apply_upstream(user["id"], operation["operation_id"])
        return upstream_view(user)

    @app.get("/api/me/traffic", response_model=TrafficView)
    def traffic(user=Depends(current_user)):
        allocation = store.allocation(user["id"])
        if not allocation or not allocation["ready"]:
            return TrafficView(trafficLimitBytes=settings.traffic_limit_bytes, maxSourceIps=settings.max_source_ips)
        result = agent.traffic(allocation)
        # Whitelist aggregates; never disclose remote connections or other users.
        try:
            return TrafficView(upload=max(0, int(result.get("upload", 0))), download=max(0, int(result.get("download", 0))),
                               total=max(0, int(result.get("total", 0))), available=result.get("available") is True,
                               collectedAt=result.get("collectedAt"),
                               trafficLimitBytes=result.get("trafficLimitBytes") or allocation.get("traffic_limit_bytes", allocation["request"]["trafficLimitBytes"]),
                               maxSourceIps=result.get("maxSourceIps") or allocation["request"]["maxSourceIps"],
                               activeSourceIpCount=len(result.get("activeSourceIps") or []),
                               onlineConnectionCount=len(result.get("onlineConnections") or []), status=result.get("status") or "active")
        except (ValueError, TypeError):
            raise AgentError(502, "节点流量数据格式异常") from None

    from .subscription import install_subscription_routes
    install_subscription_routes(app, store, agent, settings, current_user, authorize_write)
    from .profiles_api import install_profile_routes
    install_profile_routes(app, store, agent, settings, current_user, authorize_write)
    return app
