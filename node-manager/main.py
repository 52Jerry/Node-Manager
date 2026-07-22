import logging
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from auth import verify_token
from config import config
from models.request import (
    BindProxyRequest,
    CreateUserRequest,
    CreateUserResponse,
    NodeListResponse,
    NodeStatusResponse,
    OperationResponse,
    ReloadResponse,
    TrafficResponse,
    UserListResponse,
)
from monitor.status import get_node_status
from monitor.traffic import get_user_traffic
from singbox.manager import (
    SingboxConfigError,
    bind_proxy,
    create_user,
    delete_user,
    is_api_available,
    list_users,
    reload_singbox,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = FastAPI(
    title="Python Node Manager API",
    version="1.2.0",
    description="Manage users, residential proxy bindings, and node health for a sing-box node.",
)

static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.exception_handler(SingboxConfigError)
async def singbox_error_handler(_request: Request, exc: SingboxConfigError):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


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


@app.post("/api/user/create", response_model=CreateUserResponse, tags=["users"])
def create_user_endpoint(request: CreateUserRequest, _token: str = Depends(verify_token)):
    return create_user(
        request.userId,
        list(request.protocols),
        socks_username=request.socksUsername,
        socks_password=request.socksPassword,
        proxy=request.proxy.model_dump() if request.proxy else None,
    )


@app.get("/api/users", response_model=UserListResponse, tags=["users"])
def get_users(
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=20, ge=1, le=100),
    keyword: str | None = Query(default=None, max_length=64),
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
    total = len(items)
    start = (page - 1) * pageSize
    page_items = items[start:start + pageSize]
    for item in page_items:
        traffic = get_user_traffic(item["userId"])
        item.update(
            upload=traffic["upload"],
            download=traffic["download"],
            total=traffic["total"],
        )
    return {"items": page_items, "page": page, "pageSize": pageSize, "total": total}


@app.post("/api/user/bind-proxy", response_model=OperationResponse, tags=["users"])
def bind_proxy_endpoint(request: BindProxyRequest, _token: str = Depends(verify_token)):
    return bind_proxy(request.userId, request.proxy.model_dump())


@app.delete("/api/user/delete/{userId}", response_model=OperationResponse, tags=["users"])
def delete_user_endpoint(userId: str, _token: str = Depends(verify_token)):
    if not userId or len(userId) > 64:
        raise HTTPException(status_code=422, detail="invalid userId")
    return delete_user(userId)


@app.get("/api/user/{userId}/traffic", response_model=TrafficResponse, tags=["users"])
def get_user_traffic_endpoint(userId: str, _token: str = Depends(verify_token)):
    return get_user_traffic(userId)


@app.post("/api/singbox/reload", response_model=ReloadResponse, tags=["sing-box"])
def singbox_reload(_token: str = Depends(verify_token)):
    return ReloadResponse(success=reload_singbox())


@app.get("/api/singbox/api/status", tags=["sing-box"])
def api_status(_token: str = Depends(verify_token)):
    return {"available": is_api_available(), "usage": "metrics-only"}


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
