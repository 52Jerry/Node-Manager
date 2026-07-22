import logging
import os

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from auth import verify_token
from config import config
from models.request import (
    BindProxyRequest,
    CreateUserRequest,
    CreateUserResponse,
    NodeStatusResponse,
    OperationResponse,
    ReloadResponse,
    TrafficResponse,
)
from monitor.status import get_node_status
from monitor.traffic import get_user_traffic
from singbox.manager import (
    SingboxConfigError,
    bind_proxy,
    create_user,
    delete_user,
    is_api_available,
    reload_singbox,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = FastAPI(
    title="Python Node Manager API",
    version="1.1.0",
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
    return create_user(request.userId, list(request.protocols))


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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=config.server.port)
