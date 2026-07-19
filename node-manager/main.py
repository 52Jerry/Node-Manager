from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uuid
import json
import base64
import os
from config import config
from auth import verify_token
from singbox.manager import (
    read_config, write_config, reload_singbox, get_next_available_port,
    is_api_available, create_user_via_api, bind_proxy_via_api,
    create_route_via_api, delete_user_via_api
)
from singbox.inbound import create_vless_inbound, create_vmess_inbound, create_socks_inbound, remove_user_inbounds, generate_uuid
from singbox.outbound import create_socks_outbound, add_outbound, remove_user_outbound
from singbox.route import add_user_rule, remove_user_rule
from monitor.status import get_node_status
from monitor.traffic import get_user_traffic
from models.request import CreateUserRequest, BindProxyRequest, CreateUserResponse, NodeStatusResponse, TrafficResponse, ReloadResponse

app = FastAPI(title="Python Node Manager", version="1.0")

static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

security = HTTPBearer()

@app.get("/")
def root():
    return FileResponse(os.path.join(static_dir, "index.html"))

def get_next_port_in_memory(config_data: dict, start_port: int = 5000) -> int:
    used_ports = set()
    for inbound in config_data.get("inbounds", []):
        if "listen_port" in inbound:
            used_ports.add(inbound["listen_port"])
    port = start_port
    while port in used_ports:
        port += 1
    return port

def build_vless_url(user_uuid: str, host: str, port: int) -> str:
    return f"vless://{user_uuid}@{host}:{port}?encryption=none&flow=&type=tcp&host=&path="

def build_vmess_url(user_uuid: str, host: str, port: int) -> str:
    vmess_dict = {
        "v": "2",
        "ps": "NodeManager",
        "add": host,
        "port": str(port),
        "id": user_uuid,
        "aid": "0",
        "net": "tcp",
        "type": "none",
        "host": "",
        "path": "",
        "tls": ""
    }
    vmess_json = json.dumps(vmess_dict, indent=None, separators=(",", ":"))
    return "vmess://" + base64.b64encode(vmess_json.encode()).decode()

@app.get("/api/node/status", response_model=NodeStatusResponse)
def get_status(token: str = Depends(verify_token)):
    status = get_node_status(config.node.id)
    status["host"] = config.node.host
    status["api_available"] = is_api_available()
    return status

@app.post("/api/user/create", response_model=CreateUserResponse)
def create_user(request: CreateUserRequest, token: str = Depends(verify_token)):
    user_id = request.userId
    protocols = request.protocols
    
    user_uuid = generate_uuid()
    
    use_api = is_api_available()
    config_data = read_config() if not use_api else None
    
    vless_port = None
    vmess_port = None
    socks_port = None
    socks_username = None
    socks_password = None
    
    vless_url = None
    vmess_url = None
    socks_info = None
    
    next_port = 5000
    
    if "vless" in protocols:
        if use_api:
            vless_port = get_next_available_port(next_port)
            create_user_via_api(user_id, "vless", vless_port, user_uuid)
        else:
            vless_port = get_next_port_in_memory(config_data, next_port)
            vless_inbound = create_vless_inbound(user_id, user_uuid, vless_port)
            config_data["inbounds"].append(vless_inbound)
        vless_url = build_vless_url(user_uuid, config.node.host, vless_port)
        next_port = vless_port + 1
    
    if "vmess" in protocols:
        if use_api:
            vmess_port = get_next_available_port(next_port)
            create_user_via_api(user_id, "vmess", vmess_port, user_uuid)
        else:
            vmess_port = get_next_port_in_memory(config_data, next_port)
            vmess_inbound = create_vmess_inbound(user_id, user_uuid, vmess_port)
            config_data["inbounds"].append(vmess_inbound)
        vmess_url = build_vmess_url(user_uuid, config.node.host, vmess_port)
        next_port = vmess_port + 1
    
    if "socks" in protocols:
        socks_username = str(uuid.uuid4())[:8]
        socks_password = str(uuid.uuid4())[:12]
        if use_api:
            socks_port = get_next_available_port(next_port)
            create_user_via_api(user_id, "socks", socks_port, None, socks_username, socks_password)
        else:
            socks_port = get_next_port_in_memory(config_data, next_port)
            socks_inbound = create_socks_inbound(user_id, socks_port, socks_username, socks_password)
            config_data["inbounds"].append(socks_inbound)
        socks_info = {
            "host": config.node.host,
            "port": socks_port,
            "username": socks_username,
            "password": socks_password
        }
    
    if not use_api:
        if not write_config(config_data):
            raise HTTPException(status_code=500, detail="Failed to write sing-box config")
    
    return CreateUserResponse(
        userId=user_id,
        uuid=user_uuid,
        vless=vless_url,
        vmess=vmess_url,
        socks=socks_info
    )

@app.post("/api/user/bind-proxy")
def bind_proxy(request: BindProxyRequest, token: str = Depends(verify_token)):
    user_id = request.userId
    proxy_data = {
        "type": request.proxy.type,
        "server": request.proxy.server,
        "port": request.proxy.port,
        "username": request.proxy.username,
        "password": request.proxy.password
    }
    
    use_api = is_api_available()
    
    if use_api:
        bind_proxy_via_api(user_id, proxy_data)
        create_route_via_api(user_id)
    else:
        config_data = read_config()
        outbound = create_socks_outbound(user_id, proxy_data)
        config_data = add_outbound(config_data, outbound)
        config_data = add_user_rule(config_data, user_id)
        
        if not write_config(config_data):
            raise HTTPException(status_code=500, detail="Failed to write sing-box config")
        
        if not reload_singbox():
            raise HTTPException(status_code=500, detail="Failed to reload sing-box")
    
    return {"success": True, "api_used": use_api}

@app.delete("/api/user/delete/{userId}")
def delete_user(userId: str, token: str = Depends(verify_token)):
    use_api = is_api_available()
    
    if use_api:
        success = delete_user_via_api(userId)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete user via API")
    else:
        config_data = read_config()
        config_data = remove_user_inbounds(config_data, userId)
        config_data = remove_user_outbound(config_data, userId)
        config_data = remove_user_rule(config_data, userId)
        
        if not write_config(config_data):
            raise HTTPException(status_code=500, detail="Failed to write sing-box config")
        
        if not reload_singbox():
            raise HTTPException(status_code=500, detail="Failed to reload sing-box")
    
    return {"success": True, "api_used": use_api}

@app.post("/api/singbox/reload", response_model=ReloadResponse)
def singbox_reload(token: str = Depends(verify_token)):
    success = reload_singbox()
    return ReloadResponse(success=success)

@app.get("/api/user/{userId}/traffic", response_model=TrafficResponse)
def get_user_traffic_endpoint(userId: str, token: str = Depends(verify_token)):
    return get_user_traffic(userId)

@app.get("/api/singbox/api/status")
def api_status(token: str = Depends(verify_token)):
    return {"available": is_api_available()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.server.port)