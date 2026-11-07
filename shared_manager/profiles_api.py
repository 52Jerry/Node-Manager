"""Owned connection profiles and recoverable residential proxy imports."""
from __future__ import annotations

from datetime import datetime, timezone
import hmac
import json
import secrets
from typing import Literal

from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .agent import AgentError
from .app import ConnectionView, MessageView, SocksView, TrafficView, UpstreamRequest, UpstreamView
from .presentation import display_links
from .profile_locks import profile_lock
from .profile_provisioning import confirm_initial_proxy
from .residential_import import ImportFormatError, parse_import
from .store import CapacityError, PendingUpstream, ProfileConflict, ProfileDeleting, ProfileNotFound


class ProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    idempotencyKey: str = Field(min_length=1, max_length=128)
    trafficLimitBytes: int | None = Field(default=None, ge=1, le=9007199254740991, strict=True)


class ProfileRename(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)


class ProfilePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trafficLimitBytes: int = Field(ge=1, le=9007199254740991, strict=True)


class ProfileView(BaseModel):
    id: str
    name: str
    state: Literal["PENDING", "READY", "DELETING"]
    createdAt: str
    expiresAt: str | None
    upstream: UpstreamView
    trafficLimitBytes: int


class ProfileList(BaseModel):
    items: list[ProfileView]


class ImportText(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=65536)


class ImportRequest(ImportText):
    idempotencyKey: str = Field(min_length=1, max_length=128)


class PreviewRow(BaseModel):
    line: int
    name: str
    server: str
    port: int | None
    username: str
    passwordConfigured: bool
    valid: bool
    error: str | None


class ImportPreview(BaseModel):
    items: list[PreviewRow]
    validCount: int
    failedCount: int


class ImportedRow(BaseModel):
    line: int
    name: str
    profileId: str | None = None
    state: Literal["READY", "PENDING", "FAILED"]
    error: str | None = None


class ImportResult(BaseModel):
    items: list[ImportedRow]
    createdCount: int
    failedCount: int


def install_profile_routes(app, store, agent, settings, current_user, authorize_write):
    with store.connection() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS profile_imports (
            owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_key TEXT NOT NULL, fingerprint TEXT NOT NULL, plan BLOB NOT NULL,
            PRIMARY KEY(owner_id, request_key))""")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS profile_import_content ON profile_imports(owner_id, fingerprint)")
        db.execute("""CREATE TABLE IF NOT EXISTS profile_import_key_aliases (
            owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_key TEXT NOT NULL, fingerprint TEXT NOT NULL, canonical_key TEXT NOT NULL,
            PRIMARY KEY(owner_id, request_key))""")

    @app.exception_handler(ProfileNotFound)
    async def not_found(_request, _exc):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "连接不存在"}, status_code=404)

    @app.exception_handler(ProfileDeleting)
    async def deleting(_request, _exc):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "连接正在删除，请稍后重试"}, status_code=409)

    @app.exception_handler(ProfileConflict)
    async def conflict(_request, _exc):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "请求与已有操作冲突，请刷新后重试"}, status_code=409)

    def owned(owner, profile_id, *, deleting=False):
        profile = store.get_profile(owner, profile_id)
        if not profile:
            raise HTTPException(404, "连接不存在")
        if profile["deleting"] and not deleting:
            raise HTTPException(409, "连接正在删除，请稍后重试")
        return profile

    def upstream_view(owner, profile_id):
        state = store.get_profile_upstream(owner, profile_id)
        payload = state["pending"] or state["applied"]
        return UpstreamView(mode=payload["mode"], state="PENDING" if state["pending"] else "APPLIED",
                            server=payload.get("server"), port=payload.get("port"), username=payload.get("username"),
                            passwordConfigured=bool(payload.get("password")))

    def profile_view(profile):
        upstream = upstream_view(profile["owner_id"], profile["id"])
        return ProfileView(id=profile["id"], name=profile["name"],
                           state="DELETING" if profile["deleting"] else "READY" if profile["ready"] and upstream.state != "PENDING" else "PENDING",
                           createdAt=datetime.fromtimestamp(profile["created_at"], timezone.utc).isoformat(),
                           expiresAt=profile["request"].get("expiresAt"),
                           upstream=upstream, trafficLimitBytes=profile.get("traffic_limit_bytes", profile["request"]["trafficLimitBytes"]))

    def result_view(owner, profile, result):
        confirm_initial_proxy(store, agent, owner, profile)
        try:
            view = ConnectionView(expiresAt=result.get("expiresAt") or profile["request"]["expiresAt"],
                                  links=display_links(result, profile["name"]), socks=SocksView(**result["socks"]))
        except (ValueError, TypeError, KeyError):
            raise AgentError(502, "连接信息不完整，请稍后重试") from None
        if not store.mark_profile_ready(owner, profile["id"]):
            raise HTTPException(409, "连接状态已变化，请刷新后重试")
        return view

    def generate(owner, profile_id):
        with profile_lock(owner, profile_id):
            profile = owned(owner, profile_id)
            return result_view(owner, profile, agent.connections(profile, create=True))

    def apply_upstream(owner, profile_id, payload):
        profile = owned(owner, profile_id)
        if not profile["ready"]:
            raise HTTPException(409, "请先生成连接，再配置住宅代理")
        operation = store.prepare_profile_upstream(owner, profile_id, payload)
        try:
            agent.apply_upstream(profile, operation)
        except AgentError as exc:
            if exc.status in {409, 422}:
                store.reject_profile_upstream(owner, profile_id, operation["operation_id"])
            raise
        store.apply_profile_upstream(owner, profile_id, operation["operation_id"])
        return upstream_view(owner, profile_id)

    def rows(text):
        try:
            return parse_import(text)
        except ImportFormatError as exc:
            raise HTTPException(422, str(exc)) from None

    def import_plan(owner, body):
        request_key = hmac.new(store.key, ("import-key:" + body.idempotencyKey).encode(), "sha256").hexdigest()
        fingerprint = hmac.new(store.key, body.text.encode(), "sha256").hexdigest()
        def decode(row, key):
            value = row[1]
            aad = ("profile-import:" + owner + ":" + key).encode()
            return key, json.loads(store.cipher.decrypt(value[:12], value[12:], aad))
        def finish(row, canonical_key):
            with store.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                alias = db.execute("SELECT fingerprint FROM profile_import_key_aliases WHERE owner_id=? AND request_key=?", (owner, request_key)).fetchone()
                if alias and not hmac.compare_digest(alias[0], fingerprint):
                    raise HTTPException(409, "相同导入标识的内容不同，请使用原内容重试")
                db.execute("INSERT OR IGNORE INTO profile_import_key_aliases VALUES (?, ?, ?, ?)",
                           (owner, request_key, fingerprint, canonical_key))
            return decode(row, canonical_key)
        aad = ("profile-import:" + owner + ":" + request_key).encode()
        with store.connection() as db:
            alias = db.execute("SELECT fingerprint,canonical_key FROM profile_import_key_aliases WHERE owner_id=? AND request_key=?", (owner, request_key)).fetchone()
            if alias:
                if not hmac.compare_digest(alias[0], fingerprint):
                    raise HTTPException(409, "相同导入标识的内容不同，请使用原内容重试")
                persisted = db.execute("SELECT fingerprint,plan FROM profile_imports WHERE owner_id=? AND request_key=?", (owner, alias[1])).fetchone()
                return decode(persisted, alias[1])
            prior = db.execute("SELECT fingerprint,plan FROM profile_imports WHERE owner_id=? AND request_key=?", (owner, request_key)).fetchone()
        if prior:
            if not hmac.compare_digest(prior[0], fingerprint):
                raise HTTPException(409, "相同导入标识的内容不同，请使用原内容重试")
            return finish(prior, request_key)
        with store.connection() as db:
            identical = db.execute("SELECT fingerprint,plan,request_key FROM profile_imports WHERE owner_id=? AND fingerprint=?", (owner, fingerprint)).fetchone()
        if identical:
            return finish(identical, identical[2])
        parsed = rows(body.text)
        if any(row.error for row in parsed):
            raise HTTPException(422, "导入内容存在无效或重复行，请先预览并修正")
        plan = []
        for row in parsed:
            try:
                payload = agent.public_upstream(row.server, row.port, row.username, row.password)
            except AgentError:
                raise HTTPException(422, f"第 {row.line} 行代理地址不可用，请检查后重试") from None
            plan.append({"line": row.line, "name": row.name, "payload": payload})
        nonce = secrets.token_bytes(12)
        encrypted = nonce + store.cipher.encrypt(nonce, json.dumps(plan).encode(), aad)
        with store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR IGNORE INTO profile_imports VALUES (?, ?, ?, ?)", (owner, request_key, fingerprint, encrypted))
            prior = db.execute("SELECT fingerprint,plan FROM profile_imports WHERE owner_id=? AND request_key=?", (owner, request_key)).fetchone()
            if not prior:
                identical = db.execute("SELECT fingerprint,plan,request_key FROM profile_imports WHERE owner_id=? AND fingerprint=?", (owner, fingerprint)).fetchone()
                prior, canonical_key = identical, identical[2]
            else:
                canonical_key = request_key
            if not hmac.compare_digest(prior[0], fingerprint):
                raise HTTPException(409, "相同导入标识的内容不同，请使用原内容重试")
        return finish(prior, canonical_key)

    @app.get("/api/me/profiles", response_model=ProfileList)
    def list_profiles(user=Depends(current_user)):
        return ProfileList(items=[profile_view(p) for p in store.list_profiles(user["id"], include_deleting=True)])

    @app.post("/api/me/profiles", response_model=ProfileView, status_code=201)
    def create_profile(body: ProfileCreate, user=Depends(authorize_write)):
        store.throttle("profile-create", user["id"], 30, 60)
        try:
            profile = store.create_profile(user["id"], body.name, body.idempotencyKey, traffic_limit_bytes=body.trafficLimitBytes)
        except CapacityError:
            raise HTTPException(409, "每个账号最多创建 100 条连接") from None
        except ValueError:
            raise HTTPException(422, "连接名称或请求标识无效") from None
        generate(user["id"], profile["id"])
        return profile_view(owned(user["id"], profile["id"]))

    @app.post("/api/me/profiles/import/preview", response_model=ImportPreview)
    def preview_import(body: ImportText, user=Depends(authorize_write)):
        parsed = rows(body.text)
        valid = sum(row.error is None for row in parsed)
        return ImportPreview(items=[row.summary() for row in parsed], validCount=valid, failedCount=len(parsed) - valid)

    @app.post("/api/me/profiles/import", response_model=ImportResult)
    def import_profiles(body: ImportRequest, user=Depends(authorize_write)):
        store.throttle("profile-import", user["id"], 12, 900)
        request_key, plan = import_plan(user["id"], body)
        results = []
        for row in plan:
            profile = None
            try:
                profile = store.create_profile(user["id"], row["name"], "import-" + request_key[:48] + "-" + str(row["line"]),
                                               initial_proxy=row["payload"])
                with profile_lock(user["id"], profile["id"]):
                    generate(user["id"], profile["id"])
                results.append(ImportedRow(line=row["line"], name=row["name"], profileId=profile["id"], state="READY"))
            except AgentError as exc:
                results.append(ImportedRow(line=row["line"], name=row["name"], profileId=profile["id"] if profile else None,
                                           state="PENDING" if profile and exc.status not in {409, 422} else "FAILED", error=exc.message))
            except PendingUpstream:
                results.append(ImportedRow(line=row["line"], name=row["name"], profileId=profile["id"] if profile else None,
                                           state="PENDING", error="原出口变更仍在确认，请使用相同内容重试"))
            except (CapacityError, ProfileConflict, ProfileDeleting, ProfileNotFound):
                results.append(ImportedRow(line=row["line"], name=row["name"], profileId=profile["id"] if profile else None,
                                           state="FAILED", error="连接数量已达上限，或原连接状态已变化，请刷新后检查"))
        succeeded = sum(row.state == "READY" for row in results)
        return ImportResult(items=results, createdCount=succeeded, failedCount=len(results) - succeeded)

    @app.patch("/api/me/profiles/{profile_id}", response_model=ProfileView)
    def rename_profile(profile_id: str, body: ProfileRename, user=Depends(authorize_write)):
        with profile_lock(user["id"], profile_id):
            try:
                return profile_view(store.rename_profile(user["id"], profile_id, body.name))
            except ValueError:
                raise HTTPException(422, "连接名称须为 1–64 个可见字符") from None

    @app.get("/api/me/profiles/{profile_id}/connections", response_model=ConnectionView)
    def connections(profile_id: str, user=Depends(current_user)):
        with profile_lock(user["id"], profile_id):
            profile = owned(user["id"], profile_id)
            return result_view(user["id"], profile, agent.connections(profile))

    @app.patch("/api/me/profiles/{profile_id}/policy", response_model=ProfileView)
    def update_policy(profile_id: str, body: ProfilePolicy, user=Depends(authorize_write)):
        store.throttle("profile-policy", user["id"], 30, 60)
        with profile_lock(user["id"], profile_id):
            profile = owned(user["id"], profile_id)
            if not profile["ready"]:
                raise HTTPException(409, "请先生成连接，再修改流量额度")
            agent.update_traffic_limit(profile, body.trafficLimitBytes)
            updated = store.update_profile_policy(user["id"], profile_id, body.trafficLimitBytes)
            return profile_view(updated)

    @app.post("/api/me/profiles/{profile_id}/connections", response_model=ConnectionView)
    def generate_connections(profile_id: str, user=Depends(authorize_write)):
        store.throttle("profile-generate", user["id"], 60, 60)
        return generate(user["id"], profile_id)

    @app.get("/api/me/profiles/{profile_id}/upstream", response_model=UpstreamView)
    def upstream(profile_id: str, user=Depends(current_user)):
        with profile_lock(user["id"], profile_id):
            profile = owned(user["id"], profile_id)
            state = store.get_profile_upstream(user["id"], profile_id)
            if state["pending"] and profile["ready"] and agent.upstream_matches(profile, state["pending"]):
                store.apply_profile_upstream(user["id"], profile_id, state["pending_id"])
            return upstream_view(user["id"], profile_id)

    @app.put("/api/me/profiles/{profile_id}/upstream", response_model=UpstreamView)
    def set_upstream(profile_id: str, body: UpstreamRequest, user=Depends(authorize_write)):
        store.throttle("profile-upstream", user["id"], 60, 60)
        with profile_lock(user["id"], profile_id):
            owned(user["id"], profile_id)
            state = store.get_profile_upstream(user["id"], profile_id)
            if state["pending"]:
                payload = {"mode": "socks5", "server": body.server.strip().strip("[]").rstrip(".").lower(),
                           "port": body.port, "username": body.username, "password": body.password}
            else:
                payload = agent.public_upstream(body.server, body.port, body.username, body.password)
            return apply_upstream(user["id"], profile_id, payload)

    @app.delete("/api/me/profiles/{profile_id}/upstream", response_model=UpstreamView)
    def restore_default(profile_id: str, user=Depends(authorize_write)):
        store.throttle("profile-upstream", user["id"], 60, 60)
        with profile_lock(user["id"], profile_id):
            return apply_upstream(user["id"], profile_id, {"mode": "direct"})

    @app.get("/api/me/profiles/{profile_id}/traffic", response_model=TrafficView)
    def traffic(profile_id: str, user=Depends(current_user)):
        profile = owned(user["id"], profile_id)
        result = agent.traffic(profile) if profile["ready"] else {}
        try:
            return TrafficView(upload=max(0, int(result.get("upload", 0))), download=max(0, int(result.get("download", 0))),
                               total=max(0, int(result.get("total", 0))), available=result.get("available") is True,
                               collectedAt=result.get("collectedAt"), trafficLimitBytes=result.get("trafficLimitBytes") or profile.get("traffic_limit_bytes", profile["request"]["trafficLimitBytes"]),
                               maxSourceIps=profile["request"]["maxSourceIps"], activeSourceIpCount=len(result.get("activeSourceIps") or []),
                               onlineConnectionCount=len(result.get("onlineConnections") or []), status=result.get("status") or "active")
        except (ValueError, TypeError):
            raise AgentError(502, "流量数据暂不可用") from None

    @app.delete("/api/me/profiles/{profile_id}", response_model=MessageView)
    def delete_profile(profile_id: str, user=Depends(authorize_write)):
        with profile_lock(user["id"], profile_id):
            profile = store.begin_delete_profile(user["id"], profile_id)
            if profile["ready"]:
                # A suspended profile still requires identity proof before its
                # privileged deletion; inspectionOnly does not re-enable it.
                result = agent.request("GET", "/api/user/" + profile["node_user_id"] + "/connections?inspectionOnly=true",
                                       missing_user_id=profile["node_user_id"])
                if result is not None:
                    agent.verify(result, profile)
            else:
                # Resolve the original create receipt first. A transient 404
                # cannot prove an old timed-out create will never commit.
                try:
                    result = agent.connections(profile, create=True)
                except AgentError as exc:
                    if exc.status != 409:
                        raise
                    # The serialized original create has decisively rejected.
                    # Confirm absence before removing only its local identity.
                    result = agent.request("GET", "/api/user/" + profile["node_user_id"] + "/connections?inspectionOnly=true",
                                           missing_user_id=profile["node_user_id"])
                    if result is not None:
                        raise exc
            if result is not None:
                agent.request("DELETE", "/api/user/delete/" + profile["node_user_id"],
                              headers={"Idempotency-Key": "shared-delete:" + profile["node_user_id"]})
                remaining = agent.request("GET", "/api/user/" + profile["node_user_id"] + "/connections?inspectionOnly=true",
                                          missing_user_id=profile["node_user_id"])
                if remaining is not None:
                    raise AgentError(503, "删除结果尚未确认，请稍后重试")
            store.delete_profile(user["id"], profile_id)
            return MessageView(message="连接已删除")

    return {"profile_view": profile_view, "generate": generate}
