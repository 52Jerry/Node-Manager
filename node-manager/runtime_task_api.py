"""Authenticated async user AND route mutations over the runtime writer."""
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal, Union

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from auth import verify_token
from models.request import CreateUserRequest, BindProxyRequest
from singbox import manager
import runtime_write_queue as queue


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Versioned(Strict):
    expectedUserVersion: int | None = Field(default=None, ge=0)


class Create(Versioned):
    action: Literal["create"]
    user: CreateUserRequest


class Delete(Versioned):
    action: Literal["delete"]
    userId: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")


class Access(Delete):
    action: Literal["access"]
    enabled: bool


class Route(Versioned):
    action: Literal["route"]
    binding: BindProxyRequest


class Direct(Delete):
    action: Literal["direct"]


class Credentials(Delete):
    action: Literal["credentials"]
    uuid: str | None = Field(default=None, pattern=r"^[0-9a-fA-F-]{36}$")
    socksUsername: str | None = Field(default=None, min_length=1, max_length=255)
    socksPassword: str | None = Field(default=None, min_length=1, max_length=255)


Command = Annotated[Union[Create, Delete, Access, Route, Direct, Credentials], Field(discriminator="action")]


class Submission(Strict):
    commands: list[Command] = Field(min_length=1, max_length=128)


def compile_command(command):
    if isinstance(command, Create):
        r = command.user
        callback = manager.capture_mutation(lambda: manager.create_user(
            r.userId, list(r.protocols), r.uuid or None, r.socksUsername, r.socksPassword,
            r.proxy.model_dump() if r.proxy else None, r.trafficLimitBytes, r.maxSourceIps,
            r.expiresAt, r.requireReadiness))
        def create(data, registry):
            if r.expiresAt and manager._as_utc(r.expiresAt) <= datetime.now(timezone.utc):
                raise manager.SingboxConfigError("queued user expiration is no longer valid")
            return callback(data, registry)
        return create
    if isinstance(command, Access):
        callback = manager.capture_mutation(lambda: manager.set_user_access(command.userId, command.enabled))
        def access(data, registry):
            result = callback(data, registry)
            # Native runtime publication closes affected sessions atomically.
            # Do not report the legacy pre-publication Clash close count.
            result.pop("activeConnectionsClosed", None)
            return result
        return access
    if isinstance(command, Route):
        r = command.binding
        return manager.capture_mutation(lambda: manager.bind_proxy(
            r.userId, r.proxy.model_dump(), r.syncSocksCredentials, r.uuid or None))
    if isinstance(command, Direct):
        def direct(data, registry):
            if not manager._user_exists(data, registry, command.userId):
                raise manager.SingboxConfigError("user not found")
            manager._set_direct_binding(data, registry, command.userId)
            return {"success": True, "userId": command.userId, "route": "direct"}
        return direct
    if isinstance(command, Credentials):
        if not command.uuid and not command.socksUsername:
            raise HTTPException(422, "credentials are required")
        if bool(command.socksUsername) != bool(command.socksPassword):
            raise HTTPException(422, "both SOCKS credentials are required")
        def credentials(data, registry):
            if not manager._user_exists(data, registry, command.userId):
                raise manager.SingboxConfigError("user not found")
            if command.uuid:
                manager._rotate_protocol_credentials(data, registry, command.userId, command.uuid)
            if command.socksUsername:
                manager._update_socks_credentials(data, registry, command.userId, command.socksUsername, command.socksPassword)
            return {"success": True, "userId": command.userId}
        return credentials
    callback = manager.capture_mutation(lambda: manager.delete_user(command.userId))
    def delete(data, registry):
        expiry = manager._as_utc(manager._registry_user(registry, command.userId).get("expiresAt"))
        if expiry and datetime.now(timezone.utc) >= expiry + timedelta(hours=24):
            raise manager.SingboxConfigError("EXPIRED_USER_REQUIRES_DATABASE_ARCHIVE_AND_SOCKS_PROBE")
        return callback(data, registry)
    return delete


router = APIRouter(prefix="/api/singbox/tasks", tags=["runtime-tasks"], dependencies=[Depends(verify_token)])


@router.post("", status_code=202)
def submit(request: Submission, response: Response,
           idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128)):
    from singbox.runtime_client import enabled as runtime_enabled
    # The route exists on mixed-version nodes, but the durable writer is only
    # available with the matching single-process core. 404 lets older control
    # planes keep their established legacy mutation path during migration.
    if not runtime_enabled():
        raise HTTPException(404, "runtime task mode is disabled")
    import json
    payload = request.model_dump(mode="json")
    size = len(json.dumps(payload, separators=(",", ":")).encode())
    if size > 1 << 20: raise HTTPException(413, "runtime task payload exceeds 1 MiB")
    writer = queue.start()
    callbacks = [compile_command(command) for command in request.commands]
    keys = [command.user.userId if isinstance(command, Create) else
            command.binding.userId if isinstance(command, Route) else command.userId
            for command in request.commands]
    if len(set(keys)) != len(keys):
        raise HTTPException(422, "one operation per user per task; submit subsequent changes as ordered tasks")
    def apply(data, registry):
        results = []
        versions = registry.setdefault("runtimeUserVersions", {})
        for command, callback, user_id in zip(request.commands, callbacks, keys):
            from runtime_history import user_version
            previous = user_version(user_id,registry)
            if command.expectedUserVersion is not None and command.expectedUserVersion != previous:
                raise manager.SingboxConfigError("user version changed; refresh before submitting a new task")
            value = callback(data, registry)
            versions[user_id] = previous + 1
            results.append({**value, "userVersion": previous + 1})
        return {"items": results,
                "verificationScope": "files-and-runtime"}
    task_id, replayed = writer.submit(apply, key="task:" + idempotency_key,
                                     payload=payload, size=size, units=len(callbacks), keys=keys)
    response.headers.update({"Location": "/api/singbox/tasks/" + task_id,
                             "Cache-Control": "no-store", "Idempotency-Replayed": str(replayed).lower()})
    return writer.status(task_id)


@router.get("")
def state(response: Response):
    response.headers["Cache-Control"] = "no-store"
    return queue.start().snapshot()


@router.get("/{task_id}")
def status(task_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    result = queue.start().status(task_id)
    if result is None: raise HTTPException(404, "runtime task not found")
    return result


@router.get("/{task_id}/result")
def result(task_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store, private"
    writer = queue.start()
    row = writer.status(task_id)
    if row is None: raise HTTPException(404, "runtime task not found")
    if row["state"] != "SUCCEEDED": raise HTTPException(409, row)
    return writer.wait(task_id, timeout=0)


@router.get("/user-version/{user_id}")
def version(user_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    with manager._config_lock():
        from runtime_history import user_version
        return {"userId": user_id, "userVersion": user_version(user_id,manager.read_registry())}
