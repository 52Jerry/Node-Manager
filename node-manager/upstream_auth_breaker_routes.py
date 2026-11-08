"""Authenticated configuration; manual recovery is a single-probe request."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, model_validator

from auth import verify_token
import upstream_auth_breaker as breaker


class SafeValidationRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def safe(request):
            try:
                return await handler(request)
            except RequestValidationError:
                raise HTTPException(422, "BREAKER_REQUEST_INVALID") from None
        return safe


router = APIRouter(prefix="/api/singbox/upstream-auth-breaker", tags=["upstream-auth-breaker"],
                   dependencies=[Depends(verify_token)], route_class=SafeValidationRoute)


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    enabled: bool
    threshold: int = Field(default=3, ge=1, le=100)
    windowSeconds: int = Field(default=30, ge=1, le=3600)
    cooldownSeconds: int = Field(default=300, ge=1, le=86400)
    maxCooldownSeconds: int = Field(default=1800, ge=1, le=86400)
    expectedRevision: int = Field(ge=0, le=2**53 - 1)
    controllerId: str | None = None
    controllerRevision: int | None = Field(default=None, ge=0, le=2**53 - 1)

    @model_validator(mode="after")
    def coherent(self):
        if self.maxCooldownSeconds < self.cooldownSeconds:
            raise ValueError("invalid cooldown")
        if (self.controllerId is None) != (self.controllerRevision is None):
            raise ValueError("controller fields must be supplied together")
        if self.controllerId is not None and self.controllerId != "website":
            raise ValueError("unknown controller")
        return self


class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    requestId: str = Field(pattern=r"^[A-Za-z0-9_-]{16,128}$")


def _invoke(response, function, *args, **kwargs):
    response.headers["Cache-Control"] = "no-store"
    try:
        return function(*args, **kwargs)
    except breaker.BreakerError as error:
        raise HTTPException(error.status, error.code) from None


@router.get("")
def inspect(response: Response):
    return _invoke(response, breaker.inspect)


@router.put("")
def update(request: PolicyUpdate, response: Response):
    values = request.model_dump()
    return _invoke(response, breaker.update, {name: values[name] for name in breaker.FIELDS},
                   request.expectedRevision, request.controllerId, request.controllerRevision)


@router.post("/circuits/{circuit_id}/probe", status_code=202)
def probe(circuit_id: str, request: Probe, response: Response):
    return _invoke(response, breaker.request_probe, circuit_id, request.requestId)
