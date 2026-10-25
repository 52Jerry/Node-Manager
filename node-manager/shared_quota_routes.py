from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from auth import verify_token
from monitor import shared_quota

router = APIRouter(prefix="/api/users/shared-quota", tags=["shared-quota"])


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InspectRequest(StrictModel):
    userIds: list[str] | None = Field(default=None, min_length=1, max_length=10000)


class Epoch(StrictModel):
    cycleStart: int | None = Field(default=None, ge=0)
    manualResetAt: int | None = Field(default=None, ge=0)
    renewalResetKey: str | None = Field(default=None, max_length=128)
    version: int = Field(default=0, ge=0)


class SourceUser(StrictModel):
    userId: str = Field(min_length=1, max_length=64)
    identityDigest: str = Field(pattern=r"^[a-f0-9]{64}$")
    limitBytes: int = Field(gt=0, le=2**63 - 1)
    nativeTotalBytes: int = Field(ge=0, le=2**63 - 1)
    epoch: Epoch
    epochToken: str = Field(pattern=r"^[a-f0-9]{64}$")


class Update(StrictModel):
    targetUserId: str = Field(min_length=1, max_length=64)
    expectedTargetEpochToken: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: SourceUser


class ApplyRequest(StrictModel):
    sourceNodeId: str = Field(min_length=1, max_length=128)
    observedAt: str = Field(min_length=1, max_length=64)
    updates: list[Update] = Field(min_length=1, max_length=50)


@router.post("/inspect")
def inspect(request: InspectRequest, response: Response, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    try:
        return shared_quota.inspect_users(request.userIds)
    except shared_quota.QuotaEvidenceRejected as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@router.post("/apply")
def apply(request: ApplyRequest, response: Response, _token: str = Depends(verify_token)):
    response.headers["Cache-Control"] = "no-store"
    try:
        return shared_quota.apply_users(request.sourceNodeId, request.observedAt,
                                         [item.model_dump() for item in request.updates])
    except shared_quota.QuotaEvidenceRejected as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
