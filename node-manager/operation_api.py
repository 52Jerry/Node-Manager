"""Opt-in HTTP transport for versioned operations, with explicit native adapters.

Nothing is mounted by importing this module. main.py/A1 must supply the existing
token dependency, actual local node ID, and native handlers before include_router.
An empty/missing action registry fails closed, never logging a fake success.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import Any, Callable, Mapping

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictInt, StrictStr

from operations import Observation, Operation, OperationConflict, OperationStore, OperationStoreError


@dataclass(frozen=True)
class PreparedAction:
    # prepare() may validate request shape, but no mutation is allowed there.
    # Native guards/readback must be repeated inside these callbacks, under the
    # operation scope lock and the native WG -> config/runtime lock order.
    apply: Callable[[], Any]
    readback: Callable[[], Observation]


class OperationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operationId: StrictStr = Field(min_length=1, max_length=512)
    nodeId: StrictStr = Field(min_length=1, max_length=512)
    assetKey: StrictStr = Field(min_length=1, max_length=512)
    ownerRef: StrictStr = Field(min_length=1, max_length=512)
    action: StrictStr = Field(min_length=1, max_length=128)
    generation: StrictInt = Field(ge=1, le=2**63 - 1)
    desiredVersion: StrictInt = Field(ge=1, le=2**63 - 1)
    requestHash: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    payload: dict[str, JsonValue]


def _error(status: int, code: str) -> HTTPException:
    return HTTPException(status, {"code": code}, headers={"Cache-Control": "no-store, private"})


def _no_floats(value: Any) -> bool:
    if isinstance(value, float):
        return False
    if isinstance(value, dict):
        return all(_no_floats(item) for item in value.values())
    if isinstance(value, list):
        return all(_no_floats(item) for item in value)
    return True


def create_operation_router(
    store: OperationStore,
    node_id: str,
    authorize: Callable[..., Any],
    handlers: Mapping[str, Callable[[Operation, dict[str, JsonValue]], PreparedAction]],
) -> APIRouter:
    if not isinstance(node_id, str) or not node_id or node_id != node_id.strip():
        raise ValueError("an explicit canonical local node ID is required")
    # Freeze the registry at construction; there is no permissive runtime fallback.
    registry = dict(handlers)
    router = APIRouter(prefix="/api/operations", tags=["operations"], dependencies=[Depends(authorize)])

    def prepare(request: OperationRequest) -> tuple[Operation, PreparedAction]:
        if request.nodeId != node_id:
            raise _error(409, "NODE_TARGET_MISMATCH")
        handler = registry.get(request.action)
        if handler is None:
            raise _error(422, "UNSUPPORTED_OPERATION_ACTION")
        if not _no_floats(request.payload):
            raise _error(422, "CANONICAL_PAYLOAD_REQUIRES_INTEGER_OR_STRING_NUMBERS")
        try:
            operation = Operation(request.operationId, request.nodeId, request.assetKey,
                                  request.ownerRef, request.action, request.generation,
                                  request.desiredVersion)
            actual_hash = operation.request_hash(request.payload)
            if not hmac.compare_digest(actual_hash, request.requestHash):
                raise _error(409, "REQUEST_HASH_MISMATCH")
            prepared = handler(operation, request.payload)
            if not isinstance(prepared, PreparedAction):
                raise _error(503, "OPERATION_ADAPTER_UNAVAILABLE")
            return operation, prepared
        except (TypeError, ValueError):
            raise _error(422, "INVALID_OPERATION_PAYLOAD") from None

    @router.post("")
    def execute_operation(request: OperationRequest, response: Response):
        response.headers["Cache-Control"] = "no-store, private"
        operation, action = prepare(request)
        try:
            receipt = store.execute(operation, request.payload, action.apply, action.readback)
        except OperationConflict:
            raise _error(409, "OPERATION_CONTENT_CONFLICT") from None
        except OperationStoreError:
            raise _error(503, "OPERATION_JOURNAL_UNAVAILABLE") from None
        response.status_code = 409 if receipt.status == "REJECTED" else 202 if receipt.status == "UNKNOWN" else 200
        return {"success": receipt.status == "APPLIED" and receipt.current, **receipt.as_dict()}

    @router.get("/{operation_id}")
    def read_operation(operation_id: str, response: Response):
        response.headers["Cache-Control"] = "no-store, private"
        try:
            receipt = store.read(operation_id)
        except ValueError:
            raise _error(422, "INVALID_OPERATION_ID") from None
        except OperationStoreError:
            raise _error(503, "OPERATION_JOURNAL_UNAVAILABLE") from None
        if receipt is None:
            raise _error(404, "OPERATION_NOT_OBSERVED")
        return {"success": receipt.status == "APPLIED" and receipt.current, **receipt.as_dict()}

    @router.post("/{operation_id}/readback")
    def readback_operation(operation_id: str, request: OperationRequest, response: Response):
        response.headers["Cache-Control"] = "no-store, private"
        if operation_id != request.operationId:
            raise _error(409, "OPERATION_ID_MISMATCH")
        operation, action = prepare(request)
        try:
            receipt = store.reconcile(operation, request.payload, action.readback)
        except OperationConflict:
            raise _error(409, "OPERATION_CONTENT_CONFLICT") from None
        except OperationStoreError:
            raise _error(503, "OPERATION_JOURNAL_UNAVAILABLE") from None
        if receipt is None:
            raise _error(404, "OPERATION_NOT_OBSERVED")
        response.status_code = 409 if receipt.status == "REJECTED" else 202 if receipt.status == "UNKNOWN" else 200
        return {"success": receipt.status == "APPLIED" and receipt.current, **receipt.as_dict()}

    return router
