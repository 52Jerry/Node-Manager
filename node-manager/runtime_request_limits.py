"""Bound request buffering before FastAPI/Pydantic decode on mutation routes."""
from __future__ import annotations

import asyncio
from fastapi.responses import JSONResponse


class RuntimeRequestLimits:
    def __init__(self, app):
        self.app = app
        self.active = 0
        self.large_active = 0

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        mutation = scope.get("method") in {"POST", "PUT", "PATCH", "DELETE"}
        guarded = path.startswith(("/api/singbox/tasks", "/api/user/", "/api/users/replication"))
        if scope["type"] != "http" or not mutation or not guarded:
            return await self.app(scope, receive, send)
        # ASGI execution increments this before the first await, on one loop.
        large = path.startswith("/api/users/replication")
        if self.active >= 32 or (large and self.large_active):
            return await JSONResponse({"code": "REQUEST_ADMISSION_FULL"}, status_code=429,
                                      headers={"Retry-After": "1"})(scope, receive, send)
        limit = (8 << 20) if path.startswith("/api/users/replication") else (1 << 20) if path.startswith("/api/singbox/tasks") else (64 << 10)
        self.active += 1
        if large: self.large_active += 1
        try:
            body = bytearray()
            while True:
                try:
                    message = await asyncio.wait_for(receive(), 15)
                except asyncio.TimeoutError:
                    return await JSONResponse({"code": "REQUEST_BODY_TIMEOUT"}, status_code=408)(scope, receive, send)
                if message["type"] == "http.disconnect": return
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > limit:
                    return await JSONResponse({"code": "REQUEST_BODY_TOO_LARGE"}, status_code=413)(scope, receive, send)
                body.extend(chunk)
                if not message.get("more_body", False): break
            delivered = False
            async def buffered():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()
            from runtime_write_queue import submission_size
            token = submission_size.set(max(1, len(body)))
            try:
                await self.app(scope, buffered, send)
            finally:
                submission_size.reset(token)
        finally:
            self.active -= 1
            if large: self.large_active -= 1
