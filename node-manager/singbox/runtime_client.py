"""Private Unix-socket client. Never retries a mutation or falls back to HUP."""
from __future__ import annotations
import http.client
import json
import os
import re
import socket
from pathlib import Path
from typing import Any
from config import config
from .errors import SingboxConfigError

class RuntimeUnavailable(SingboxConfigError):
    pass

class RuntimeRejected(SingboxConfigError):
    def __init__(self, status: int):
        super().__init__(f"runtime request rejected (HTTP {status})")
        self.status = status

def configured_socket() -> str:
    return os.environ.get("NODE_MANAGER_SINGBOX_RUNTIME_SOCKET", getattr(config.singbox, "runtime_socket", "")).strip()

def enabled() -> bool:
    return bool(configured_socket())

def check_mode() -> str:
    path = configured_socket()
    if not path or not Path(path).is_absolute():
        raise RuntimeUnavailable("runtime socket must be an absolute path")
    if os.environ.get("NODE_MANAGER_VLESS_PUBLICATION_SPEC"):
        raise RuntimeUnavailable("runtime socket and VLESS generation publication cannot be enabled together")
    return path

class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = path
    def connect(self):
        if not hasattr(socket, "AF_UNIX"):
            raise RuntimeUnavailable("Unix sockets are unavailable in this Python runtime")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)

def validate_status(value: Any) -> dict:
    if (not isinstance(value, dict) or not isinstance(value.get("instanceId"), str)
            or not 1 <= len(value["instanceId"]) <= 128
            or type(value.get("revision")) is not int or not 0 <= value["revision"] < 2**63
            or not isinstance(value.get("contentHash"), str)
            or re.fullmatch(r"[0-9a-f]{64}", value["contentHash"]) is None):
        raise RuntimeUnavailable("invalid runtime receipt")
    return {key: value[key] for key in ("instanceId", "revision", "contentHash")}

class RuntimeClient:
    def _request(self, method: str, path: str, body: dict | None = None):
        connection = UnixConnection(check_mode(), 15)
        try:
            connection.request(method, "/management/v1/" + path,
                body=None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            data = response.read((16 << 20) + 1)
            if response.status != 200:
                raise RuntimeRejected(response.status)
            if len(data) > 16 << 20:
                raise RuntimeUnavailable("runtime response is too large")
            return json.loads(data)
        except RuntimeRejected:
            raise
        except (OSError, http.client.HTTPException, ValueError) as error:
            raise RuntimeUnavailable("runtime socket request failed") from error
        finally:
            connection.close()
    def status(self) -> dict:
        return validate_status(self._request("GET", "status"))
    def preview(self, data: dict) -> dict:
        value = self._request("POST", "preview", {"config": data})
        if not isinstance(value, dict) or type(value.get("supported")) is not bool:
            raise RuntimeUnavailable("invalid runtime preview")
        status = validate_status(value.get("runtime"))
        desired = validate_status({**status, "contentHash": value.get("contentHash")})["contentHash"]
        return {"runtime": status, "contentHash": desired, "supported": value["supported"]}
    def apply(self, data: dict, expected: dict) -> dict:
        value = self._request("PUT", "configuration", {"config": data,
            "expectedInstanceId": expected["instanceId"], "expectedRevision": expected["revision"]})
        status = validate_status(value)
        if type(value.get("closedSessions", 0)) is not int or type(value.get("cleanupPending", False)) is not bool:
            raise RuntimeUnavailable("invalid runtime update receipt")
        return {**status, "closedSessions": value.get("closedSessions", 0),
                "cleanupPending": value.get("cleanupPending", False)}
    def fence(self, status: dict) -> dict:
        return validate_status(self._request("POST", "fence", {
            "expectedInstanceId": status["instanceId"], "expectedRevision": status["revision"]}))
    def counters(self) -> dict:
        value = self._request("GET", "counters")
        if (not isinstance(value, dict) or not isinstance(value.get("instanceId"), str)
                or not 1 <= len(value["instanceId"]) <= 128 or not isinstance(value.get("users"), list)):
            raise RuntimeUnavailable("invalid runtime counters")
        seen = set()
        version = value.get("counterVersion", 1)
        if type(version) is not int or version not in (1, 2):
            raise RuntimeUnavailable("unsupported runtime counter version")
        for row in value["users"]:
            if (not isinstance(row, dict) or not all(isinstance(row.get(k), str) and row[k] for k in ("inbound", "user"))
                    or any(type(row.get(k)) is not int or not 0 <= row[k] < 2**63 for k in ("upload", "download"))):
                raise RuntimeUnavailable("invalid user counter")
            if version == 2 and (not isinstance(row.get("id"), str) or not row["id"]
                    or len(row["id"]) > 128 or type(row.get("retirable")) is not bool):
                raise RuntimeUnavailable("invalid counter retirement identity")
            key = row["inbound"], row["user"]
            if key in seen:
                raise RuntimeUnavailable("duplicate user counter")
            seen.add(key)
        return value

    def acknowledge_counters(self, instance: str, rows: list[dict]) -> list[dict]:
        if not 1 <= len(rows) <= 256:
            raise ValueError("invalid counter acknowledgement batch")
        fields = ("inbound", "user", "id", "upload", "download")
        requested = {tuple(row[k] for k in fields) for row in rows}
        value = self._request("POST", "counters/ack", {
            "expectedInstanceId": instance, "users": [{k: row[k] for k in fields} for row in rows]})
        if (not isinstance(value, dict) or value.get("instanceId") != instance
                or not isinstance(value.get("retired"), list)):
            raise RuntimeUnavailable("invalid counter acknowledgement")
        seen = set()
        for row in value["retired"]:
            if not isinstance(row, dict):
                raise RuntimeUnavailable("invalid retired counter")
            identity = tuple(row.get(k) for k in fields)
            if (any(not isinstance(row.get(k), str) or not row[k] for k in fields[:3])
                    or any(type(row.get(k)) is not int for k in fields[3:])
                    or identity not in requested or identity in seen):
                raise RuntimeUnavailable("unrequested retired counter")
            seen.add(identity)
        return value["retired"]
