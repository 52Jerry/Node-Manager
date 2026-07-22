import hashlib
import json
import os
import tempfile
import threading
import time
import base64
from pathlib import Path
from typing import Any, Callable

from cryptography.fernet import Fernet, InvalidToken

from config import config


STORE_PATH = Path(
    os.environ.get("NODE_MANAGER_IDEMPOTENCY_STORE", "/var/lib/node-manager/idempotency.json")
)
RETENTION_SECONDS = 24 * 60 * 60
MAX_ENTRIES = 1000
store_lock = threading.Lock()


class IdempotencyConflict(RuntimeError):
    pass


def _cipher() -> Fernet:
    digest = hashlib.sha256(config.security.token.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _encrypt_response(response: dict[str, Any]) -> str:
    raw = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _cipher().encrypt(raw).decode("ascii")


def _decrypt_response(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    try:
        raw = _cipher().decrypt(value.encode("ascii"))
        response = json.loads(raw.decode("utf-8"))
    except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return response if isinstance(response, dict) else None


def _empty_store() -> dict[str, Any]:
    return {"version": 1, "entries": {}}


def _read_store() -> dict[str, Any]:
    if not STORE_PATH.exists():
        return _empty_store()
    try:
        with STORE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _empty_store()
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        return _empty_store()
    return data


def _write_store(data: dict[str, Any]) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, temp_name = tempfile.mkstemp(prefix="idempotency.", suffix=".json", dir=STORE_PATH.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, STORE_PATH)
    finally:
        temp_path.unlink(missing_ok=True)


def _fingerprint(operation: str, payload: Any) -> str:
    canonical = json.dumps(
        {"operation": operation, "payload": payload},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _prune(entries: dict[str, Any], now: float) -> None:
    expired = [
        key
        for key, value in entries.items()
        if not isinstance(value, dict) or now - float(value.get("createdAt", 0)) > RETENTION_SECONDS
    ]
    for key in expired:
        entries.pop(key, None)
    if len(entries) <= MAX_ENTRIES:
        return
    oldest = sorted(entries, key=lambda key: float(entries[key].get("createdAt", 0)))
    for key in oldest[: len(entries) - MAX_ENTRIES]:
        entries.pop(key, None)


def execute_idempotent(
    key: str | None,
    operation: str,
    payload: Any,
    callback: Callable[[], dict[str, Any]],
) -> tuple[dict[str, Any], bool]:
    if not key:
        return callback(), False

    fingerprint = _fingerprint(operation, payload)
    with store_lock:
        store = _read_store()
        entries = store["entries"]
        now = time.time()
        _prune(entries, now)
        existing = entries.get(key)
        if existing:
            if existing.get("fingerprint") != fingerprint:
                raise IdempotencyConflict(
                    "the idempotency key was already used with a different request"
                )
            response = _decrypt_response(existing.get("responseEncrypted"))
            if response is None and isinstance(existing.get("response"), dict):
                response = existing["response"]
            if response is not None:
                return response, True
            raise IdempotencyConflict(
                "the stored idempotent response cannot be decrypted; use a new key"
            )

        result = callback()
        entries[key] = {
            "fingerprint": fingerprint,
            "createdAt": now,
            "responseEncrypted": _encrypt_response(result),
        }
        _write_store(store)
        return result, False
