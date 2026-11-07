"""Canonical JSON persistence with transient, in-memory SQL transactions.

No SQLite database is opened on disk in JSON mode. The SQL engine exists only
for the duration of a locked transaction, preserving the portal's constraints
and queries while JSON remains the sole durable source of account state.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
import time


FORMAT = "shared-node-manager-json"
VERSION = 1
_locks_guard = threading.Lock()
_locks: dict[str, threading.RLock] = {}
_active = threading.local()


def _quote(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _reject_constant(_value):
    raise ValueError("JSON 数据库包含无效数值")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON 数据库包含重复字段")
        result[key] = value
    return result


def _encode(value):
    if isinstance(value, bytes):
        return {"$blob": base64.b64encode(value).decode("ascii")}
    if value is None or type(value) in (int, str):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("JSON 数据库包含不支持的数据类型")


def _decode(value):
    if value is None or type(value) in (int, str):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) is dict and set(value) == {"$blob"} and isinstance(value["$blob"], str):
        try:
            return base64.b64decode(value["$blob"], validate=True)
        except (ValueError, UnicodeError):
            pass
    raise ValueError("JSON 数据库包含无效字段值")


def _snapshot(db: sqlite3.Connection) -> dict:
    if db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
        raise ValueError("JSON 数据库不支持迁移触发器或视图")
    schema = [{"type": row[0], "name": row[1], "sql": row[2]}
              for row in db.execute("""SELECT type, name, sql FROM sqlite_master
                  WHERE type IN ('table', 'index') AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
                  ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, name""")]
    tables = {}
    for entry in schema:
        if entry["type"] != "table":
            continue
        name = entry["name"]
        columns = [row[1] for row in db.execute("PRAGMA table_info(" + _quote(name) + ")")]
        rows = [{"rowid": row[0], "values": [_encode(value) for value in row[1:]]}
                for row in db.execute("SELECT rowid, * FROM " + _quote(name) + " ORDER BY rowid")]
        tables[name] = {"columns": columns, "rows": rows}
    return {"format": FORMAT, "version": VERSION, "schema": schema, "tables": tables}


def _canonical(document: dict) -> bytes:
    return (json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _restore(document: dict) -> sqlite3.Connection:
    """Validate a complete snapshot before exposing its transient connection."""
    if (type(document) is not dict or set(document) != {"format", "version", "schema", "tables"}
            or document["format"] != FORMAT or type(document["version"]) is not int
            or document["version"] != VERSION or type(document["schema"]) is not list
            or type(document["tables"]) is not dict):
        raise ValueError("JSON 数据库格式或版本无效")
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    try:
        names = set()
        table_names = set()
        for entry in document["schema"]:
            if (type(entry) is not dict or set(entry) != {"type", "name", "sql"}
                    or entry["type"] not in {"table", "index"}
                    or not isinstance(entry["name"], str) or not entry["name"]
                    or entry["name"].startswith("sqlite_") or entry["name"] in names
                    or not isinstance(entry["sql"], str)
                    or not re.match(r"\s*CREATE\s+(?:UNIQUE\s+)?" + entry["type"] + r"\b",
                                    entry["sql"], re.IGNORECASE)):
                raise ValueError("JSON 数据库结构无效")
            names.add(entry["name"])
            if entry["type"] == "table":
                table_names.add(entry["name"])
                db.execute(entry["sql"])
        if set(document["tables"]) != table_names:
            raise ValueError("JSON 数据库表数据不完整")
        for name, table in document["tables"].items():
            columns = [row[1] for row in db.execute("PRAGMA table_info(" + _quote(name) + ")")]
            if (type(table) is not dict or set(table) != {"columns", "rows"}
                    or table["columns"] != columns or type(table["rows"]) is not list):
                raise ValueError("JSON 数据库字段结构无效")
            statement = ("INSERT INTO " + _quote(name) + " (rowid," + ",".join(map(_quote, columns))
                         + ") VALUES (" + ",".join("?" for _ in range(len(columns) + 1)) + ")")
            for row in table["rows"]:
                if (type(row) is not dict or set(row) != {"rowid", "values"}
                        or type(row["rowid"]) is not int or type(row["values"]) is not list
                        or len(row["values"]) != len(columns)):
                    raise ValueError("JSON 数据库记录无效")
                db.execute(statement, [row["rowid"], *map(_decode, row["values"])])
        for entry in document["schema"]:
            if entry["type"] == "index":
                db.execute(entry["sql"])
        db.commit()
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("JSON 数据库引用关系无效")
        # Check SQL names/types, missing declarations and altered row ordering.
        if _snapshot(db) != document:
            raise ValueError("JSON 数据库内容与结构不一致")
        db.execute("PRAGMA foreign_keys=ON")
        return db
    except (sqlite3.Error, OverflowError, TypeError) as exc:
        db.close()
        raise ValueError("JSON 数据库内容无效") from exc
    except Exception:
        db.close()
        raise


def _atomic_write(path: Path, document: dict):
    content = _canonical(document)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class JsonDatabase:
    """Serialize complete transactions across threads and operating processes."""
    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        with _locks_guard:
            self.thread_lock = _locks.setdefault(str(self.path), threading.RLock())

    @contextmanager
    def _locked(self):
        with self.thread_lock:
            active = getattr(_active, "paths", set())
            if str(self.path) in active:
                raise RuntimeError("不能嵌套打开同一 JSON 数据库事务")
            descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            acquired = False
            try:
                os.chmod(self.lock_path, 0o600)
                if os.name == "nt":
                    import msvcrt
                    if os.fstat(descriptor).st_size == 0:
                        os.write(descriptor, b"\0")
                    deadline = time.monotonic() + 30
                    while True:
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        try:
                            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("JSON 数据库事务等待超时")
                            time.sleep(.025)
                else:
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                acquired = True
                _active.paths = active | {str(self.path)}
                yield
            finally:
                if acquired:
                    _active.paths = active
                    if os.name == "nt":
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @contextmanager
    def connection(self):
        with self._locked():
            if self.path.exists():
                try:
                    original = json.loads(self.path.read_text(encoding="utf-8"),
                                          object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
                except (OSError, UnicodeError, ValueError) as exc:
                    raise ValueError("JSON 数据库无法读取，请恢复完整备份") from exc
                db = _restore(original)
            else:
                original = None
                db = sqlite3.connect(":memory:")
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA foreign_keys=ON")
            try:
                with db:
                    yield db
                updated = _snapshot(db)
                if updated != original:
                    _atomic_write(self.path, updated)
            finally:
                db.close()


def migrate_sqlite_to_json(source: Path, target: Path) -> dict:
    """Copy a consistent, read-only legacy snapshot without changing identities."""
    source, target = Path(source).resolve(), Path(target).resolve()
    if not source.is_file() or source == target or target.suffix.lower() != ".json":
        raise ValueError("JSON 数据库迁移路径无效")
    database = JsonDatabase(target)
    with database._locked():
        if target.exists():
            raise FileExistsError("目标 JSON 数据库已存在，拒绝覆盖")
        original = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
        snapshot = sqlite3.connect(":memory:")
        try:
            original.backup(snapshot)
            document = _snapshot(snapshot)
        finally:
            snapshot.close()
            original.close()
        rebuilt = _restore(document)
        rebuilt.close()
        _atomic_write(target, document)
    return {"migrated": True, "sourceFormat": "sqlite", "targetFormat": "json",
            "tableCounts": {name: len(table["rows"]) for name, table in document["tables"].items()},
            "logicalSha256": hashlib.sha256(_canonical(document)).hexdigest()}
