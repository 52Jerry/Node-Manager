"""Parse residential SOCKS lists without returning credentials in diagnostics."""
from __future__ import annotations

import csv
import base64
from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import unquote, urlsplit


class ImportFormatError(ValueError):
    pass


@dataclass
class ResidentialRow:
    line: int
    name: str = ""
    server: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    error: str | None = None

    def summary(self):
        return {"line": self.line, "name": self.name, "server": self.server,
                "port": self.port or None, "username": self.username,
                "passwordConfigured": bool(self.password), "valid": self.error is None,
                "error": self.error}


def _validate(row):
    if not row.name or len(row.name) > 64 or any(ord(c) < 32 for c in row.name):
        raise ImportFormatError("连接名称须为 1–64 个可见字符")
    row.server = row.server.strip().strip("[]").rstrip(".").lower()
    if not row.server or len(row.server) > 253 or any(c in row.server for c in "/\\@%#?, \t\r\n"):
        raise ImportFormatError("代理地址格式无效")
    if not 1 <= row.port <= 65535:
        raise ImportFormatError("端口须在 1–65535 之间")
    if bool(row.username) != bool(row.password) or max(len(row.username.encode()), len(row.password.encode())) > 255:
        raise ImportFormatError("代理账号和密码须同时填写或留空，且各不超过 255 字节")
    try:
        address = ipaddress.ip_address(row.server)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global or address.is_multicast:
            raise ImportFormatError("请填写有效的公网代理地址")
        row.server = str(address)
    except ValueError as exc:
        if isinstance(exc, ImportFormatError):
            raise
        if ":" in row.server or any(not p or len(p) > 63 for p in row.server.split(".")):
            raise ImportFormatError("代理地址格式无效") from None
    return row


def parse_import(text: str) -> list[ResidentialRow]:
    if not isinstance(text, str) or len(text) > 65536:
        raise ImportFormatError("导入内容不能超过 64 KiB")
    text = text.lstrip("\ufeff")
    rows = []
    seen = set()
    for line_number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        row = ResidentialRow(line=line_number, name=f"连接 {len(rows) + 1}")
        try:
            value = raw.lstrip()
            if "://" in value:
                parsed = urlsplit(value.strip())
                if parsed.scheme.lower() not in {"socks5", "socks"} or not parsed.hostname or parsed.port is None or parsed.query or parsed.path not in {"", "/"}:
                    raise ImportFormatError("请使用完整的 SOCKS5 地址")
                row.server, row.port = parsed.hostname, parsed.port
                row.username = unquote(parsed.username or "", errors="strict")
                row.password = unquote(parsed.password or "", errors="strict")
                if parsed.scheme.lower() == "socks" and parsed.username and parsed.password is None:
                    auth = row.username
                    decoded = base64.b64decode(auth + "=" * (-len(auth) % 4), altchars=b"-_", validate=True).decode("utf-8")
                    row.username, row.password = decoded.split(":", 1)
                if parsed.fragment:
                    row.name = unquote(parsed.fragment, errors="strict").strip()
            else:
                # Recognize the unambiguous colon form before CSV so a comma
                # inside its password does not get interpreted as a separator.
                match = re.fullmatch(r"(?:\[([^\]]+)\]|([^:,\s]+)):(\d+)(?::([^:]*):(.*))?", value)
                if match:
                    row.server, row.port = match.group(1) or match.group(2), int(match.group(3))
                    row.username, row.password = match.group(4) or "", match.group(5) or ""
                elif "," in value:
                    fields = next(csv.reader([value], strict=True))
                    lowered = [f.strip().lower() for f in fields]
                    if lowered in [["name", "host", "port", "username", "password"],
                                   ["name", "server", "port", "username", "password"],
                                   ["名称", "地址", "端口", "账号", "密码"]]:
                        continue
                    if len(fields) != 5:
                        raise ImportFormatError("CSV 须包含名称、地址、端口、账号、密码五列")
                    row.name, row.server, port, row.username, row.password = fields
                    row.name = row.name.strip()
                    row.port = int(port.strip())
                else:
                    raise ImportFormatError("支持 地址:端口:账号:密码、SOCKS5 链接或五列 CSV")
            _validate(row)
            identity = (row.server, row.port, row.username, row.password)
            if identity in seen:
                raise ImportFormatError("该代理在本次导入中重复")
            seen.add(identity)
        except (ValueError, UnicodeError, csv.Error) as exc:
            # Do not echo a malformed source string: it may contain a password.
            row.error = str(exc) if isinstance(exc, ImportFormatError) else "格式无效，请检查地址、端口和认证信息"
            row.name = f"连接 {len(rows) + 1}"
            row.password = ""
            # An invalid delimiter may have put a credential into any parsed
            # field. Keep diagnostics to the line and safe generated name.
            row.server, row.port, row.username = "", 0, ""
        rows.append(row)
        if len(rows) > 50:
            raise ImportFormatError("每次最多导入 50 条代理")
    if not rows:
        raise ImportFormatError("请先填写需要导入的代理")
    return rows
