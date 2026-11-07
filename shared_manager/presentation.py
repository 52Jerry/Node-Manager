"""Customer-facing protocol labels without internal allocation identifiers."""
from __future__ import annotations

import base64
import json
from urllib.parse import quote, urlsplit, urlunsplit

from .agent import AgentError


def display_links(result: dict, name: str):
    extra = result.get("protocolsAll") or {}
    values = [result.get("vless") or extra.get("vless"), result.get("vmess") or extra.get("vmess"), extra.get("socksAcceleration")]
    output = []
    for protocol, value in zip(["vless", "vmess", "socks"], values):
        if not isinstance(value, str) or not value.startswith(protocol + "://") or "\n" in value or "\r" in value:
            raise AgentError(502, "连接信息暂不可用，请稍后重试")
        try:
            label = name + " · " + ("SOCKS5" if protocol == "socks" else protocol.upper())
            if protocol == "vmess":
                raw = value[len("vmess://"):]
                payload = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
                payload["ps"] = label
                value = "vmess://" + base64.b64encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()).decode()
            else:
                parsed = urlsplit(value)
                value = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, quote(label, safe="")))
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            raise AgentError(502, "连接信息暂不可用，请稍后重试") from None
        output.append({"protocol": protocol, "uri": value})
    return output
