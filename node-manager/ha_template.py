"""Portable protocol configuration, deliberately excluding host and API secrets."""
from __future__ import annotations

import copy

from config import config
from singbox import manager


FIELDS = {"type", "listen_port", "tls", "transport", "multiplex"}
LOCAL_FIELDS = {"tag", "users", "listen", "tcp_fast_open", "tcp_multi_path",
                "udp_fragment", "udp_timeout", "sniff", "sniff_override_destination",
                "sniff_timeout", "domain_strategy"}
FILE_FIELDS = {"certificate_path", "key_path", "acme", "certificate_provider"}


def tags():
    return {"vless": config.singbox.vless_tag, "vmess": config.singbox.vmess_tag,
            "trojan": config.singbox.trojan_tag, "socks": config.singbox.socks_tag}


def validate_template(template):
    if len(set(tags().values())) != len(tags()):
        raise manager.SingboxConfigError("managed protocol tags must be unique")
    if not isinstance(template, dict) or not template or set(template) - set(tags()):
        raise manager.SingboxConfigError("unsupported shared protocol template")
    ports = set()
    for protocol, inbound in template.items():
        if not isinstance(inbound, dict) or set(inbound) - FIELDS or inbound.get("type") != protocol:
            raise manager.SingboxConfigError("unsupported shared inbound configuration")
        port = inbound.get("listen_port")
        if type(port) is not int or not 1 <= port <= 65535 or port in ports:
            raise manager.SingboxConfigError("invalid or duplicate shared listener port")
        ports.add(port)

        def portable(value):
            if isinstance(value, dict):
                if set(value) & FILE_FIELDS:
                    raise manager.SingboxConfigError("shared TLS must not reference host-local files or ACME")
                for child in value.values():
                    portable(child)
            elif isinstance(value, list):
                for child in value:
                    portable(child)
        portable(inbound)
        if any(key in inbound and not isinstance(inbound[key], dict) for key in ("tls", "transport", "multiplex")):
            raise manager.SingboxConfigError("invalid shared protocol options")
        reality = inbound.get("tls", {}).get("reality")
        if reality is not None:
            try:
                manager._reality_client_options(inbound)
            except Exception:
                raise manager.SingboxConfigError("invalid shared Reality configuration") from None
    return template


def export_template(data):
    result = {}
    for protocol, tag in tags().items():
        matches = [item for item in data.get("inbounds", []) if item.get("tag") == tag]
        if len(matches) > 1:
            raise manager.SingboxConfigError("duplicate managed inbound tag")
        if not matches:
            continue
        inbound = matches[0]
        if set(inbound) - FIELDS - LOCAL_FIELDS:
            raise manager.SingboxConfigError("inbound contains nonportable settings; shared configuration refused")
        result[protocol] = {key: copy.deepcopy(value) for key, value in inbound.items() if key in FIELDS}
    return validate_template(result)


def apply_template(data, registry, template, group_key, desired, retired):
    validate_template(template)
    if any(auth.protocol not in template for user in desired.values() for auth in user.auth):
        raise manager.SingboxConfigError("shared template missing a required user protocol")
    owner = registry.get("sharedProtocolOwner")
    if owner and owner != group_key:
        raise manager.SingboxConfigError("shared protocol configuration belongs to another group")
    affected = set(tags().values())
    if any(sum(item.get("tag") == tag for item in data.get("inbounds", [])) > 1 for tag in affected):
        raise manager.SingboxConfigError("duplicate managed inbound tag")
    # Do not change the ports/keys of independent customers on this server.
    known_names = set()
    for user in [*desired.values(), *retired.values()]:
        known_names.update(manager._user_auth_names(registry, user.userId))
        known_names.update(auth.username for auth in user.auth if auth.username)
    for inbound in data.get("inbounds", []):
        if inbound.get("tag") in affected:
            if any(entry.get("name", entry.get("username")) not in known_names
                   for entry in inbound.get("users", [])):
                raise manager.SingboxConfigError("shared listener has independent accounts; migration required")
        elif inbound.get("listen_port") in {item["listen_port"] for item in template.values()}:
            raise manager.SingboxConfigError("shared port conflicts with an independent listener")
    if {item["listen_port"] for item in template.values()} & {config.server.port, config.singbox.api_port}:
        raise manager.SingboxConfigError("shared port conflicts with management API")
    omitted = {tag for protocol, tag in tags().items() if protocol not in template}
    data["inbounds"] = [item for item in data.get("inbounds", []) if item.get("tag") not in omitted]
    for protocol, options in template.items():
        inbound = next((item for item in data.get("inbounds", []) if item.get("tag") == tags()[protocol]), None)
        if inbound is None:
            inbound = {"tag": tags()[protocol], "listen": "::", "users": []}
            data.setdefault("inbounds", []).append(inbound)
        for key in FIELDS:
            inbound.pop(key, None)
        inbound.update(copy.deepcopy(options))
    registry["sharedProtocolOwner"] = group_key
