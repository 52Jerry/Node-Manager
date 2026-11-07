"""Explicit, identity-checked removal of one user's upstream SOCKS binding."""
from __future__ import annotations

import hmac

from singbox import manager


def restore_direct(user_id: str, expected_uuid: str, expected_socks_username: str):
    def apply(data, registry):
        if not manager._user_exists(data, registry, user_id):
            raise manager.SingboxConfigError("user not found")
        actual_uuid = manager._find_user_uuid(data, registry, user_id)
        actual_socks_username = manager._public_socks_username(registry, user_id)
        if (not hmac.compare_digest(actual_uuid.encode(), expected_uuid.encode())
                or not hmac.compare_digest(actual_socks_username.encode(), expected_socks_username.encode())):
            raise manager.SingboxConfigError("user identity changed")
        manager._set_direct_binding(data, registry, user_id, replace_existing=True)
        manager._audit("user.proxy.unbind", user_id)
        return {"success": True, "userId": user_id, "message": "restored direct route"}
    return manager.mutate_config(apply)
