"""Confirm imported residential intent before releasing any connection links."""
from .agent import AgentError


def confirm_initial_proxy(store, agent, owner_id, profile):
    if profile["ready"] or not profile["request"].get("proxy"):
        return
    state = store.get_profile_upstream(owner_id, profile["id"])
    desired = state["pending"] or state["applied"]
    if desired.get("mode") != "socks5" or not agent.upstream_matches(profile, desired):
        raise AgentError(503, "住宅代理配置尚未确认，请使用原导入内容重试")
    if state["pending_id"]:
        store.apply_profile_upstream(owner_id, profile["id"], state["pending_id"])
