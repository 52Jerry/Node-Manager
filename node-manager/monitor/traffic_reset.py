from __future__ import annotations

from datetime import datetime, timezone

from monitor import traffic
from singbox.manager import SingboxConfigError, get_user_policies


def reset_traffic(user_id: str, cycle_start: datetime | None = None) -> dict:
    """Reset usage only, without changing expiry, credentials, policy or sampling baselines."""
    if user_id not in get_user_policies():
        raise SingboxConfigError("user not found")
    cycle_key = int(cycle_start.timestamp() * 1000) if cycle_start else None
    with traffic.collection_lock:
        with traffic.traffic_lock:
            store = traffic._read_store()
            user = store["users"].setdefault(user_id, {})
            if cycle_key is not None and int(user.get("lastTrafficCycleStart", -1)) >= cycle_key:
                return {"success": True, "userId": user_id, "trafficReset": False}
            # Do not acknowledge/reset counters if removing the quota block fails.
            traffic.sync_user_enforcements({user_id: {"trafficBlocked": False, "blockedSourceIps": []}})
            user.update(upload=0, download=0, activeSourceIps=[], blockedSourceIps=[],
                        sourceIpLastSeen={}, status="active", updatedAt=datetime.now(timezone.utc).isoformat())
            if cycle_key is not None:
                user["lastTrafficCycleStart"] = cycle_key
                user["lastManualTrafficResetAt"] = 0
            else:
                user["lastManualTrafficResetAt"] = int(datetime.now(timezone.utc).timestamp() * 1000000)
            traffic._write_store(store)
    return {"success": True, "userId": user_id, "trafficReset": True}
