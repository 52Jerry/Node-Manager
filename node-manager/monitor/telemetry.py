"""Admin-only telemetry projection. No client-supplied identity is trusted."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from monitor.source_identity import normalize_ip, source_ip_diagnostics


def sample_state(sample_time: str | None, available: bool, max_age: float,
                 reason: str | None = None) -> dict[str, Any]:
    age = None
    if isinstance(sample_time, str) and sample_time:
        try:
            stamp = datetime.fromisoformat(sample_time.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - stamp).total_seconds()
        except (ValueError, TypeError):
            pass
    stale = age is None or age < 0 or age > max_age
    usable = available and not stale
    return {"sampleTime": sample_time, "stalenessSeconds": age,
            "stale": stale, "telemetryStatus": "fresh" if usable else "unavailable",
            "unavailableReason": None if usable else reason or (
                "no_sample" if sample_time is None else "sample_stale" if stale else "api_unavailable"),
            "telemetryAvailable": usable}


def connection_summary(connections: list[dict[str, Any]] | None) -> dict[str, Any]:
    diagnostics = source_ip_diagnostics(connections)
    sources = {normalize_ip(item.get("sourceIp")) for item in connections or []}
    sources.discard(None)
    credentials = {item.get("credentialId") for item in connections or []}
    credentials.discard(None)
    return {"activeConnections": None if connections is None else len(connections),
            "observedSourceCount": None if connections is None else len(sources),
            # Even zero sessions cannot prove that there are zero registered devices.
            "verifiedDeviceCount": None, "deviceIdentityConfidence": "unverified",
            "deviceUnavailableReason": "native_shared_credential_no_verified_device_identity",
            "credentialCount": None if connections is None else len(credentials),
            "credentialCountBasis": "authenticated_user_aliases_not_distinct_secrets",
            **diagnostics}


def admin_projection(payload: dict[str, Any], *, role: str,
                     account_active: bool = True) -> dict[str, Any]:
    """Defense in depth; the HTTP controller must also enforce current server roles."""
    if not account_active or role not in {"admin", "superadmin"}:
        raise PermissionError("administrator telemetry required")
    fields = ("activeConnections", "observedSourceCount", "verifiedDeviceCount",
              "credentialCount", "credentialCountBasis", "sourceConfidence", "deviceIdentityConfidence",
              "deviceUnavailableReason", "sampleTime", "stalenessSeconds", "stale",
              "telemetryStatus", "telemetryAvailable", "unavailableReason",
              "measurementQuality", "measuredTotal", "lastKnownTotal", "quotaDecision",
              "alertRequired", "policyStatus", "sourceLimitDecision")
    # Source and destination addresses, hosts and stable credential hashes are not
    # needed for counts. The current snapshot remains in the node's restricted store.
    return {field: payload.get(field) for field in fields}
