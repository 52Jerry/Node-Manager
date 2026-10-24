"""Pure R4 previews, deliberately without node/storage/network mutation.

An eligible preview is not an execution authorization. A1 must first integrate
asset locking, durable tasks and exact runtime transfer/readback. No plan below
creates a second residential owner, shares an administrator private key, resets
quota, purchases upstream inventory or creates a synthetic paid order.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_KINDS = frozenset({"UPSTREAM_CONFIRMED", "ADMIN_AUDIT_CONFIRMED"})


def _time(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(label + " must include a timezone; do not reinterpret local dates")
    return value


def _positive(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonnegative(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _reference(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip() and not any(
        ord(char) < 32 or ord(char) == 127 for char in value)


@dataclass(frozen=True)
class OwnerPolicy:
    owner_ref: str
    residential_identity_sha256: str
    quota_limit_bytes: int | None
    quota_used_bytes: int | None
    source_ip_limit: int | None
    blocked: bool | None


@dataclass(frozen=True)
class InventorySnapshot:
    asset_key: str
    node_id: str
    ownership_version: int
    generation: int
    owner_kind: str
    policy: OwnerPolicy
    source_kind: str
    source_evidence_ref: str | None
    source_verified: bool | None
    source_expires_at: datetime | None
    node_owner_present: bool | None
    exact_binding_verified: bool | None
    other_authorized_bindings: int | None
    business_refunded: bool | None
    business_paused: bool | None
    transfer_in_progress: bool | None
    mirror_present: bool | None = None


@dataclass(frozen=True)
class CustomerReservation:
    owner_ref: str
    resource_id: str
    subscription_id: str
    local_identity_ref: str
    grant_evidence_ref: str | None
    grant_verified: bool | None
    grant_expires_at: datetime | None
    enabled: bool | None
    node_owner_present: bool | None
    business_refunded: bool | None
    business_paused: bool | None


@dataclass(frozen=True)
class HandoffRequest:
    transfer_id: str
    asset_key: str
    expected_owner_ref: str
    expected_ownership_version: int
    expected_generation: int
    expected_residential_identity_sha256: str
    target: CustomerReservation


@dataclass(frozen=True)
class Preview:
    kind: str
    eligible: bool
    reasons: tuple[str, ...]
    notes: tuple[str, ...]
    asset_key: str
    expected_owner_ref: str | None
    expected_ownership_version: int | None
    expected_generation: int | None
    target_owner_ref: str | None
    preserved_policy: OwnerPolicy | None
    steps: tuple[str, ...]
    execution_enabled: bool = False

    def as_dict(self) -> dict[str, Any]:
        policy = self.preserved_policy
        return {
            "kind": self.kind, "eligible": self.eligible, "reasons": list(self.reasons),
            "notes": list(self.notes), "assetKey": self.asset_key,
            "expectedOwnerRef": self.expected_owner_ref,
            "expectedOwnershipVersion": self.expected_ownership_version,
            "expectedGeneration": self.expected_generation, "targetOwnerRef": self.target_owner_ref,
            "preservedPolicy": None if policy is None else {
                "ownerRef": policy.owner_ref, "quotaLimitBytes": policy.quota_limit_bytes,
                "quotaUsedBytes": policy.quota_used_bytes, "sourceIpLimit": policy.source_ip_limit,
                "blocked": policy.blocked,
            },
            "steps": list(self.steps), "executionEnabled": self.execution_enabled,
        }


def preview_handoff(snapshot: InventorySnapshot, request: HandoffRequest, now: datetime) -> Preview:
    """Validate a disabled local reservation; never provision its node owner."""
    _time(now, "now")
    reasons: list[str] = []
    notes = ["PREVIEW_ONLY", "REVALIDATE_UNDER_ASSET_LOCK_BEFORE_EACH_STEP",
             "NO_ADMIN_PRIVATE_KEY_DELIVERY", "NO_SECOND_ACTIVE_RESIDENTIAL_OWNER"]
    if snapshot.mirror_present is False:
        notes.append("MIRROR_MISSING_IS_NOT_REVOCATION_EVIDENCE")
    if not all(_reference(value) for value in (
        request.transfer_id, snapshot.asset_key, snapshot.node_id, snapshot.policy.owner_ref,
        request.asset_key, request.expected_owner_ref, request.target.owner_ref,
        request.target.resource_id, request.target.subscription_id, request.target.local_identity_ref,
    )):
        reasons.append("IDENTITY_REQUIRED")
    if snapshot.asset_key != request.asset_key:
        reasons.append("ASSET_MISMATCH")
    if snapshot.owner_kind != "ADMIN_INVENTORY":
        reasons.append("OWNER_KIND_MISMATCH")
    if snapshot.policy.owner_ref != request.expected_owner_ref:
        reasons.append("OWNER_MISMATCH")
    if request.target.owner_ref == snapshot.policy.owner_ref:
        reasons.append("TARGET_MUST_HAVE_SEPARATE_LOCAL_IDENTITY")
    if (not _positive(snapshot.ownership_version) or not _positive(request.expected_ownership_version)
            or snapshot.ownership_version != request.expected_ownership_version
            or not _positive(snapshot.generation) or not _positive(request.expected_generation)
            or snapshot.generation != request.expected_generation):
        reasons.append("STALE_OWNERSHIP_VERSION")
    if (not _DIGEST.fullmatch(snapshot.policy.residential_identity_sha256 or "")
            or snapshot.policy.residential_identity_sha256 != request.expected_residential_identity_sha256):
        reasons.append("FULL_RESIDENTIAL_IDENTITY_MISMATCH")
    if (snapshot.source_kind not in _SOURCE_KINDS or snapshot.source_verified is not True
            or not _reference(snapshot.source_evidence_ref)):
        reasons.append("SOURCE_UNVERIFIED_PRESERVE_CURRENT")
    if snapshot.source_expires_at is None:
        reasons.append("SOURCE_EXPIRY_UNKNOWN")
    elif _time(snapshot.source_expires_at, "source_expires_at") <= now:
        reasons.append("SOURCE_EXPIRED")
    if snapshot.node_owner_present is not True or snapshot.exact_binding_verified is not True:
        reasons.append("EXACT_OLD_BINDING_REQUIRED")
    if snapshot.other_authorized_bindings != 0 or not _nonnegative(snapshot.other_authorized_bindings):
        reasons.append("SHARED_OR_UNKNOWN_OLD_OWNER")
    if snapshot.business_refunded is not False or snapshot.business_paused is not False:
        reasons.append("BUSINESS_RESTRICTION_OR_UNKNOWN")
    if snapshot.transfer_in_progress is not False:
        reasons.append("TRANSFER_ALREADY_ACTIVE_OR_UNKNOWN")
    policy = snapshot.policy
    if (not _nonnegative(policy.quota_limit_bytes) or not _nonnegative(policy.quota_used_bytes)
            or not _nonnegative(policy.source_ip_limit) or not isinstance(policy.blocked, bool)):
        reasons.append("OLD_POLICY_UNKNOWN")
    elif policy.blocked or (policy.quota_limit_bytes > 0 and policy.quota_used_bytes >= policy.quota_limit_bytes):
        reasons.append("OLD_POLICY_BLOCKED")
    target = request.target
    if target.enabled is not False or target.node_owner_present is not False:
        reasons.append("TARGET_MUST_BE_LOCAL_DISABLED_RESERVATION")
    if target.grant_verified is not True or not _reference(target.grant_evidence_ref):
        reasons.append("REAL_CUSTOMER_GRANT_REQUIRED")
    if target.grant_expires_at is None:
        reasons.append("CUSTOMER_EXPIRY_UNKNOWN")
    elif _time(target.grant_expires_at, "grant_expires_at") <= now:
        reasons.append("CUSTOMER_GRANT_EXPIRED")
    elif snapshot.source_expires_at is not None and target.grant_expires_at > snapshot.source_expires_at:
        reasons.append("CUSTOMER_GRANT_EXCEEDS_SOURCE")
    if target.business_refunded is not False or target.business_paused is not False:
        reasons.append("CUSTOMER_BUSINESS_RESTRICTION_OR_UNKNOWN")
    steps = () if reasons else (
        "LOCK_ASSET_AND_REVALIDATE_SOURCE_OWNER_VERSION_GRANT",
        "PERSIST_HANDOFF_AND_KEEP_CUSTOMER_RESERVATION_DISABLED",
        "TRANSFER_EXACT_OLD_BINDING_WITH_FULL_IDENTITY_GUARD",
        "READBACK_OLD_BINDING_RELEASED_BEFORE_TARGET_ENABLE",
        "ENABLE_TARGET_WITH_NEW_CUSTOMER_IDENTITY_AND_VERIFY",
        "CAS_COMMIT_CUSTOMER_OWNERSHIP_AND_DELIVERY",
    )
    return Preview("INVENTORY_HANDOFF", not reasons, tuple(reasons), tuple(notes), snapshot.asset_key,
                   snapshot.policy.owner_ref, snapshot.ownership_version, snapshot.generation,
                   target.owner_ref, snapshot.policy, steps)


@dataclass(frozen=True)
class WireguardOnlyCandidate:
    asset_key: str
    is_new_inventory: bool | None
    source_verified: bool | None
    source_evidence_ref: str | None
    residential_identity_sha256: str
    business_plan_ref: str | None
    business_explicit_unlimited: bool | None
    quota_limit_bytes: int | None
    source_ip_limit: int | None
    business_refunded: bool | None
    business_paused: bool | None
    expires_at: datetime | None
    existing_owner_policy: OwnerPolicy | None = None


def preview_wireguard_only(candidate: WireguardOnlyCandidate, now: datetime) -> Preview:
    """First version supports explicitly unlimited, unrestricted NEW inventory.

    A reused owner keeps its real policy unchanged; it is never converted to an
    unlimited owner to pass these checks. Ordinary protocol continuity is a
    separate release criterion, and there is no call to createUser or HUP here.
    """
    _time(now, "now")
    reasons: list[str] = []
    if not _reference(candidate.asset_key) or not _DIGEST.fullmatch(candidate.residential_identity_sha256 or ""):
        reasons.append("FULL_RESIDENTIAL_IDENTITY_REQUIRED")
    if candidate.is_new_inventory is not True:
        reasons.append("NEW_INVENTORY_ONLY")
    if candidate.source_verified is not True or not _reference(candidate.source_evidence_ref):
        reasons.append("SOURCE_UNVERIFIED_PRESERVE_CURRENT")
    if (candidate.business_explicit_unlimited is not True or not _reference(candidate.business_plan_ref)
            or not _nonnegative(candidate.quota_limit_bytes) or candidate.quota_limit_bytes != 0
            or not _nonnegative(candidate.source_ip_limit) or candidate.source_ip_limit != 0):
        reasons.append("EXPLICIT_UNLIMITED_WITHOUT_SOURCE_IP_LIMIT_REQUIRED")
    if candidate.business_refunded is not False or candidate.business_paused is not False:
        reasons.append("BUSINESS_RESTRICTION_OR_UNKNOWN")
    if candidate.expires_at is None:
        reasons.append("EXPIRY_UNKNOWN")
    elif _time(candidate.expires_at, "expires_at") <= now:
        reasons.append("EXPIRED")
    policy = candidate.existing_owner_policy
    if policy is not None:
        if (not _reference(policy.owner_ref)
                or policy.residential_identity_sha256 != candidate.residential_identity_sha256):
            reasons.append("EXISTING_OWNER_IDENTITY_MISMATCH")
        if (not _nonnegative(policy.quota_limit_bytes) or policy.quota_limit_bytes != 0
                or not _nonnegative(policy.source_ip_limit) or policy.source_ip_limit != 0
                or not _nonnegative(policy.quota_used_bytes) or policy.blocked is not False):
            reasons.append("PRESERVE_EXISTING_POLICY_UNSUPPORTED_FOR_WG_ONLY")
    steps = () if reasons else (
        "LOCK_ASSET_AND_REVALIDATE_SOURCE_BUSINESS_VERSION",
        "RESERVE_WG_ONLY_OWNER_OR_REUSE_EXACT_OWNER_WITH_UNCHANGED_POLICY",
        "APPLY_VERSIONED_WG_ONLY_RUNTIME_WITHOUT_ORDINARY_PROTOCOL_CREATE_USER",
        "READBACK_OWNER_PEER_ROUTE_AND_VERIFY_CONTINUITY_BEFORE_DELIVERY",
    )
    return Preview("NEW_INVENTORY_WG_ONLY", not reasons, tuple(reasons),
                   ("PREVIEW_ONLY", "PRESERVE_QUOTA_USED_LIMIT_AND_BLOCKED",
                    "ORDINARY_PROTOCOL_CONTINUITY_REQUIRES_SEPARATE_ACCEPTANCE"),
                   candidate.asset_key, None if policy is None else policy.owner_ref,
                   None, None, None, policy, steps)
