"""Read-only replication approval contract. No import of the legacy apply path."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import re
import uuid
from dataclasses import asdict, dataclass


SCHEMA = "niusu.replication-preview.v1"
PERMISSION_READ = "singbox.replication.preview.restricted"
PERMISSION_APPROVE = "singbox.replication.approve"
PERMISSION_RESTORE = "singbox.replication.restore.approve"
ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class SafetyError(ValueError):
    """Only fixed codes, never input values or credentials, belong in errors."""


@dataclass(frozen=True)
class SafetyPolicy:
    max_users: int = 10000
    max_bytes: int = 16 * 1024 * 1024
    max_remove_count: int = 10
    max_remove_ratio: float = 0.01
    allow_deletes: bool = False
    ttl_seconds: int = 300

    def __post_init__(self):
        if (type(self.max_users) is not int or not 1 <= self.max_users <= 10000
                or type(self.max_bytes) is not int or not 1 <= self.max_bytes <= 16 * 1024 * 1024
                or type(self.max_remove_count) is not int or self.max_remove_count < 0
                or type(self.allow_deletes) is not bool
                or type(self.max_remove_ratio) not in (int, float)
                or not math.isfinite(self.max_remove_ratio) or not 0 <= self.max_remove_ratio <= 1
                or type(self.ttl_seconds) is not int or not 1 <= self.ttl_seconds <= 900):
            raise SafetyError("INVALID_POLICY")


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise SafetyError("UNSERIALIZABLE_INPUT") from None


def instant(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


class ReplicationSafety:
    """A caller supplies locked immutable reads and server-owned evidence/policy.

    HMAC seals are integrity proofs, not permission grants. Revalidation must run
    inside the same transaction/lock as a future independently verified adapter.
    """

    def __init__(self, secret: bytes, policy: SafetyPolicy | None = None):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise SafetyError("INVALID_APPROVAL_KEY")
        self._secret = secret
        self.policy = policy or SafetyPolicy()

    def _seal(self, value):
        return hmac.new(self._secret, canonical(value), hashlib.sha256).hexdigest()

    def _ref(self, user_id):
        return self._seal({"userId": user_id})[:24]

    def _state_digest(self, snapshot):
        state = copy.deepcopy(snapshot)
        if isinstance(state.get("capture"), dict):
            state["capture"].pop("capturedAt", None)
        return self._seal(state)

    @staticmethod
    def _permit(permissions, permission):
        if permission not in permissions:
            raise SafetyError("FORBIDDEN")

    def _snapshot(self, snapshot):
        if not isinstance(snapshot, dict) or type(snapshot.get("version")) is not int or snapshot["version"] not in (1, 2):
            raise SafetyError("UNSUPPORTED_SCHEMA")
        for name in ("users", "retired"):
            values = snapshot.get(name, [] if name == "retired" else None)
            if not isinstance(values, list):
                raise SafetyError("INVALID_USER_SET")
            if len(values) > self.policy.max_users:
                raise SafetyError("INPUT_TOO_LARGE")
        if len(snapshot["users"]) + len(snapshot.get("retired", [])) > self.policy.max_users:
            raise SafetyError("INPUT_TOO_LARGE")
        if len(canonical(snapshot)) > self.policy.max_bytes:
            raise SafetyError("INPUT_TOO_LARGE")
        index = {}
        for user in [*snapshot["users"], *snapshot.get("retired", [])]:
            if not isinstance(user, dict) or not isinstance(user.get("userId"), str) or not ID.fullmatch(user["userId"]):
                raise SafetyError("INVALID_USER_ID")
            if user["userId"] in index:
                raise SafetyError("DUPLICATE_USER_ID")
            index[user["userId"]] = user
        return index

    def preview(self, source, target, evidence, *, group_key, target_id, mode,
                permissions=frozenset(), now=None):
        self._permit(permissions, PERMISSION_READ)
        if (mode not in ("renewal-sync", "isolated-restore")
                or not isinstance(group_key, str) or not ID.fullmatch(group_key)
                or not isinstance(target_id, str) or not ID.fullmatch(target_id)):
            raise SafetyError("INVALID_SCOPE")
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise SafetyError("INVALID_TIME")
        src, dst = self._snapshot(source), self._snapshot(target)
        if not isinstance(evidence, dict) or len(evidence) > self.policy.max_users:
            raise SafetyError("INVALID_EVIDENCE")
        if len(canonical(evidence)) > self.policy.max_bytes:
            raise SafetyError("INPUT_TOO_LARGE")
        desired = {u["userId"]: copy.deepcopy(u) for u in source["users"]}
        rows, blockers, reviews = [], set(), []
        counts = dict(added=0, updated=0, unchanged=0, removed=0, excluded=0, expired=0,
                      missingAuth=0, missingUpstream=0, unsupported=0, unknownOwner=0)

        def reason(row, code, confidence="unknown", origin="unverified"):
            row["reasons"].append({"code": code, "confidence": confidence, "source": origin})

        for user_id in sorted(set(src) | set(dst)):
            user = src.get(user_id)
            proof = evidence.get(user_id, {})
            if not isinstance(proof, dict):
                raise SafetyError("INVALID_EVIDENCE")
            row = {"userRef": self._ref(user_id), "action": "retain", "reasons": []}
            origin = proof.get("origin", "unknown")
            row["origin"] = origin if origin in ("website-order", "admin-batch") else "unknown"
            state = proof.get("status", "unknown")
            removal_proven = state in ("revoked", "refunded") and bool(proof.get("statusEvidenceRevision"))
            expiry_kind = proof.get("expiryKind", "unknown")
            expiry = instant(proof.get("expiresAt"))
            if user is not None:
                if row["origin"] == "website-order" and any(proof.get(key) is False
                        for key in ("profilePresent", "subscriptionPresent", "resourcePresent")):
                    blockers.add("MISSING_BUSINESS_RECORD")
                    reason(row, "MISSING_BUSINESS_RECORD", "reported", "website")
                if state in ("revoked", "refunded") and not removal_proven:
                    blockers.add("UNPROVEN_STATUS")
                    reason(row, "UNPROVEN_STATUS", "reported", "business-status")
                if removal_proven:
                    if user_id in desired:
                        counts["excluded"] += 1
                    desired.pop(user_id, None)
                    reason(row, "EXPLICIT_REVOKED", "verified", "business-status")
                elif user_id not in desired:
                    blockers.add("UNPROVEN_RETIREMENT")
                    reason(row, "UNPROVEN_RETIREMENT")
                elif state == "disabled":
                    blockers.add("DISABLED_REVIEW")
                    reason(row, "DISABLED_REVIEW", "reported", "business-status")
                if expiry_kind in ("order", "upstream") and expiry and proof.get("expiryEvidenceRevision"):
                    reason(row, "ORDER_EXPIRY" if expiry_kind == "order" else "UPSTREAM_EXPIRY",
                           "verified", expiry_kind)
                    if expiry <= now:
                        counts["expired"] += 1
                        blockers.add("CONFIRMED_EXPIRY_REVIEW")
                        reason(row, "CONFIRMED_EXPIRY_REVIEW", "verified", expiry_kind)
                    if instant(user.get("expiresAt")) != expiry:
                        blockers.add("EXPIRY_CONFLICT")
                        reason(row, "EXPIRY_CONFLICT", "reported", "registry-vs-business")
                else:
                    code = "INFERRED_EXPIRY" if expiry_kind == "inferred" else "REGISTERED_EXPIRY" if instant(user.get("expiresAt")) else "UNKNOWN_EXPIRY"
                    reason(row, code, "inferred" if code == "INFERRED_EXPIRY" else "unknown", "registry")
                    reviews.append({"userRef": row["userRef"], "code": code})
                if row["origin"] == "unknown":
                    counts["unknownOwner"] += 1
                    reason(row, "UNKNOWN_OWNER")
                    reviews.append({"userRef": row["userRef"], "code": "UNKNOWN_OWNER"})
                if user_id in desired:
                    auth = user.get("auth")
                    protocols = [a.get("protocol") for a in auth if isinstance(a, dict)] if isinstance(auth, list) else []
                    invalid_auth = (not protocols or len(protocols) != len(auth)
                                    or any(not isinstance(protocol, str) for protocol in protocols)
                                    or len(protocols) != len(set(protocols))
                                    or any(not isinstance(a.get("credential"), str) or not a["credential"].strip() for a in auth))
                    if invalid_auth:
                        counts["missingAuth"] += 1
                        blockers.add("MISSING_AUTH")
                        reason(row, "MISSING_AUTH")
                    if not invalid_auth:
                        for entry in auth:
                            if entry.get("protocol") in ("vless", "vmess"):
                                try:
                                    uuid.UUID(entry["credential"])
                                except (ValueError, AttributeError):
                                    blockers.add("INVALID_AUTH")
                                    reason(row, "INVALID_AUTH")
                            if entry.get("protocol") == "socks" and (not isinstance(entry.get("username"), str)
                                    or not entry["username"].strip()
                                    or entry["username"].startswith("node-manager:")):
                                blockers.add("INVALID_AUTH")
                                reason(row, "INVALID_AUTH")
                    if (any(not isinstance(protocol, str) or protocol not in {"vless", "vmess", "socks", "trojan"}
                            for protocol in protocols) or user.get("serializationIssues")):
                        counts["unsupported"] += 1
                        blockers.add("UNSUPPORTED_CONFIG")
                        reason(row, "UNSUPPORTED_CONFIG")
                    proxy = user.get("proxy")
                    if ((proxy is not None and (not isinstance(proxy, dict) or not proxy.get("server")
                            or type(proxy.get("port")) is not int or not 1 <= proxy["port"] <= 65535
                            or not proxy.get("username") or not proxy.get("password")))
                            or (proxy is None and proof.get("directConfirmed") is not True)):
                        counts["missingUpstream"] += 1
                        blockers.add("MISSING_UPSTREAM")
                        reason(row, "MISSING_UPSTREAM")
                    if instant(user.get("createdAt")) is None:
                        blockers.add("UNKNOWN_CREATED_AT")
                        reason(row, "UNKNOWN_CREATED_AT")
                    if any(type(user.get(key, 0)) is not int or user.get(key, 0) < 0
                           for key in ("upload", "download")):
                        blockers.add("INVALID_TRAFFIC_COUNTER")
                        reason(row, "INVALID_TRAFFIC_COUNTER")
                    if any(user.get(key) is not None and (type(user[key]) is not int or user[key] <= 0)
                           for key in ("trafficLimitBytes", "maxSourceIps", "maxConnections")):
                        blockers.add("INVALID_LIMIT")
                        reason(row, "INVALID_LIMIT")
            if user_id in desired:
                if user_id not in dst:
                    row["action"] = "add"
                    counts["added"] += 1
                elif canonical(desired[user_id]) != canonical(dst[user_id]):
                    row["action"] = "update"
                    counts["updated"] += 1
                    if dst[user_id].get("auth") != user.get("auth"):
                        blockers.add("AUTH_CHANGE")
                        reason(row, "AUTH_CHANGE")
                    if dst[user_id].get("proxy") != user.get("proxy"):
                        blockers.add("UPSTREAM_CHANGE_REVIEW")
                        reason(row, "UPSTREAM_CHANGE_REVIEW", "reported", "routing")
                    if any(type(user.get(key, 0)) is int and type(dst[user_id].get(key, 0)) is int
                           and user.get(key, 0) < dst[user_id].get(key, 0) for key in ("upload", "download")):
                        blockers.add("TRAFFIC_REGRESSION_REVIEW")
                        reason(row, "TRAFFIC_REGRESSION_REVIEW", "reported", "traffic-store")
                else:
                    counts["unchanged"] += 1
            elif user_id in dst:
                if removal_proven:
                    row["action"] = "remove"
                    counts["removed"] += 1
                else:
                    row["action"] = "preserve-target"
                    blockers.add("TARGET_ONLY_REVIEW")
                    reason(row, "TARGET_ONLY_REVIEW")
            elif removal_proven:
                row["action"] = "exclude-source"
            else:
                row["action"] = "retirement-review"
            rows.append(row)
        if source.get("errors") or target.get("errors"):
            blockers.add("INCOMPLETE_CAPTURE")
        if source.get("aliases") or target.get("aliases"):
            blockers.add("ALIAS_MIGRATION_REVIEW")
        if counts["removed"] or counts["excluded"]:
            if not self.policy.allow_deletes:
                blockers.add("DELETION_DISABLED")
            if (max(counts["removed"], counts["excluded"]) > self.policy.max_remove_count
                    or counts["removed"] / max(len(dst), 1) > self.policy.max_remove_ratio
                    or counts["excluded"] / max(len(source["users"]), 1) > self.policy.max_remove_ratio):
                blockers.add("REMOVAL_THRESHOLD")
        if mode == "isolated-restore" and (counts["removed"] or counts["excluded"]):
            blockers.add("RESTORE_CANNOT_DELETE")
        if source.get("sharedConfig") != target.get("sharedConfig") and dst:
            blockers.add("SHARED_CONFIG_CHANGE")
        if mode == "isolated-restore" and not source.get("sharedConfig"):
            blockers.add("MISSING_SHARED_CONFIG")
        if source.get("sharedConfig") is not None:
            from ha_template import validate_template
            from singbox import manager
            try:
                validate_template(source["sharedConfig"])
                if any(entry.get("protocol") not in source["sharedConfig"]
                       for user in desired.values() for entry in user.get("auth", [])
                       if isinstance(entry, dict) and isinstance(entry.get("protocol"), str)):
                    blockers.add("MISSING_PROTOCOL_TEMPLATE")
                for options in source["sharedConfig"].values():
                    tls = options.get("tls", {})
                    if "reality" in tls and not tls["reality"].get("private_key"):
                        blockers.add("MISSING_REALITY_KEY")
            except (manager.SingboxConfigError, TypeError, AttributeError):
                blockers.add("INVALID_SHARED_CONFIG")
        if source.get("generation") is not None and target.get("generation") is not None:
            if type(source["generation"]) is not int or type(target["generation"]) is not int:
                blockers.add("INVALID_GENERATION")
            elif source["generation"] < target["generation"]:
                blockers.add("STALE_GENERATION")
        expires = now + timedelta(seconds=self.policy.ttl_seconds)
        body = {"schema": SCHEMA, "groupKey": group_key, "targetId": target_id, "mode": mode,
                "createdAt": now.isoformat(), "validUntil": expires.isoformat(),
                "sourceDigest": self._state_digest(source), "targetDigest": self._state_digest(target),
                "evidenceDigest": self._seal(evidence), "policyDigest": self._seal(asdict(self.policy)),
                "counts": counts, "details": rows, "blockers": sorted(blockers),
                "requiredReviews": sorted(reviews, key=lambda r: (r["userRef"], r["code"])),
                "desiredCount": len(desired), "executable": not blockers and not reviews,
                "readOnly": True}
        return {**body, "previewDigest": self._seal(body)}

    def approve(self, preview, *, actor_id, audit_id, permissions=frozenset(),
                reviewed=(), now=None):
        permission = PERMISSION_RESTORE if preview.get("mode") == "isolated-restore" else PERMISSION_APPROVE
        self._permit(permissions, permission)
        self._verify_preview(preview, now)
        if preview["blockers"]:
            raise SafetyError("PREVIEW_BLOCKED")
        expected = {(r["userRef"], r["code"]) for r in preview["requiredReviews"]}
        if set(reviewed) != expected:
            raise SafetyError("REVIEW_REQUIRED")
        if not actor_id or not audit_id:
            raise SafetyError("AUDIT_REQUIRED")
        body = {"schema": SCHEMA, "previewDigest": preview["previewDigest"],
                "actorId": actor_id, "auditId": audit_id, "validUntil": preview["validUntil"],
                "reviews": [list(r) for r in sorted(expected)]}
        return {**body, "approvalSeal": self._seal(body)}

    def _verify_preview(self, preview, now=None):
        body = {key: value for key, value in preview.items() if key != "previewDigest"}
        if not hmac.compare_digest(str(preview.get("previewDigest", "")), self._seal(body)):
            raise SafetyError("PREVIEW_TAMPERED")
        current = now or datetime.now(timezone.utc)
        if instant(preview.get("validUntil")) is None or not instant(preview["createdAt"]) <= current < instant(preview["validUntil"]):
            raise SafetyError("PREVIEW_EXPIRED")

    def revalidate(self, preview, approval, source, target, evidence, *, permissions=frozenset(), now=None):
        self._permit(permissions, PERMISSION_RESTORE if preview.get("mode") == "isolated-restore" else PERMISSION_APPROVE)
        self._verify_preview(preview, now)
        body = {key: value for key, value in approval.items() if key != "approvalSeal"}
        if (not hmac.compare_digest(str(approval.get("approvalSeal", "")), self._seal(body))
                or approval.get("previewDigest") != preview["previewDigest"]):
            raise SafetyError("APPROVAL_INVALID")
        fresh = self.preview(source, target, evidence, group_key=preview["groupKey"],
                             target_id=preview["targetId"], mode=preview["mode"],
                             permissions={PERMISSION_READ}, now=now)
        for field in ("sourceDigest", "targetDigest", "evidenceDigest", "policyDigest", "counts",
                      "details", "blockers", "requiredReviews", "desiredCount"):
            if fresh[field] != preview[field]:
                raise SafetyError("PREVIEW_STALE")
        if fresh["blockers"]:
            raise SafetyError("PREVIEW_BLOCKED")
        return {"validated": True, "previewDigest": preview["previewDigest"],
                "auditId": approval["auditId"], "readOnly": True,
                "requiresAtomicAdapter": True}
