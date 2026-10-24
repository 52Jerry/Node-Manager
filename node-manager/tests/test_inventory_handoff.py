"""Pure preview boundaries: no owner creation, quota changes or fake purchases."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inventory_handoff import (
    CustomerReservation, HandoffRequest, InventorySnapshot, OwnerPolicy,
    WireguardOnlyCandidate, preview_handoff, preview_wireguard_only,
)


class InventoryPreviewTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 22, 8, tzinfo=timezone.utc)
        self.expiry = self.now + timedelta(days=30)
        self.policy = OwnerPolicy("admin:inventory:7", "a" * 64, 1024, 512, 2, False)
        self.inventory = InventorySnapshot(
            asset_key="EXTERNAL:3:9007199254740993", node_id="node:3",
            ownership_version=17, generation=4, owner_kind="ADMIN_INVENTORY", policy=self.policy,
            source_kind="UPSTREAM_CONFIRMED", source_evidence_ref="sync-run:41:instance:9",
            source_verified=True, source_expires_at=self.expiry, node_owner_present=True,
            exact_binding_verified=True, other_authorized_bindings=0,
            business_refunded=False, business_paused=False, transfer_in_progress=False,
            mirror_present=True,
        )
        self.target = CustomerReservation(
            owner_ref="customer:81", resource_id="resource:91", subscription_id="subscription:82",
            local_identity_ref="reserved-disabled:83", grant_evidence_ref="real-paid-grant:84",
            grant_verified=True, grant_expires_at=self.expiry - timedelta(days=1),
            enabled=False, node_owner_present=False, business_refunded=False, business_paused=False,
        )
        self.request = HandoffRequest("transfer:1", self.inventory.asset_key, self.policy.owner_ref,
                                      17, 4, self.policy.residential_identity_sha256, self.target)
        self.wg = WireguardOnlyCandidate(
            asset_key=self.inventory.asset_key, is_new_inventory=True, source_verified=True,
            source_evidence_ref="new-purchase-evidence:41", residential_identity_sha256="a" * 64,
            business_plan_ref="explicit-unlimited-plan:1", business_explicit_unlimited=True,
            quota_limit_bytes=0, source_ip_limit=0, business_refunded=False, business_paused=False,
            expires_at=self.expiry,
        )

    def preview(self, snapshot=None, request=None):
        return preview_handoff(snapshot or self.inventory, request or self.request, self.now)

    def test_handoff_only_prepares_disabled_local_identity_and_preserves_existing_policy(self):
        before = (self.inventory, self.request)
        result = self.preview()
        self.assertTrue(result.eligible, result.reasons)
        self.assertFalse(result.execution_enabled)
        self.assertEqual(before, (self.inventory, self.request))
        self.assertEqual(self.policy, result.preserved_policy)
        self.assertIn("READBACK_OLD_BINDING_RELEASED_BEFORE_TARGET_ENABLE", result.steps)
        self.assertNotIn("CREATE_SECOND_OWNER", result.steps)
        self.assertNotIn("uuid", json.dumps(result.as_dict()).lower())

    def test_target_already_created_on_node_or_enabled_is_rejected(self):
        for target in (replace(self.target, enabled=True), replace(self.target, node_owner_present=True),
                       replace(self.target, enabled=None)):
            result = self.preview(request=replace(self.request, target=target))
            self.assertFalse(result.eligible)
            self.assertIn("TARGET_MUST_BE_LOCAL_DISABLED_RESERVATION", result.reasons)

    def test_real_grant_required_and_refund_pause_expiry_still_block(self):
        for target in (replace(self.target, grant_verified=False),
                       replace(self.target, grant_evidence_ref=None),
                       replace(self.target, business_refunded=True),
                       replace(self.target, business_paused=True),
                       replace(self.target, grant_expires_at=self.now),
                       replace(self.target, grant_expires_at=self.expiry + timedelta(days=1))):
            result = self.preview(request=replace(self.request, target=target))
            self.assertFalse(result.eligible, target)
            self.assertEqual((), result.steps)

    def test_stale_version_old_owner_or_ip_only_identity_cannot_transfer(self):
        for request in (replace(self.request, expected_ownership_version=16),
                        replace(self.request, expected_generation=3),
                        replace(self.request, expected_owner_ref="admin:other"),
                        replace(self.request, expected_residential_identity_sha256="198.65.60.27"),
                        replace(self.request, asset_key="EXTERNAL:4:9007199254740993")):
            self.assertFalse(self.preview(request=request).eligible)

    def test_shared_or_unknown_owner_is_never_detached(self):
        for bindings in (1, 7, None, False):
            result = self.preview(snapshot=replace(self.inventory, other_authorized_bindings=bindings))
            self.assertFalse(result.eligible)
            self.assertIn("SHARED_OR_UNKNOWN_OLD_OWNER", result.reasons)

    def test_valid_manual_asset_missing_mirror_remains_eligible_without_revoke(self):
        snapshot = replace(self.inventory, source_kind="ADMIN_AUDIT_CONFIRMED",
                           source_evidence_ref="original-create-audit:9", mirror_present=False)
        result = self.preview(snapshot=snapshot)
        self.assertTrue(result.eligible)
        self.assertIn("MIRROR_MISSING_IS_NOT_REVOCATION_EVIDENCE", result.notes)
        self.assertEqual(self.policy, result.preserved_policy)

    def test_admin_created_fallback_or_ip_inferred_metadata_is_not_source_proof(self):
        for source in ("ADMIN_CREATED", "IP_METADATA_INFERRED", "UNKNOWN"):
            result = self.preview(snapshot=replace(self.inventory, source_kind=source))
            self.assertFalse(result.eligible)
            self.assertIn("SOURCE_UNVERIFIED_PRESERVE_CURRENT", result.reasons)

    def test_quota_or_blocked_is_preserved_and_cannot_be_cleared_by_retry(self):
        for policy in (replace(self.policy, blocked=True),
                       replace(self.policy, quota_used_bytes=1024),
                       replace(self.policy, quota_limit_bytes=None)):
            snapshot = replace(self.inventory, policy=policy)
            for _ in range(2):
                result = self.preview(snapshot=snapshot)
                self.assertFalse(result.eligible)
                self.assertEqual(policy, result.preserved_policy)

    def test_naive_dates_are_rejected_without_timezone_reinterpretation(self):
        with self.assertRaises(ValueError):
            preview_handoff(self.inventory, self.request, self.now.replace(tzinfo=None))
        with self.assertRaises(ValueError):
            self.preview(snapshot=replace(self.inventory, source_expires_at=self.expiry.replace(tzinfo=None)))

    def test_wg_only_supports_explicit_unlimited_new_inventory_as_preview(self):
        result = preview_wireguard_only(self.wg, self.now)
        self.assertTrue(result.eligible)
        self.assertFalse(result.execution_enabled)
        self.assertIn("ORDINARY_PROTOCOL_CONTINUITY_REQUIRES_SEPARATE_ACCEPTANCE", result.notes)
        self.assertIn("APPLY_VERSIONED_WG_ONLY_RUNTIME_WITHOUT_ORDINARY_PROTOCOL_CREATE_USER", result.steps)

    def test_wg_only_rejects_existing_stock_limits_and_unknown_business_semantics(self):
        for candidate in (replace(self.wg, is_new_inventory=False),
                          replace(self.wg, quota_limit_bytes=1024),
                          replace(self.wg, source_ip_limit=1),
                          replace(self.wg, business_explicit_unlimited=None),
                          replace(self.wg, business_plan_ref=None),
                          replace(self.wg, business_paused=True),
                          replace(self.wg, source_verified=None),
                          replace(self.wg, expires_at=self.now)):
            result = preview_wireguard_only(candidate, self.now)
            self.assertFalse(result.eligible, candidate)
            self.assertEqual((), result.steps)

    def test_wg_reused_owner_policy_is_retained_and_limits_or_blocks_are_never_reset(self):
        for policy in (self.policy, replace(self.policy, blocked=True),
                       replace(self.policy, quota_limit_bytes=0, source_ip_limit=0, blocked=True)):
            result = preview_wireguard_only(replace(self.wg, existing_owner_policy=policy), self.now)
            self.assertFalse(result.eligible)
            self.assertEqual(policy, result.preserved_policy)
        unlimited = replace(self.policy, quota_limit_bytes=0, source_ip_limit=0, quota_used_bytes=9000)
        result = preview_wireguard_only(replace(self.wg, existing_owner_policy=unlimited), self.now)
        self.assertTrue(result.eligible)
        self.assertEqual(9000, result.preserved_policy.quota_used_bytes)
        self.assertFalse(result.preserved_policy.blocked)

    def test_wg_only_cannot_reuse_owner_with_different_full_residential_identity(self):
        policy = replace(self.policy, quota_limit_bytes=0, source_ip_limit=0,
                         residential_identity_sha256="b" * 64)
        result = preview_wireguard_only(replace(self.wg, existing_owner_policy=policy), self.now)
        self.assertFalse(result.eligible)
        self.assertIn("EXISTING_OWNER_IDENTITY_MISMATCH", result.reasons)


if __name__ == "__main__":
    unittest.main()
