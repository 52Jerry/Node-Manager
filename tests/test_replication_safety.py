import copy
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import test_next_stage as fixture
from test_next_stage import manager, traffic
from ha_template import export_template
from replication_safety import (ReplicationSafety, SafetyPolicy, SafetyError,
                                PERMISSION_READ, PERMISSION_APPROVE, PERMISSION_RESTORE)
from replication_reconciliation import capture_local


NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
READ = {PERMISSION_READ}
APPROVE = {PERMISSION_APPROVE}
RESTORE = {PERMISSION_RESTORE}


def user(user_id="batch-1", expiry="2026-11-04T12:00:00Z"):
    return {"userId": user_id, "createdAt": "2026-09-04T12:00:00Z", "expiresAt": expiry,
            "auth": [{"protocol": "vless", "credential": "11111111-1111-4111-8111-111111111111"}],
            "proxy": {"server": "203.0.113.10", "port": 1080,
                      "username": "fake-upstream", "password": "fake-password"},
            "upload": 10, "download": 20}


def snapshot(*users, version=1):
    return {"version": version, "users": list(users)}


def proof(expiry="2026-11-04T12:00:00Z", origin="website-order"):
    return {"origin": origin, "status": "active", "expiryKind": "order",
            "expiresAt": expiry, "expiryEvidenceRevision": "fixture-order-r1"}


class SafetyTest(unittest.TestCase):
    def setUp(self):
        self.safety = ReplicationSafety(b"fake-approval-secret-not-production" * 2)

    def preview(self, source, target=None, evidence=None, **kwargs):
        return self.safety.preview(source, target or snapshot(), evidence or {},
                                   group_key="fixture-group", target_id="fixture-target",
                                   mode=kwargs.pop("mode", "renewal-sync"), permissions=READ, now=NOW, **kwargs)

    def approval(self, preview, permissions=APPROVE):
        reviewed = [(r["userRef"], r["code"]) for r in preview["requiredReviews"]]
        return self.safety.approve(preview, actor_id="fake-reviewer", audit_id="fake-audit-r1",
                                   permissions=permissions, reviewed=reviewed, now=NOW)

    def test_paid_user_preserved_and_secret_free_report(self):
        source = snapshot(user())
        p = self.preview(source, evidence={"batch-1": proof()})
        self.assertTrue(p["executable"])
        self.assertEqual(p["desiredCount"], 1)
        text = json.dumps(p)
        for secret in ("batch-1", "11111111-1111", "fake-upstream", "fake-password", "203.0.113.10"):
            self.assertNotIn(secret, text)
        self.assertEqual(p, self.preview(source, evidence={"batch-1": proof()}))

    def test_paused_cleanup_inferred_registered_unknown_dates_are_not_deleted(self):
        for kind, expiry, expected in (("inferred", "2025-01-01T00:00:00Z", "INFERRED_EXPIRY"),
                                       ("registered", "2025-01-01T00:00:00Z", "REGISTERED_EXPIRY"),
                                       ("unknown", None, "UNKNOWN_EXPIRY")):
            with self.subTest(kind=kind):
                source = snapshot(user(expiry=expiry), version=2)
                source["capture"] = {"expirationCleanupEnabled": False}
                p = self.preview(source, evidence={"batch-1": {"origin": "admin-batch", "expiryKind": kind}})
                self.assertEqual(p["desiredCount"], 1)
                self.assertEqual(p["counts"]["removed"], 0)
                self.assertFalse(p["executable"])
                self.assertIn(expected, [r["code"] for r in p["requiredReviews"]])
                with self.assertRaisesRegex(SafetyError, "REVIEW_REQUIRED"):
                    self.safety.approve(p, actor_id="a", audit_id="b", permissions=APPROVE, now=NOW)
                self.approval(p)

    def test_mixed_origin_and_confirmed_expiry_do_not_silently_filter(self):
        paid = user("paid")
        old = user("old", "2025-01-01T00:00:00Z")
        source = snapshot(paid, old)
        evidence = {"paid": proof(), "old": {"origin": "admin-batch", "expiryKind": "inferred"}}
        p = self.preview(source, evidence=evidence)
        self.assertEqual(p["desiredCount"], 2)
        self.assertEqual({r["origin"] for r in p["details"]}, {"website-order", "admin-batch"})
        evidence["old"] = proof(old["expiresAt"])
        p = self.preview(source, evidence=evidence)
        self.assertEqual(p["desiredCount"], 2)
        self.assertIn("CONFIRMED_EXPIRY_REVIEW", p["blockers"])
        with self.assertRaisesRegex(SafetyError, "PREVIEW_BLOCKED"):
            self.approval(p)

    def test_expiry_conflict_disabled_and_unproven_retired_block(self):
        source = snapshot(user())
        for evidence, code in (({"batch-1": proof("2026-12-01T00:00:00Z")}, "EXPIRY_CONFLICT"),
                                ({"batch-1": {**proof(), "status": "disabled"}}, "DISABLED_REVIEW")):
            self.assertIn(code, self.preview(source, evidence=evidence)["blockers"])
        source = snapshot()
        source["retired"] = [user()]
        self.assertIn("UNPROVEN_RETIREMENT", self.preview(source)["blockers"])

    def test_missing_business_records_and_unproven_revocation_are_not_approvable(self):
        for change, code in (({"profilePresent": False}, "MISSING_BUSINESS_RECORD"),
                             ({"subscriptionPresent": False}, "MISSING_BUSINESS_RECORD"),
                             ({"resourcePresent": False}, "MISSING_BUSINESS_RECORD"),
                             ({"status": "revoked"}, "UNPROVEN_STATUS")):
            p = self.preview(snapshot(user()), evidence={"batch-1": {**proof(), **change}})
            self.assertEqual(p["desiredCount"], 1)
            self.assertIn(code, p["blockers"])
            with self.assertRaisesRegex(SafetyError, "PREVIEW_BLOCKED"):
                self.approval(p)

    def test_explicit_revocation_default_deletion_threshold_and_restore_limits(self):
        source = snapshot(user())
        evidence = {"batch-1": {**proof(), "status": "revoked", "statusEvidenceRevision": "fake-status-r1"}}
        p = self.preview(source, target=source, evidence=evidence)
        self.assertEqual(p["counts"]["removed"], 1)
        self.assertIn("DELETION_DISABLED", p["blockers"])
        self.assertIn("REMOVAL_THRESHOLD", p["blockers"])
        self.safety = ReplicationSafety(b"a" * 32, SafetyPolicy(allow_deletes=True, max_remove_ratio=1))
        self.assertFalse(self.preview(source, target=source, evidence=evidence)["blockers"])
        restore = self.preview(source, target=source, evidence=evidence, mode="isolated-restore")
        self.assertIn("RESTORE_CANNOT_DELETE", restore["blockers"])
        self.assertIn("MISSING_SHARED_CONFIG", restore["blockers"])

    def test_target_only_unknown_ownership_is_not_removed(self):
        p = self.preview(snapshot(), target=snapshot(user()))
        self.assertEqual(p["counts"]["removed"], 0)
        self.assertEqual(p["details"][0]["action"], "preserve-target")
        self.assertIn("TARGET_ONLY_REVIEW", p["blockers"])

    def test_restore_cannot_exclude_source_user_absent_from_target(self):
        source = snapshot(user())
        source["sharedConfig"] = export_template(fixture.base_singbox_config())
        evidence = {"batch-1": {**proof(), "status": "revoked", "statusEvidenceRevision": "fixture-r1"}}
        p = self.preview(source, evidence=evidence, mode="isolated-restore")
        self.assertEqual(p["counts"]["removed"], 0)
        self.assertEqual(p["counts"]["excluded"], 1)
        self.assertEqual(p["details"][0]["action"], "exclude-source")
        self.assertIn("RESTORE_CANNOT_DELETE", p["blockers"])
        self.assertIn("DELETION_DISABLED", p["blockers"])

    def test_count_threshold_independent_of_ratio_and_auth_change(self):
        source = snapshot(*[user("u" + str(n)) for n in range(11)])
        evidence = {u["userId"]: {**proof(), "status": "revoked", "statusEvidenceRevision": "r1"}
                    for u in source["users"]}
        self.safety = ReplicationSafety(b"a" * 32, SafetyPolicy(allow_deletes=True, max_remove_ratio=1))
        p = self.preview(source, source, evidence)
        self.assertEqual(p["counts"]["removed"], 11)
        self.assertIn("REMOVAL_THRESHOLD", p["blockers"])
        target = snapshot(user())
        target["users"][0]["auth"][0]["credential"] = "22222222-2222-4222-8222-222222222222"
        self.assertIn("AUTH_CHANGE", self.preview(snapshot(user()), target, {"batch-1": proof()})["blockers"])

    def test_counter_regression_cannot_reset_usage(self):
        target = snapshot(user())
        target["users"][0]["download"] = 100
        p = self.preview(snapshot(user()), target, {"batch-1": proof()})
        self.assertIn("TRAFFIC_REGRESSION_REVIEW", p["blockers"])
        self.assertEqual(target["users"][0]["download"], 100)

    def test_upstream_credentials_cannot_be_replaced_with_normal_approval(self):
        target = snapshot(user())
        target["users"][0]["proxy"]["password"] = "different-fake-password"
        p = self.preview(snapshot(user()), target, {"batch-1": proof()})
        self.assertIn("UPSTREAM_CHANGE_REVIEW", p["blockers"])
        with self.assertRaisesRegex(SafetyError, "PREVIEW_BLOCKED"):
            self.approval(p)

    def test_malformed_auth_is_fixed_code_rejection_and_template_covers_protocols(self):
        for field, value in (("protocol", []), ("username", 123)):
            sample = user()
            if field == "username":
                sample["auth"][0]["protocol"] = "socks"
            sample["auth"][0][field] = value
            p = self.preview(snapshot(sample), evidence={"batch-1": proof()})
            self.assertTrue({"MISSING_AUTH", "INVALID_AUTH"} & set(p["blockers"]))
        source = snapshot(user())
        source["sharedConfig"] = {"socks": export_template(fixture.base_singbox_config())["socks"]}
        self.assertIn("MISSING_PROTOCOL_TEMPLATE", self.preview(source, mode="isolated-restore")["blockers"])

    def test_unknown_auth_proxy_and_configuration_abort_not_drop(self):
        for transform, expected in ((lambda u: u.update(auth=[]), "MISSING_AUTH"),
                                    (lambda u: u["auth"][0].update(credential=""), "MISSING_AUTH"),
                                    (lambda u: u["proxy"].pop("password"), "MISSING_UPSTREAM"),
                                    (lambda u: u.update(proxy=None), "MISSING_UPSTREAM"),
                                    (lambda u: u["auth"][0].update(protocol="hysteria2"), "UNSUPPORTED_CONFIG"),
                                    (lambda u: u.update(serializationIssues=["MULTI_PROXY"]), "UNSUPPORTED_CONFIG")):
            sample = user()
            transform(sample)
            p = self.preview(snapshot(sample), evidence={"batch-1": proof()})
            self.assertEqual(p["desiredCount"], 1)
            self.assertIn(expected, p["blockers"])

    def test_source_target_evidence_policy_and_preview_change_invalidates_approval(self):
        source, target, evidence = snapshot(user()), snapshot(), {"batch-1": proof()}
        p = self.preview(source, target, evidence)
        a = self.approval(p)
        for changed_source, changed_target, changed_evidence in (
                (snapshot(user("new")), target, evidence),
                (source, snapshot(user("other")), evidence),
                (source, target, {"batch-1": {**proof(), "expiryEvidenceRevision": "r2"}})):
            with self.assertRaisesRegex(SafetyError, "PREVIEW_STALE"):
                self.safety.revalidate(p, a, changed_source, changed_target, changed_evidence,
                                       permissions=APPROVE, now=NOW)
        other = ReplicationSafety(self.safety._secret, SafetyPolicy(max_remove_count=20))
        with self.assertRaisesRegex(SafetyError, "PREVIEW_STALE"):
            other.revalidate(p, a, source, target, evidence, permissions=APPROVE, now=NOW)
        changed = copy.deepcopy(p)
        changed["counts"]["removed"] = 99
        with self.assertRaisesRegex(SafetyError, "PREVIEW_TAMPERED"):
            self.approval(changed)

    def test_time_crossing_expiry_rechecks_business_decision(self):
        expiry = (NOW + timedelta(seconds=30)).isoformat()
        source, evidence = snapshot(user(expiry=expiry)), {"batch-1": proof(expiry)}
        p = self.preview(source, evidence=evidence)
        a = self.approval(p)
        with self.assertRaisesRegex(SafetyError, "PREVIEW_STALE"):
            self.safety.revalidate(p, a, source, snapshot(), evidence, permissions=APPROVE,
                                   now=NOW + timedelta(seconds=31))
        with self.assertRaisesRegex(SafetyError, "PREVIEW_EXPIRED"):
            self.safety.revalidate(p, a, source, snapshot(), evidence, permissions=APPROVE,
                                   now=NOW + timedelta(seconds=300))

    def test_repeat_and_parallel_validation_are_read_only(self):
        source, target, evidence = snapshot(user()), snapshot(), {"batch-1": proof()}
        before = copy.deepcopy((source, target, evidence))
        p = self.preview(source, target, evidence)
        a = self.approval(p)

        def verify(_):
            return self.safety.revalidate(p, a, source, target, evidence, permissions=APPROVE, now=NOW)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(verify, range(16)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(before, (source, target, evidence))
        self.assertTrue(results[0]["requiresAtomicAdapter"])

    def test_permissions_approval_scope_and_audit(self):
        with self.assertRaisesRegex(SafetyError, "FORBIDDEN"):
            self.safety.preview(snapshot(user()), snapshot(), {}, group_key="g", target_id="t",
                                mode="renewal-sync", permissions=set(), now=NOW)
        p = self.preview(snapshot(user()), evidence={"batch-1": proof()})
        with self.assertRaisesRegex(SafetyError, "FORBIDDEN"):
            self.approval(p, READ)
        with self.assertRaisesRegex(SafetyError, "AUDIT_REQUIRED"):
            self.safety.approve(p, actor_id="a", audit_id="", permissions=APPROVE, now=NOW)
        a = self.approval(p)
        a["auditId"] = "tampered"
        with self.assertRaisesRegex(SafetyError, "APPROVAL_INVALID"):
            self.safety.revalidate(p, a, snapshot(user()), snapshot(), {"batch-1": proof()},
                                   permissions=APPROVE, now=NOW)

    def test_schema_limits_and_no_serialization_loss(self):
        for version in (1, 2):
            self.assertEqual(self.preview(snapshot(user(), version=version))["desiredCount"], 1)
        with self.assertRaisesRegex(SafetyError, "UNSUPPORTED_SCHEMA"):
            self.preview(snapshot(version=3))
        with self.assertRaisesRegex(SafetyError, "DUPLICATE_USER_ID"):
            self.preview(snapshot(user(), user()))
        with self.assertRaisesRegex(SafetyError, "INPUT_TOO_LARGE"):
            self.preview(snapshot(*[user(str(n)) for n in range(10001)]))
        sample = user()
        sample["cannotSerialize"] = object()
        with self.assertRaisesRegex(SafetyError, "UNSERIALIZABLE_INPUT"):
            self.preview(snapshot(sample))
        sample["cannotSerialize"] = float("nan")
        with self.assertRaisesRegex(SafetyError, "UNSERIALIZABLE_INPUT"):
            self.preview(snapshot(sample))

    def test_isolated_restore_requires_separate_permission_and_preserves_historical_user(self):
        source = snapshot(user(expiry="2025-01-01T00:00:00Z"), version=2)
        source["sharedConfig"] = export_template(fixture.base_singbox_config())
        before = copy.deepcopy(source)
        p = self.preview(source, mode="isolated-restore", evidence={"batch-1": {"origin": "admin-batch", "expiryKind": "inferred"}})
        self.assertEqual(p["desiredCount"], 1)
        self.assertFalse(p["blockers"])
        with self.assertRaisesRegex(SafetyError, "FORBIDDEN"):
            self.approval(p, APPROVE)
        a = self.approval(p, RESTORE)
        result = self.safety.revalidate(p, a, source, snapshot(),
                                       {"batch-1": {"origin": "admin-batch", "expiryKind": "inferred"}},
                                       permissions=RESTORE, now=NOW)
        self.assertTrue(result["validated"])
        self.assertEqual(before, source)

    def test_invalid_uuid_reality_counters_aliases_and_stale_generation_block(self):
        cases = []
        bad = snapshot(user())
        bad["users"][0]["auth"][0]["credential"] = "fake-not-uuid"
        cases.append((bad, snapshot(), "INVALID_AUTH"))
        bad = snapshot(user())
        bad["users"][0]["download"] = -1
        cases.append((bad, snapshot(), "INVALID_TRAFFIC_COUNTER"))
        bad = snapshot(user())
        bad["sharedConfig"] = export_template(fixture.base_singbox_config())
        bad["sharedConfig"]["vless"]["tls"]["reality"]["private_key"] = "bad-fake-key"
        cases.append((bad, snapshot(), "INVALID_SHARED_CONFIG"))
        bad = snapshot(user())
        bad["aliases"] = {"old": "batch-1"}
        cases.append((bad, snapshot(), "ALIAS_MIGRATION_REVIEW"))
        bad, target = snapshot(user()), snapshot()
        bad["generation"], target["generation"] = 1, 2
        cases.append((bad, target, "STALE_GENERATION"))
        for source, target, code in cases:
            with self.subTest(code=code):
                self.assertIn(code, self.preview(source, target, {"batch-1": proof()})["blockers"])

    def test_approval_cannot_bind_a_different_target_or_mode(self):
        source, target, evidence = snapshot(user()), snapshot(), {"batch-1": proof()}
        p = self.preview(source, target, evidence)
        a = self.approval(p)
        other = self.safety.preview(source, target, evidence, group_key="fixture-group",
                                    target_id="different-target", mode="renewal-sync", permissions=READ, now=NOW)
        with self.assertRaisesRegex(SafetyError, "APPROVAL_INVALID"):
            self.safety.revalidate(other, a, source, target, evidence, permissions=APPROVE, now=NOW)


class LocalCaptureTest(unittest.TestCase):
    tearDown = fixture.ManagerTestCase.tearDown
    _write_config = fixture.ManagerTestCase._write_config

    def setUp(self):
        fixture.ManagerTestCase.setUp(self)
        self.safety = ReplicationSafety(b"fake-isolated-reconciliation-key" * 2)

    def capture(self):
        return capture_local(self.safety, group_key="test-group", permissions=READ)

    def test_paused_missing_expiration_custom_and_multi_proxy_never_drop(self):
        manager.create_user("historical", ["vless"])
        registry = manager.read_registry()
        registry["users"]["historical"].pop("expiresAt")
        manager._write_registry(registry)
        data = manager.read_config()
        data["outbounds"].append({"type": "socks", "tag": manager.USER_OUTBOUND_PREFIX + "historical",
                                   "server": "203.0.113.10", "server_port": 1080,
                                   "username": "fake-u", "password": "fake-p", "bind_interface": "test0"})
        self._write_config(data)
        before = (self.config_path.read_bytes(), self.registry_path.read_bytes())
        with patch.object(manager, "EXPIRATION_ENABLED", False), \
                patch.object(traffic, "_write_store") as write, \
                patch.object(manager, "reload_singbox") as reload:
            result = self.capture()
            write.assert_not_called()
            reload.assert_not_called()
        self.assertEqual(len(result["users"]), 1)
        self.assertIsNone(result["users"][0]["expiresAt"])
        self.assertIn("MULTI_PROXY", result["users"][0]["serializationIssues"])
        self.assertIn("CUSTOM_OUTBOUND", result["users"][0]["serializationIssues"])
        self.assertFalse(result["capture"]["expirationCleanupEnabled"])
        self.assertEqual(before, (self.config_path.read_bytes(), self.registry_path.read_bytes()))
        self.assertFalse(self.traffic_path.exists())

    def test_capture_revisions_ignore_sampling_time_but_include_full_config_and_traffic(self):
        manager.create_user("historical", ["vless"])
        first, second = self.capture(), self.capture()
        self.assertEqual(self.safety._state_digest(first), self.safety._state_digest(second))
        data = manager.read_config()
        data["route"]["rules"].append({"domain_suffix": ["example.test"], "action": "reject"})
        self._write_config(data)
        self.assertNotEqual(self.safety._state_digest(first), self.safety._state_digest(self.capture()))
        store = traffic._empty_store()
        store["users"]["historical"] = {"upload": 31, "download": 42}
        traffic._write_store(store)
        result = self.capture()
        self.assertEqual((result["users"][0]["upload"], result["users"][0]["download"]), (31, 42))

    def test_bad_reality_and_missing_uuid_are_visible_and_block_restore(self):
        manager.create_user("historical", ["vless"])
        data = manager.read_config()
        data["inbounds"][0]["users"][0].pop("uuid")
        data["inbounds"][0]["tls"]["reality"]["private_key"] = "fake-invalid-key"
        self._write_config(data)
        result = self.capture()
        self.assertEqual(len(result["users"]), 1)
        self.assertTrue(result["errors"])
        p = self.safety.preview(result, snapshot(), {}, group_key="test-group", target_id="test-target",
                                mode="isolated-restore", permissions=READ, now=NOW)
        self.assertIn("MISSING_AUTH", p["blockers"])
        self.assertIn("MISSING_SHARED_CONFIG", p["blockers"])

    def test_capture_requires_restricted_permission(self):
        with self.assertRaisesRegex(SafetyError, "FORBIDDEN"):
            capture_local(self.safety, group_key="test-group")

    def test_failed_restore_validation_keeps_original_config_registry_and_traffic(self):
        manager.create_user("historical", ["vless"])
        store = traffic._empty_store()
        store["users"]["historical"] = {"upload": 99, "download": 20}
        traffic._write_store(store)
        original = (self.config_path.read_bytes(), self.registry_path.read_bytes(), self.traffic_path.read_bytes())
        source = self.capture()
        source["users"][0]["auth"][0]["credential"] = "fake-invalid-uuid"
        p = self.safety.preview(source, snapshot(), {}, group_key="g", target_id="t",
                                mode="isolated-restore", permissions=READ, now=NOW)
        with patch.object(manager, "mutate_config") as mutate, patch.object(traffic, "_write_store") as write:
            with self.assertRaisesRegex(SafetyError, "PREVIEW_BLOCKED"):
                self.safety.approve(p, actor_id="fake-a", audit_id="fake-b", permissions=RESTORE, now=NOW)
            mutate.assert_not_called()
            write.assert_not_called()
        self.assertEqual(original, (self.config_path.read_bytes(), self.registry_path.read_bytes(), self.traffic_path.read_bytes()))

    def test_orphan_protocol_auth_is_not_hidden(self):
        data = manager.read_config()
        data["inbounds"][2]["users"].append({"username": "unregistered", "password": "fake-orphan-password"})
        self._write_config(data)
        result = self.capture()
        self.assertEqual(result["capture"]["unregisteredAuthCount"], 1)
        self.assertIn("UNREGISTERED_PROTOCOL_AUTH", result["errors"])

    def test_unknown_protocol_credentials_block_incomplete_capture(self):
        data = manager.read_config()
        data["inbounds"].append({"tag": "unsupported-fixture", "type": "hysteria2",
                                 "users": [{"name": "orphan", "password": "fake-secret"}]})
        self._write_config(data)
        result = self.capture()
        self.assertIn("UNSUPPORTED_PROTOCOL_AUTH", result["errors"])
        p = self.safety.preview(result, snapshot(), {}, group_key="g", target_id="t",
                                mode="isolated-restore", permissions=READ, now=NOW)
        self.assertIn("INCOMPLETE_CAPTURE", p["blockers"])


if __name__ == "__main__":
    unittest.main()
