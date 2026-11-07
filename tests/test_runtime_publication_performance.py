"""Performance paths must retain drift, process, CAS and crash protection."""
import copy
import json
import unittest
from unittest.mock import patch

import runtime_metrics
import runtime_publication as publication
from singbox.runtime_client import RuntimeClient
import test_runtime_publication as fixtures
from test_runtime_publication import manager


class PublicationFastPathTests(unittest.TestCase):
    setUp = fixtures.RuntimePublicationTests.setUp

    def test_verified_baseline_needs_only_target_preview(self):
        desired = copy.deepcopy(self.config)
        desired["inbounds"][2]["users"] = [{"username": "synthetic", "password": "synthetic-password"}]
        with patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            prepared = publication.prepare(self.config, desired)
        self.assertEqual(preview.call_count, 1)
        self.assertEqual(prepared["expected"], self.fake.status())
        self.assertNotEqual(prepared["previousHash"], prepared["targetHash"])
        self.assertEqual(self.fake.puts, 0)

    def test_same_hash_but_new_instance_or_revision_requires_full_verification(self):
        for field, changed in [("instance", "new-process"), ("revision", 4)]:
            with self.subTest(field=field):
                publication._remember_baseline(self.config, self.fake.status())
                setattr(self.fake, field, changed)
                with patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
                    publication.prepare(self.config, self.config)
                self.assertEqual(preview.call_count, 2)

    def test_changed_disk_cannot_use_cached_runtime_baseline(self):
        changed = copy.deepcopy(self.config)
        changed["log"] = {"level": "error"}
        with patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            with self.assertRaisesRegex(manager.SingboxConfigError, "drift"):
                publication.prepare(changed, changed)
        self.assertEqual(preview.call_count, 2)
        self.assertFalse(publication.paths()[0].exists())

    def test_external_runtime_change_still_refuses_cached_baseline(self):
        self.fake.data["log"] = {"level": "warn"}
        with self.assertRaisesRegex(manager.SingboxConfigError, "drift"):
            publication.prepare(self.config, self.config)
        self.assertEqual(self.fake.puts, 0)

    def test_uncached_restart_uses_both_previews(self):
        with patch.object(publication, "_verified_baseline", None), \
                patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            publication.prepare(self.config, self.config)
        self.assertEqual(preview.call_count, 2)

    def test_changed_socket_during_preview_is_rejected(self):
        original = publication.check_mode()
        with patch.object(publication, "check_mode", side_effect=[original, original + ".other"]):
            with self.assertRaisesRegex(publication.RuntimeRecoveryRequired, "socket changed"):
                publication.prepare(self.config, self.config)

    def test_staged_registry_reads_previous_registry_only_once(self):
        with patch.object(manager, "read_registry", wraps=manager.read_registry) as read:
            publication.commit(self.config, manager.read_registry(), self.config)
        # One explicit call above and one old snapshot needed for ownership.
        self.assertEqual(read.call_count, 2)


class RuntimeDiagnosticTests(unittest.TestCase):
    def test_fixed_categories_do_not_retain_error_credentials(self):
        secret = "never-retain-this-password"
        with patch.object(runtime_metrics, "_rejections", {}):
            runtime_metrics.rejection(ValueError("user already exists: " + secret))
            runtime_metrics.rejection(ValueError(secret))
            result = runtime_metrics.snapshot()
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["mutationRejections"], {"USER_ALREADY_EXISTS": 1, "POLICY_REJECTED": 1})

    def test_failed_phase_is_recorded_without_exception_body(self):
        @runtime_metrics.timed("prepare")
        def fail():
            raise ValueError("synthetic-secret")
        with patch.object(runtime_metrics, "_phases", {}):
            with self.assertRaises(ValueError):
                fail()
            state = runtime_metrics.snapshot()
        self.assertEqual(state["phases"]["prepare"]["failures"], 1)
        self.assertGreaterEqual(state["phases"]["prepare"]["lastMs"], 0)
        self.assertNotIn("synthetic-secret", json.dumps(state))
