"""A raw-identical config may reuse only an exact verified native baseline."""
import copy
import unittest
from unittest.mock import patch

import test_runtime_publication as fixtures
from test_runtime_publication import manager
from singbox.runtime_client import RuntimeClient, RuntimeRejected, RuntimeUnavailable
import runtime_publication as publication


class MetadataPrepareTests(unittest.TestCase):
    setUp = fixtures.RuntimePublicationTests.setUp
    files = fixtures.RuntimePublicationTests.files

    def test_same_raw_config_and_exact_status_avoid_large_preview(self):
        with patch.object(RuntimeClient, "preview", side_effect=AssertionError("large preview not required")), \
             patch.object(RuntimeClient, "status", wraps=RuntimeClient().status) as status:
            prepared = publication.prepare(self.config, copy.deepcopy(self.config))
        self.assertEqual(status.call_count, 1)
        self.assertEqual(prepared["expected"], self.fake.status())
        self.assertEqual(prepared["targetHash"], prepared["previousHash"])
        self.assertEqual(self.fake.puts, 0)
        self.assertEqual(self.fake.fences, 0)

    def test_equivalent_raw_dictionary_order_keeps_verified_fast_path(self):
        reordered = dict(reversed(list(self.config.items())))
        with patch.object(RuntimeClient, "preview", side_effect=AssertionError("unexpected preview")):
            prepared = publication.prepare(self.config, reordered)
        self.assertEqual(prepared["expected"], self.fake.status())

    def test_missing_cache_keeps_both_normal_previews(self):
        with patch.object(publication, "_verified_baseline", None), \
             patch.object(RuntimeClient, "status", side_effect=AssertionError("cache miss should preview")), \
             patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            publication.prepare(self.config, self.config)
        self.assertEqual(preview.call_count, 2)

    def test_changed_target_raw_config_still_runs_native_schema_preview(self):
        desired = copy.deepcopy(self.config)
        desired["inbounds"][2]["users"] = [{"username": "synthetic", "password": "synthetic-password"}]
        with patch.object(RuntimeClient, "status", side_effect=AssertionError("changed config must preview")), \
             patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            prepared = publication.prepare(self.config, desired)
        self.assertEqual(preview.call_count, 1)
        self.assertNotEqual(prepared["targetHash"], prepared["previousHash"])

    def test_changed_previous_raw_config_cannot_use_a_status_hash_match(self):
        changed = copy.deepcopy(self.config)
        changed["log"] = {"level": "error"}
        with patch.object(RuntimeClient, "status", side_effect=AssertionError("wrong raw proof")), \
             patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            with self.assertRaisesRegex(manager.SingboxConfigError, "drift"):
                publication.prepare(changed, changed)
        self.assertEqual(preview.call_count, 2)

    def test_revision_change_with_same_hash_requires_full_native_proof(self):
        self.fake.revision += 1
        with patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            prepared = publication.prepare(self.config, self.config)
        self.assertEqual(preview.call_count, 2)
        self.assertEqual(prepared["expected"]["revision"], self.fake.revision)

    def test_new_process_with_same_hash_requires_full_native_proof(self):
        self.fake.instance = "replacement-core"
        with patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            prepared = publication.prepare(self.config, self.config)
        self.assertEqual(preview.call_count, 2)
        self.assertEqual(prepared["expected"]["instanceId"], "replacement-core")

    def test_changed_native_hash_still_refuses_drift_before_any_write(self):
        before = self.files()
        self.fake.data["log"] = {"level": "warn"}
        with patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            with self.assertRaisesRegex(manager.SingboxConfigError, "drift"):
                publication.prepare(self.config, self.config)
        self.assertEqual(preview.call_count, 2)
        self.assertEqual(self.files(), before)
        self.assertFalse(publication.paths()[0].exists())

    def test_optional_status_failure_falls_back_to_verified_native_preview(self):
        for error in [RuntimeUnavailable("temporary status error"), RuntimeRejected(404)]:
            with self.subTest(error=type(error).__name__), \
                 patch.object(RuntimeClient, "status", side_effect=error), \
                 patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
                publication.prepare(self.config, self.config)
            self.assertEqual(preview.call_count, 1)

    def test_socket_change_during_fast_status_check_fails_closed(self):
        socket = publication.check_mode()
        with patch.object(publication, "check_mode", side_effect=[socket, socket + ".replacement"]), \
             patch.object(RuntimeClient, "preview", side_effect=AssertionError("must not send a preview to new socket")):
            with self.assertRaisesRegex(publication.RuntimeRecoveryRequired, "socket changed"):
                publication.prepare(self.config, self.config)

    def test_native_change_after_status_is_still_caught_by_metadata_cas(self):
        before = self.files()
        original_status = RuntimeClient().status
        raced = False
        def racing_status():
            nonlocal raced
            observed = original_status()
            if not raced:
                raced = True
                self.fake.revision += 1
            return observed
        registry = manager.read_registry()
        registry["metadata_epoch"] = 1
        with patch.object(RuntimeClient, "status", side_effect=racing_status):
            with self.assertRaisesRegex(manager.SingboxConfigError, "metadata fence rejected"):
                publication.commit(self.config, registry, self.config)
        self.assertEqual(self.files(), before)
        self.assertFalse(publication.paths()[0].exists())
        self.assertEqual(self.fake.puts, 0)


if __name__ == "__main__":
    unittest.main()
