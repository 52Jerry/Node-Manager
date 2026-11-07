"""Unchanged-core metadata commits need a durable CAS proof, never hash guessing."""
import copy
import json
import unittest
from unittest.mock import patch

import test_runtime_publication as fixtures
from test_runtime_publication import manager
from singbox.runtime_client import RuntimeClient, RuntimeRejected, RuntimeUnavailable
import runtime_publication as publication


class MetadataPublicationTests(unittest.TestCase):
    setUp = fixtures.RuntimePublicationTests.setUp
    create = fixtures.RuntimePublicationTests.create
    files = fixtures.RuntimePublicationTests.files

    def ready(self):
        self.create()
        self.original_puts = self.fake.puts
        self.original_revision = self.fake.revision

    def metadata(self, version=1):
        current = manager.read_config()
        registry = manager.read_registry()
        registry.setdefault("runtimeUserVersions", {})["customer"] = version
        return publication.commit(current, registry, current)

    def journal(self):
        return json.loads(publication.paths()[0].read_text())

    def crash_with_proof(self):
        with patch.object(publication, "_write_records", side_effect=SystemExit("fixture crash")):
            with self.assertRaises(SystemExit):
                self.metadata()
        journal = self.journal()
        self.assertEqual(journal["version"], 2)
        self.assertEqual(journal["prepared"]["mode"], "metadata-fence")
        self.assertIn("metadataFence", journal)
        return journal

    def test_registry_only_keeps_versions_but_uses_small_fence_not_full_apply(self):
        self.ready()
        before_config = manager.read_config()
        with patch.object(RuntimeClient, "preview", wraps=RuntimeClient().preview) as preview:
            receipt = self.metadata()
        self.assertEqual(preview.call_count, 0)
        self.assertEqual(self.fake.puts, self.original_puts)
        self.assertEqual(self.fake.fences, 1)
        self.assertEqual(receipt["revision"], self.original_revision + 1)
        self.assertEqual(manager.read_config(), before_config)
        self.assertEqual(manager.read_registry()["runtimeUserVersions"]["customer"], 1)
        self.assertEqual(json.loads(publication.paths()[1].read_text())["runtime"], receipt)
        self.assertFalse(publication.paths()[0].exists())

    def test_core_changes_still_use_normal_publication(self):
        self.ready()
        manager.mutate_config(lambda data, registry: data["inbounds"][2]["users"][0].update(password="rotated"))
        self.assertEqual(self.fake.puts, self.original_puts + 1)
        self.assertEqual(self.fake.fences, 0)

    def test_equal_normalized_hash_cannot_hide_a_raw_config_change(self):
        self.ready()
        previous = manager.read_config()
        desired = copy.deepcopy(previous)
        desired["log"] = {"level": "error"}
        prepared = {"socket": publication.check_mode(), "expected": self.fake.status(),
                    "previousHash": self.fake.status()["contentHash"],
                    "targetHash": self.fake.status()["contentHash"]}
        with patch.object(publication, "publish", side_effect=SystemExit("normal publication crash")):
            with self.assertRaises(SystemExit):
                publication.commit_files(desired, previous, {manager.CONFIG_PATH: publication.canonical(desired)}, prepared)
        self.assertEqual(self.journal()["version"], 1)
        self.assertNotIn("mode", self.journal()["prepared"])
        self.assertEqual(self.fake.fences, 0)

    def test_bundle_is_not_written_before_durable_fence_proof(self):
        self.ready()
        original = publication._write_records
        seen = []
        def verify(records):
            journal = self.journal()
            self.assertEqual(journal["version"], 2)
            self.assertEqual(journal["metadataFence"], self.fake.status())
            seen.append(True)
            return original(records)
        with patch.object(publication, "_write_records", side_effect=verify):
            self.metadata()
        self.assertTrue(seen)

    def test_crash_before_fence_aborts_and_invalidates_a_delayed_old_fence(self):
        self.ready()
        before = self.files()
        with patch.object(publication, "publish_metadata", side_effect=SystemExit("before fence")):
            with self.assertRaises(SystemExit):
                self.metadata()
        journal = self.journal()
        self.assertEqual(journal["version"], 2)
        self.assertNotIn("metadataFence", journal)
        expected = journal["prepared"]["expected"]
        self.assertEqual(publication.recover_locked(), "unchanged")
        self.assertEqual(self.files(), before)
        with self.assertRaises(RuntimeRejected):
            RuntimeClient().fence(expected)
        self.assertEqual(self.fake.puts, self.original_puts)

    def test_lost_fence_reply_never_treats_same_hash_as_success(self):
        for applied in [False, True]:
            with self.subTest(fence_applied=applied):
                # Distinct fixture/paths and process baseline for each case.
                if applied:
                    self.setUp()
                self.ready()
                before = self.files()
                original = self.fake.request
                intercepted = []
                def lose(method, path, body=None):
                    if path == "fence" and not intercepted:
                        intercepted.append(copy.deepcopy(body))
                        if applied:
                            original(method, path, body)
                        raise RuntimeUnavailable("lost fence reply")
                    return original(method, path, body)
                with patch.object(RuntimeClient, "_request", side_effect=lose):
                    with self.assertRaisesRegex(manager.SingboxConfigError, "metadata fence rejected"):
                        self.metadata()
                self.assertEqual(self.files(), before)
                self.assertFalse(publication.paths()[0].exists())
                self.assertEqual(self.fake.puts, self.original_puts)
                with self.assertRaises(RuntimeRejected):
                    self.fake.request("POST", "fence", intercepted[0])

    def test_conflict_with_unchanged_core_aborts_without_publishing_metadata(self):
        self.ready()
        before = self.files()
        original = self.fake.request
        conflicted = False
        def conflict(method, path, body=None):
            nonlocal conflicted
            if path == "fence" and not conflicted:
                conflicted = True
                self.fake.revision += 1
                raise RuntimeRejected(409)
            return original(method, path, body)
        with patch.object(RuntimeClient, "_request", side_effect=conflict):
            with self.assertRaisesRegex(manager.SingboxConfigError, "metadata fence rejected"):
                self.metadata()
        self.assertEqual(self.files(), before)
        self.assertFalse(publication.paths()[0].exists())

    def test_disconnect_after_fence_without_durable_proof_aborts_on_reconnect(self):
        self.ready()
        before = self.files()
        original = self.fake.request
        def disconnect(method, path, body=None):
            value = original(method, path, body)
            if path == "fence":
                self.fake.offline = True
                raise RuntimeUnavailable("disconnected after fence")
            return value
        with patch.object(RuntimeClient, "_request", side_effect=disconnect):
            with self.assertRaises(publication.RuntimeRecoveryRequired):
                self.metadata()
        self.assertNotIn("metadataFence", self.journal())
        self.assertEqual(self.files(), before)
        self.fake.offline = False
        self.assertEqual(publication.recover_locked(), "unchanged")
        self.assertEqual(self.files(), before)

    def test_crash_after_proof_recovers_registry_without_another_native_write(self):
        self.ready()
        self.crash_with_proof()
        self.assertNotIn("customer", manager.read_registry().get("runtimeUserVersions", {}))
        fences = self.fake.fences
        self.assertEqual(publication.recover_locked(), "applied")
        self.assertEqual(manager.read_registry()["runtimeUserVersions"]["customer"], 1)
        self.assertEqual(self.fake.puts, self.original_puts)
        self.assertEqual(self.fake.fences, fences)

    def test_failure_before_proof_replace_aborts_while_failure_after_replace_recovers(self):
        for after_replace in [False, True]:
            with self.subTest(proof_visible=after_replace):
                if after_replace:
                    self.setUp()
                self.ready()
                before = self.files()
                original = publication.atomic
                injected = False
                def fail(path, content, *args, **kwargs):
                    nonlocal injected
                    if path == publication.paths()[0] and "metadataFence" in json.loads(content) and not injected:
                        injected = True
                        if after_replace:
                            original(path, content, *args, **kwargs)
                        raise OSError("proof fsync failure")
                    return original(path, content, *args, **kwargs)
                with patch.object(publication, "atomic", side_effect=fail):
                    if after_replace:
                        receipt = self.metadata()
                        self.assertEqual(receipt, self.fake.status())
                    else:
                        with self.assertRaisesRegex(manager.SingboxConfigError, "previous files restored"):
                            self.metadata()
                if after_replace:
                    self.assertEqual(manager.read_registry()["runtimeUserVersions"]["customer"], 1)
                else:
                    self.assertEqual(self.files(), before)
                self.assertFalse(publication.paths()[0].exists())

    def test_related_files_roll_forward_together_after_a_partial_bundle_crash(self):
        self.ready()
        extra = self.root / "traffic-related.json"
        extra.write_text(json.dumps({"upload": 91}), encoding="utf-8")
        original = publication.restore
        crashed = False
        def fail(path, record):
            nonlocal crashed
            if str(path) == str(self.registry_path.resolve()) and not crashed:
                crashed = True
                raise SystemExit("mid-bundle crash")
            return original(path, record)
        with publication.related_transaction():
            publication.stage_related(extra, {"upload": 92})
            with patch.object(publication, "restore", side_effect=fail):
                with self.assertRaises(SystemExit):
                    self.metadata()
        self.assertEqual(self.journal()["version"], 2)
        self.assertEqual(publication.recover_locked(), "applied")
        self.assertEqual(manager.read_registry()["runtimeUserVersions"]["customer"], 1)
        self.assertEqual(json.loads(extra.read_text()), {"upload": 92})
        self.assertEqual(self.fake.puts, self.original_puts)

    def test_unproven_abort_does_not_overwrite_newer_related_counter_data(self):
        self.ready()
        extra = self.root / "traffic-related.json"
        extra.write_text(json.dumps({"upload": 91}), encoding="utf-8")
        with publication.related_transaction():
            publication.stage_related(extra, {"upload": 0})
            with patch.object(publication, "publish_metadata", side_effect=SystemExit("before fence")):
                with self.assertRaises(SystemExit):
                    self.metadata()
        extra.write_text(json.dumps({"upload": 97}), encoding="utf-8")
        self.assertEqual(publication.recover_locked(), "unchanged")
        self.assertEqual(json.loads(extra.read_text()), {"upload": 97})

    def test_durable_proof_rejects_process_revision_or_config_change(self):
        for change in ["instance", "revision", "config"]:
            with self.subTest(change=change):
                if change != "instance":
                    self.setUp()
                self.ready()
                self.crash_with_proof()
                before = self.files()
                if change == "instance":self.fake.instance = "replacement-core"
                elif change == "revision":self.fake.revision += 1
                else:self.fake.data["log"] = {"level": "error"}
                with self.assertRaises(publication.RuntimeRecoveryRequired):
                    publication.recover_locked()
                self.assertTrue(publication.paths()[0].exists())
                self.assertEqual(self.files(), before)

    def test_v2_metadata_intent_cannot_be_downgraded_to_v1_hash_recovery(self):
        self.ready()
        with patch.object(publication, "publish_metadata", side_effect=SystemExit("before fence")):
            with self.assertRaises(SystemExit):self.metadata()
        journal = self.journal()
        # The deployed old reader accepts version 1 only; version 2 makes an
        # operator rollback fail closed instead of guessing from equal hashes.
        self.assertEqual(journal["version"], 2)
        journal.pop("integrity")
        journal["version"] = 1
        journal["integrity"] = publication.digest(journal)
        publication.paths()[0].write_bytes(publication.canonical(journal))
        before = self.files()
        with self.assertRaises(publication.RuntimeRecoveryRequired):publication.recover_locked()
        self.assertEqual(self.files(), before)
        self.assertTrue(publication.paths()[0].exists())

    def test_invalid_present_proof_is_not_treated_as_an_unwritten_bundle(self):
        self.ready()
        journal = self.crash_with_proof()
        journal.pop("integrity")
        journal["metadataFence"] = None
        journal["integrity"] = publication.digest(journal)
        publication.paths()[0].write_bytes(publication.canonical(journal))
        before = self.files()
        with self.assertRaises(publication.RuntimeRecoveryRequired):publication.recover_locked()
        self.assertEqual(self.files(), before)
        self.assertTrue(publication.paths()[0].exists())

    def test_initial_wal_directory_fsync_failure_cannot_commit_metadata(self):
        self.ready()
        before = self.files()
        original = publication.atomic
        def fail(path, content, *args, **kwargs):
            original(path, content, *args, **kwargs)
            if path == publication.paths()[0]:raise OSError("initial WAL directory fsync")
        with patch.object(publication, "atomic", side_effect=fail):
            with self.assertRaises(publication.RuntimeRecoveryRequired):self.metadata()
        self.assertEqual(self.fake.puts, self.original_puts)
        self.assertEqual(self.fake.fences, 0)
        self.assertNotIn("metadataFence", self.journal())
        self.assertEqual(publication.recover_locked(), "unchanged")
        self.assertEqual(self.files(), before)


if __name__ == "__main__":
    unittest.main()
