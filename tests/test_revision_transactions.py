"""Offline fault injection for the complete publication bundle and its undo log."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from test_revision_apply import RevisionApplyTestBase, manager, revision_module as rev
import revision_transaction as tx


class RevisionTransactionTests(RevisionApplyTestBase):
    def setUp(self):
        super().setUp()
        self.runtime = patch.object(rev, "is_singbox_running", return_value=True)
        self.runtime.start()
        self.addCleanup(self.runtime.stop)

    def publish(self, version="one", expires="2027-01-01T00:00:00+00:00"):
        return self.apply({"inbounds": [{"tag": version}]},
                          {"version": 1, "users": {"customer": {"expiresAt": expires}}}, version)

    def files(self):
        return {key: tx._capture(path) for key, path in tx._paths().items()}

    def test_registry_failure_cannot_ack_and_restores_every_file(self):
        self.publish()
        before = self.files()
        with patch.object(manager, "_write_registry", side_effect=OSError("fixture disk failure")):
            with self.assertRaisesRegex(manager.SingboxConfigError, "previous bundle restored"):
                self.publish("two")
        self.assertEqual(self.files(), before)
        self.assertFalse(rev.JOURNAL_PATH.exists())

    def test_registry_only_change_with_same_revision_conflicts(self):
        first = self.publish()
        before = self.files()
        with self.assertRaisesRegex(manager.SingboxConfigError, "content conflict"):
            self.publish(expires="2027-02-01T00:00:00+00:00")
        self.assertEqual(self.files(), before)
        self.assertNotEqual(first["configHash"], first["bundleHash"])

    def test_delayed_old_revision_cannot_undo_new_revision(self):
        self.publish("one")
        self.publish("two")
        before = self.files()
        with self.assertRaisesRegex(manager.SingboxConfigError, "stale revision"):
            self.publish("one")
        self.assertEqual(self.files(), before)

    def test_replay_and_state_detect_registry_drift(self):
        self.publish()
        self.registry_path.write_text(json.dumps({"version": 1, "users": {}}), encoding="utf-8")
        with self.assertRaisesRegex(manager.SingboxConfigError, "drift"):
            self.publish()
        state = rev.get_revision_state()
        self.assertEqual(state["status"], "drifted")
        self.assertFalse(state["filesVerified"])

    def test_rollback_restores_registry_and_metadata_bundle(self):
        one = self.publish("one")
        self.publish("two", "2027-02-01T00:00:00+00:00")
        result = rev.rollback_to_last_known_good()
        self.assertEqual(result["bundleHash"], one["bundleHash"])
        self.assertEqual(json.loads(self.registry_path.read_text())["users"]["customer"]["expiresAt"],
                         "2027-01-01T00:00:00+00:00")
        self.assertTrue(rev.get_revision_state()["filesVerified"])

    def test_config_only_legacy_backup_is_not_a_complete_rollback(self):
        rev._write_config_snapshot(rev.LAST_GOOD_PATH, {"inbounds": []})
        with self.assertRaisesRegex(manager.SingboxConfigError, "complete last_known_good"):
            rev.rollback_to_last_known_good()
        self.assertFalse(self.config_path.exists())

    def test_unversioned_existing_bundle_has_a_distinct_rollback_identity(self):
        self.config_path.write_text(json.dumps({"inbounds": [{"tag": "legacy"}]}))
        self._write_registry_stub({"users": {"customer": {"expiresAt": "legacy"}}})
        self.publish()
        result = rev.rollback_to_last_known_good()
        self.assertTrue(result["currentRevisionId"].startswith("local-"))
        self.assertEqual(json.loads(self.config_path.read_text())["inbounds"][0]["tag"], "legacy")
        self.assertEqual(json.loads(self.registry_path.read_text())["users"]["customer"]["expiresAt"], "legacy")

    def test_cached_api_receipt_rechecks_actual_files_and_signature(self):
        from test_next_stage import main
        from starlette.responses import Response
        self.publish()
        request = main.DesiredRevisionRequest(config={"inbounds": [{"tag": "one"}]},
            registry={"version": 1, "users": {"customer": {"expiresAt": "2027-01-01T00:00:00+00:00"}}},
            revisionId="one")
        signature = rev._sign({"config": request.config, "registry": request.registry})
        with patch.object(main, "execute_idempotent", return_value=({"success": True}, True)):
            with self.assertRaisesRegex(manager.SingboxConfigError, "signature"):
                main.apply_revision_endpoint(request, Response(), "bad-signature", "fixture-key", "fixture-token")
            self._write_registry_stub({"users": {}})
            with self.assertRaisesRegex(manager.SingboxConfigError, "drift"):
                main.apply_revision_endpoint(request, Response(), signature, "fixture-key", "fixture-token")

    def test_corrupt_undo_log_refuses_recovery_without_writing_files(self):
        self.publish()
        with patch.object(manager, "_write_registry", side_effect=SystemExit("fixture crash")):
            with self.assertRaises(SystemExit):
                self.publish("two")
        journal = json.loads(rev.JOURNAL_PATH.read_text())
        journal["before"]["registry"] = None
        tx._json_write(rev.JOURNAL_PATH, journal)
        before = self.files()
        with self.assertRaisesRegex(manager.SingboxConfigError, "recovery required"):
            rev.recover_pending_revision()
        self.assertEqual(self.files(), before)
        self.assertTrue(rev.JOURNAL_PATH.exists())

    def test_all_snapshot_and_metadata_write_failures_restore_whole_bundle(self):
        self.publish()
        for path in (rev.LAST_GOOD_PATH, rev.LAST_GOOD_BUNDLE_PATH,
                     rev.CURRENT_PATH, rev.CURRENT_BUNDLE_PATH, rev.STATE_PATH):
            with self.subTest(file=path.name):
                before = self.files()
                original = tx._json_write
                def fail(target, value):
                    if target == path:
                        raise OSError("fixture metadata disk failure")
                    return original(target, value)
                with patch.object(tx, "_json_write", side_effect=fail):
                    with self.assertRaises(manager.SingboxConfigError):
                        self.publish("two")
                self.assertEqual(self.files(), before)
                self.assertFalse(rev.JOURNAL_PATH.exists())

    def test_disk_readback_mismatch_cannot_ack_success(self):
        self.publish()
        before = self.files()
        with patch.object(manager, "_write_registry", side_effect=lambda value: self._write_registry_stub({"users": {}})):
            with self.assertRaisesRegex(manager.SingboxConfigError, "readback mismatch"):
                self.publish("two")
        self.assertEqual(self.files(), before)

    def test_precommit_crash_is_recovered_before_further_mutations(self):
        self.publish()
        before = self.files()
        original = manager._write_registry
        def crash_after_registry(value):
            original(value)
            raise SystemExit("fixture crash")
        with patch.object(manager, "_write_registry", side_effect=crash_after_registry):
            with self.assertRaises(SystemExit):
                self.publish("two")
        self.assertTrue(rev.JOURNAL_PATH.exists())
        with self.assertRaisesRegex(manager.SingboxConfigError, "recovery required"):
            manager.mutate_config(lambda data, registry: None)
        partial_files = self.files()
        with self.assertRaisesRegex(manager.SingboxConfigError, "recovery required"):
            manager.update_proxy_metadata("customer", {"countryCode": "US"})
        self.assertEqual(self.files(), partial_files)
        self.assertTrue(rev.recover_pending_revision())
        self.assertEqual(self.files(), before)
        self.assertFalse(rev.JOURNAL_PATH.exists())
        self.assertFalse(rev.recover_pending_revision())

    def test_crash_after_state_write_before_commit_restores_prior_state(self):
        self.publish()
        before = self.files()
        original = tx._json_write
        def crash(path, value):
            original(path, value)
            if path == rev.STATE_PATH:
                raise SystemExit("fixture crash")
        with patch.object(tx, "_json_write", side_effect=crash):
            with self.assertRaises(SystemExit):
                self.publish("two")
        rev.recover_pending_revision()
        self.assertEqual(self.files(), before)

    def test_crash_after_commit_retains_new_bundle(self):
        self.publish()
        original = tx._json_write
        def crash(path, value):
            original(path, value)
            if path == rev.JOURNAL_PATH and value.get("phase") == "committed":
                raise SystemExit("fixture crash after durable commit")
        with patch.object(tx, "_json_write", side_effect=crash):
            with self.assertRaises(SystemExit):
                self.publish("two")
        committed = self.files()
        rev.recover_pending_revision()
        self.assertEqual(self.files(), committed)
        self.assertTrue(rev.get_revision_state()["filesVerified"])

    def test_recovery_failure_retains_journal_and_never_claims_restored(self):
        self.publish()
        self.reload_singbox.return_value = False
        with self.assertRaisesRegex(manager.SingboxConfigError, "recovery required"):
            self.publish("two")
        self.assertEqual(rev.get_revision_state()["status"], "recovery-required")
        self.assertTrue(rev.JOURNAL_PATH.exists())
        self.reload_singbox.return_value = True
        self.assertTrue(rev.recover_pending_revision())
        self.assertEqual(rev.get_revision_state()["currentRevisionId"], "one")

    def test_failed_explicit_rollback_restores_newer_registry_state_and_files(self):
        self.publish("one")
        self.publish("two", "2027-02-01T00:00:00+00:00")
        before = self.files()
        self.reload_singbox.side_effect = [False, True]
        with self.assertRaisesRegex(manager.SingboxConfigError, "rollback failed"):
            rev.rollback_to_last_known_good()
        self.assertEqual(self.files(), before)
        self.assertFalse(rev.JOURNAL_PATH.exists())

    def test_pending_journal_blocks_reload_and_startup_before_collectors(self):
        from test_next_stage import main
        self.publish()
        with patch.object(manager, "_write_registry", side_effect=SystemExit("fixture crash")):
            with self.assertRaises(SystemExit):
                self.publish("two")
        with patch.object(main, "reload_singbox") as reload:
            with self.assertRaisesRegex(manager.SingboxConfigError, "recovery required"):
                main.singbox_reload("fixture-token")
            reload.assert_not_called()
        with patch.object(rev, "recover_pending_revision", side_effect=manager.SingboxConfigError("recovery required")), \
                patch.object(main, "start_traffic_collector") as collector:
            with self.assertRaises(manager.SingboxConfigError):
                main.startup_tasks()
            collector.assert_not_called()

    def test_publication_and_normal_mutation_use_one_lock(self):
        self.publish()
        entered, release, mutation_started, mutated = (threading.Event() for _ in range(4))
        def pause_reload():
            entered.set()
            if not release.wait(3):
                raise RuntimeError("fixture timeout")
            return True
        def mutation():
            mutation_started.set()
            return manager.mutate_config(lambda data, registry: mutated.set())
        with patch.object(rev, "reload_singbox", side_effect=pause_reload), \
                patch.object(manager, "read_config", side_effect=lambda: json.loads(self.config_path.read_text())):
            with ThreadPoolExecutor(max_workers=2) as pool:
                applying = pool.submit(self.publish, "two")
                self.assertTrue(entered.wait(3))
                mutating = pool.submit(mutation)
                self.assertTrue(mutation_started.wait(3))
                self.assertFalse(mutated.wait(.05))
                release.set()
                self.assertTrue(applying.result(timeout=3)["success"])
                mutating.result(timeout=3)
        self.assertTrue(mutated.is_set())
