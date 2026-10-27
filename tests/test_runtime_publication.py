"""Fault injection for the single-process publication protocol, without systemd."""
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_next_stage import manager, main, traffic, base_singbox_config
import revision as rev
import revision_transaction as tx
import runtime_publication as publication
from singbox.runtime_client import RuntimeClient, RuntimeUnavailable, RuntimeRejected


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class FakeRuntime:
    def __init__(self, data):
        self.data = copy.deepcopy(data)
        self.revision = 0
        self.instance = "fixture-process"
        self.mode = "normal"
        self.offline = False
        self.pending = None
        self.puts = 0
        self.fences = 0
        self.native = []
    def status(self):
        if self.offline:
            raise RuntimeUnavailable("fixture runtime unavailable")
        return {"instanceId": self.instance, "revision": self.revision, "contentHash": fingerprint(self.data)}
    def apply(self, body):
        if body["expectedInstanceId"] != self.instance:
            raise RuntimeRejected(409)
        if fingerprint(body["config"]) != fingerprint(self.data):
            if body["expectedRevision"] != self.revision:
                raise RuntimeRejected(409)
            self.data = copy.deepcopy(body["config"])
            self.revision += 1
        return {**self.status(), "closedSessions": 0, "cleanupPending": False}
    def request(self, method, path, body=None):
        if path == "preview":
            return {"runtime": self.status(), "contentHash": fingerprint(body["config"]),
                    "supported": self.mode != "unsupported"}
        if path == "status":
            return self.status()
        if path == "counters":
            self.status()
            return {"instanceId": self.instance, "users": copy.deepcopy(self.native)}
        if path == "fence":
            self.fences += 1
            if body["expectedInstanceId"] != self.instance or body["expectedRevision"] != self.revision:
                raise RuntimeRejected(409)
            self.revision += 1
            return self.status()
        if path in {"users", "configuration"}:
            self.puts += 1
            if self.mode == "reject":
                raise RuntimeRejected(422)
            if self.mode == "timeout_before":
                self.pending = copy.deepcopy(body)
                raise RuntimeUnavailable("fixture timeout")
            if self.mode == "disconnect_before":
                self.pending = copy.deepcopy(body)
                self.offline = True
                raise RuntimeUnavailable("fixture timeout")
            receipt = self.apply(body)
            if self.mode in {"timeout_after", "disconnect_after"}:
                self.offline = self.mode == "disconnect_after"
                raise RuntimeUnavailable("fixture lost receipt")
            return receipt
        raise AssertionError(path)


class RuntimePublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "singbox.json"
        self.registry_path = self.root / "users.json"
        self.config = base_singbox_config()
        self.config["inbounds"][2]["require_auth"] = True
        self.config["outbounds"] = [{"type": "direct", "tag": "direct"}]
        self.config["route"]["final"] = "direct"
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.registry_path.write_text(json.dumps({"version": 2, "users": {}}), encoding="utf-8")
        self.fake = FakeRuntime(self.config)
        patches = [patch.dict(os.environ, {"NODE_MANAGER_SINGBOX_RUNTIME_SOCKET": str(self.root / "runtime.sock"),
                    "NODE_MANAGER_RUNTIME_STATE_DIR": str(self.root / "runtime")}),
                   patch.object(manager, "CONFIG_PATH", self.config_path),
                   patch.object(manager, "REGISTRY_PATH", self.registry_path),
                   patch.object(rev, "CONFIG_PATH", self.config_path),
                   patch.object(rev, "check_config", return_value=(True, "")),
                   patch.object(RuntimeClient, "_request", side_effect=self.fake.request),
                   patch.object(manager, "_run", side_effect=AssertionError("runtime mode invoked a subprocess")),
                   patch.object(traffic, "TRAFFIC_PATH", self.root / "traffic.json")]
        for name, filename in {"REVISIONS_DIR": "revisions", "STATE_PATH": "revisions/state.json",
            "CURRENT_PATH": "revisions/current.json", "LAST_GOOD_PATH": "revisions/last-good.json",
            "CURRENT_BUNDLE_PATH": "revisions/current.bundle.json", "LAST_GOOD_BUNDLE_PATH": "revisions/last-good.bundle.json",
            "JOURNAL_PATH": "revisions/transaction.json", "REJECTED_DIR": "revisions/rejected"}.items():
            patches.append(patch.object(rev, name, self.root / filename))
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.env_legacy = os.environ.pop("NODE_MANAGER_VLESS_PUBLICATION_SPEC", None)
        if self.env_legacy is not None:
            self.addCleanup(os.environ.__setitem__, "NODE_MANAGER_VLESS_PUBLICATION_SPEC", self.env_legacy)
        publication.initialize_locked()
    def create(self, user="customer"):
        return manager.create_user(user, ["socks", "vmess"], socks_username=user, socks_password="fixture-password")
    def files(self):
        return self.config_path.read_bytes(), self.registry_path.read_bytes()
    def test_create_delete_credentials_and_outbound_changes_use_one_runtime(self):
        self.create()
        self.assertIn("customer", manager.read_registry()["users"])
        self.assertEqual(manager.read_config(), self.fake.data)
        manager.mutate_config(lambda data, registry: data["inbounds"][2]["users"][0].update(password="rotated"))
        manager.delete_user("customer")
        self.assertEqual(self.fake.instance, "fixture-process")
        self.assertEqual(self.fake.data["inbounds"][2]["users"], [])
        self.assertTrue(self.fake.data["inbounds"][2]["require_auth"])
        self.assertEqual(self.fake.puts, 3)
        self.assertFalse(publication.paths()[0].exists())
    def test_confirmed_rejection_restores_files_and_never_reloads(self):
        before = self.files()
        self.fake.mode = "reject"
        with self.assertRaisesRegex(manager.SingboxConfigError, "rejected"):
            self.create()
        self.assertEqual(self.files(), before)
        self.assertEqual(self.fake.fences, 1)
        self.assertFalse(publication.paths()[0].exists())
    def test_journal_fsync_failure_after_replace_blocks_writes_until_recovery(self):
        before = self.files()
        original = publication.atomic
        def fail_after_journal_replace(path, *args, **kwargs):
            original(path, *args, **kwargs)
            if Path(path) == publication.paths()[0]:
                raise OSError("injected directory fsync failure")
        with patch.object(publication, "atomic", side_effect=fail_after_journal_replace):
            with self.assertRaises(publication.RuntimeRecoveryRequired):
                self.create()
        self.assertEqual(self.files(), before)
        self.assertEqual(self.fake.puts, 0)
        self.assertTrue(publication.paths()[0].exists())
        with self.assertRaises(publication.RuntimeRecoveryRequired):
            self.create("other")
        self.assertEqual(publication.recover_locked(), "unchanged")
        self.assertFalse(publication.paths()[0].exists())
    def test_runtime_capability_is_only_advertised_when_configured(self):
        self.assertIn("singbox.runtime.users.v1", main.get_agent_info("fixture")["capabilities"])
        with patch.dict(os.environ, {"NODE_MANAGER_SINGBOX_RUNTIME_SOCKET": ""}):
            self.assertNotIn("singbox.runtime.users.v1", main.get_agent_info("fixture")["capabilities"])
    def test_successful_recovery_does_not_query_runtime_again(self):
        original_receipt = publication._receipt
        original_recover = publication.recover_locked
        failed = False
        def fail_first_receipt(*args, **kwargs):
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("injected receipt write failure")
            return original_receipt(*args, **kwargs)
        def go_offline_after_recovery(**kwargs):
            result = original_recover(**kwargs)
            self.fake.offline = True
            return result
        with patch.object(publication, "_receipt", side_effect=fail_first_receipt), \
                patch.object(publication, "recover_locked", side_effect=go_offline_after_recovery):
            result = self.create()
        self.assertTrue(result["success"])
        self.assertEqual(manager.read_config(), self.fake.data)
        self.assertFalse(publication.paths()[0].exists())
    def test_journal_removal_sync_failure_keeps_committed_result(self):
        original_sync = publication.sync_dir
        journal = publication.paths()[0]
        def fail_after_unlink(path):
            if Path(path) == journal.parent and not journal.exists():
                raise OSError("injected journal deletion sync failure")
            return original_sync(path)
        with patch.object(publication, "sync_dir", side_effect=fail_after_unlink):
            result = self.create()
        self.assertTrue(result["success"])
        self.assertEqual(manager.read_config(), self.fake.data)
        self.assertFalse(journal.exists())
    def test_timeout_after_apply_is_verified_without_reapplying_or_rollback(self):
        self.fake.mode = "timeout_after"
        self.create()
        self.assertEqual(self.fake.puts, 1)
        self.assertEqual(self.files()[0], self.config_path.read_bytes())
        self.assertIn("customer", manager.read_registry()["users"])
        self.assertEqual(manager.read_config(), self.fake.data)
    def test_timeout_before_apply_fences_delayed_request_before_restoring_files(self):
        before = self.files()
        self.fake.mode = "timeout_before"
        with self.assertRaises(manager.SingboxConfigError):
            self.create()
        self.assertEqual(self.files(), before)
        self.assertEqual(self.fake.fences, 1)
        with self.assertRaises(RuntimeRejected):
            self.fake.apply(self.fake.pending)
        self.assertEqual(self.fake.data, self.config)
    def test_unknown_commit_blocks_mutations_and_rolls_forward_after_reconnect(self):
        self.fake.mode = "disconnect_after"
        with self.assertRaises(publication.RuntimeRecoveryRequired):
            self.create()
        self.assertTrue(publication.paths()[0].exists())
        with self.assertRaisesRegex(manager.SingboxConfigError, "recovery required"):
            self.create("second")
        self.fake.offline = False
        self.fake.mode = "normal"
        self.assertEqual(publication.recover_locked(), "applied")
        self.assertEqual(manager.read_config(), self.fake.data)
        self.assertIn("customer", manager.read_registry()["users"])
        self.assertEqual(self.fake.puts, 1)
    def test_unknown_not_applied_can_abort_and_late_put_cannot_resurrect_user(self):
        before = self.files()
        self.fake.mode = "disconnect_before"
        with self.assertRaises(publication.RuntimeRecoveryRequired):
            self.create()
        self.fake.offline = False
        self.assertEqual(publication.recover_locked(), "unchanged")
        self.assertEqual(self.files(), before)
        with self.assertRaises(RuntimeRejected):
            self.fake.apply(self.fake.pending)
    def test_crash_after_runtime_commit_recovers_all_files_without_another_put(self):
        original = publication._receipt
        with patch.object(publication, "_receipt", side_effect=SystemExit("fixture crash")):
            with self.assertRaises(SystemExit):
                self.create()
        self.assertTrue(publication.paths()[0].exists())
        self.assertEqual(publication.recover_locked(), "applied")
        self.assertEqual(self.fake.puts, 1)
        self.assertEqual(manager.read_config(), self.fake.data)
    def test_disk_failure_before_apply_restores_complete_bundle(self):
        before = self.files()
        original = publication.atomic
        def fail(path, data, *args, **kwargs):
            if Path(path) == self.registry_path and json.loads(data).get("users"):
                raise OSError("fixture disk failure")
            return original(path, data, *args, **kwargs)
        with patch.object(publication, "atomic", side_effect=fail):
            with self.assertRaisesRegex(manager.SingboxConfigError, "previous files restored"):
                self.create()
        self.assertEqual(self.files(), before)
        self.assertEqual(self.fake.puts, 0)
    def test_conflicting_external_runtime_retains_journal_and_does_not_overwrite(self):
        self.fake.mode = "disconnect_before"
        with self.assertRaises(publication.RuntimeRecoveryRequired):
            self.create()
        self.fake.offline = False
        self.fake.data["log"] = {"level": "warn"}
        with self.assertRaises(publication.RuntimeRecoveryRequired):
            publication.recover_locked()
        self.assertTrue(publication.paths()[0].exists())
        self.assertEqual(self.fake.data["log"], {"level": "warn"})
    def test_runtime_drift_and_unsupported_topology_fail_before_writes(self):
        before = self.files()
        self.fake.data["log"] = {"level": "warn"}
        with self.assertRaisesRegex(manager.SingboxConfigError, "drift"):
            self.create()
        self.assertEqual(self.files(), before)
        self.fake.data = copy.deepcopy(self.config)
        self.fake.mode = "unsupported"
        with self.assertRaisesRegex(manager.SingboxConfigError, "unsupported"):
            self.create()
        self.assertEqual(self.files(), before)
        self.assertFalse(publication.paths()[0].exists())
    def test_legacy_publisher_and_runtime_socket_cannot_mix(self):
        before = self.files()
        with patch.dict(os.environ, {"NODE_MANAGER_VLESS_PUBLICATION_SPEC": "fixture.json"}):
            with self.assertRaisesRegex(manager.SingboxConfigError, "cannot be enabled together"):
                self.create()
        self.assertEqual(self.files(), before)
    def test_related_traffic_is_staged_and_recovered_with_credentials(self):
        extra = self.root / "traffic.json"
        self.fake.mode = "disconnect_after"
        with publication.related_transaction():
            publication.stage_related(extra, {"fixture": "target"})
            with self.assertRaises(publication.RuntimeRecoveryRequired):
                self.create()
        self.assertEqual(json.loads(extra.read_text()), {"fixture": "target"})
        self.fake.offline = False
        publication.recover_locked()
        self.assertEqual(json.loads(extra.read_text()), {"fixture": "target"})
        self.assertIn("customer", manager.read_registry()["users"])
    def test_pending_transaction_cannot_be_bypassed_by_disabling_runtime_mode(self):
        self.fake.mode = "disconnect_after"
        with self.assertRaises(publication.RuntimeRecoveryRequired):
            self.create()
        with patch.dict(os.environ, {"NODE_MANAGER_SINGBOX_RUNTIME_SOCKET": ""}):
            with self.assertRaises(publication.RuntimeRecoveryRequired):
                self.create("other")
            with self.assertRaises(publication.RuntimeRecoveryRequired):
                publication.recover_locked()
    def test_revision_bundle_replay_rollback_and_running_hash_verification(self):
        desired = copy.deepcopy(self.config)
        desired["inbounds"][2]["users"] = [{"username": "customer", "password": "one"}]
        registry = {"version": 2, "users": {"customer": {"socksUsername": "customer"}}}
        def publish(revision):
            return rev.apply_desired_revision(desired, registry, rev._sign({"config": desired, "registry": registry}), revision, True)
        result = publish("one")
        self.assertEqual(result["verificationScope"], "files-and-runtime")
        desired["inbounds"][2]["users"][0]["password"] = "two"
        publish("two")
        self.assertTrue(publish("two")["replayed"])
        rev.rollback_to_last_known_good()
        self.assertEqual(self.fake.data["inbounds"][2]["users"][0]["password"], "one")
        with patch.object(rev, "is_singbox_running", return_value=True):
            self.assertTrue(rev.get_revision_state()["runtimeVerified"])
    def test_cumulative_counters_replace_connection_sampling_not_add_to_it(self):
        self.create()
        self.fake.native = [{"inbound": "socks", "user": "customer", "upload": 30, "download": 40}]
        snapshot = {"connections": [{"id": "connection", "chains": ["node-manager-out:customer"],
            "upload": 300, "download": 400, "metadata": {"sourceIP": "198.51.100.2"}}]}
        with patch.object(traffic.singbox_api, "get_connections", return_value=snapshot):
            self.assertTrue(traffic.collect_traffic())
            self.assertTrue(traffic.collect_traffic())
        usage = traffic._read_store()["users"]["customer"]
        self.assertEqual((usage["upload"], usage["download"]), (30, 40))
        manager.delete_user("customer")
        self.fake.native[0].update(upload=35, download=45)
        with patch.object(traffic.singbox_api, "get_connections", return_value={"connections": []}):
            self.assertTrue(traffic.collect_traffic())
        self.assertEqual(traffic._read_store()["users"]["customer"]["upload"], 35)
    def test_counter_capture_survives_missing_clash_snapshot(self):
        self.create()
        self.fake.native = [{"inbound": "socks", "user": "customer", "upload": 7, "download": 9}]
        with patch.object(traffic.singbox_api, "get_connections", return_value=None):
            self.assertFalse(traffic.collect_traffic())
        self.assertEqual(traffic._read_store()["users"]["customer"]["upload"], 7)
