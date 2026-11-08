import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

APP_ROOT = Path(__file__).resolve().parents[1] / "node-manager"
sys.path.insert(0, str(APP_ROOT))

import monitor.health_check as health_check


class StopAfterWaits:
    def __init__(self, count):
        self.count = count
        self.waits = 0

    def is_set(self):
        return self.waits >= self.count

    def wait(self, _timeout):
        self.waits += 1
        return self.waits >= self.count


class HealthCheckTests(unittest.TestCase):
    def setUp(self):
        with health_check._lock:
            self.failures_before = dict(health_check._failure_counts)
            self.dead_before = health_check._dead_outbounds.copy()
            health_check._failure_counts.clear()
            health_check._dead_outbounds.clear()

    def tearDown(self):
        with health_check._lock:
            health_check._failure_counts.clear()
            health_check._failure_counts.update(self.failures_before)
            health_check._dead_outbounds.clear()
            health_check._dead_outbounds.update(self.dead_before)

    @staticmethod
    def outbound(user="test-user", **updates):
        return {"tag": "node-manager-out:" + user, "server": "socks.invalid", "port": 1080, **updates}

    def run_rounds(self, snapshots, results=(), fail_threshold=2):
        stop_event = StopAfterWaits(len(snapshots))
        with patch.object(health_check, "stop_event", stop_event), \
                patch.object(health_check, "_extract_outbounds", side_effect=snapshots), \
                patch.object(health_check, "_check_tcp", side_effect=results):
            health_check._health_check_loop(1, fail_threshold, 0.1, 1)

    def test_fail_threshold_records_dead_proxy_and_checker_continues(self):
        stop_event = StopAfterWaits(2)
        failures_before = dict(health_check._failure_counts)
        dead_before = health_check._dead_outbounds.copy()
        checker_errors = []
        health_check._failure_counts.clear()
        health_check._dead_outbounds.clear()

        def run_checker():
            try:
                health_check._health_check_loop(
                    interval=1,
                    fail_threshold=2,
                    tcp_timeout=0.1,
                    batch_size=1,
                )
            except BaseException as exc:
                checker_errors.append(exc)

        try:
            with patch.object(health_check, "stop_event", stop_event), \
                    patch.object(health_check, "_extract_outbounds", return_value=[{
                        "tag": "node-manager-out:test-user",
                        "server": "socks.invalid",
                        "port": 1080,
                    }]), \
                    patch.object(health_check, "_check_tcp", return_value=False):
                checker = threading.Thread(target=run_checker, daemon=True)
                checker.start()
                checker.join(timeout=3)

            self.assertFalse(checker.is_alive(), "checker did not stop after the test signal")
            self.assertEqual(checker_errors, [])
            self.assertEqual(stop_event.waits, 2, "checker stopped before completing both rounds")
            self.assertEqual(health_check.get_dead_outbounds(), [{
                "userId": "test-user",
                "tag": "node-manager-out:test-user",
                "server": "socks.invalid",
                "port": 1080,
                "failCount": 2,
            }])
        finally:
            health_check._failure_counts.clear()
            health_check._failure_counts.update(failures_before)
            health_check._dead_outbounds.clear()
            health_check._dead_outbounds.update(dead_before)

    def test_repeated_failures_keep_one_unresolved_record_and_one_new_warning(self):
        outbound = self.outbound()
        with patch.object(health_check.logger, "warning") as warning:
            self.run_rounds([[outbound]] * 8, [False] * 8)
        self.assertEqual(len(health_check.get_dead_outbounds()), 1)
        self.assertEqual(health_check.get_dead_outbounds()[0]["failCount"], 2)
        self.assertEqual(sum(call.args[0].startswith("DEAD OUTBOUNDS DETECTED")
                             for call in warning.call_args_list), 1)

    def test_bulk_outage_keeps_full_review_list_but_bounds_log_samples(self):
        outbounds = [self.outbound(str(user)) for user in range(200)]
        with patch.object(health_check.logger, "warning") as warning:
            self.run_rounds([outbounds], [False] * 200, fail_threshold=1)
        self.assertEqual(len(health_check.get_dead_outbounds()), 200)
        self.assertEqual(warning.call_count, 12)
        self.assertEqual(sum("[DEAD]" in call.args[0] for call in warning.call_args_list), 10)

    def test_recovery_removes_unresolved_failure_and_resets_threshold(self):
        outbound = self.outbound()
        self.run_rounds([[outbound]] * 4, [False, False, True, False])
        self.assertEqual(health_check.get_dead_outbounds(), [])
        self.assertEqual(health_check._failure_counts, {outbound["tag"]: 1})
        health_check._record_probe_result(outbound, False, 2)
        self.assertEqual(len(health_check.get_dead_outbounds()), 1)

    def test_empty_valid_configuration_prunes_removed_and_pending_failures(self):
        health_check._record_probe_result(self.outbound("dead"), False, 1)
        health_check._record_probe_result(self.outbound("pending"), False, 2)
        self.run_rounds([[]])
        self.assertEqual(health_check.get_dead_outbounds(), [])
        self.assertEqual(health_check._failure_counts, {})

    def test_configuration_read_failure_keeps_prior_unresolved_state(self):
        health_check._record_probe_result(self.outbound(), False, 1)
        self.run_rounds([None])
        self.assertEqual(len(health_check.get_dead_outbounds()), 1)
        with patch.object(health_check, "read_config", side_effect=OSError("unreadable")):
            self.assertIsNone(health_check._extract_outbounds())

    def test_removed_tag_is_pruned_while_remaining_tag_is_retained(self):
        kept = self.outbound("kept")
        removed = self.outbound("removed")
        health_check._record_probe_result(kept, False, 1)
        health_check._record_probe_result(removed, False, 1)
        self.run_rounds([[kept]], [False], fail_threshold=1)
        self.assertEqual([item["tag"] for item in health_check.get_dead_outbounds()], [kept["tag"]])

    def test_record_limit_preserves_recent_failures_and_refreshes_existing_tag(self):
        with patch.object(health_check, "MAX_DEAD_OUTBOUNDS", 3):
            for user in range(5):
                health_check._record_probe_result(self.outbound(str(user)), False, 1)
            self.assertEqual([item["userId"] for item in health_check.get_dead_outbounds()], ["2", "3", "4"])
            health_check._record_probe_result(self.outbound("2", port=1081), False, 1)
            health_check._record_probe_result(self.outbound("5"), False, 1)
        records = health_check.get_dead_outbounds()
        self.assertEqual([item["userId"] for item in records], ["4", "2", "5"])
        self.assertEqual(records[1]["port"], 1081)

    def test_public_records_are_copies_and_manual_clear_keeps_api_shape(self):
        health_check._record_probe_result(self.outbound(), False, 1)
        records = health_check.get_dead_outbounds()
        records[0]["server"] = "changed.invalid"
        records.clear()
        self.assertEqual(health_check.get_dead_outbounds()[0]["server"], "socks.invalid")
        health_check.clear_dead_outbounds()
        self.assertEqual(health_check.get_dead_outbounds(), [])

    def test_heartbeat_read_does_not_wait_for_network_probe(self):
        probe_started = threading.Event()
        release_probe = threading.Event()
        reader_done = threading.Event()

        def blocking_probe(*_args):
            probe_started.set()
            if not release_probe.wait(2):
                raise AssertionError("test did not release TCP probe")
            return False

        with patch.object(health_check, "stop_event", StopAfterWaits(1)), \
                patch.object(health_check, "_extract_outbounds", return_value=[self.outbound()]), \
                patch.object(health_check, "_check_tcp", side_effect=blocking_probe):
            checker = threading.Thread(target=health_check._health_check_loop, args=(1, 2, 0.1, 1))
            reader = threading.Thread(target=lambda: (health_check.get_dead_outbounds(), reader_done.set()))
            checker.start()
            try:
                self.assertTrue(probe_started.wait(1), "TCP probe did not start")
                reader.start()
                self.assertTrue(reader_done.wait(1), "heartbeat read waited on TCP probe")
            finally:
                release_probe.set()
                checker.join(3)
                if reader.ident is not None:
                    reader.join(3)
        self.assertFalse(checker.is_alive())

    @staticmethod
    def executor_factory(created):
        executor_type = health_check.concurrent.futures.ThreadPoolExecutor

        def create(**kwargs):
            executor = executor_type(**kwargs)
            executor.shutdown = Mock(wraps=executor.shutdown)
            created.append(executor)
            return executor

        return create

    def test_one_executor_is_reused_across_batches_and_check_rounds(self):
        outbounds = [self.outbound(str(user)) for user in range(5)]
        created = []
        factory = self.executor_factory(created)
        as_completed = health_check.concurrent.futures.as_completed
        with patch.object(health_check, "stop_event", StopAfterWaits(2)), \
                patch.object(health_check, "_extract_outbounds", return_value=outbounds), \
                patch.object(health_check, "_check_tcp", return_value=True) as probe, \
                patch.object(health_check.concurrent.futures, "ThreadPoolExecutor", side_effect=factory) as constructor, \
                patch.object(health_check.concurrent.futures, "as_completed", wraps=as_completed) as batches:
            health_check._health_check_loop(1, 2, 0.1, 2)
        constructor.assert_called_once_with(max_workers=2, thread_name_prefix="health-probe")
        self.assertEqual(probe.call_count, 10)
        self.assertEqual([len(call.args[0]) for call in batches.call_args_list], [2, 2, 1, 2, 2, 1])
        created[0].shutdown.assert_called_once_with(wait=True)

    def test_stop_after_current_batch_prevents_submitting_next_batch(self):
        stop_event = threading.Event()
        outbounds = [self.outbound(str(user)) for user in range(5)]
        created = []
        factory = self.executor_factory(created)

        def stop_during_probe(*_args):
            stop_event.set()
            return True

        with patch.object(health_check, "stop_event", stop_event), \
                patch.object(health_check, "_extract_outbounds", return_value=outbounds) as extract, \
                patch.object(health_check, "_check_tcp", side_effect=stop_during_probe) as probe, \
                patch.object(health_check.concurrent.futures, "ThreadPoolExecutor", side_effect=factory):
            health_check._health_check_loop(1, 2, 0.1, 2)
        self.assertEqual(probe.call_count, 2, "a later batch was submitted after stop")
        extract.assert_called_once_with()
        created[0].shutdown.assert_called_once_with(wait=True)

    def test_executor_is_closed_on_probe_error_and_workers_remain_capped(self):
        created = []
        factory = self.executor_factory(created)
        with patch.object(health_check, "stop_event", StopAfterWaits(1)), \
                patch.object(health_check, "_extract_outbounds", return_value=[self.outbound()]), \
                patch.object(health_check, "_check_tcp", side_effect=RuntimeError("probe failed")), \
                patch.object(health_check.concurrent.futures, "ThreadPoolExecutor", side_effect=factory) as constructor:
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                health_check._health_check_loop(1, 2, 0.1, 100)
        constructor.assert_called_once_with(max_workers=50, thread_name_prefix="health-probe")
        created[0].shutdown.assert_called_once_with(wait=True)


if __name__ == "__main__":
    unittest.main()
