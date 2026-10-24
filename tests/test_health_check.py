import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

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
    def test_fail_threshold_records_dead_proxy_and_checker_continues(self):
        stop_event = StopAfterWaits(2)
        failures_before = dict(health_check._failure_counts)
        dead_before = list(health_check._dead_outbounds)
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
            health_check._dead_outbounds.extend(dead_before)


if __name__ == "__main__":
    unittest.main()
