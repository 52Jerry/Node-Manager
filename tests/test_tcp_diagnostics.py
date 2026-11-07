import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("tcp_diagnostics", Path(__file__).parents[1] / "scripts/diagnose_tcp.py")
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class TCPDiagnosticTests(unittest.TestCase):
    def test_redirected_ingress_is_not_classified_as_upstream(self):
        self.assertEqual(diagnostics.classify("150.242.80.15:24168", "203.0.113.1:12345", "entry"), "user-to-entry")
        self.assertEqual(diagnostics.classify("10.44.0.1:20168", "10.44.0.32:12345", "hk"), "entry-to-hk")
        self.assertEqual(diagnostics.classify("168.93.208.118:55555", "198.51.100.2:7797", "hk"), "hk-to-residential")
        self.assertIsNone(diagnostics.classify("[::1]:8088", "[::1]:55555", "hk"))

    def test_churn_and_counter_reset_are_not_fabricated_as_zero_loss(self):
        old = {"same": {"group": "entry-to-hk", "segs_out": 20, "retrans": 2, "bytes_sent": 500}}
        fresh = {"new": {"group": "entry-to-hk", "segs_out": 30, "retrans": 0, "rtt": 1},
                 "same": {"group": "entry-to-hk", "segs_out": 5, "retrans": 0, "rtt": 2}}
        row = diagnostics.summarize(old, fresh)["entry-to-hk"]
        self.assertEqual(row["observedSockets"], 2)
        self.assertEqual(row["survivingSockets"], 0)
        self.assertIsNone(row["retransToSentPct"])

    def test_ratios_use_same_surviving_flow_denominator(self):
        before = {"flow": {"group": "hk-to-residential", "segs_out": 100, "retrans": 5, "bytes_sent": 1000}}
        after = {"flow": {"group": "hk-to-residential", "segs_out": 300, "retrans": 7, "bytes_sent": 2000, "rtt": 50}}
        row = diagnostics.summarize(before, after)["hk-to-residential"]
        self.assertEqual(row["retransToSentPct"], 1)
