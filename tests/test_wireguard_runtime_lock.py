"""Concurrent lock model, not a real Linux xtables/iptables integration test."""
import base64
import copy
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
import wireguard as wg
import wireguard_routes as routes
import wireguard_hotload as hotload


class ConcurrentXtablesModel:
    """A real thread holds a Python lock; commands follow modeled -w semantics.

    The permanent-lock case waits the actual requested 5 seconds. No shell,
    network, Linux firewall, WireGuard interface, or system service is invoked.
    """

    def __init__(self, chain=None, release_after=0.03, missing=None, error=None):
        self.chain = chain
        self.release_after = release_after
        self.missing = missing
        self.error = error
        self.lock = threading.Lock()
        self.held = threading.Event()
        self.attempted = threading.Event()
        self.stop = threading.Event()
        self.calls = []
        self.contentions = []
        self.thread = None

    def __enter__(self):
        if self.chain is not None:
            def holder():
                with self.lock:
                    self.held.set()
                    self.attempted.wait(10)
                    self.stop.wait(self.release_after)
            self.thread = threading.Thread(target=holder, daemon=True)
            self.thread.start()
            if not self.held.wait(2):
                raise AssertionError("lock-holder thread did not start")
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.attempted.set()
        if self.thread:
            self.thread.join(2)
            if self.thread.is_alive():
                raise AssertionError("lock-holder thread did not stop")

    def run(self, args, **kwargs):
        self.calls.append((list(args), dict(kwargs)))
        if self.error is not None:
            raise self.error
        output = ""
        returncode = 0
        if args == ["ip", "-4", "rule", "show"]:
            output = "100: from all fwmark 0x178/0xffffffff lookup 178\n"
            if self.missing == "mark":
                output = "0: from all lookup local\n"
        elif args == ["ip", "-4", "route", "show", "table", "178"]:
            output = "local default dev lo scope host\n"
            if self.missing == "route":
                output = ""
        elif args == ["systemctl", "is-active", routes.SERVICE]:
            output = "inactive\n" if self.missing == "service" else "active\n"
        elif args == ["systemctl", "show", routes.SERVICE, "--property=MainPID", "--value"]:
            output = "4242\n"
        elif args == ["ss", "-H", "-lntup"]:
            output = ('tcp LISTEN 0 4096 0.0.0.0:61037 0.0.0.0:* users:(("sing-box",pid=4242,fd=1))\n'
                      'udp UNCONN 0 0 0.0.0.0:61037 0.0.0.0:* users:(("sing-box",pid=4242,fd=2))\n')
        elif args[0] == "iptables" and "-S" in args:
            chain = args[args.index("-S") + 1]
            managed = {"PREROUTING": "NIUSU_WGM_PRE", "INPUT": "NIUSU_WGM_IN",
                       "FORWARD": "NIUSU_WGM_FWD"}[chain]
            if chain == self.chain:
                wait = float(args[args.index("-w") + 1]) if "-w" in args else 0
                self.attempted.set()
                start = time.monotonic()
                acquired = self.lock.acquire(timeout=wait)
                self.contentions.append({"chain": chain, "wait": wait,
                                         "elapsed": time.monotonic() - start,
                                         "acquired": acquired})
                if acquired:
                    self.lock.release()
                else:
                    returncode = 4
            output = f"-A {chain} -j {managed}\n" if self.missing != chain else ""
        else:
            raise AssertionError("unmodeled external command: " + repr(args))
        return subprocess.CompletedProcess(args, returncode, output,
                                           "modeled xtables lock unavailable" if returncode else "")


class WireguardRuntimeLockTest(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(hotload, "STATE_PATH", root / "hotload-state.json"))
        self.keys = [base64.b64encode(bytes([i]) * 32).decode() for i in (1, 2, 3)]
        self.kernel = {self.keys[2]: ["10.99.0.1/32"]}
        self.kernel_commands = []
        now = datetime.now(timezone.utc)
        self.expiry = now + timedelta(hours=1)
        self.users = {"users": {f"user-{i}": {"expiresAt": (now + timedelta(days=1)).isoformat()}
                                for i in (1, 2)}}
        self.source = {"outbounds": [{"type": "socks", "tag": f"node-manager-out:user-{i}",
                                     "server": "192.0.2.1", "server_port": 1080}
                                    for i in (1, 2)]}
        for target, name, value in ((wg, "REGISTRY_PATH", root / "peers.json"),
                                    (wg, "LOCK_PATH", root / "peers.lock"),
                                    (wg.config.wireguard, "enabled", True),
                                    (wg.config.wireguard, "interface", "wg0")):
            self.enterContext(patch.object(target, name, value))
        self.enterContext(patch.object(wg.manager, "_config_lock", side_effect=nullcontext))
        self.enterContext(patch.object(wg.manager, "read_registry", side_effect=lambda: copy.deepcopy(self.users)))
        self.enterContext(patch.object(wg.manager, "read_config", side_effect=lambda: copy.deepcopy(self.source)))
        self.enterContext(patch.object(wg, "_invoke", side_effect=self.kernel_command))
        # Route mutation is independently covered by test_wireguard_routes.py.
        # Keep this fixture focused on the real runtime check -> reconcile path.
        self.enterContext(patch.object(wg, "_recovery_error", None))
        self.enterContext(patch.object(wg, "_quarantine_inactive"))
        self.enterContext(patch.object(routes, "quarantine_sources"))
        self.sync_routes = self.enterContext(patch.object(wg, "_sync_routes"))
        with patch.object(wg, "_runtime_ready", return_value=True):
            for i in (1, 2):
                address = f"10.77.0.{i + 1}/32"
                wg.apply_peer(f"peer-{i}", self.keys[i - 1], address, [address],
                              f"user-{i}", self.expiry)
        self.kernel_commands.clear()
        self.sync_routes.reset_mock()

    def kernel_command(self, args):
        self.kernel_commands.append(list(args))
        if args == ["show", "wg0", "public-key"]:
            return base64.b64encode(bytes([4]) * 32).decode()
        if args == ["show", "wg0", "allowed-ips"]:
            return "\n".join(key + "\t" + ",".join(addresses) for key, addresses in self.kernel.items())
        if args[:3] == ["set", "wg0", "peer"]:
            if args[4] == "remove":
                self.kernel.pop(args[3], None)
            elif args[4] == "allowed-ips":
                self.kernel[args[3]] = [args[5]]
            else:
                raise AssertionError("unmodeled wg command")
            return ""
        raise AssertionError("unmodeled wg command: " + repr(args))

    def assert_active(self):
        self.assertEqual({p["status"] for p in wg._read()["peers"].values()}, {"ACTIVE"})
        self.assertEqual(set(self.kernel), set(self.keys))
        self.assertFalse(any(cmd[0] == "set" for cmd in self.kernel_commands))

    def assert_retained_with_recovery_pending(self):
        self.assert_active()
        self.assertIsNotNone(wg._recovery_error)

    def check_temporary_lock(self, chain):
        with ConcurrentXtablesModel(chain) as model, patch.object(routes.subprocess, "run", side_effect=model.run):
            wg.reconcile()
        self.assert_active()
        self.assertEqual(len(model.contentions), 1)
        self.assertEqual(model.contentions[0]["wait"], 5)
        self.assertTrue(model.contentions[0]["acquired"])
        self.assertGreaterEqual(model.contentions[0]["elapsed"], 0.02)
        self.assertLess(model.contentions[0]["elapsed"], 5)

    def test_temporary_prerouting_lock_preserves_active(self):
        self.check_temporary_lock("PREROUTING")

    def test_temporary_input_lock_preserves_active(self):
        self.check_temporary_lock("INPUT")

    def test_temporary_forward_lock_preserves_active(self):
        self.check_temporary_lock("FORWARD")

    def test_permanent_lock_waits_five_seconds_then_retains_peers(self):
        with ConcurrentXtablesModel("PREROUTING", release_after=None) as model, \
                patch.object(routes.subprocess, "run", side_effect=model.run):
            with self.assertRaises(wg.WireguardError):
                wg.reconcile()
        self.assert_retained_with_recovery_pending()
        self.assertEqual(len(model.contentions), 1)
        self.assertFalse(model.contentions[0]["acquired"])
        self.assertGreaterEqual(model.contentions[0]["elapsed"], 4.9)
        self.assertLess(model.contentions[0]["elapsed"], 8)

    def test_missing_required_jumps_fail_readiness_without_peer_removal(self):
        for chain in ("PREROUTING", "INPUT", "FORWARD"):
            with self.subTest(chain=chain), ConcurrentXtablesModel(missing=chain) as model, \
                    patch.object(routes.subprocess, "run", side_effect=model.run):
                self.assertFalse(routes.runtime_ready())
        with ConcurrentXtablesModel(missing="INPUT") as model, \
                patch.object(routes.subprocess, "run", side_effect=model.run):
            with self.assertRaises(wg.WireguardError):
                wg.reconcile()
        self.assert_retained_with_recovery_pending()

    def test_missing_policy_route_still_unready(self):
        for missing in ("mark", "route"):
            with self.subTest(missing=missing), ConcurrentXtablesModel(missing=missing) as model, \
                    patch.object(routes.subprocess, "run", side_effect=model.run):
                self.assertFalse(routes.runtime_ready())

    def test_inactive_service_keeps_peers_for_recovery(self):
        with ConcurrentXtablesModel(missing="service") as model, \
                patch.object(routes.subprocess, "run", side_effect=model.run):
            with self.assertRaises(wg.WireguardError):
                wg.reconcile()
        self.assert_retained_with_recovery_pending()

    def test_subprocess_timeout_keeps_peers_for_recovery(self):
        with ConcurrentXtablesModel(error=subprocess.TimeoutExpired("modeled command", 15)) as model, \
                patch.object(routes.subprocess, "run", side_effect=model.run):
            with self.assertRaises(wg.WireguardError):
                wg.reconcile()
        self.assert_retained_with_recovery_pending()

    def test_missing_executable_keeps_peers_for_recovery(self):
        with ConcurrentXtablesModel(error=OSError("modeled missing executable")) as model, \
                patch.object(routes.subprocess, "run", side_effect=model.run):
            with self.assertRaises(wg.WireguardError):
                wg.reconcile()
        self.assert_retained_with_recovery_pending()

    def test_healthy_runtime_still_preserves_active(self):
        with ConcurrentXtablesModel() as model, patch.object(routes.subprocess, "run", side_effect=model.run):
            wg.reconcile()
        self.assert_active()
        self.assertEqual(len(model.calls), 8)
        self.assertTrue(all(kwargs["timeout"] == 15 for _, kwargs in model.calls[:6]))
        self.assertTrue(all(0 < kwargs["timeout"] <= 2 for _, kwargs in model.calls[6:]))

    def test_exited_generation_does_not_prevent_route_recovery(self):
        with patch.object(wg, "_runtime_ready", return_value=False), \
                patch.object(wg, "_runtime_failure_reason", return_value="ACTIVE_GENERATION_UNREADY"):
            wg.reconcile()
        self.sync_routes.assert_called_once()
        self.assert_active()
        self.assertIsNone(wg._recovery_error)


if __name__ == "__main__":
    unittest.main()
