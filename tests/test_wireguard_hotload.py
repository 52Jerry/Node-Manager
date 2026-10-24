import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
import wireguard_hotload as hotload


def config(port=hotload.BASE_PORT, sources=None):
    return {
        "inbounds": [{"tag": "wg-tproxy", "type": "tproxy", "listen_port": port}],
        "route": {"rules": [{"source_ip_cidr": [source]} for source in (sources or [])]},
    }


def record(port, value, created_at=100.0):
    body = json.dumps(hotload._canonical_config(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return {"port": port, "createdAt": created_at, "sha256": hashlib.sha256(body).hexdigest()}


def state_for(*ports, active=None, legacy_marked=True):
    ports = ports or (hotload.BASE_PORT,)
    return {
        "version": 1,
        "activePort": active if active is not None else ports[0],
        "legacyMarked": legacy_marked,
        "generations": [record(port, config(port)) for port in ports],
    }


class HotloadFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state_path = self.root / "state.json"
        self.state_patch = patch.object(hotload, "STATE_PATH", self.state_path)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)


class StateTests(HotloadFixture):
    def test_legacy_migration_skips_already_pinned_live_flows(self):
        entries = [{"source": ipaddress.ip_address("10.77.0.42"), "mark": 0x01000178}]
        routes = Mock(_valid_source=lambda value: value)
        with (patch.object(hotload, "_conntrack_entries", side_effect=[entries, entries]),
              patch.object(hotload, "_run") as run):
            hotload._migrate_legacy({"peer": {"address": "10.77.0.42/32"}}, routes)
        run.assert_not_called()

    def test_legacy_migration_accepts_update_race_only_after_fresh_mark_verification(self):
        before = [{"source": ipaddress.ip_address("10.77.0.42"), "mark": 0x178}]
        after = [{"source": ipaddress.ip_address("10.77.0.42"), "mark": 0x01000178}]
        error = RuntimeError("no entries updated"); error.code = "GATEWAY_CONNTRACK_EXIT_1"
        for current in (after, []):
            with self.subTest(current=current), patch.object(hotload, "_conntrack_entries", side_effect=[before,current,current]), patch.object(hotload, "_run", side_effect=error):
                hotload._migrate_legacy({"peer": {"address": "10.77.0.42/32"}}, Mock(_valid_source=lambda value:value))

    def test_legacy_migration_does_not_ignore_failed_update_with_unpinned_flows(self):
        before = [{"source": ipaddress.ip_address("10.77.0.42"), "mark": 0x178}]
        error = RuntimeError("update rejected"); error.code = "GATEWAY_CONNTRACK_EXIT_1"
        with (patch.object(hotload, "_conntrack_entries", side_effect=[before,before]),
              patch.object(hotload, "_run", side_effect=error)):
            with self.assertRaises(hotload.HotloadPendingError):
                hotload._migrate_legacy({"peer": {"address": "10.77.0.42/32"}}, Mock(_valid_source=lambda value:value))

    def test_legacy_migration_does_not_accept_unreadable_fresh_state(self):
        before = [{"source": ipaddress.ip_address("10.77.0.42"), "mark": 0x178}]
        error = RuntimeError("update rejected"); error.code = "GATEWAY_CONNTRACK_EXIT_1"
        with (patch.object(hotload, "_conntrack_entries", side_effect=[before,OSError("failed")]),
              patch.object(hotload, "_run", side_effect=error)):
            with self.assertRaises(hotload.HotloadPendingError):
                hotload._migrate_legacy({"peer": {"address": "10.77.0.42/32"}}, Mock(_valid_source=lambda value:value))

    def test_state_rejects_duplicate_generations_and_unmarked_promotion(self):
        duplicate = state_for(hotload.BASE_PORT, hotload.BASE_PORT + 1)
        duplicate["generations"][1]["port"] = hotload.BASE_PORT
        with self.assertRaises(ValueError):
            hotload._validate_state(duplicate)

        unmarked = state_for(hotload.BASE_PORT, hotload.BASE_PORT + 1,
                             active=hotload.BASE_PORT + 1, legacy_marked=False)
        with self.assertRaises(ValueError):
            hotload._validate_state(unmarked)

    def test_nft_precheck_rejects_notrack_and_ct_mark_write(self):
        cases = (
            '{"nftables":[{"rule":{"expr":[{"notrack":null}]}}]}',
            '{"nftables":[{"rule":{"expr":[{"mangle":{"key":{"ct":{"key":"mark"}},'
            '"value":{"concat":[]}}}]}}]}',
        )
        for output in cases:
            with self.subTest(output=output), patch.object(hotload, "_run", return_value=output):
                with self.assertRaises(hotload.HotloadPendingError):
                    hotload._check_nft_ownership()

    def test_nft_precheck_allows_empty_ruleset_and_fails_closed_on_tool_error(self):
        with patch.object(hotload, "_run", return_value='{"nftables":[]}'):
            hotload._check_nft_ownership()
        with patch.object(hotload, "_run", side_effect=OSError("nft unavailable")):
            with self.assertRaises(hotload.HotloadPendingError):
                hotload._check_nft_ownership()

    def test_legacy_mark_raw_notrack_and_mangle_conflicts_fail_closed(self):
        with patch.object(hotload, "_conntrack_entries", return_value=[
                {"source": ipaddress.ip_address("192.0.2.1"), "mark": 0x02000000}]), \
                self.assertRaises(hotload.HotloadPendingError):
            hotload._check_initial_mark_ownership()
        with patch.object(hotload, "_run", return_value="-A PREROUTING -j NOTRACK\n"), \
                self.assertRaises(hotload.HotloadPendingError):
            hotload._check_raw_notrack()
        with patch.object(hotload, "_run", return_value=(
                "-A PREROUTING -j CONNMARK --set-xmark 0x02000000/0xff000000\n")), \
                self.assertRaises(hotload.HotloadPendingError):
            hotload._check_mangle_mark_ownership()

    def test_retry_mark_check_allows_only_our_base_cookie_on_owned_sources(self):
        managed = ipaddress.ip_address("10.77.0.42")
        expected = [{"source": managed, "mark": (hotload.BASE_COOKIE << 24) | 0x1234}]
        with patch.object(hotload, "_conntrack_entries", return_value=expected):
            hotload._check_initial_mark_ownership({managed})
        conflict = expected + [{"source": ipaddress.ip_address("192.0.2.1"), "mark": 0x02000000}]
        with patch.object(hotload, "_conntrack_entries", return_value=conflict):
            with self.assertRaises(hotload.HotloadPendingError):
                hotload._check_initial_mark_ownership({managed})

    def test_legacy_migration_assigns_base_cookie_and_preserves_low_mark_bits(self):
        source = ipaddress.ip_address("10.77.0.42")
        before = [{"source": source, "mark": 0x1234}]
        after = [{"source": source, "mark": (hotload.BASE_COOKIE << 24) | 0x1234}]
        routes = Mock()
        routes._valid_source.side_effect = lambda value: value
        with (patch.object(hotload, "_conntrack_entries", side_effect=[before, after]),
              patch.object(hotload, "_run") as run):
            hotload._migrate_legacy({"peer": {"address": "10.77.0.42/32"}}, routes)
        self.assertIn("--mark", run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][-1], "0x01000000/0xff000000")

    def test_candidate_start_failure_is_stopped_and_never_persisted(self):
        routes = Mock()
        routes.SINGBOX = "/usr/bin/sing-box"
        rendered = config(sources=["10.77.0.48/32"])

        def run(args, timeout=15):
            if args[0] == routes.SINGBOX:
                return ""
            if args[1] == "start":
                raise RuntimeError("service failed")
            if args[1] == "show":
                return "inactive\n"
            return ""

        with (patch.object(hotload, "_active_unit", return_value=False),
              patch.object(hotload, "_run", side_effect=run) as run_mock):
            with self.assertRaises(hotload.HotloadPendingError):
                hotload._start_new_candidate(routes, state_for(), rendered, self.root / "base.json")

        self.assertFalse(hotload.read_state())
        self.assertIn("stop", [entry.args[0][1] for entry in run_mock.call_args_list
                                if len(entry.args[0]) > 1])

    def test_legacy_retry_rechecks_ownership_before_migration(self):
        base = config(sources=["10.77.0.42/32"])
        routes = Mock()
        routes.CONFIG_PATH = self.root / "base.json"
        routes._eligible_sources.return_value = ["10.77.0.42/32"]
        routes._can_reuse_loaded_config.return_value = True
        routes.CONFIG_PATH.write_text(json.dumps(base), encoding="utf-8")
        state = {"version": 1, "activePort": hotload.BASE_PORT, "legacyMarked": False,
                 "generations": [record(hotload.BASE_PORT, base)]}
        hotload._write_state(state)

        with (patch.object(hotload, "_routes", return_value=routes),
              patch.object(hotload, "_check_raw_notrack") as raw_check,
              patch.object(hotload, "_check_initial_mark_ownership") as mark_check,
              patch.object(hotload, "_check_nft_ownership") as nft_check,
              patch.object(hotload, "_check_mangle_mark_ownership") as mangle_check,
              patch.object(hotload, "_migrate_legacy") as migrate):
            hotload.sync_routes({}, base, {}, {})

        raw_check.assert_called_once()
        mark_check.assert_called_once_with(set())
        nft_check.assert_called_once()
        mangle_check.assert_called_once()
        migrate.assert_called_once()
        self.assertTrue(hotload.read_state(required=True)["legacyMarked"])

    def test_capacity_exhaustion_does_not_choose_a_tracked_slot(self):
        state = state_for(*range(hotload.BASE_PORT, hotload.PORT_LIMIT), active=hotload.BASE_PORT)
        with patch.object(hotload, "_active_unit") as active_check:
            self.assertIsNone(hotload._allocate_port(state))
        active_check.assert_not_called()

    def test_full_slot_pool_never_starts_or_stops_a_service(self):
        state = state_for(*range(hotload.BASE_PORT, hotload.PORT_LIMIT), active=hotload.BASE_PORT)
        routes = Mock()
        routes.SINGBOX = "/usr/bin/sing-box"
        with (patch.object(hotload, "_run") as run,
              self.assertRaises(hotload.HotloadPendingError)):
            hotload._start_new_candidate(routes, state, config(sources=["10.77.0.49/32"]),
                                         self.root / "base.json")
        run.assert_not_called()


class StartupTests(HotloadFixture):
    def test_base_readiness_uses_the_non_template_service_and_its_listeners(self):
        listeners = (
            f"tcp LISTEN 0 4096 0.0.0.0:{hotload.BASE_PORT} 0.0.0.0:* "
            "users:((\"sing-box\",pid=4321,fd=7))\n"
            f"udp UNCONN 0 0 [::]:{hotload.BASE_PORT} [::]:* "
            "users:((\"sing-box\",pid=4321,fd=8))\n"
        )
        with patch.object(hotload, "_run", side_effect=["4321\n", listeners]) as run:
            self.assertTrue(hotload._ready(hotload.BASE_PORT))
        self.assertEqual(hotload._service(hotload.BASE_PORT), "niusu-wireguard-proxy.service")
        self.assertEqual(run.call_args_list[0].args[0][2], "niusu-wireguard-proxy.service")

    def test_candidate_waits_for_delayed_listeners_before_persisting(self):
        routes = Mock()
        routes.SINGBOX = "/usr/bin/sing-box"
        rendered = config(sources=["10.77.0.44/32"])
        current = state_for()

        with (patch.object(hotload, "_active_unit", side_effect=[False, True]),
              patch.object(hotload, "_ready", side_effect=[False, True]) as ready,
              patch.object(hotload, "_run", return_value="") as run,
              patch.object(hotload.time, "sleep") as sleep):
            candidate = hotload._start_new_candidate(routes, current, rendered,
                                                     self.root / "base.json")

        self.assertEqual(candidate, hotload.BASE_PORT + 1)
        self.assertEqual(ready.call_count, 2)
        sleep.assert_called_once_with(0.1)
        self.assertEqual([item["port"] for item in hotload.read_state(True)["generations"]],
                         [hotload.BASE_PORT, candidate])
        self.assertNotIn("stop", [command[1] for command in run.call_args_list
                                   if len(command[0][0]) > 1])

    def test_crashed_active_candidate_is_started_before_any_route_update(self):
        routes = Mock()
        routes.CONFIG_PATH = self.root / "base.json"
        routes._eligible_sources.return_value = ["10.77.0.45/32"]
        routes._can_reuse_loaded_config.return_value = True
        base = config(sources=["10.77.0.44/32"])
        active_config = config(hotload.BASE_PORT + 1, ["10.77.0.45/32"])
        routes.CONFIG_PATH.write_text(json.dumps(base), encoding="utf-8")
        generation_path = hotload._generation_path(routes.CONFIG_PATH, hotload.BASE_PORT + 1)
        generation_path.parent.mkdir(parents=True)
        generation_path.write_text(json.dumps(active_config), encoding="utf-8")
        state = {"version": 1, "activePort": hotload.BASE_PORT + 1, "legacyMarked": True,
                 "generations": [record(hotload.BASE_PORT, base),
                                 record(hotload.BASE_PORT + 1, active_config)]}
        hotload._write_state(state)

        def firewall_update(*args, **kwargs):
            self.assertEqual(readiness.call_count, 2)

        routes._sync_firewall.side_effect = firewall_update
        readiness = Mock(side_effect=[False, True])
        with (patch.object(hotload, "_routes", return_value=routes),
              patch.object(hotload, "_wait_ready", readiness),
              patch.object(hotload, "_active_unit", return_value=False),
              patch.object(hotload, "_run", return_value="") as run):
            hotload.sync_routes({}, active_config, {}, {})

        self.assertIn(call(["systemctl", "start", hotload._service(hotload.BASE_PORT + 1)], timeout=30),
                      run.call_args_list)
        routes._sync_firewall.assert_called_once()

    def test_active_unready_candidate_is_left_running_without_restart(self):
        with (patch.object(hotload, "_wait_ready", side_effect=[False, True]),
              patch.object(hotload, "_active_unit", return_value=True),
              patch.object(hotload, "_run", return_value="") as run):
            with self.assertRaises(hotload.HotloadPendingError):
                hotload._ensure_active_generation_ready(hotload.BASE_PORT + 1)
        run.assert_not_called()


class DrainTests(HotloadFixture):
    def test_conntrack_empty_accepts_kernel_summary_but_not_flows_or_errors(self):
        with patch.object(hotload, "_run", return_value="conntrack v1.4.7 (conntrack-tools): 0 flow entries have been shown.\n"):
            self.assertTrue(hotload._conntrack_empty(hotload.BASE_PORT + 1))
        with patch.object(hotload, "_run", return_value="tcp 6 431999 ESTABLISHED src=192.0.2.1 mark=0x02000000\n"):
            self.assertFalse(hotload._conntrack_empty(hotload.BASE_PORT + 1))
        with patch.object(hotload, "_run", side_effect=OSError("conntrack missing")):
            self.assertFalse(hotload._conntrack_empty(hotload.BASE_PORT + 1))

    def test_process_drain_ignores_only_generation_listeners(self):
        port = hotload.BASE_PORT + 1
        properties = "MainPID=1234\nActiveState=active\n"
        listeners = (
            f"tcp LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:* users:((\"sing-box\",pid=1234,fd=7))\n"
            f"udp UNCONN 0 0 [::]:{port} [::]:* users:((\"sing-box\",pid=1234,fd=8))\n"
        )
        with patch.object(hotload, "_run", side_effect=[properties, listeners]):
            self.assertTrue(hotload._process_drained(port))

        established = listeners + (
            f"tcp ESTAB 0 0 192.0.2.1:45000 192.0.2.2:443 users:((\"sing-box\",pid=1234,fd=9))\n"
        )
        with patch.object(hotload, "_run", side_effect=[properties, established]):
            self.assertFalse(hotload._process_drained(port))

    def test_process_drain_fails_closed_on_queries_and_accepts_inactive_unit(self):
        port = hotload.BASE_PORT + 1
        with patch.object(hotload, "_run", side_effect=OSError("systemctl failed")):
            self.assertFalse(hotload._process_drained(port))
        with patch.object(hotload, "_run", return_value="ActiveState=inactive\nMainPID=0\n"):
            self.assertTrue(hotload._process_drained(port))

    def test_retirement_requires_conntrack_and_process_drain_and_never_stops_base(self):
        base, retired = hotload.BASE_PORT, hotload.BASE_PORT + 1
        state = state_for(base, retired, active=base)
        hotload._write_state(state)
        old = self.state_path.stat().st_mtime - hotload.MIN_DRAIN_SECONDS - 1
        import os
        os.utime(self.state_path, (old, old))
        config_path = self.root / "base.json"

        with (patch.object(hotload, "_conntrack_empty", return_value=True),
              patch.object(hotload, "_process_drained", return_value=False),
              patch.object(hotload, "_run") as run):
            unchanged = hotload._retire_inactive(copy.deepcopy(state), config_path)
        self.assertEqual(len(unchanged["generations"]), 2)
        run.assert_not_called()

        with (patch.object(hotload, "_conntrack_empty", return_value=True),
              patch.object(hotload, "_process_drained", return_value=True),
              patch.object(hotload, "_run", side_effect=["", "inactive\n"]) as run):
            reduced = hotload._retire_inactive(copy.deepcopy(state), config_path)
        self.assertEqual([item["port"] for item in reduced["generations"]], [base])
        stopped = [entry.args[0] for entry in run.call_args_list if entry.args[0][1] == "stop"]
        self.assertEqual(stopped, [["systemctl", "stop", hotload._service(retired)]])


class PromotionTests(HotloadFixture):
    def test_firewall_failure_rolls_back_to_old_active_generation(self):
        routes = Mock()
        routes._eligible_sources.side_effect = lambda value: value["sources"]
        routes._sync_firewall.side_effect = [RuntimeError("switch failed"), None]
        old = state_for(hotload.BASE_PORT)
        rendered = {"sources": ["10.77.0.46/32", "10.77.0.47/32"]}
        old_config = {"sources": ["10.77.0.46/32"]}

        with self.assertRaises(hotload.HotloadPendingError):
            hotload._promote(routes, {}, rendered, {}, {}, old, old_config, hotload.BASE_PORT + 1)

        self.assertEqual(routes._sync_firewall.call_count, 2)
        rollback = routes._sync_firewall.call_args_list[1]
        self.assertEqual(rollback.kwargs["active_sources"], ["10.77.0.46/32"])
        self.assertEqual(rollback.kwargs["hotload_state"]["activePort"], hotload.BASE_PORT)

    def test_state_commit_failure_restores_old_active_and_keeps_prepared_candidate(self):
        routes = Mock()
        routes._eligible_sources.side_effect = lambda value: value["sources"]
        old = state_for(hotload.BASE_PORT, hotload.BASE_PORT + 1, active=hotload.BASE_PORT)
        rendered = {"sources": ["10.77.0.51/32"]}
        old_config = {"sources": ["10.77.0.50/32"]}
        hotload._write_state(old)
        write_state = hotload._write_state

        def fail_promoted_state(candidate):
            if candidate["activePort"] == hotload.BASE_PORT + 1:
                raise OSError("state volume temporarily unavailable")
            write_state(candidate)

        with (patch.object(hotload, "_write_state", side_effect=fail_promoted_state),
              patch.object(hotload, "_run") as run):
            with self.assertRaises(hotload.HotloadPendingError):
                hotload._promote(routes, {}, rendered, {}, {}, old, old_config, hotload.BASE_PORT + 1)

        persisted = hotload.read_state(required=True)
        self.assertEqual(persisted["activePort"], hotload.BASE_PORT)
        self.assertIn(hotload.BASE_PORT + 1, [item["port"] for item in persisted["generations"]])
        self.assertEqual(routes._sync_firewall.call_count, 2)
        self.assertEqual(routes._sync_firewall.call_args_list[0].kwargs["hotload_state"]["activePort"],
                         hotload.BASE_PORT + 1)
        self.assertEqual(routes._sync_firewall.call_args_list[1].kwargs["hotload_state"]["activePort"],
                         hotload.BASE_PORT)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
