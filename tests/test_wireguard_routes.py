import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "node-manager"))
import wireguard_routes as routes
import wireguard
import wireguard_hotload as hotload


class WireguardRouteConfigTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        marker = self.root / 'reuse-output-owned'
        marker.write_text(routes.OUTPUT_CHAIN + '\n', encoding='ascii')
        self.enterContext(patch.object(routes, 'OUTPUT_CHAIN_MARKER', marker))
        hot_marker = self.root / 'hotload-chain-owned'
        hot_marker.write_text(routes.HOTLOAD_CHAIN + '\n', encoding='ascii')
        self.enterContext(patch.object(routes, 'HOTLOAD_CHAIN_MARKER', hot_marker))
        self.enterContext(patch.object(hotload, 'STATE_PATH', self.root / 'hotload-state.json'))
        self.now = datetime.now(timezone.utc)
        self.user_id = "subscription-1"
        self.outbound = {
            "type": "socks", "tag": "node-manager-out:" + self.user_id,
            "server": "residential.invalid", "server_port": 1080,
            "username": "user", "password": "secret",
        }
        identity = {key: self.outbound.get(key) for key in (
            "type", "server", "server_port", "version", "username", "password", "detour")}
        fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        self.peers = {"peer-1": {
            "peerId": "peer-1", "publicKey": "ignored", "address": "10.77.0.2/32",
            "nodeUserId": self.user_id, "expiresAt": (self.now + timedelta(hours=1)).isoformat(),
            "exitFingerprint": fingerprint, "status": "ACTIVE",
        }}
        self.source = {"outbounds": [self.outbound]}
        self.registry = {"users": {self.user_id: {"expiresAt": (self.now + timedelta(hours=2)).isoformat()}}}

    def test_active_peer_maps_to_its_bound_socks_and_has_reject_fallback(self):
        result = routes.build_config(self.peers, self.source, self.registry, self.now)
        self.assertEqual(result["inbounds"][0]["listen_port"], routes.PORT)
        selected = [rule for rule in result["route"]["rules"] if rule.get("source_ip_cidr")]
        self.assertEqual(selected, [{
            "inbound": ["wg-tproxy"], "source_ip_cidr": ["10.77.0.2/32"], "outbound": "wg-egress-peer-1"}])
        self.assertEqual(result["outbounds"][1]["server"], "residential.invalid")
        self.assertEqual(result["route"]["final"], "wg-reject")
        self.assertEqual(result["outbounds"][1]["password"], "secret")

    def test_urltest_binding_clones_members_and_health_settings_with_unique_tags(self):
        aggregate_tag = "node-manager-out:" + self.user_id
        member_a = {
            "type": "socks", "tag": aggregate_tag + "-0", "server": "proxy-a.invalid",
            "server_port": 1080, "username": "a", "password": "secret-a",
        }
        member_b = {
            "type": "socks", "tag": aggregate_tag + "-1", "server": "proxy-b.invalid",
            "server_port": 1081, "username": "b", "password": "secret-b",
        }
        aggregate = {
            "type": "urltest", "tag": aggregate_tag,
            "outbounds": [member_a["tag"], member_b["tag"]],
            "url": "https://probe.invalid/generate_204", "interval": "30s", "tolerance": 25,
        }
        source = {"outbounds": [aggregate, member_a, member_b]}
        lookup = {outbound["tag"]: outbound for outbound in source["outbounds"]}
        fingerprint = wireguard._binding_from_snapshot(
            self.user_id, self.now + timedelta(minutes=30), self.registry, lookup, self.now)
        self.peers["peer-1"]["exitFingerprint"] = fingerprint
        renamed = {
            aggregate_tag: {**aggregate, "tag": aggregate_tag + "-renamed",
                            "outbounds": ["renamed-member-a", "renamed-member-b"]},
            "renamed-member-a": {**member_a, "tag": "renamed-member-a"},
            "renamed-member-b": {**member_b, "tag": "renamed-member-b"},
        }
        self.assertEqual(wireguard._binding_from_snapshot(
            self.user_id, self.now + timedelta(minutes=30), self.registry, renamed, self.now), fingerprint)

        result = routes.build_config(self.peers, source, self.registry, self.now)

        created = result["outbounds"][1:]
        members = created[:2]
        cloned_aggregate = created[2]
        self.assertEqual([item["server"] for item in members], ["proxy-a.invalid", "proxy-b.invalid"])
        self.assertEqual(len({item["tag"] for item in created}), 3)
        self.assertNotIn(member_a["tag"], {item["tag"] for item in created})
        self.assertNotIn(member_b["tag"], {item["tag"] for item in created})
        self.assertEqual(cloned_aggregate["type"], "urltest")
        self.assertEqual(cloned_aggregate["outbounds"], [item["tag"] for item in members])
        self.assertEqual(cloned_aggregate["url"], aggregate["url"])
        self.assertEqual(cloned_aggregate["interval"], "30s")
        self.assertEqual(cloned_aggregate["tolerance"], 25)
        self.assertEqual(result["route"]["rules"][1]["outbound"], cloned_aggregate["tag"])

    def test_urltest_with_missing_or_non_socks_member_is_rejected_and_not_routed(self):
        aggregate_tag = "node-manager-out:" + self.user_id
        aggregate = {"type": "urltest", "tag": aggregate_tag,
                     "outbounds": [aggregate_tag + "-0", aggregate_tag + "-missing"],
                     "url": "https://probe.invalid/", "interval": "30s", "tolerance": 25}
        member = {"type": "socks", "tag": aggregate_tag + "-0", "server": "proxy.invalid",
                  "server_port": 1080}
        source = {"outbounds": [aggregate, member]}
        lookup = {outbound["tag"]: outbound for outbound in source["outbounds"]}

        with self.assertRaises(wireguard.WireguardError):
            wireguard._binding_from_snapshot(
                self.user_id, self.now + timedelta(minutes=30), self.registry, lookup, self.now)
        result = routes.build_config(self.peers, source, self.registry, self.now)
        self.assertFalse(any(rule.get("source_ip_cidr") for rule in result["route"]["rules"]))

        aggregate["outbounds"][1] = "node-manager-out:" + self.user_id + "-1"
        source["outbounds"].append({"type": "direct", "tag": aggregate["outbounds"][1], "server": "ignored"})
        lookup = {outbound["tag"]: outbound for outbound in source["outbounds"]}
        with self.assertRaises(wireguard.WireguardError):
            wireguard._binding_from_snapshot(
                self.user_id, self.now + timedelta(minutes=30), self.registry, lookup, self.now)

    def test_expired_or_changed_binding_never_gets_an_outbound(self):
        peer = self.peers["peer-1"]
        peer["expiresAt"] = (self.now - timedelta(seconds=1)).isoformat()
        expired = routes.build_config(self.peers, self.source, self.registry, self.now)
        self.assertFalse(any(rule.get("source_ip_cidr") for rule in expired["route"]["rules"]))
        peer["expiresAt"] = (self.now + timedelta(hours=1)).isoformat()
        peer["exitFingerprint"] = "changed"
        changed = routes.build_config(self.peers, self.source, self.registry, self.now)
        self.assertFalse(any(rule.get("source_ip_cidr") for rule in changed["route"]["rules"]))

    def test_suspended_user_cannot_use_tproxy_egress_or_receive_a_peer_binding(self):
        self.registry["users"][self.user_id]["accessEnabled"] = False
        result = routes.build_config(self.peers, self.source, self.registry, self.now)
        self.assertFalse(any(rule.get("source_ip_cidr") for rule in result["route"]["rules"]))
        with self.assertRaises(wireguard.WireguardError):
            wireguard._binding_from_snapshot(
                self.user_id,
                self.now + timedelta(hours=1),
                self.registry,
                {self.outbound["tag"]: self.outbound},
                self.now,
            )

    def test_non_active_peer_is_never_routed(self):
        self.peers["peer-1"]["status"] = "REVOKED"
        result = routes.build_config(self.peers, self.source, self.registry, self.now)
        self.assertFalse(any(rule.get("source_ip_cidr") for rule in result["route"]["rules"]))

    def test_quarantine_preserves_other_existing_grants_and_does_not_restart(self):
        current = ('-A NIUSU_WGM_IN -i wg0 -s 10.77.0.2/32 -m mark --mark 0x178/0xffffffff -j ACCEPT\n'
                   '-A NIUSU_WGM_IN -i wg0 -s 10.77.0.3/32 -m mark --mark 0x178/0xffffffff -j ACCEPT\n')
        with patch.object(routes, '_run', side_effect=[current, '-A INPUT -j NIUSU_WGM_IN', '-A FORWARD -j NIUSU_WGM_FWD']) as run, \
                patch.object(routes, '_sync_firewall') as firewall:
            routes.quarantine_sources(self.peers, ['10.77.0.2/32'])
        firewall.assert_called_once_with(self.peers, active_sources=['10.77.0.3/32'])
        self.assertTrue(all(c.args[0][0] == 'iptables' for c in run.call_args_list))

    def test_quarantine_restores_missing_deny_jumps(self):
        with patch.object(routes, '_run', return_value=''), patch.object(routes, '_sync_firewall'), \
                patch.object(routes, '_iptables') as iptables:
            routes.quarantine_sources(self.peers, ['10.77.0.2/32'])
        self.assertEqual([c.args for c in iptables.call_args_list], [
            ('-I', 'INPUT', '1', '-i', 'wg0', '-j', 'NIUSU_WGM_IN'),
            ('-I', 'FORWARD', '1', '-i', 'wg0', '-j', 'NIUSU_WGM_FWD')])

    def test_unchanged_active_refresh_does_not_restart_proxy(self):
        rendered = routes.build_config(self.peers, self.source, self.registry, self.now)
        config_path = Path(self.enterContext(tempfile.TemporaryDirectory())) / 'singbox.json'
        config_path.write_text(json.dumps(rendered), encoding='utf-8')
        with patch.object(routes, 'CONFIG_PATH', config_path), patch.object(routes, '_valid_runtime', return_value=True), \
                patch.object(routes, '_sync_firewall') as firewall, patch.object(routes, '_run') as run:
            routes.sync_routes(self.peers, self.source, self.registry)
        run.assert_not_called()
        firewall.assert_called_once()

    def test_firewall_restore_batches_owned_chains_and_fails_closed(self):
        with patch.object(routes, "_managed_sources", return_value=(
                ["10.77.0.2/32", "10.77.0.3/32"], ["10.77.0.2/32"])):
            with patch.object(routes, "_run", return_value=""), \
                    patch.object(routes.subprocess, "run", return_value=subprocess.CompletedProcess(
                        args=[], returncode=0, stdout="", stderr="")) as run:
                routes._sync_firewall(self.peers)

        self.assertEqual(run.call_count, 2)
        test_call, apply_call = run.call_args_list
        self.assertIn("--noflush", test_call.args[0])
        self.assertIn("--test", test_call.args[0])
        self.assertIn("--noflush", apply_call.args[0])
        self.assertNotIn("--test", apply_call.args[0])
        self.assertEqual(test_call.kwargs["input"], apply_call.kwargs["input"])

        batch = apply_call.kwargs["input"]
        self.assertEqual(batch.count("*filter"), 1)
        self.assertEqual(batch.count("*mangle"), 1)
        self.assertIn("-F NIUSU_WGM_IN", batch)
        self.assertIn("-F NIUSU_WGM_FWD", batch)
        self.assertIn("-F NIUSU_WGM_PRE", batch)
        self.assertNotIn("-F INPUT", batch)
        self.assertNotIn("-F FORWARD", batch)
        self.assertNotIn("-F PREROUTING", batch)

        active_accept = (
            f"-A NIUSU_WGM_IN -i wg0 -s 10.77.0.2/32 -m mark --mark {routes.MARK} -j ACCEPT"
        )
        active_drop = "-A NIUSU_WGM_IN -s 10.77.0.2/32 -j DROP"
        inactive_drop = "-A NIUSU_WGM_IN -s 10.77.0.3/32 -j DROP"
        self.assertLess(batch.index(active_accept), batch.index(active_drop))
        self.assertIn(inactive_drop, batch)

        mangle = batch.split("*mangle\n", 1)[1].split("COMMIT", 1)[0]
        self.assertIn("-s 10.77.0.2/32 -p tcp -j TPROXY", mangle)
        self.assertIn("-s 10.77.0.2/32 -p udp -j TPROXY", mangle)
        self.assertNotIn("10.77.0.3/32", mangle)

    def test_real_route_change_uses_hotload_and_preserves_base_config(self):
        old_rendered = routes.build_config(self.peers, self.source, self.registry, self.now)
        old_bytes = json.dumps(old_rendered, separators=(",", ":")).encode("utf-8")
        self.source["outbounds"][0]["server_port"] = 1081
        identity = {key: self.source["outbounds"][0].get(key) for key in (
            "type", "server", "server_port", "version", "username", "password", "detour")}
        self.peers["peer-1"]["exitFingerprint"] = routes._binding_fingerprint(identity)
        config_path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "singbox.json"
        config_path.write_bytes(old_bytes)
        with patch.object(routes, "CONFIG_PATH", config_path), \
                patch.object(routes, "_valid_runtime", return_value=True), \
                patch.object(hotload, "sync_routes") as update, \
                patch.object(routes, "_run") as run:
            routes.sync_routes(self.peers, self.source, self.registry)

        self.assertEqual(config_path.read_bytes(), old_bytes)
        update.assert_called_once()
        self.assertEqual(update.call_args.args[1]['outbounds'][1]['server_port'], 1081)
        run.assert_not_called()

    def test_rejected_hotload_does_not_restart_or_overwrite_base(self):
        old_rendered = routes.build_config(self.peers, self.source, self.registry, self.now)
        config_path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "singbox.json"
        config_path.write_text(json.dumps(old_rendered), encoding="utf-8")
        self.source["outbounds"][0]["server_port"] = 1081
        identity = {key: self.source["outbounds"][0].get(key) for key in (
            "type", "server", "server_port", "version", "username", "password", "detour")}
        self.peers["peer-1"]["exitFingerprint"] = routes._binding_fingerprint(identity)
        with patch.object(routes, "CONFIG_PATH", config_path), \
                patch.object(routes, "_valid_runtime", return_value=True), \
                patch.object(hotload, "sync_routes", side_effect=RuntimeError('candidate unavailable')), \
                patch.object(routes, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, 'candidate unavailable'):
                routes.sync_routes(self.peers, self.source, self.registry)

        self.assertEqual(json.loads(config_path.read_text()), old_rendered)
        run.assert_not_called()

    def test_status_only_change_reuses_online_fix_without_starting_a_generation(self):
        old = routes.build_config(self.peers, self.source, self.registry, self.now)
        config_path = self.root / 'singbox.json'
        config_path.write_text(json.dumps(old), encoding='utf-8')
        self.registry['users'][self.user_id]['accessEnabled'] = False
        with patch.object(routes, 'CONFIG_PATH', config_path), \
                patch.object(routes, '_valid_runtime', return_value=True), \
                patch.object(routes, '_sync_firewall') as firewall, \
                patch.object(hotload, 'sync_routes') as update, \
                patch.object(routes, '_run') as run:
            routes.sync_routes(self.peers, self.source, self.registry)
        update.assert_not_called()
        run.assert_not_called()
        self.assertEqual(firewall.call_args.args[3], [])
        self.assertEqual(json.loads(config_path.read_text()), old)

    def test_persisted_generation_takes_precedence_over_unchanged_base_file(self):
        rendered = routes.build_config(self.peers, self.source, self.registry, self.now)
        config_path = self.root / 'singbox.json'
        config_path.write_text(json.dumps(rendered), encoding='utf-8')
        with patch.object(routes, 'CONFIG_PATH', config_path), \
                patch.object(routes, '_valid_runtime', return_value=True), \
                patch.object(hotload, 'read_state', return_value={'activePort': 61038}), \
                patch.object(hotload, 'sync_routes') as update:
            routes.sync_routes(self.peers, self.source, self.registry)
        update.assert_called_once()

    def test_hotload_marks_old_sessions_before_assigning_new_connections(self):
        state = {'activePort': 61038, 'generations': [{'port': 61037}, {'port': 61038}]}
        rules = routes._hotload_generation_rules(state)
        self.assertIn('RELATED,ESTABLISHED', rules[0])
        self.assertIn('0x1000000/0xff000000', rules[0])
        new_connections = rules[2]
        self.assertIn('0x0/0xff000000', new_connections)
        self.assertIn('0x2000000/0xff000000', new_connections)
        redirects = [rule for rule in rules if 'TPROXY' in rule]
        self.assertEqual(len(redirects), 4)
        self.assertEqual({rule[rule.index('--on-port') + 1] for rule in redirects}, {'61037', '61038'})
        self.assertTrue(all(rule[-1] == routes.MARK for rule in redirects))
        self.assertEqual(routes._hotload_prerouting_rules(['10.77.0.2/32'], state), [
            ['-i', 'wg0', '-s', '10.77.0.2/32', '-j', routes.HOTLOAD_CHAIN]])

    def test_quarantine_keeps_hotload_connection_routes_and_only_removes_target_grant(self):
        state = {'activePort': 61038, 'generations': [{'port': 61037}, {'port': 61038}]}
        with patch.object(hotload, 'read_state', return_value=state), \
                patch.object(routes, '_run', return_value=''), \
                patch.object(routes, '_iptables_restore') as restore:
            routes._sync_firewall(self.peers, active_sources=[])
        batch = restore.call_args.args[0]
        self.assertIn('-F NIUSU_WG_REUSE_OUT', batch)
        self.assertIn('-d 10.77.0.2/32 -j DROP', batch)
        self.assertNotIn('-j ACCEPT', batch)
        self.assertIn('--on-port 61037', batch)
        self.assertIn('--on-port 61038', batch)

    def test_generation_firewall_rejects_unknown_or_duplicate_ports(self):
        for ports in ([61037, 61037], [61037, 5001], [61037, 61045]):
            with self.subTest(ports=ports), self.assertRaises(RuntimeError):
                routes._hotload_prerouting_rules([], {
                    'activePort': ports[-1], 'generations': [{'port': port} for port in ports]})

    def test_base_readiness_requires_both_proxy_listeners(self):
        with patch.object(routes, '_valid_runtime', return_value=True), \
                patch.object(hotload, 'read_state', return_value=None), \
                patch.object(hotload, '_ready', return_value=False) as ready:
            self.assertFalse(routes.runtime_ready())
        ready.assert_called_once_with(routes.PORT)
        self.assertEqual(routes.runtime_failure_reason(), 'PROXY_LISTENER_UNREADY')

    def test_active_generation_death_is_visible_without_restarting_it(self):
        with patch.object(routes, '_valid_runtime', return_value=True), \
                patch.object(hotload, 'read_state', return_value={'activePort': 61038}), \
                patch.object(hotload, '_ready', return_value=False) as ready, \
                patch.object(hotload, '_ensure_active_generation_ready') as recover:
            self.assertFalse(routes.runtime_ready())
        ready.assert_called_once_with(61038)
        recover.assert_not_called()
        self.assertEqual(routes.runtime_failure_reason(), 'ACTIVE_GENERATION_UNREADY')

    def test_corrupt_generation_state_cannot_report_runtime_ready(self):
        with patch.object(routes, '_valid_runtime', return_value=True), \
                patch.object(hotload, 'read_state', side_effect=hotload.HotloadPendingError('invalid state')):
            self.assertFalse(routes.runtime_ready())
        self.assertEqual(routes.runtime_failure_reason(), 'HOTLOAD_STATE_UNAVAILABLE')

    def test_firewall_comparison_ignores_only_kernel_display_defaults(self):
        desired = ['-i', 'wg0', '-s', '10.77.0.2/32', '-m', 'mark', '--mark',
                   '0x178/0xffffffff', '-j', 'ACCEPT']
        shown = ['-s', '10.77.0.2/32', '-i', 'wg0', '-m', 'mark', '--mark', '0x178', '-j', 'ACCEPT']
        self.assertEqual(routes._canonical_firewall_rule(desired), routes._canonical_firewall_rule(shown))
        desired_tproxy = ['-i', 'wg0', '-p', 'tcp', '-j', 'TPROXY', '--on-port', '61038',
                          '--tproxy-mark', routes.MARK]
        shown_tproxy = ['-i', 'wg0', '-p', 'tcp', '-j', 'TPROXY', '--on-port', '61038',
                        '--on-ip', '0.0.0.0', '--tproxy-mark', routes.MARK]
        self.assertEqual(routes._canonical_firewall_rule(desired_tproxy),
                         routes._canonical_firewall_rule(shown_tproxy))
        different_port = [value if value != '61038' else '61039' for value in shown_tproxy]
        self.assertNotEqual(routes._canonical_firewall_rule(desired_tproxy),
                            routes._canonical_firewall_rule(different_port))


if __name__ == "__main__":
    unittest.main()
