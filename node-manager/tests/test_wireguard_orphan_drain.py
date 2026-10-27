import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from wireguard_drain import OrphanUdpWindow, socks_hosts, process_identity, residual_udp_fingerprint, tproxy_reply_inodes


def config():
    return {'inbounds': [{'type': 'tproxy', 'tag': 'wg-tproxy'}],
            'outbounds': [{'type': 'block'}, {'type': 'socks', 'server': '8.8.8.8'}]}


LISTEN = 'udp UNCONN 0 0 0.0.0.0:61043 0.0.0.0:* users:(("sing-box",pid=123,fd=3)) ino:1\n'
TCP_LISTEN = 'tcp LISTEN 0 4096 0.0.0.0:61043 0.0.0.0:* users:(("sing-box",pid=123,fd=4)) ino:2\n'
UDP = 'udp ESTAB 0 0 192.0.2.10:50000 8.8.8.8:23456 users:(("sing-box",pid=123,fd=5)) ino:3\n'
SOCKETS = LISTEN + TCP_LISTEN + UDP


class OrphanDrainTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.window = OrphanUdpWindow(clock=lambda: self.now)

    def observe(self, sockets=SOCKETS, pid=123, start='1000', digest='hash', inodes=None):
        return self.window.observe(61043, pid, start, digest, sockets, frozenset({'8.8.8.8'}),
                                   {'1', '2', '3'} if inodes is None else inodes)

    def test_two_observations_need_a_full_minute(self):
        self.assertFalse(self.observe()); self.now += 59.9; self.assertFalse(self.observe())
        self.now += 0.1; self.assertTrue(self.observe())

    def test_live_tcp_control_always_prevents_reclaim_and_resets_window(self):
        self.assertFalse(self.observe()); self.now += 61
        tcp = 'tcp ESTAB 0 0 192.0.2.10:50001 8.8.8.8:1080 users:(("sing-box",pid=123,fd=6)) ino:4\n'
        self.assertFalse(self.observe(SOCKETS + tcp, inodes={'1','2','3','4'}))
        self.assertFalse(self.observe()); self.now += 61; self.assertTrue(self.observe())

    def test_unowned_or_client_udp_is_never_classified_as_orphan(self):
        for remote in ['10.77.0.2:55555', '1.1.1.1:53']:
            self.assertFalse(self.observe(SOCKETS.replace('8.8.8.8:23456', remote)))

    def test_queued_datagrams_block_reclaim(self):
        for queue in ['1 0', '0 1']:
            self.assertFalse(self.observe(SOCKETS.replace('udp ESTAB 0 0', 'udp ESTAB ' + queue)))

    def test_missing_inode_ownership_blocks_reclaim(self):
        self.assertFalse(self.observe(inodes={'1','2','3','4'}))
        self.assertFalse(self.observe(SOCKETS.replace('ino:3', 'missing:3')))

    def test_shared_socket_blocks_reclaim(self):
        self.assertFalse(self.observe(SOCKETS.replace('pid=123,fd=5', 'pid=123,fd=5),("other",pid=456,fd=5')))

    def test_foreign_listener_blocks_reclaim(self):
        self.assertFalse(self.observe(SOCKETS + LISTEN.replace('pid=123', 'pid=999').replace('ino:1', 'ino:9')))

    def test_changed_pid_start_socket_or_config_restarts_observation(self):
        for changes in [{'start':'2000'}, {'digest':'new'}, {'sockets':SOCKETS.replace(':23456', ':23457')},
                        {'pid':124, 'sockets':SOCKETS.replace('pid=123','pid=124')}]:
            self.window = OrphanUdpWindow(clock=lambda: self.now)
            self.assertFalse(self.observe()); self.now += 61
            self.assertFalse(self.observe(**changes))

    def test_clearing_after_conntrack_activity_restarts_observation(self):
        self.assertFalse(self.observe()); self.now += 61; self.window.forget(61043)
        self.assertFalse(self.observe())

    def test_no_residual_udp_is_not_an_orphan_exception(self):
        self.assertFalse(self.observe(LISTEN + TCP_LISTEN, inodes={'1','2'}))

    def test_transparent_tproxy_reply_socket_requires_kernel_option_and_relay(self):
        reply='udp UNCONN 0 0 1.1.1.1:53 0.0.0.0:* users:(("sing-box",pid=123,fd=7)) ino:7\n inet-sockopt: ( mc_loop transparent )\n'
        self.assertFalse(self.observe(SOCKETS+reply,inodes={'1','2','3','7'}));self.now+=61
        self.assertTrue(self.observe(SOCKETS+reply,inodes={'1','2','3','7'}))
        self.assertFalse(self.observe(SOCKETS+reply.replace('transparent','freebind'),inodes={'1','2','3','7'}))
        self.assertFalse(self.observe(LISTEN+TCP_LISTEN+reply,inodes={'1','2','7'}))

    def test_only_standard_literal_socks5_configs_are_accepted(self):
        self.assertEqual(socks_hosts(config()), frozenset({'8.8.8.8'}))
        for field, value in [('version','4'), ('udp_over_tcp',True), ('udp_over_tcp',{}),
                              ('detour','direct'), ('netns','other'), ('server','relay.test')]:
            candidate = config(); candidate['outbounds'][1][field] = value
            with self.assertRaises((ValueError, TypeError)): socks_hosts(candidate)
        candidate = config(); candidate['dns'] = {}
        with self.assertRaises(ValueError): socks_hosts(candidate)

    def test_proc_crosscheck_excludes_unix_and_detects_missing_inet_tables(self):
        with tempfile.TemporaryDirectory() as folder:
            proc = Path(folder); process = proc/'123'; (process/'fd').mkdir(parents=True); (process/'net').mkdir()
            (process/'stat').write_text('123 (name with spaces) ' + ' '.join(['0']*19 + ['999'] + ['0']*5))
            (process/'fd'/'3').touch(); (process/'fd'/'4').touch()
            for table in ['tcp','tcp6','udp','udp6','raw','raw6']:
                (process/'net'/table).write_text('header\n' + (' '.join(['0']*9+['10'])+'\n' if table=='udp' else ''))
            with patch.object(Path, 'readlink', lambda path: Path('socket:[10]' if path.name=='3' else 'socket:[20]')):
                self.assertEqual(process_identity(123,proc), ('999', {'10'}))
                (process/'net'/'tcp6').unlink()
                with self.assertRaises(OSError): process_identity(123,proc)

    def test_reply_socket_must_be_nonlocal_in_same_namespace_with_empty_queues(self):
        import types
        reply='udp UNCONN 0 0 1.1.1.1:53 0.0.0.0:* users:(("sing-box",pid=123,fd=7)) ino:7\n'
        local=reply.replace('1.1.1.1','128.1.1.1').replace('ino:7','ino:8')
        with patch.object(Path,'readlink',return_value=Path('net:[123]')), \
             patch('wireguard_drain.subprocess.run',return_value=types.SimpleNamespace(stdout='1: eth0 inet 128.1.1.1/24 scope global')):
            self.assertEqual(tproxy_reply_inodes(123,SOCKETS+reply+local),frozenset({'7'}))
            self.assertEqual(tproxy_reply_inodes(123,reply.replace('0 0 1.1.1.1','1 0 1.1.1.1')),frozenset())
        with patch.object(Path,'readlink',side_effect=[Path('net:[123]'),Path('net:[999]')]):
            with self.assertRaises(ValueError):tproxy_reply_inodes(123,reply)

    def test_actual_hotload_hook_uses_window_and_rejects_new_tcp_activity(self):
        import types
        spec=importlib.util.spec_from_file_location('drain_hook_test',ROOT/'wireguard_hotload.py')
        hot=importlib.util.module_from_spec(spec);spec.loader.exec_module(hot)
        hot._orphan_udp_window=self.window
        state={'activePort':61046,'generations':[{'port':61043,'sha256':'hash'}]}
        def command(args,**kwargs):
            return 'ActiveState=active\nMainPID=123' if args[0]=='systemctl' else SOCKETS
        with patch.object(hot,'_run',side_effect=command),patch.object(hot,'read_state',return_value=state), \
             patch.object(hot,'_routes',return_value=types.SimpleNamespace(CONFIG_PATH='fixture.json')), \
             patch.object(hot,'_verify_generation_file',return_value=config()), \
             patch('wireguard_drain.process_identity',return_value=('1000',{'1','2','3'})), \
             patch('wireguard_drain.tproxy_reply_inodes',return_value=frozenset()):
            self.assertFalse(hot._process_drained(61043));self.now+=61
            self.assertTrue(hot._process_drained(61043))
            state['activePort']=61043
            self.assertFalse(hot._process_drained(61043))
            self.assertNotIn(61043,self.window.observations)

    def test_conntrack_reappearance_immediately_before_stop_blocks_gc(self):
        spec=importlib.util.spec_from_file_location('drain_race_test',ROOT/'wireguard_hotload.py')
        hot=importlib.util.module_from_spec(spec);spec.loader.exec_module(hot)
        with tempfile.TemporaryDirectory() as folder:
            import os
            path=Path(folder)/'state';path.write_text('{}');os.utime(path,(1,1))
            state={'activePort':61046,'generations':[{'port':61037},{'port':61043},{'port':61046}]}
            with patch.object(hot,'STATE_PATH',path),patch.object(hot,'_conntrack_empty',side_effect=[True,False]), \
                 patch.object(hot,'_process_drained',return_value=True),patch.object(hot,'_run') as commands:
                self.assertEqual(hot._retire_inactive(state,Path(folder)/'config'),state)
                commands.assert_not_called()

    def test_exact_port_maintenance_preserves_all_other_generations(self):
        import os
        spec=importlib.util.spec_from_file_location('drain_scope_test',ROOT/'wireguard_hotload.py')
        hot=importlib.util.module_from_spec(spec);spec.loader.exec_module(hot)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'state';path.write_text('{}');os.utime(path,(1,1))
            state={'activePort':61046,'generations':[{'port':61037},{'port':61039},{'port':61043},{'port':61046}]}
            def command(args,**kwargs):
                self.assertEqual(args[2],hot._service(61043));return 'inactive' if args[1]=='show' else ''
            with patch.object(hot,'STATE_PATH',path),patch.object(hot,'_conntrack_empty',return_value=True), \
                 patch.object(hot,'_process_drained',return_value=True),patch.object(hot,'_run',side_effect=command), \
                 patch.object(hot,'_write_state') as persisted:
                result=hot._retire_inactive(state,Path(folder)/'config',only_ports={61043})
                self.assertEqual(result['generations'],[{'port':61037},{'port':61039},{'port':61046}])
                persisted.assert_called_once_with(result)


if __name__ == '__main__': unittest.main(verbosity=2)
