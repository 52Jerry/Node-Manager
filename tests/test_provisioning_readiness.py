"""Admission checks must fail closed without changing customer configuration."""
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from test_next_stage import manager, main, base_singbox_config
import test_next_stage as fixtures
import provisioning_readiness as readiness


class ReadinessTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'config.json'
        self.data = base_singbox_config()
        self.path.write_text(json.dumps(self.data))
        for target, value in [('CONFIG_PATH', self.path)]:
            p = patch.object(manager, target, value); p.start(); self.addCleanup(p.stop)
        for target, value in [('_pid', 42), ('_identity', 123), ('_listeners', [
                {'network':'tcp','address':'::','port':port,'pids':{42}} for port in (20168, 20169, 5001)])]:
            p = patch.object(readiness, target, return_value=value); p.start(); self.addCleanup(p.stop)
        p = patch.dict(os.environ, {}, clear=False); p.start(); self.addCleanup(p.stop)
        os.environ.pop('NODE_MANAGER_VLESS_PUBLICATION_SPEC', None)

    def check(self, protocols=None):
        return readiness.readiness(protocols or ['vless', 'socks'])

    def test_verified_listener_and_guard_capability(self):
        result = self.check()
        self.assertEqual(result['state'], 'READY')
        self.assertTrue(result['createGuard'])
        self.assertEqual(result['protocols'], ['socks', 'vless'])

    def test_missing_inbound_is_disabled_without_observing_process(self):
        self.data['inbounds'].pop(0)
        self.path.write_text(json.dumps(self.data))
        self.assertEqual(self.check()['state'], 'DISABLED')
        readiness._pid.assert_not_called()

    def test_wrong_protocol_duplicate_tag_and_invalid_port_are_unknown(self):
        for invalid in [{'type':'vmess'}, {'listen_port':True}]:
            with self.subTest(invalid=invalid):
                value = base_singbox_config(); value['inbounds'][0].update(invalid)
                self.path.write_text(json.dumps(value))
                self.assertEqual(self.check()['state'], 'UNKNOWN')
        value = base_singbox_config(); value['inbounds'].append(value['inbounds'][0])
        self.path.write_text(json.dumps(value))
        self.assertEqual(self.check()['state'], 'UNKNOWN')

    def test_no_listener_and_wrong_or_hidden_owner_cannot_be_ready(self):
        for rows, state in [([], 'UNAVAILABLE'), ([{'network':'tcp','address':'::','port':20168,'pids':{9}}], 'UNKNOWN'),
                            ([{'network':'tcp','address':'::','port':20168,'pids':set()}], 'UNKNOWN')]:
            readiness._listeners.return_value = rows
            self.assertEqual(self.check(['vless'])['state'], state)

    def test_stopped_core_is_unavailable(self):
        readiness._pid.return_value = 0
        self.assertEqual(self.check()['state'], 'UNAVAILABLE')

    def test_loopback_listener_does_not_prove_a_wildcard_listener_is_ready(self):
        readiness._listeners.return_value = [{'network':'tcp','address':'127.0.0.1','port':20168,'pids':{42}}]
        self.assertEqual(self.check(['vless'])['state'], 'UNAVAILABLE')

    def test_observation_failures_and_malformed_metadata_are_unknown(self):
        for failure in [PermissionError('private'), subprocess.TimeoutExpired('ss',1), readiness.ObservationUnknown('private')]:
            readiness._listeners.side_effect = failure
            result = self.check()
            self.assertEqual(result['state'], 'UNKNOWN')
            self.assertNotIn('private', json.dumps(result))
        readiness._listeners.side_effect = None
        self.path.write_text('{"inbounds":[null]}')
        self.assertEqual(self.check()['state'], 'UNKNOWN')

    def test_config_changed_during_observation_or_not_expected_is_unknown(self):
        def change():
            self.path.write_text(json.dumps({'inbounds':[]}))
            return []
        readiness._listeners.side_effect = change
        self.assertEqual(self.check()['state'], 'UNKNOWN')
        self.assertEqual(readiness.readiness(['vless'], expected=self.data)['state'], 'UNKNOWN')

    def test_rolling_generation_requires_route_owner_and_immutable_config(self):
        generation = {'inbounds':[{'type':'vless','tag':'vless-reality','listen_port':31001,'listen':'127.0.0.1'}]}
        genpath = self.path.parent/'generation.json'; genpath.write_text(json.dumps(generation))
        state = {'phase':'steady','bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                 if os.name != 'nt' else 'boot', 'activeId':'a', 'generations':[
                    {'id':'a','pid':84,'startTicks':123,'unit':'niusu-vless-gen-012345abcdef.service',
                     'port':31001,'configPath':str(genpath),
                     'configHash':hashlib.sha256(json.dumps(generation,sort_keys=True,separators=(',',':')).encode()).hexdigest()}]}
        statepath=self.path.parent/'state.json'; statepath.write_text(json.dumps(state))
        specpath=self.path.parent/'spec.json'
        specpath.write_text(json.dumps({'enabled':True,'vlessTag':'vless-reality','statePath':str(statepath)}))
        os.environ['NODE_MANAGER_VLESS_PUBLICATION_SPEC']=str(specpath)
        rules='\n'.join(['-A NIUSU_VLESS_ACTIVE -p tcp --dport 20168 -j REDIRECT --to-ports 31001',
                         '-A PREROUTING -p tcp --dport 20168 -j NIUSU_VLESS_ACTIVE',
                         '-A OUTPUT -p tcp --dport 20168 -j NIUSU_VLESS_ACTIVE'])
        original = Path.read_text
        def read(path,*args,**kwargs):
            return state['bootId'] if path.as_posix()=='/proc/sys/kernel/random/boot_id' else original(path,*args,**kwargs)
        readiness._pid.side_effect=lambda unit: 42 if unit=='sing-box' else 84
        readiness._listeners.return_value=[{'network':'tcp','address':'127.0.0.1','port':31001,'pids':{84}}]
        with patch.object(Path,'read_text',read), patch.object(readiness,'_run',return_value=rules):
            self.assertEqual(self.check(['vless'])['state'],'READY')
            genpath.write_text('{}')
            self.assertEqual(self.check(['vless'])['state'],'UNKNOWN')
            genpath.write_text(json.dumps(generation))
            state['phase']='switching';statepath.write_text(json.dumps(state))
            self.assertEqual(self.check(['vless'])['state'],'UNKNOWN')

    def test_api_requires_auth_and_disables_response_cache(self):
        client=TestClient(main.app)
        self.assertEqual(client.get('/api/singbox/provisioning-readiness?protocols=vless').status_code,401)
        response=client.get('/api/singbox/provisioning-readiness?protocols=vless',headers={'Authorization':'Bearer test-token'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertEqual(response.json()['state'],'READY')
        response=client.get('/api/singbox/provisioning-readiness?protocols=invalid',headers={'Authorization':'Bearer test-token'})
        self.assertEqual(response.status_code,422)


class WriteGuardTest(unittest.TestCase):
    setUp = fixtures.ManagerTestCase.setUp
    tearDown = fixtures.ManagerTestCase.tearDown
    _write_config = fixtures.ManagerTestCase._write_config
    def test_disabled_listener_does_not_write_registry_or_publish_configuration(self):
        before=self.config_path.read_bytes()
        with patch.object(readiness,'readiness',return_value={'state':'DISABLED'}):
            with self.assertRaisesRegex(manager.SingboxConfigError,'PROVISIONING_DISABLED'):
                manager.create_user('guarded',['vless'],require_readiness=True)
        self.assertEqual(self.config_path.read_bytes(),before)
        self.assertFalse(self.registry_path.exists())
        self.write_mock.assert_not_called()

    def test_cached_create_is_rechecked_without_changing_idempotency_identity(self):
        client=TestClient(main.app)
        headers={'Authorization':'Bearer test-token','Idempotency-Key':'readiness-replay'}
        payload={'userId':'guarded-replay','protocols':['socks']}
        first=client.post('/api/user/create',json=payload,headers=headers)
        self.assertEqual(first.status_code,200,first.text)
        payload['requireReadiness']=True
        with patch.object(readiness,'assert_user_provisioning_allowed') as guard:
            second=client.post('/api/user/create',json=payload,headers=headers)
            self.assertEqual(second.status_code,200,second.text)
            self.assertEqual(second.headers['Idempotency-Replayed'],'true')
            guard.assert_called_once()
        with patch.object(readiness,'assert_user_provisioning_allowed',side_effect=manager.SingboxConfigError('PROVISIONING_DISABLED')):
            self.assertEqual(client.post('/api/user/create',json=payload,headers=headers).status_code,409)
