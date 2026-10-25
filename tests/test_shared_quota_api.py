import unittest
from datetime import datetime,timedelta,timezone
import test_next_stage as fixture
from test_next_stage import manager,traffic,main,TestClient


class SharedQuotaApiTests(unittest.TestCase):
    setUp=fixture.ManagerTestCase.setUp
    tearDown=fixture.ManagerTestCase.tearDown
    _write_config=fixture.ManagerTestCase._write_config

    def create(self):
        manager.create_user('user-1',['vless','socks'],socks_username='customer',socks_password='example-secret',
            traffic_limit_bytes=100,proxy={'server':'192.0.2.1','port':80,'username':'proxy','password':'proxy-secret'})

    def test_requires_auth_and_never_exports_auth_or_proxy_material(self):
        self.create();client=TestClient(main.app)
        self.assertEqual(client.post('/api/users/shared-quota/inspect',json={}).status_code,401)
        response=client.post('/api/users/shared-quota/inspect',json={},headers={'Authorization':'Bearer test-token'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertEqual(len(response.json()['users']),1)
        for secret in ['example-secret','proxy-secret','192.0.2.1','credential','password']:
            self.assertNotIn(secret,response.text)

    def test_single_bounded_apply_and_repeat_publish_rules_once(self):
        self.create();client=TestClient(main.app);headers={'Authorization':'Bearer test-token'}
        snapshot=client.post('/api/users/shared-quota/inspect',json={},headers=headers).json()
        native=next(row for row in snapshot['users'] if row['userId']=='user-1')
        source={k:v for k,v in native.items() if k not in ['peerObservedBytes','peerEvidenceCount']}
        source['userId']='source-1';source['nativeTotalBytes']=101
        body={'sourceNodeId':'other-node','observedAt':snapshot['observedAt'],
              'updates':[{'targetUserId':'user-1','expectedTargetEpochToken':source['epochToken'],'source':source}]}
        self.write_mock.reset_mock()
        first=client.post('/api/users/shared-quota/apply',json=body,headers=headers)
        second=client.post('/api/users/shared-quota/apply',json=body,headers=headers)
        self.assertEqual(first.status_code,200,first.text);self.assertEqual(second.status_code,200,second.text)
        self.assertEqual(first.json()['blockedUsers'],['user-1'])
        self.assertEqual(second.json()['updatedCount'],0)
        self.assertEqual(self.write_mock.call_count,1)
        self.assertEqual(traffic._read_store()['users']['user-1'].get('upload',0),0)
        self.assertTrue(manager.read_registry()['users']['user-1']['enforcementTrafficBlocked'])

    def test_other_users_are_not_changed(self):
        manager.create_user('independent',['vless'],traffic_limit_bytes=100)
        before=manager.read_registry()['users']['independent'].copy()
        self.test_single_bounded_apply_and_repeat_publish_rules_once()
        self.assertEqual(manager.read_registry()['users']['independent'],before)

    def test_existing_native_reset_route_is_registered_once(self):
        routes=[r for r in main.app.routes if getattr(r,'path',None)=='/api/user/{userId}/traffic/reset']
        self.assertEqual(len(routes),1)

    def test_future_cycle_is_rejected_without_writing_usage(self):
        self.create();traffic._write_store({'users':{'user-1':{'upload':8,'download':12}},'connections':{}})
        before=self.traffic_path.read_bytes()
        response=TestClient(main.app).post('/api/user/user-1/traffic/reset',
            json={'cycleStart':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()},
            headers={'Authorization':'Bearer test-token','Idempotency-Key':'future-cycle'})
        self.assertEqual(response.status_code,422)
        self.assertEqual(self.traffic_path.read_bytes(),before)

    def test_authorized_cycle_reset_clears_shared_proof_without_other_counter_or_baseline_changes(self):
        self.test_single_bounded_apply_and_repeat_publish_rules_once()
        store=traffic._read_store();store['users']['independent']={'upload':17,'download':23}
        store['connections']={'ongoing':{'userId':'user-1','upload':100,'download':200}}
        traffic._write_store(store)
        response=TestClient(main.app).post('/api/user/user-1/traffic/reset',
            json={'cycleStart':(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()},
            headers={'Authorization':'Bearer test-token','Idempotency-Key':'legitimate-cycle'})
        self.assertEqual(response.status_code,200,response.text)
        result=traffic._read_store()
        self.assertNotIn('sharedQuotaEvidence',result['users']['user-1'])
        self.assertIn('other-node',result['users']['user-1']['sharedQuotaRetiredSources'])
        self.assertEqual(result['users']['independent'],store['users']['independent'])
        self.assertEqual(result['connections'],store['connections'])
        self.assertFalse(manager.read_registry()['users']['user-1'].get('enforcementTrafficBlocked',False))


if __name__=='__main__':unittest.main()
