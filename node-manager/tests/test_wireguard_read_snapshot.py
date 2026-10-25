"""Exercise captured-production snapshot candidates without node access."""
import ast,base64,copy,importlib.util,json,sys,tempfile,threading,types,unittest
from pathlib import Path
from unittest.mock import patch,Mock

REPO=Path(__file__).resolve().parents[1]
config=types.SimpleNamespace(wireguard=types.SimpleNamespace(enabled=True,interface='wg0',command='wg'))
manager=types.ModuleType('singbox.manager')
manager.CONFIG_PATH=Path('config.json');manager.REGISTRY_PATH=Path('users.json')
manager.USER_OUTBOUND_PREFIX='proxy-';manager.SingboxConfigError=type('SingboxConfigError',(RuntimeError,),{})
manager._discover_user_ids=lambda source,users:set(users['users'])
spec=importlib.util.spec_from_file_location('snapshot_test_wireguard',REPO/'wireguard.py')
wg=importlib.util.module_from_spec(spec)
with patch.dict(sys.modules,{'config':types.SimpleNamespace(config=config),'singbox':types.SimpleNamespace(manager=manager)}):
 spec.loader.exec_module(wg)

class SnapshotTests(unittest.TestCase):
 def setUp(self):
  self.public=base64.b64encode(bytes(range(32))).decode()
  self.peer={'peerId':'sub-246-node-8','publicKey':self.public,'address':'10.77.1.2/32','allowedIps':['10.77.1.2/32'],'nodeUserId':'primary-246','expiresAt':'2099-01-01T00:00:00+00:00','status':'ACTIVE','exitFingerprint':'x'}
  self.data={'version':1,'interface':'wg0','peers':{self.peer['peerId']:self.peer}}
  self.patches=[]
  def mock(name,value):
   p=patch.object(wg,name,value);p.start();self.patches.append(p)
  mock('_read',Mock(return_value=self.data));mock('_kernel',Mock(return_value={self.public:['10.77.1.2/32']}))
  mock('_delivery_versions',Mock(return_value=('stable',)));mock('_runtime_ready',Mock(return_value=True))
  mock('_interface_addresses',Mock(return_value=['10.77.0.1/16']));mock('_runtime_failure_reason',Mock(return_value='DOWN'))
  mock('_locked',Mock(side_effect=AssertionError('must not wait for reconcile lock')))
  mock('_write',Mock(side_effect=AssertionError('must not write')));mock('_sync_routes',Mock(side_effect=AssertionError('must not sync')))
  def invoke(args):
   self.assertEqual(args[0],'show')
   return {'public-key':self.public,'latest-handshakes':self.public+' 123','transfer':self.public+' 5 7'}[args[-1]]
  mock('_invoke',Mock(side_effect=invoke));mock('_recovery_error',None)
  self.source={'outbounds':[{'tag':'proxy-good','type':'socks','server':'198.51.100.1','server_port':1080}]}
  self.users={'users':{'good':{'expiresAt':'2099-01-01T00:00:00+00:00','accessEnabled':True}}}
  manager.read_config=Mock(side_effect=lambda:copy.deepcopy(self.source))
  manager.read_registry=Mock(side_effect=lambda:copy.deepcopy(self.users))
  mock('_read_binding_snapshot',Mock(side_effect=lambda:(manager.read_config(),manager.read_registry())))
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
 def test_status_is_fresh_kernel_checked_and_no_mutation(self):
  result=wg.status();p=result['peers'][0]
  self.assertTrue(result['routingReady']);self.assertTrue(p['kernelPresent']);self.assertEqual((p['receiveBytes'],p['transmitBytes']),(5,7))
  wg._read.assert_called_once();wg._runtime_ready.assert_called_once();wg._locked.assert_not_called();wg._write.assert_not_called()
 def test_status_returns_while_actual_reconcile_mutex_is_held(self):
  results=[]
  wg._mutex.acquire()
  try:
   t=threading.Thread(target=lambda:results.append(wg.status()));t.start();t.join(1)
   self.assertFalse(t.is_alive());self.assertTrue(results[0]['success'])
  finally:wg._mutex.release()
 def test_status_retries_mixed_generation_once(self):
  wg._delivery_versions.side_effect=[1,2,2,2]
  self.assertTrue(wg.status()['success']);self.assertEqual(wg._read.call_count,2)
 def test_status_two_mixed_generations_fail_retryably(self):
  wg._delivery_versions.side_effect=[1,2,3,4]
  with self.assertRaises(wg.WireguardError) as e:wg.status()
  self.assertEqual(e.exception.code,'DELIVERY_SNAPSHOT_CHANGED')
 def test_status_recovery_change_retries(self):
  def ready():wg._recovery_error='RECOVERY';return True
  wg._runtime_ready.side_effect=ready
  result=wg.status();self.assertFalse(result['routingReady']);self.assertEqual(result['recoveryReason'],'RECOVERY');self.assertEqual(wg._read.call_count,2)
 def test_status_missing_kernel_is_not_hidden(self):
  wg._kernel.return_value={};self.assertFalse(wg.status()['peers'][0]['kernelPresent'])
 def test_status_runtime_failure_is_not_cached_or_hidden(self):
  wg._runtime_ready.return_value=False;r=wg.status();self.assertFalse(r['routingReady']);self.assertEqual(r['runtimeReason'],'DOWN')
 def test_status_still_validates_entire_registry(self):
  wg._read.side_effect=wg.WireguardError('invalid registry')
  with self.assertRaises(wg.WireguardError):wg.status()
 def test_access_reads_one_snapshot_and_keeps_rights(self):
  self.assertEqual(wg.wireguard_access_snapshot(),{'good':True})
  manager.read_config.assert_called_once();manager.read_registry.assert_called_once();wg._locked.assert_not_called()
 def test_access_retains_all_expiry_block_and_outbound_checks(self):
  for name,update in [('disabled',{'accessEnabled':False}),('traffic',{'enforcementTrafficBlocked':True}),('expired',{'expiresAt':'2000-01-01T00:00:00+00:00'}),('blocked',{'expirationBlocked':True}),('bad_date',{'expiresAt':'invalid'}),('missing_outbound',{})]:
   self.users['users'][name]={**self.users['users']['good'],**update}
   if name!='missing_outbound':self.source['outbounds'].append({**self.source['outbounds'][0],'tag':'proxy-'+name})
  result=wg.wireguard_access_snapshot();self.assertTrue(result.pop('good'));self.assertFalse(any(result.values()))
 def test_access_retries_mixed_generation_and_does_not_cache_rights(self):
  wg._delivery_versions.side_effect=[1,2,2,2]
  old=manager.read_registry.side_effect
  def registry():
   r=old()
   if manager.read_registry.call_count>=2:r['users']['good']['accessEnabled']=False
   return r
  manager.read_registry.side_effect=registry
  self.assertEqual(wg.wireguard_access_snapshot(),{'good':False});self.assertEqual(manager.read_config.call_count,2)
 def test_access_two_mixed_generations_fail_retryably(self):
  wg._delivery_versions.side_effect=[1,2,3,4]
  with self.assertRaises(wg.WireguardError) as e:wg.wireguard_access_snapshot()
  self.assertEqual(e.exception.code,'DELIVERY_SNAPSHOT_CHANGED')
 def test_access_registry_and_source_not_mutated(self):
  before=copy.deepcopy((self.source,self.users));wg.wireguard_access_snapshot();self.assertEqual(before,(self.source,self.users))
 def test_route_503_mapping_and_other_errors_remain_409(self):
  class HTTPException(Exception):
   def __init__(self,status_code,detail):self.status_code=status_code
  class Response:
   def __init__(self):self.headers={}
  source=(REPO/'main.py').read_text(encoding='utf-8')
  funcs=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name in {'wireguard_peer_status','wireguard_access_snapshot_endpoint'}]
  for f in funcs:
   f.decorator_list=[];f.args.defaults=[];f.args.args=f.args.args[:1]
   env={'Response':Response,'HTTPException':HTTPException,'WireguardError':wg.WireguardError}
   name='wireguard_status' if f.name=='wireguard_peer_status' else 'wireguard_access_snapshot'
   exec(compile(ast.Module(body=[f],type_ignores=[]),'<route>','exec'),env)
   for code,expected in [('DELIVERY_SNAPSHOT_CHANGED',503),('OTHER',409)]:
    env[name]=Mock(side_effect=wg.WireguardError('retry',code));response=Response()
    with self.assertRaises(HTTPException) as e:env[f.name](response)
    self.assertEqual(e.exception.status_code,expected);self.assertEqual(response.headers['Cache-Control'],'no-store')
 def test_snapshot_route_auth_and_contract_preserved(self):
  source=(REPO/'main.py').read_text(encoding='utf-8')
  routes={n.name:n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}
  for name,path in [('wireguard_peer_status','/api/wireguard/status'),('wireguard_access_snapshot_endpoint','/api/wireguard/access-snapshot')]:
   route=routes[name]
   self.assertEqual([a.arg for a in route.args.args],['response','_token'])
   self.assertEqual(ast.unparse(route.args.defaults[-1]),'Depends(verify_token)')
   self.assertEqual(len(route.decorator_list),1)
   decorator=route.decorator_list[0]
   self.assertEqual(ast.unparse(decorator.func),'app.get')
   self.assertEqual(decorator.args[0].value,path)
   self.assertIn("response.headers['Cache-Control'] = 'no-store'",ast.unparse(route))

if __name__=='__main__':unittest.main(verbosity=2)
