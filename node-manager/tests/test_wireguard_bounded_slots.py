"""The tenth slot is bounded, uniquely marked, and retains all GC safeguards."""
import copy,importlib.util,os,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch

REPO=Path(__file__).resolve().parents[1]
stubs={'config':types.SimpleNamespace(config=types.SimpleNamespace()),'singbox':types.SimpleNamespace(manager=types.SimpleNamespace()),'wireguard':types.SimpleNamespace(WireguardError=RuntimeError,_binding_fingerprint=lambda x:'test',_resolve_exit_binding=lambda *a:None)}
def load(name,filename):
 spec=importlib.util.spec_from_file_location(name,REPO/filename);module=importlib.util.module_from_spec(spec)
 with patch.dict(sys.modules,stubs):spec.loader.exec_module(module)
 return module
hot=load('bounded_slot_hot','wireguard_hotload.py');routes=load('bounded_slot_routes','wireguard_routes.py')

def state(count):
 return {'version':1,'activePort':61037+count-1,'legacyMarked':True,'generations':[{'port':61037+i,'createdAt':1.0,'sha256':'0'*64} for i in range(count)]}

class BoundedSlotTests(unittest.TestCase):
 def test_limit_is_explicit_ten_without_environment_switch(self):
  self.assertEqual(hot.SLOT_COUNT,10);self.assertEqual(hot.PORT_LIMIT,61047)
 def test_original_eight_slot_state_still_valid(self):self.assertEqual(len(hot._validate_state(state(8))['generations']),8)
 def test_ninth_and_tenth_slot_states_valid(self):
  for n in [9,10]:self.assertEqual(len(hot._validate_state(state(n))['generations']),n)
 def test_eleventh_slot_rejected(self):
  with self.assertRaises(ValueError):hot._validate_state(state(11))
  with self.assertRaises(RuntimeError):routes._hotload_generation_rules(state(11))
 def test_duplicate_port_rejected(self):
  s=state(10);s['generations'][-1]['port']=61037
  with self.assertRaises(ValueError):hot._validate_state(s)
  with self.assertRaises(RuntimeError):routes._hotload_generation_rules(s)
 def test_boolean_port_is_not_owned(self):self.assertFalse(hot._owned_port(True))
 def test_old_unmarked_flow_pin_is_preserved(self):
  rules=routes._hotload_generation_rules(state(10))
  for proto in ['tcp','udp']:
   self.assertIn(['-i','wg0','-p',proto,'-m','connmark','--mark','0x0/0xff000000','-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','CONNMARK','--set-xmark','0x1000000/0xff000000'],rules)
 def test_all_ten_cookies_are_unique_and_keep_low_mark_bits(self):
  rules=routes._hotload_generation_rules(state(10));cookies=set()
  for port in range(61037,61047):
   selected=[r for r in rules if '--on-port' in r and r[r.index('--on-port')+1]==str(port)]
   self.assertEqual(len(selected),2)
   for row in selected:
    cookie=row[row.index('--mark')+1];cookies.add(cookie)
    value,mask=cookie.split('/');self.assertEqual(int(mask,16),0xff000000);self.assertEqual(int(value,16)&0x00ffffff,0)
    self.assertEqual(row[row.index('--tproxy-mark')+1],'0x178/0xffffffff')
  self.assertEqual(len(cookies),10);self.assertIn('0x9000000/0xff000000',cookies);self.assertIn('0xa000000/0xff000000',cookies)
 def test_allocation_uses_ninth_then_tenth_without_stopping_old_units(self):
  with patch.object(hot,'_active_unit',return_value=False),patch.object(hot,'_run',side_effect=AssertionError('must not stop services')):
   self.assertEqual(hot._allocate_port(state(8)),61045);self.assertEqual(hot._allocate_port(state(9)),61046);self.assertIsNone(hot._allocate_port(state(10)))
 def test_foreign_running_port_is_not_stolen(self):
  with patch.object(hot,'_active_unit',return_value=True):self.assertIsNone(hot._allocate_port(state(8)))
 def test_full_limit_error_remains_safe_and_no_candidate_write(self):
  rendered={'inbounds':[{'tag':'wg-tproxy','type':'tproxy','listen_port':61037}],'outbounds':[],'route':{}}
  with patch.object(hot,'_allocate_port',return_value=None),patch.object(hot,'_save_generation',side_effect=AssertionError('must not write')):
   with self.assertRaisesRegex(hot.HotloadPendingError,'all ten'):hot._start_new_candidate(types.SimpleNamespace(),state(10),rendered,Path('unused'))
 def test_active_port_must_belong_to_generation(self):
  s=state(8);s['activePort']=61046
  with self.assertRaises(ValueError):hot._validate_state(s)
 def test_invalid_legacy_marked_state_still_rejected(self):
  s=state(10);s['legacyMarked']=False
  with self.assertRaises(ValueError):hot._validate_state(s)
 def test_generation_metadata_validation_preserved(self):
  s=state(10);s['generations'][0]['sha256']='invalid'
  with self.assertRaises(ValueError):hot._validate_state(s)
 def test_gc_preserves_old_generation_with_conntrack_flows(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'state.json';path.write_text('{}');os.utime(path,(time.time()-120,time.time()-120))
   s=state(3)
   with patch.object(hot,'STATE_PATH',path),patch.object(hot,'_conntrack_empty',return_value=False) as flows,patch.object(hot,'_process_drained',return_value=True),patch.object(hot,'_run',side_effect=AssertionError('must not stop live flows')) as commands:
    self.assertEqual(hot._retire_inactive(s,Path(folder)/'singbox.json'),s);flows.assert_called_once_with(61038);commands.assert_not_called()
 def test_gc_preserves_zero_conntrack_generation_with_undrained_socket(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'state.json';path.write_text('{}');os.utime(path,(time.time()-120,time.time()-120))
   s=state(3)
   with patch.object(hot,'STATE_PATH',path),patch.object(hot,'_conntrack_empty',return_value=True),patch.object(hot,'_process_drained',return_value=False) as drained,patch.object(hot,'_run',side_effect=AssertionError('must not stop socket owner')) as commands:
    self.assertEqual(hot._retire_inactive(s,Path(folder)/'singbox.json'),s);drained.assert_called_once_with(61038);commands.assert_not_called()
 def test_gc_waits_full_minimum_drain_window(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'state.json';path.write_text('{}');s=state(3)
   with patch.object(hot,'STATE_PATH',path),patch.object(hot,'_conntrack_empty',side_effect=AssertionError('too early')) as flows,patch.object(hot,'_run',side_effect=AssertionError('too early')) as commands:
    self.assertEqual(hot._retire_inactive(s,Path(folder)/'singbox.json'),s);flows.assert_not_called();commands.assert_not_called()
 def test_gc_never_retires_base_or_current_active_generation(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'state.json';path.write_text('{}');os.utime(path,(time.time()-120,time.time()-120));s=state(2)
   with patch.object(hot,'STATE_PATH',path),patch.object(hot,'_conntrack_empty',return_value=True) as flows,patch.object(hot,'_process_drained',return_value=True),patch.object(hot,'_run',side_effect=AssertionError('must preserve base and active')) as commands:
    self.assertEqual(hot._retire_inactive(s,Path(folder)/'singbox.json'),s);flows.assert_not_called();commands.assert_not_called()
 def test_gc_only_stops_and_removes_proven_drained_inactive_generation(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder);path=root/'state.json';path.write_text('{}');os.utime(path,(time.time()-120,time.time()-120))
   old=root/'generations/61038.json';old.parent.mkdir();old.write_text('{}');s=state(3)
   def command(args,**kwargs):
    self.assertEqual(args[2],'niusu-wireguard-proxy@61038.service')
    return 'inactive' if args[1]=='show' else ''
   with patch.object(hot,'STATE_PATH',path),patch.object(hot,'_conntrack_empty',return_value=True),patch.object(hot,'_process_drained',return_value=True),patch.object(hot,'_run',side_effect=command) as commands,patch.object(hot,'_write_state') as written:
    result=hot._retire_inactive(s,root/'singbox.json')
    self.assertEqual([g['port'] for g in result['generations']],[61037,61039]);self.assertEqual(commands.call_count,2);written.assert_called_once();self.assertFalse(old.exists())

if __name__=='__main__':unittest.main(verbosity=2)
