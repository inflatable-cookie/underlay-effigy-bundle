"""Hermetic production cleanup caller controls; no native observation or signals."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import qualification_cleanup_action as action_wrapper
import tempfile
import unittest
from unittest.mock import patch
import qualification_cleanup as q
import service_baseline_handoff as services

BOOT='12345678-1234-1234-1234-123456789ABC'

class World:
    def __init__(self):
        self.states={};self.processes={};self.groups={};self.sockets={};self.routes={};self.boot=BOOT
        for index,name in enumerate(('api','front','admin')):
            base=100+index*10;address=f'127.0.0.1:{40000+index}';domain=f'{name}.test'
            state=dict(status='ready',owner='fixture-owner',generation='a'*32,runtime_generation='b'*32,
                       address=address,route_domain=domain,route_owner={'address':address,'secret':'DO_NOT_PERSIST'})
            for role,pid in zip(q.ROLES,(base,base+1,base+2)):
                start=dict(platform='macos',start_seconds=1000+pid,start_microseconds=123)
                state[role+'_pid']=pid;state[role+'_start_identity']=start;state[role+'_boot_identity']=BOOT
                self.processes[pid]=dict(pid=pid,ppid=base if role=='child' else base+1,pgid=base+1,uid=42,
                                         boot_identity=BOOT,start_identity=start,secret='DO_NOT_PERSIST')
            self.states[name]=state;self.groups[base+1]=[base+1,base+2]
            self.sockets[address]=[base+2];self.routes[domain]=address
    def match_role(self,state,role):
        live=self.kernel_identity(state[role+'_pid'])
        if live is None or live['start_identity']!=state[role+'_start_identity'] or live['boot_identity']!=state[role+'_boot_identity']:
            raise q.CleanupUnknown('role_mismatch')
        return live
    def kernel_identity(self,pid):return self.processes.get(pid)
    def boot_identity(self):return self.boot
    def group_members(self,pid):return self.groups.get(pid,[])
    def socket_pids(self,address):return self.sockets.get(address,[])
    def address_accepts(self,address):return bool(self.socket_pids(address))
    def route_matches(self,state):return self.routes.get(state['route_domain'])==state['address']
    def route_absent(self,state):return state['route_domain'] not in self.routes
    def capture(self):return q.capture(self.states,self)
    def clear(self):self.processes.clear();self.groups.clear();self.sockets.clear();self.routes.clear()

class Controls(unittest.TestCase):
    def setUp(self):self.world=World()
    def capture(self):return q.capture(self.world.states,self.world)
    def test_exact_absence_and_foreign_witness(self):
        baseline=self.capture();self.world.clear();witness=[]
        proof=q.verify_absent(baseline,self.world,lambda:witness.append('foreign-compared'))
        self.assertEqual(witness,['foreign-compared']);self.assertTrue(proof['host_listener_cleanup_verified'])
        self.assertFalse(proof['container_cleanup_verified']);self.assertFalse(proof['retirement_verified'])
        self.assertNotIn('DO_NOT_PERSIST',json.dumps(baseline))
    def test_present_reused_group_socket_route_and_boot(self):
        for mutation in ('pid','reused','group','socket','route','boot','member'):
            with self.subTest(mutation=mutation):
                self.world=World();baseline=self.capture();state=baseline['api'];self.world.clear()
                if mutation in ('pid','reused'):self.world.processes[state['listener_pid']]={'start_identity':'changed' if mutation=='reused' else state['listener_start_identity']}
                if mutation=='member':self.world.processes[state['group_members'][0]['pid']]={}
                if mutation=='group':self.world.groups[state['child_pid']]=[999]
                if mutation=='socket':self.world.sockets[state['address']]=[999]
                if mutation=='route':self.world.routes[state['route_domain']]='127.0.0.1:9'
                if mutation=='boot':self.world.boot='87654321-1234-1234-1234-123456789ABC'
                with self.assertRaises(q.CleanupUnknown):q.verify_absent(baseline,self.world,lambda:None)
    def test_unavailable_failed_stopped_missing_identity_no_capture_credit(self):
        for mutation in ('unavailable','failed','stopped','missing_microseconds','missing_generation','missing_role'):
            with self.subTest(mutation=mutation):
                self.world=World();state=self.world.states['api']
                if mutation in ('unavailable','failed','stopped'):state['status']=mutation
                if mutation=='missing_microseconds':del state['listener_start_identity']['start_microseconds']
                if mutation=='missing_generation':del state['generation']
                if mutation=='missing_role':del state['listener_pid']
                with self.assertRaises(q.CleanupUnknown):self.capture()
    def test_capture_rejects_foreign_group_and_changed_source_identity(self):
        self.world.processes[101]['start_identity']=dict(platform='macos',start_seconds=999,start_microseconds=123)
        with self.assertRaises(q.CleanupUnknown):self.capture()
        self.world=World();self.world.processes[102]['ppid']=999
        with self.assertRaises(q.CleanupUnknown):self.capture()
    def test_inventory_only_and_down_zero_never_credit(self):
        self.world.clear()
        with self.assertRaises(q.CleanupUnknown):q.verify_absent({},self.world,lambda:None)
        for status in ({'services':[]},{'ok':True,'exit':0,'services':[]}):
            with self.assertRaises(q.CleanupUnknown):q.container_cleanup_credit(status)
    def test_failed_read_and_foreign_change_privacy(self):
        baseline=self.capture();self.world.clear()
        def fail(*unused):raise RuntimeError('SECRET_BODY_ENV_ARGV')
        with patch.object(self.world,'group_members',fail):
            with self.assertRaises(q.CleanupUnknown) as caught:q.verify_absent(baseline,self.world,lambda:None)
        self.assertNotIn('SECRET',str(caught.exception))
        with self.assertRaises(q.CleanupUnknown):q.verify_absent(baseline,self.world,fail)
    def test_single_action_pending_before_return_immutable(self):
        records=[];witness=[]
        def action():
            self.assertEqual(records[0]['action'],'pending');witness.append('actual-action');return 0
        code=q.action_once(self.capture,action,records.append)
        self.assertEqual(code,0);self.assertEqual(witness,['actual-action'])
        self.assertEqual([x['action'] for x in records],['pending','passed'])
        self.assertEqual(records[0]['baseline'],records[1]['baseline'])
    def test_action_failure_separate_from_absence(self):
        records=[];q.action_once(self.capture,lambda:7,records.append)
        self.assertEqual(records[-1]['action'],'failed');self.world.clear()
        self.assertTrue(q.verify_absent(records[0]['baseline'],self.world,lambda:None)['host_listener_cleanup_verified'])
    def test_action_exception_preserves_pending_and_changed_generation_refuses(self):
        records=[]
        def fail():raise RuntimeError('SECRET')
        with self.assertRaises(RuntimeError):q.action_once(self.capture,fail,records.append)
        self.assertEqual(len(records),1);self.assertEqual(records[0]['action'],'pending')
        def change():self.world.states['api']['generation']='c'*32;return 0
        with self.assertRaises(q.CleanupUnknown):q.action_once(self.capture,change,records.append)
    def test_partial_host_absence_cannot_pass_whole_product_gate(self):
        baseline=self.capture();self.world.clear()
        proof=q.verify_absent(baseline,self.world,lambda:None)
        with self.assertRaises(q.CleanupUnknown):q.require_product_cleanup(proof)
        with self.assertRaises(q.CleanupUnknown):q.require_product_cleanup({'cleanup_verified':True,'exit':0})
    def test_private_receipt_duplicate_cap_missing_and_eof(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value);root.chmod(0o700);path=root/'proof.json'
            record=dict(schema='underlay.qualification-cleanup.v1',baseline=self.capture(),action='pending')
            q.write_private(path,root,record);self.assertEqual(q.read_private(path,root),record)
            for raw in (b'{"schema":1,"schema":2}',b'{',b'x'*(q.CAP+1)):
                path.write_bytes(raw)
                with self.assertRaises(q.CleanupUnknown):q.read_private(path,root)
            path.unlink()
            with self.assertRaises(q.CleanupUnknown):q.read_private(path,root)

class CallerControls(unittest.TestCase):
    setUp=Controls.setUp
    capture=Controls.capture
    def test_real_qualifier_single_dispatch_and_fixture_restore(self):
        spec=importlib.util.spec_from_file_location('cleanup_caller_test',Path(__file__).with_name('qualify-reference-optin.py'))
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            checkout=Path(directory)/'main';checkout.mkdir()
            manifest=checkout/'effigy.toml';original='profiles = { enabled = true, test_task = "acme-api/test", test_timeout_secs = 900 }\n'
            manifest.write_text(original);events=[];baselines=[]
            foreign={Path(directory)/name:{} for name in ('first','second')}
            world=self.world
            class Observer:
                def __init__(self,*args,**kwargs):self.world=World() if kwargs.get("profile")=="hybrid" else world
                def __getattr__(self,name):return getattr(self.world,name)
            def dispatch(argv,**kwargs):
                events.append(tuple(argv));self.assertEqual(argv[-1],'dev:test')
                self.assertIn('test_task = "qualification:cleanup-action"',manifest.read_text())
                self.assertEqual(kwargs['timeout'],5400)
                root=next(checkout.glob('qualification-cleanup-*'))
                def save(record):
                    path=root/('pending.json' if record['action']=='pending' else 'completed.json')
                    q.write_private(path,root,record)
                def configured_action():
                    pending=q.read_private(root/'pending.json',root)
                    baselines.append(pending['baseline']);events.append(('acme-api/test',));return 0
                q.action_once(self.capture,configured_action,save)
                world.clear()  # fake launcher cleanup occurs after the wrapper's return.
                return SimpleNamespace(returncode=0)
            witnesses=[]
            with patch.object(services,'prepare',return_value=('sealed-source','digest')),patch.object(services,'accept',return_value={'container_cleanup_verified':True}),patch.object(module,'EFFIGY','/qualified/effigy'),patch.object(module,'ListenerObserver',Observer),patch.object(module,'_verify_live',lambda *args:witnesses.append('foreign')),patch.object(module.RUNTIME,'run',dispatch):
                result=module.verify_disposable_action(checkout,{},foreign,object())
            self.assertEqual(manifest.read_text(),original)
            self.assertEqual(len(events),2);self.assertEqual(events[1],('acme-api/test',))
            self.assertEqual(len(baselines),1);self.assertEqual(len(witnesses),4)
            self.assertTrue(result['host_listener_cleanup_verified']);self.assertTrue(result['container_cleanup_verified'])
    def test_parent_action_error_retains_independent_absence_and_restores(self):
        spec=importlib.util.spec_from_file_location('cleanup_error_caller',Path(__file__).with_name('qualify-reference-optin.py'))
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            checkout=Path(directory);manifest=checkout/'effigy.toml'
            original='profiles = { enabled = true, test_task = "acme-api/test", test_timeout_secs = 900 }\n';manifest.write_text(original)
            world=self.world
            class Observer:
                def __init__(self,*args,**kwargs):self.world=World() if kwargs.get("profile")=="hybrid" else world
                def __getattr__(self,name):return getattr(self.world,name)
            def dispatch(*args,**kwargs):
                root=next(checkout.glob('qualification-cleanup-*'))
                q.write_private(root/'pending.json',root,dict(schema='underlay.qualification-cleanup.v1',baseline=self.capture(),action='pending'))
                world.clear();raise RuntimeError('SECRET_BODY_ENV_ARGV')
            with patch.object(services,'prepare',return_value=('sealed-source','digest')),patch.object(services,'accept',return_value={'container_cleanup_verified':True}),patch.object(module,'ListenerObserver',Observer),patch.object(module,'_verify_live',lambda *args:None),patch.object(module.RUNTIME,'run',dispatch):
                with self.assertRaises(q.CleanupUnknown) as caught:module.verify_disposable_action(checkout,{}, {checkout/'one':{},checkout/'two':{}},object())
            self.assertEqual(str(caught.exception),'configured_action_unknown');self.assertEqual(manifest.read_text(),original)
            root=next(checkout.glob('qualification-cleanup-*'));proof=json.loads((root/'absence.json').read_text())
            self.assertIsNone(proof['action_exit']);self.assertTrue(proof['host_listener_cleanup_verified'])
            self.assertNotIn('SECRET',(root/'absence.json').read_text())

    def test_real_wrapper_fixed_original_selector_and_pending_before_action(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout=Path(directory);(checkout/'.git').mkdir();root=checkout/'proof';root.mkdir(mode=0o700)
            calls=[];world=self.world
            class Observer:
                def __init__(self,*args):pass
                def capture(self):return q.capture(world.states,world)
            def run(argv,**kwargs):
                self.assertEqual(q.read_private(root/'pending.json',root)['action'],'pending')
                calls.append(argv);self.assertEqual(argv[-1],'acme-api/test');self.assertEqual(kwargs['timeout'],900)
                return SimpleNamespace(returncode=0)
            fake=SimpleNamespace(require_effigy_binary=lambda **kw:'/qualified/effigy',RUNTIME=SimpleNamespace(run=run))
            with patch('private_caller_environment.verify_context',return_value=True),patch.object(services,'read',return_value=({'context':{'cwd':str(checkout),'private_home':os.environ.get('HOME'),'colima_home':os.environ.get('COLIMA_HOME'),'lima_home':os.environ.get('LIMA_HOME')}},None)),patch.object(services,'capture_ready',return_value=(SimpleNamespace(snapshot=lambda:{'containers':{}}),{'owned':{},'foreign':{}})),patch.object(action_wrapper,'load_qualifier',lambda:fake),patch.object(action_wrapper,'ListenerObserver',Observer),patch.object(sys,'argv',['wrapper',str(checkout),str(root)]):
                self.assertEqual(action_wrapper.main(),0)
            self.assertEqual(len(calls),1);self.assertEqual(q.read_private(root/'completed.json',root)['action'],'passed')

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
