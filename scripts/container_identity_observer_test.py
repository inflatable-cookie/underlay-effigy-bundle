"""Source-backed reader controls using fresh owned executable fake hosts only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import container_identity_observer as observer

class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        for name in ('colima','lima','cwd','main'):(self.root/name).mkdir(mode=0o700)
        instance=self.root/'lima'/'owned';instance.mkdir(mode=0o700)
        config=instance/'lima.yaml';config.write_text('fixture-only configuration');config.chmod(0o600)
        self.fake=self.root/'fake-limactl'
        source='''#!INTERPRETER
import json,os,sys,time,shlex
from pathlib import Path
root=Path(__file__).parent
v=json.loads((root/'transport.json').read_text())
a=sys.argv[1:]
expected=['shell','--workdir',str(root/'cwd'),'owned','sudo','nerdctl','--namespace','original','--address','/run/containerd/containerd.sock']
allowed={'HOME','COLIMA_HOME','LIMA_HOME','SSH','PATH','LANG','LC_ALL','LC_CTYPE'}
nonce_prefix=['shell','--workdir',str(root/'cwd'),'owned','/bin/cat']
is_nonce=a[:len(nonce_prefix)]==nonce_prefix
valid=(a[:len(expected)]==expected or is_nonce) and not any(k.startswith(('CONTAINERD_','NERDCTL_')) for k in os.environ)
valid=valid and os.environ.get('LIMA_HOME')==str(root/'lima') and os.environ.get('COLIMA_HOME')==str(root/'colima')
valid=valid and shlex.split(os.environ.get('SSH',''))==[str(root/'fake-limactl'),'-o','ControlMaster=no','-o','ControlPersist=no']
if not valid:sys.exit(21)
mode=v.get('mode')
if is_nonce:
    p=Path(a[-1])
    if len(a)!=6 or p.parent!=root/'cwd' or not p.name.startswith('.observer-cwd-'):sys.exit(24)
    if mode=='nonce_missing':sys.exit(1)
    if mode=='nonce_overflow':sys.stdout.write('x'*70000);sys.exit(0)
    if mode=='nonce_stall':time.sleep(1)
    if mode=='nonce_secret':sys.stderr.write('SYNTHETIC_SECRET_NONCE');sys.exit(1)
    if mode=='nonce_replaced':
        p.unlink();p.write_bytes(b'replacement');p.chmod(0o600)
    data=p.read_bytes()
    if mode=='nonce_wrong':data=b'wrong'
    if mode=='nonce_truncated':data=data[:-1]
    sys.stdout.buffer.write(data);sys.exit(0)
args=a[len(expected):]
if mode=='stall':time.sleep(1)
if mode=='stderr':sys.stderr.write('SYNTHETIC_SECRET_BODY_ENV_ARGV');sys.exit(0)
if mode=='overflow':sys.stdout.write('x'*70000);sys.exit(0)
if args==['ps','--all','--no-trunc','--quiet']:
    count_file=root/'count';count=int(count_file.read_text()) if count_file.exists() else 0
    count_file.write_text(str(count+1));count_file.chmod(0o600)
    ids=sorted(v['records'])
    if mode=='changing' and count%2:ids=[]
    text=''.join(x+'\\n' for x in ids)
    if mode=='partial':text=text.rstrip('\\n')
    if mode=='duplicate' and ids:text+=ids[0]+'\\n'
    sys.stdout.write(text)
elif len(args)==7 and args[:5]==['container','inspect','--mode','dockercompat','--format']:
    if mode=='inspect_failure':sys.stderr.write('SYNTHETIC_SECRET');sys.exit(1)
    # Verify the real fixed redacted source template, not a mock success callback.
    template=args[5]
    if 'Env' in template or 'Args' in template or 'Mounts' in template or len(template)>1024:sys.exit(23)
    value=v['records'][args[6]]
    if mode=='wrong_id':value=dict(value,id='e'*64)
    text=json.dumps(value)+'\\n'
    if mode=='extra_field':text=text[:-2]+',"Env":"SYNTHETIC_SECRET"}\\n'
    sys.stdout.write(text)
else:sys.exit(22)
'''.replace('INTERPRETER',sys.executable)
        self.fake.write_text(source);self.fake.chmod(0o700)
        self.ctx=dict(schema='underlay.container-observer-context.v1',limactl=str(self.fake),limactl_sha256=self.sha(self.fake),ssh=str(self.fake),ssh_sha256=self.sha(self.fake),colima_home=str(self.root/'colima'),lima_home=str(self.root/'lima'),cwd=str(self.root/'cwd'),config=str(config),config_sha256=self.sha(config),instance='owned',namespace='original',address='/run/containerd/containerd.sock',boot=None,scopes=[dict(project='primary',checkout=str(self.root/'main'),services=['api','portless'],primary=None,oneoffs=[])],foreign={})
        self.foreign=self.record('f'*64,'foreign','foreign-service',str(self.root/'other'))
        self.ctx['foreign']={self.foreign['id']:self.foreign}
        self.original={key:copy.deepcopy(value) for key,value in self.ctx.items() if key!='schema'}
        self.records={x['id']:x for x in (self.record('a'*64,'primary','api',str(self.root/'main')),self.record('b'*64,'primary','portless',str(self.root/'main')),self.foreign)}
        self.write()
    def tearDown(self):self.temp.cleanup()
    def sha(self,p):return hashlib.sha256(p.read_bytes()).hexdigest()
    def record(self,full_id,project,service,checkout):return dict(id=full_id,created='2026-10-14T01:02:03.123456789Z',project=project,checkout=checkout,service=service,oneoff='false',running=True,status='running')
    def write(self,mode=None):
        p=self.root/'transport.json';p.write_text(json.dumps(dict(records=self.records,mode=mode)));p.chmod(0o600)
    def reader(self,ctx=None,env=None):return observer.Observer(self.ctx if ctx is None else ctx,{} if env is None else env,self.root,self.original)
    def test_actual_read_baseline_exact_absence_foreign_and_primary_none(self):
        reader=self.reader();before=reader.baseline();self.assertEqual(len(before['owned']),2)
        self.records={self.foreign['id']:self.foreign};self.write()
        result=reader.after(before)
        self.assertTrue(result['container_cleanup_verified']);self.assertEqual(result['foreign_count'],1)
        self.assertFalse(result['retirement_verified']);self.assertFalse(result['remote_cancellation_verified'])
        self.assertTrue(all(x['stdout_eof'] and x['stderr_eof'] and x['leader_reaped'] and x['stderr_observed']==0 for x in result['read_capture']))
    def test_unknown_boot_is_legitimate_read_association_without_signal_authority(self):
        reader=self.reader();before=reader.baseline()
        self.records={self.foreign['id']:self.foreign};self.write()
        result=reader.after(before)
        self.assertFalse(result['backend_boot_verified']);self.assertFalse(result['vm_signal_authority'])
        self.assertEqual(len(result['cwd_correspondence']),2)
        for evidence in result['cwd_correspondence']:
            self.assertTrue(evidence['cwd_correspondence']);self.assertTrue(evidence['owned_nonce_removed'])
            self.assertEqual(evidence['byte_count'],65);self.assertNotIn('stdout_sha256',evidence)
        self.assertEqual(list((self.root/'cwd').iterdir()),[])
    def test_nonce_wrong_missing_truncated_secret_and_replacement_hold_inventory(self):
        for mode in ('nonce_missing','nonce_wrong','nonce_truncated','nonce_secret','nonce_overflow','nonce_replaced'):
            with self.subTest(mode=mode):
                self.write(mode)
                with self.assertRaises(observer.Refusal) as caught:self.reader().baseline()
                self.assertNotIn('SECRET',str(caught.exception))
                self.assertFalse((self.root/'count').exists())
                files=list((self.root/'cwd').iterdir())
                if mode=='nonce_replaced':
                    self.assertEqual(str(caught.exception),'nonce_cleanup_identity_unknown')
                    self.assertEqual(len(files),1);self.assertEqual(files[0].read_bytes(),b'replacement')
                    files[0].unlink() # this test created the replacement; no old scope exists
                else:self.assertEqual(files,[])
    def test_nonce_deadline_and_read_error_remove_only_own_file_without_inventory(self):
        self.write('nonce_stall')
        with patch.object(observer,'CALL_SECONDS',.02):
            with self.assertRaises(observer.Refusal):self.reader().baseline()
        self.assertEqual(list((self.root/'cwd').iterdir()),[])
        self.assertFalse((self.root/'count').exists())
        self.write();registered=set();original_register=observer.selectors.DefaultSelector.register
        original_read=observer.os.read
        def register(selector,stream,*args):
            registered.add(stream.fileno());return original_register(selector,stream,*args)
        def read(fd,count):
            if fd in registered:raise OSError('SYNTHETIC_SECRET')
            return original_read(fd,count)
        with patch.object(observer.selectors.DefaultSelector,'register',register),patch.object(observer.os,'read',read):
            with self.assertRaises(observer.Refusal) as caught:self.reader().baseline()
        self.assertEqual(str(caught.exception),'capture_read')
        self.assertEqual(list((self.root/'cwd').iterdir()),[])
        self.assertFalse((self.root/'count').exists())
    def test_original_routing_and_environment_refuse_before_dispatch(self):
        for key,value in (('namespace','foreign'),('lima_home',str(self.root/'colima')),('instance',''),('cwd','/Users/operator'),('address','/foreign.sock'),('boot','unknown')):
            with self.subTest(key=key):
                ctx=copy.deepcopy(self.ctx);ctx[key]=value
                with self.assertRaises(observer.Refusal):self.reader(ctx)
        for env in ({'LIMA_HOME':'foreign'},{'NERDCTL_CONFIG':''},{'CONTAINERD_NAMESPACE':'foreign'},{'SSH':'hook'}):
            with self.assertRaises(observer.Refusal):self.reader(env=env)
        self.assertFalse((self.root/'count').exists())
    def test_changed_root_config_and_digest_refuse(self):
        reader=self.reader();path=Path(self.ctx['config']);path.write_text('changed');path.chmod(0o600)
        with self.assertRaises(observer.Refusal):reader.snapshot()
        with self.assertRaises(observer.Refusal):self.reader()
        self.assertFalse((self.root/'count').exists())
    def test_undeclared_foreign_scope_and_owned_checkout_service_refuse(self):
        for key,value in (('project','unclassified'),('checkout',str(self.root/'other')),('service','undeclared'),('oneoff','true')):
            with self.subTest(key=key):
                self.records['a'*64][key]=value;self.write()
                with self.assertRaises(observer.Refusal) as caught:self.reader().baseline()
                self.assertEqual(str(caught.exception),'unclassified_inventory' if key=='project' else ('owned_oneoff_unknown' if key=='oneoff' else 'owned_scope_mismatch'))
                self.records['a'*64]=self.record('a'*64,'primary','api',str(self.root/'main'))
    def test_reused_old_id_replacement_foreign_state_or_creation_refuse(self):
        original_records=copy.deepcopy(self.records)
        for kind in ('old_id','replacement','foreign_state','foreign_created','foreign_missing','foreign_new'):
            with self.subTest(kind=kind):
                self.records=copy.deepcopy(original_records);self.write()
                reader=self.reader();baseline=reader.baseline()
                self.records={self.foreign['id']:copy.deepcopy(self.foreign)}
                if kind=='old_id':self.records['a'*64]=baseline['owned']['a'*64]
                if kind=='replacement':self.records['c'*64]=self.record('c'*64,'primary','api',str(self.root/'main'))
                if kind=='foreign_state':self.records['f'*64].update(status='exited',running=False)
                if kind=='foreign_created':self.records['f'*64]['created']='2026-10-15T01:02:03Z'
                if kind=='foreign_missing':self.records={}
                if kind=='foreign_new':self.records['c'*64]=self.record('c'*64,'new','other','/unknown')
                self.write()
                with self.assertRaises(observer.Refusal):reader.after(baseline)
    def test_actual_transport_nonzero_partial_duplicate_changing_and_privacy(self):
        for mode in ('inspect_failure','partial','duplicate','changing','stderr','overflow','wrong_id','extra_field'):
            with self.subTest(mode=mode):
                count=self.root/'count'
                if count.exists():count.unlink()
                self.write(mode)
                with self.assertRaises(observer.Refusal) as caught:self.reader().baseline()
                expected={'inspect_failure':'capture_nonzero','partial':'inventory_framing','duplicate':'inventory_identity','changing':'changing_inventory','stderr':'stderr_output','overflow':'capture_cap','wrong_id':'inspect_schema','extra_field':'inspect_schema'}
                self.assertEqual(str(caught.exception),expected[mode])
    def test_empty_baseline_cannot_prove_anything(self):
        self.records={};self.write()
        with self.assertRaises(observer.Refusal):self.reader().baseline()
    def test_actual_host_deadline_read_error_and_child_settlement(self):
        self.write('stall');reader=self.reader()
        argv=reader.argv(['ps','--all','--no-trunc','--quiet'])
        with self.assertRaises(observer.Refusal):observer.host_capture(argv,reader.env,reader.context['cwd'],time.monotonic()+.02)
        self.write()
        registered=set();original_register=observer.selectors.DefaultSelector.register;original_read=observer.os.read
        def register(selector,stream,*args):
            registered.add(stream.fileno());return original_register(selector,stream,*args)
        def read(fd,count):
            if fd in registered:raise OSError('SYNTHETIC_SECRET')
            return original_read(fd,count)
        with patch.object(observer.selectors.DefaultSelector,'register',register),patch.object(observer.os,'read',read):
            with self.assertRaises(observer.Refusal) as caught:observer.host_capture(argv,reader.env,reader.context['cwd'],time.monotonic()+1)
        self.assertEqual(str(caught.exception),'capture_read')
    def test_argv_injection_arbitrary_read_and_unknown_schema_refuse(self):
        reader=self.reader()
        with self.assertRaises(observer.Refusal):reader.read(['exec','sh','-c','secret'],time.monotonic()+1)
        with self.assertRaises(observer.Refusal):reader.read(['container','inspect','--mode','dockercompat','--format',observer.TEMPLATE,'a'*64+';touch'],time.monotonic()+1)
        ctx=copy.deepcopy(self.ctx);ctx['arbitrary_callback']='secret'
        with self.assertRaises(observer.Refusal):self.reader(ctx)
        self.assertFalse((self.root/'count').exists())
    def test_optional_compose_labels_absent_preserved_under_closed_original_up_policy(self):
        for row in self.records.values():
            if row['project']=='primary':row['checkout']=None;row['oneoff']=None
        self.write();reader=self.reader();before=reader.baseline()
        self.assertTrue(all(row['checkout'] is None and row['oneoff'] is None for row in before['owned'].values()))
        self.records={k:r for k,r in self.records.items() if k in self.ctx['foreign']};self.write()
        self.assertTrue(reader.after(before)['container_cleanup_verified'])

    def test_actual_primary_worktree_service_and_oneoff_inventory(self):
        second=self.root/'worktree';second.mkdir(mode=0o700)
        scope=dict(project='second',checkout=str(second),services=['api','portless'],primary='api',oneoffs=['api'])
        self.ctx['scopes'].append(scope);self.original['scopes']=copy.deepcopy(self.ctx['scopes'])
        for token,service in (('c','api'),('d','portless')):
            row=self.record(token*64,'second',service,str(second));self.records[row['id']]=row
        oneoff=self.record('e'*64,'second','api',str(second));oneoff['oneoff']='true';self.records[oneoff['id']]=oneoff
        self.write();reader=self.reader();baseline=reader.baseline()
        self.assertEqual(len(baseline['owned']),5)
        self.records={self.foreign['id']:self.foreign};self.write();self.assertTrue(reader.after(baseline)['container_cleanup_verified'])
    def test_baseline_cannot_be_invented_rebased_or_post_retried(self):
        reader=self.reader()
        with self.assertRaises(observer.Refusal):reader.after({'binding':reader.binding,'owned':{},'foreign':self.ctx['foreign']})
        before=reader.baseline()
        with self.assertRaises(observer.Refusal):reader.baseline()
        tampered=copy.deepcopy(before);tampered['owned']={}
        with self.assertRaises(observer.Refusal):reader.after(tampered)
        self.records={self.foreign['id']:self.foreign};self.write();reader.after(before)
        with self.assertRaises(observer.Refusal):reader.after(before)
    def test_missing_caller_admission_never_dispatches_down(self):
        import importlib.util
        path=Path(__file__).with_name('qualify-reference-container.py')
        spec=importlib.util.spec_from_file_location('missing_container_caller',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        receipts=[]
        with patch.object(module,'effigy_json',side_effect=AssertionError('must not dispatch')):
            self.assertFalse(module.independently_observe_container_down('/not-a-tool',self.root/'main',{},receipts,None))
        self.assertEqual(receipts[0]['reason'],'original_backend_routing_admission_required')
    def test_actual_container_caller_baseline_down_after_order(self):
        import importlib.util
        path=Path(__file__).with_name('qualify-reference-container.py')
        spec=importlib.util.spec_from_file_location('container_cleanup_caller',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        fake_effigy=self.root/'fake-effigy'
        fake_effigy.write_text('#!'+sys.executable+'''
import json,sys
from pathlib import Path
r=Path(__file__).parent
if sys.argv[1:]!=['--repo',str(r/'main'),'container','down','--json']:sys.exit(31)
value=json.loads((r/'transport.json').read_text())
if int((r/'count').read_text())!=2:sys.exit(32)
value['records']={k:v for k,v in value['records'].items() if v['project']=='foreign'}
(r/'transport.json').write_text(json.dumps(value))
(r/'transport.json').chmod(0o600)
print(json.dumps({'ok':True,'result':{}}))
''')
        fake_effigy.chmod(0o700);reader=self.reader();receipts=[]
        env=dict(os.environ,UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT=str(self.root))
        self.assertTrue(module.independently_observe_container_down(str(fake_effigy),self.root/'main',env,receipts,reader))
        self.assertTrue(receipts[0]['container_baseline_observed']);self.assertTrue(receipts[1]['container_cleanup_verified'])
        self.assertEqual(int((self.root/'count').read_text()),4)
        self.assertNotIn('SECRET',json.dumps(receipts))
    def test_down_zero_without_owned_removal_cannot_pass_actual_caller(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('zero_down_caller',Path(__file__).with_name('qualify-reference-container.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        fake=self.root/'zero-down';fake.write_text('#!'+sys.executable+'\nprint(\'{{"ok":true,"result":{}}}\'[1:-1])\n');fake.chmod(0o700)
        with self.assertRaises(observer.Refusal) as caught:
            module.independently_observe_container_down(str(fake),self.root/'main',dict(os.environ,UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT=str(self.root)),[],self.reader())
        self.assertEqual(str(caught.exception),'owned_id_present')
    def test_decode_reached_before_final_snapshot_deadline_refusal(self):
        reader=self.reader();original_inventory=observer.inventory;original_clock=time.monotonic;witness=[]
        def inventory(raw):
            result=original_inventory(raw);witness.append('decoded_inventory');return result
        def clock():return original_clock()+(31 if len(witness)==2 else 0)
        with patch.object(observer,'inventory',inventory),patch.object(observer.time,'monotonic',clock):
            with self.assertRaises(observer.Refusal) as caught:reader.snapshot()
        self.assertEqual(witness,['decoded_inventory','decoded_inventory']);self.assertEqual(str(caught.exception),'snapshot_late')
    def test_context_boot_mutation_refuses_before_dispatch(self):
        reader=self.reader();reader.context['boot']='unknown'
        with self.assertRaises(observer.Refusal) as caught:reader.snapshot()
        self.assertEqual(str(caught.exception),'context_changed');self.assertFalse((self.root/'count').exists())
    def test_decoder_duplicate_unknown_short_and_unterminated_ids(self):
        for raw in (b'a\n',b'a'*64,b'\n',b'a'*64+b'\n'+b'a'*64+b'\n'):
            with self.assertRaises(observer.Refusal):observer.inventory(raw)
        raw=json.dumps(self.records['a'*64]).encode()
        with self.assertRaises(observer.Refusal):observer.projection(raw,'a'*64)
        with self.assertRaises(observer.Refusal):observer.strict_json(b'{"id":1,"id":2}')

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
