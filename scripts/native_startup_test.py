"""Finite source-only controls; no Reference, engine, VM, gateway or app starts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from dev import startup_evidence as native, owned_capture
from qualification_refusal import project
from route_observation import outer_refusals
from qualification_runtime import require_effigy_binary

SCRIPTS=Path(__file__).resolve().parent
BASE=Path('/Users/tom/.local/share/northstar/release-audits/effigy/bounded-refusal-accounting/final-main-bd259769')

# This is a controlled native backend, selected by a private Effigy task. It
# produces the owning envelope shape and executes only finite local sh recipes.
PRODUCER=r'''
import json,os,sys,subprocess,signal
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(5)
from pathlib import Path
sys.path.insert(0,os.environ['CONTROL_SCRIPTS'])
from dev import silo_client as silo
root=Path.cwd();args=json.loads(os.environ['CONTROL_ARGS']);stage=os.environ['CONTROL_STAGE']
mode=os.environ.get('CONTROL_MODE','ok');target=os.environ.get('CONTROL_FAIL','')
if stage==target:
    if mode in ('unknown','latepublication'):sys.stderr.write('PRIVATE https://secret.invalid/?token=PRIVATE');sys.exit(7)
    if mode=='nonzero':sys.stdout.write('PRIVATE');sys.stderr.write('PRIVATE');sys.exit(7)
    if mode=='malformed':print('{"ok":true,"ok":false}');sys.exit(0)
    if mode=='warning':sys.stderr.write('PRIVATE warning\n')
if args[0]=='config':
    path=args[args.index('--path')+1]
    result={'schema':'effigy.config.v1','ok':True,'selected_path':path,
        'selected_value':{'path':path,'value':[{'name':n,'env':{k:os.environ[k] for k in os.environ if k.startswith('EFFIGY_PROFILE_')}} for n in ('api','front','admin')]}}
elif args[0]=='gateway':
    result={'private':True,'running':(root/'gateway.up').exists(),'routes':[], 'https_addr':'127.0.0.1:12345'}
    if args[1]=='up':(root/'gateway.up').touch();result['running']=True
    if args[1]=='down':(root/'gateway.up').unlink(missing_ok=True);result['running']=False
elif args[0]=='container' and args[1]=='scope':
    result={'schema':'effigy.container.scope.v1','ok':True,'checkout':str(root),'scope':{'kind':'none','token':None}}
elif args[0]=='native':
    result={}
elif args[0]=='container':
    container=args[1];operation=args[2];up=root/(container+'.up')
    states=[{'name':n,'owner':root.name+'|'+container+'|effigy|'+n,'status':'ready',
      'runtime_generation':'a'*32,'generation':'b'*32,'address':'127.0.0.1:12345',
      'internal_url':'http://127.0.0.1:12345','public_url':'https://'+n+'.control.test',
      'route_domain':n+'.control.test'} for n in ('api','front','admin')]
    if operation=='up':
        up.touch();p=root/'.effigy/runtime/host-processes'/container/'effigy';p.mkdir(parents=True,exist_ok=True)
        for state in states:(p/(state['name']+'.listener.json')).write_text(json.dumps(state))
    if operation=='down':
        up.unlink(missing_ok=True)
        p=root/'.effigy/runtime/host-processes'/container/'effigy'
        if p.exists():
            for item in p.glob('*.listener.json'):
                state=json.loads(item.read_text());state.update(status='stopped',route_owner=None);item.write_text(json.dumps(state))
    result={'services':[{'name':n,'status':'running'} for n in ('postgres','dbgate','mailpit','silo','silo_client')] if up.exists() else [],'managed_host_listeners':states}
    if operation=='shell':
        service=args[args.index('--service')+1];command=args[args.index('--command')+1]
        environment={'PATH':'/usr/bin:/bin','HOME':'/tmp'}
        if service=='silo':environment.update(MC_CONFIG_DIR='/tmp/.mc',MC_HOST_local='http://minioadmin:minioadmin@127.0.0.1:9000')
        alias={'status':'success','alias':'local','URL':'http://silo:9000','accessKey':'minioadmin','secretKey':'minioadmin','api':'S3v4','path':'auto'}
        import shlex
        shim='mc() { case "$*" in *"--json alias set "*) printf %s '+shlex.quote(json.dumps(alias))+';; *"--json alias list "*) printf %s '+shlex.quote(json.dumps(dict(alias,src='/root/.mc/config.json')))+';; *) :;; esac; }; '
        command=command.replace('/tmp/underlay-profile-cors-',str(root/'cors-'))
        child=subprocess.run(['/bin/sh','-c',shim+command],env=environment,capture_output=True,timeout=2)
        result={'schema':'effigy.container.bounded-exec.v1','schema_version':1,'ok':True,
          'container':container,'service':service,'failure':'complete','code':0,'limits':silo.BOUNDS,
          'retained':{'stdout_bytes':len(child.stdout),'stderr_bytes':len(child.stderr)},
          'preparation':{'captures':0,'retained':{'stdout_bytes':0,'stderr_bytes':0}},'attempts':1,
          'workspace_user_fallback':False,'remote_cancellation':'unverified','stdout':child.stdout.decode(),
          'stderr':child.stderr.decode(),'stdout_bytes':len(child.stdout),'stderr_bytes':len(child.stderr)}
        if mode in ('bounded','bounded_deadline') and stage==target:
            result.update(ok=False,failure='inner_command_failed',code=1,inner_code=17)
            for k in ('stdout','stderr','stdout_bytes','stderr_bytes'):result.pop(k)
            if mode=='bounded_deadline':
                result.update(failure='deadline',phase='command_execution',termination_scope='owned_host_client_group')
                result.pop('inner_code',None)
                result['retained']={'stdout_bytes':0,'stderr_bytes':0}
                result['refusal_observations']={'version':1,'operation_elapsed_ms':8001,'remaining_budget_ms':0,
                    'preparation_elapsed_ms':4,'attempt_elapsed_ms':7997,'spawn_disposition':'spawned',
                    'stdout':{'state':'eof','retained_prefix_bytes':{'semantics':'exact','bytes':0},'read_bytes':{'semantics':'exact','bytes':0}},
                    'stderr':{'state':'pending','retained_prefix_bytes':{'semantics':'unknown'},'read_bytes':{'semantics':'unknown'}},
                    'leader_exit_observed':'unknown'}
        elif child.returncode:sys.exit(19)
else:result={}
ok=result.get('ok',True)
print(json.dumps({'schema':'effigy.command.v1','schema_version':1,'binary':{},'command':{'kind':'control','name':'native'},'ok':ok,
    'result':result if ok else None,'error':None if ok else {'kind':'RunnerError','message':'PRIVATE','details':result}}))
sys.exit(0 if ok else 1)
'''

DRIVER=r'''
import json,os,sys,signal
signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(40)
from pathlib import Path
sys.path.insert(0,os.environ['CONTROL_SCRIPTS']);sys.path.insert(0,str(Path(os.environ['CONTROL_SCRIPTS'])/'dev'))
import profile_launcher as launcher
from dev import startup_evidence as native
root=Path.cwd();binary=os.environ['UNDERLAY_PROFILE_EFFIGY_BIN']
original=launcher._run_process
# All native calls still pass the real absolute-source gate and finite reader.
# Only their destination is replaced by this owned, non-engine task fixture.
def routed(identity,argv,*,cwd,env,timeout,**kwargs):
    args=argv[1:]
    if args[:1]==['--repo']:args=args[2:]
    args=[a for a in args if a!='--json']
    e=dict(env,CONTROL_ARGS=json.dumps(args),CONTROL_STAGE=native.CURRENT.get())
    return original(identity,[binary,'--repo',str(root),'native'],cwd=cwd,env=e,timeout=min(timeout,5),**kwargs)
launcher._run_process=routed
# Main performs the real source/tree/API/binary gate for every controlled
# invocation. Repeated nested calls in this immutable fake fixture use its
# admitted descriptor; production and the genuine native control are unchanged.
def same_descriptor(identity):
    info=Path(identity.binary).stat()
    if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)!=(identity.device,identity.inode,identity.size,identity.mtime_ns):
        raise launcher.ProfileError('controlled admitted descriptor changed')
launcher.verify_unchanged=same_descriptor
if os.environ.get('CONTROL_MODE')=='latepublication':
    original_emit=native.Session.emit
    def publish(self,name,state,*args,**kwargs):
        if state=='refused':raise ValueError('PRIVATE')
        return original_emit(self,name,state,*args,**kwargs)
    native.Session.emit=publish
# Live Compose/process observation is outside these controls. Keep the actual
# context caller and stage decorator, replacing only its private live producer.
def context(identity,repo,env,container):
    launcher._json_command(identity,repo,env,'container',container,'status')
    return {'ports':{'postgres':1,'smtp':2,'mailpit_http':3,'silo':4,'silo_console':5,'dbgate':6},
      'routes':{'front':'front.control.test','admin':'admin.control.test','api':'api.control.test','s3':'s3.control.test'},'https_port':12345}
launcher._profile_context=context
# Explicit settled source gate failures use actual owning input checks.
if os.environ.get('CONTROL_FAIL')=='source_gate':os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE']=str(root/'missing')
if os.environ.get('CONTROL_FAIL')=='readiness':
    original_ready=launcher._assert_profile_ready
    def refuse_ready(status,container):
        return original_ready({'services':[],'managed_host_listeners':[]},container)
    launcher._assert_profile_ready=refuse_ready
if os.environ.get('CONTROL_FAIL')=='cleanup':
    original_down=launcher._container_down
    def refuse_down(*args):
        native.ROLE.set(None)
        return native.stage('cleanup')(lambda: native.refuse('owning_gate_refused'))()
    launcher._container_down=refuse_down
try:
    result=launcher.main([os.environ.get('CONTROL_ACTION','start'),'disposable_test' if os.environ.get('CONTROL_ACTION')=='test' else 'hybrid','--repo',str(root)])
except BaseException as error:
    if isinstance(error,SystemExit):raise
    launcher._cli_failure(error);sys.exit(1)
sys.exit(result)
'''


def load_runtime():
    spec=importlib.util.spec_from_file_location('native_runtime_control',SCRIPTS/'qualify-reference-runtime.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

class NativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',UNDERLAY_PROFILE_EFFIGY_SOURCE=str(BASE/'source-checkout'),UNDERLAY_PROFILE_EFFIGY_BIN=str(BASE/'private-bin/effigy'))
        cls.binary=require_effigy_binary(env=cls.env)
        cls.runtime=load_runtime()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ur.native-source.',dir=Path.home());self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        (self.root/'native.py').write_text(PRODUCER);(self.root/'driver.py').write_text(DRIVER)
        (self.root/'effigy.toml').write_text('[tasks.native]\nrun="python3 native.py"\nrun_in="host"\n[tasks.profile]\nrun="python3 driver.py"\nrun_in="host"\n')
        controls=self.root/'controls.json';controls.write_text('{"source_only":true}');controls.chmod(0o600)
        now=time.time()
        intent={'schema':'underlay.product-batch-intent.v1','head':'a'*40,'source':'bd2597693f7c4c9ad786896a9448a7e746ff13a8',
            'binary_sha256':'2d72c3df0d61c05a150d5d86c39b2ea931eca9549b794b559fa39d95dc002a59',
            'started_at':now,'deadline_at':now+14400,'stages':['runtime','container'],'controls_sha256':hashlib.sha256(controls.read_bytes()).hexdigest()}
        p=self.root/'intent.json';p.write_text(json.dumps(intent));p.chmod(0o600)
        self.env=dict(self.env,CONTROL_SCRIPTS=str(SCRIPTS),UNDERLAY_PROFILE_BATCH_INTENT=str(p),UNDERLAY_PROFILE_BATCH_INTENT_SHA256=hashlib.sha256(p.read_bytes()).hexdigest(),EFFIGY_INTERNAL_SUPPRESS_HEADER='1',
            UNDERLAY_PROFILE_TEST_TASK='native',UNDERLAY_PROFILE_TEST_TIMEOUT_SECS='5',CONTROL_ARGS='[]',CONTROL_STAGE='test_action')
        import sys
        sys.path.insert(0,str(SCRIPTS/'dev'));import profile_launcher as launcher
        for name in launcher._LAUNCHER_FIELDS:self.env[name]='owned-bucket' if name.endswith('BUCKET') else name.lower().replace('_','-')+'.control.test'
        self.events=[]
        class Journal:
            def append(inner,event,**fields):self.events.append((event,fields))
        self.runtime.COMMAND_DIAGNOSTICS=Journal()
    def pipeline(self,stage='',mode='nonzero',action='start'):
        env=dict(self.env,CONTROL_FAIL=stage,CONTROL_MODE=mode,CONTROL_ACTION=action)
        return self.runtime.run([self.binary,'--repo',str(self.root),'profile'],cwd=self.root,env=env,timeout=40)
    def retained(self,error):
        projected=project(error,'runtime_profile')
        outer=outer_refusals(json.dumps(projected))
        self.assertTrue(outer['typed_failure_available'])
        self.assertNotIn('PRIVATE',json.dumps((self.events,projected,outer)))
        self.assertNotIn('secret.invalid',json.dumps((self.events,projected,outer)))
        record=outer['records'][0]['native_failure']
        self.assertEqual(record['effect_state'],'unknown')
        journals=list(self.root.glob('startup-*.jsonl'));self.assertTrue(journals)
        for path in journals:
            text=path.read_text();self.assertNotIn('PRIVATE',text);self.assertEqual(path.stat().st_mode&0o777,0o600)
        return record
    def test_actual_configured_launcher_start_and_status_success(self):
        self.assertEqual(self.pipeline(mode='ok').returncode,0)
        self.assertEqual(self.pipeline(mode='ok',action='status').returncode,0)
        # Idempotency uses the already-running branch with current listener files.
        self.assertEqual(self.pipeline(mode='ok').returncode,0)
        self.assertEqual(self.pipeline(mode='ok',action='down').returncode,0)
    def test_actual_source_gate_and_original_context_failures(self):
        for stage in ('source_gate','original_context','gateway_setup','services_up','managed_state','service_context'):
            with self.subTest(stage=stage):
                with self.assertRaises(native.NativeFailure) as caught:self.pipeline(stage,'unknown')
                record=self.retained(caught.exception)
                self.assertEqual(record['stage'],stage)
                self.assertEqual(record['reason'],'source_refused' if stage=='source_gate' else 'native_nonzero')
                # Every failing start is settled as a controlled process; this
                # says nothing about product or remote cleanup.
                for path in self.root.glob('*.up'):path.unlink()
    def test_actual_bootstrap_nested_refusal_and_warning(self):
        with self.assertRaises(native.NativeFailure) as caught:self.pipeline('bootstrap_readguard','bounded')
        record=self.retained(caught.exception)
        self.assertEqual(record['reason'],'bounded_native_refused')
        self.assertEqual(record['native']['bounded']['inner_code'],17)
        self.assertEqual(record['native']['error_code'],'RunnerError')
        self.assertTrue(record['callers'])
    def test_actual_nonjson_zero_exit_and_cleanup_primary(self):
        with self.assertRaises(native.NativeFailure) as caught:self.pipeline('services_up','malformed')
        record=self.retained(caught.exception);self.assertEqual(record['reason'],'native_json_refused')
        self.assertEqual(record['stage'],'services_up')
        # A later cleanup refusal cannot replace the earlier primary.
        from dev import profile_launcher as launcher
        session=native.Session(dict(self.env,UNDERLAY_PROFILE_COMMAND_NONCE=secrets.token_hex(16)),self.root,'start','hybrid')
        token=native.ACTIVE.set(session)
        try:
            primary=native.NativeFailure(native.base('native_nonzero','services_up'))
            with patch.object(launcher,'_profile_root',return_value=self.root),patch.object(launcher,'_prepare_silo_override'),patch.object(launcher,'_json_command',return_value={}),patch.object(launcher,'_private_gateway_status',return_value={}),patch.object(launcher,'_assert_stopped'),patch.object(launcher,'_ensure_private_root'),patch.object(launcher,'_gateway_start',side_effect=primary),patch.object(launcher,'_container_down',side_effect=RuntimeError('PRIVATE')):
                with self.assertRaises(native.NativeFailure) as failure:launcher._start_services(None,self.root,self.env,'hybrid')
            self.assertEqual(failure.exception.record['stage'],'services_up');self.assertTrue(failure.exception.record['cleanup_unavailable'])
        finally:native.ACTIVE.reset(token);session.close()
    def test_finite_reader_bounds_deadline_and_unknown_identity(self):
        for code,reason in [('import os;os.write(1,b"x"*300000)','stdout_overflow'),('import os;os.write(2,b"x"*300000)','stderr_overflow'),('import time;time.sleep(1)','deadline')]:
            with self.assertRaises(native.NativeFailure) as caught:
                native.capture_command([sys.executable,'-c',code],env=dict(os.environ),timeout=.1 if reason=='deadline' else 2)
            record=caught.exception.record;self.assertEqual(record['capture']['refusal'],reason);self.assertTrue(record['capture']['leader_reaped'])
            self.assertLessEqual(record['capture']['stdout']['retained_bytes'],262144)
        # A complete-looking typed prefix from an incomplete stream earns no
        # marker/schema credit, even when the direct child was owned.
        code='import sys;from dev import startup_evidence as n;sys.stderr.write(n.MARKER+__import__("json").dumps(n.base("native_nonzero","services_up"))+"\\n"+"x"*300000)'
        with self.assertRaises(native.NativeFailure) as caught:
            native.capture_command([sys.executable,'-c',code],cwd=SCRIPTS,env=dict(os.environ),timeout=2)
        self.assertEqual(caught.exception.record['reason'],'native_capture_refused')
        self.assertEqual(caught.exception.record['capture']['refusal'],'stderr_overflow')
        with patch.object(owned_capture,'kernel_identity',return_value=None):
            with self.assertRaises(native.NativeFailure) as caught:native.capture_command([sys.executable,'-c','pass'],env=dict(os.environ),timeout=2)
        self.assertFalse(caught.exception.record['capture']['identity_admitted'])
    def test_marker_closed_shape_foreign_conflicts_and_late_publication(self):
        record=native.base('native_nonzero','services_up');record.update(binding='a'*64,nonce='b'*32)
        line=native.MARKER+json.dumps(record)
        for text in (line+'\n'+line,'prefix'+line,line[:-2],line.replace('services_up','PRIVATE'),line.replace('"exit": null','"exit": null,"PRIVATE":"secret"'),line.replace('"stage": "services_up"','"stage":"services_up","stage":"services_up"')):
            self.assertEqual(native.marker_record(text,binding='a'*64,nonce='b'*32),(None,True))
        self.assertEqual(native.marker_record(line,binding='c'*64,nonce='b'*32),(None,True))
        def late(*args,**kwargs):raise RuntimeError('PRIVATE')
        with self.assertRaises(native.NativeFailure) as caught:
            native.capture_command([sys.executable,'-c','import sys;sys.exit(7)'],env=dict(os.environ),timeout=2,emit=late)
        self.assertEqual(caught.exception.record['reason'],'native_nonzero');self.assertTrue(caught.exception.record['publication_unavailable'])
        with self.assertRaises(native.NativeFailure) as caught:native.capture_command([sys.executable,'-c','pass'],env=dict(os.environ),timeout=2,emit=late)
        self.assertEqual(caught.exception.record['reason'],'journal_refused')
    def test_journal_sticky_capacity_replacement_and_binding(self):
        env=dict(self.env,UNDERLAY_PROFILE_COMMAND_NONCE=secrets.token_hex(16))
        session=native.Session(env,self.root,'start','hybrid')
        try:
            session.path.chmod(0o644)
            with self.assertRaises(ValueError):session.emit('start','entered')
            session.path.chmod(0o600)
            with self.assertRaises(ValueError):session.emit('cleanup','entered')
        finally:session.close()
        with self.assertRaises(ValueError):native.Session(dict(env,UNDERLAY_PROFILE_COMMAND_NONCE='PRIVATE'),self.root,'start','hybrid')
        first=native.Session(env,self.root,'context','hybrid');second=native.Session(env,self.root,'context','hybrid')
        try:
            self.assertNotEqual(first.path,second.path);self.assertNotEqual(first.call_id,second.call_id)
            self.assertEqual(first.nonce,second.nonce)
        finally:first.close();second.close()

class ExtendedControls(unittest.TestCase):
    setUpClass=classmethod(NativeControls.setUpClass.__func__)
    setUp=NativeControls.setUp
    pipeline=NativeControls.pipeline
    retained=NativeControls.retained

    def test_bootstrap_alias_bucket_and_nested_deadline_survive(self):
        for stage,mode in (('bootstrap_alias','nonzero'),('bootstrap_bucket','nonzero'),('bootstrap_readguard','bounded_deadline')):
            with self.subTest(stage=stage):
                with self.assertRaises(native.NativeFailure) as caught:self.pipeline(stage,mode)
                record=self.retained(caught.exception);self.assertEqual(record['stage'],stage)
                if mode=='bounded_deadline':
                    observed=record['native']['bounded']['refusal_observations']
                    self.assertEqual(observed['stderr']['read_bytes'],{'semantics':'unknown'})
                    self.assertEqual(record['native']['bounded']['phase'],'command_execution')
                # Fixture-only state disposition; no product resources exist.
                for path in self.root.glob('*.up'):path.unlink()
                for path in self.root.glob('.effigy/runtime/host-processes/*/effigy/*.listener.json'):
                    value=json.loads(path.read_text());value.update(status='stopped',route_owner=None);path.write_text(json.dumps(value))

    def test_actual_test_action_and_readiness_refusal(self):
        with self.assertRaises(native.NativeFailure) as caught:self.pipeline('test_action','unknown',action='test')
        record=self.retained(caught.exception);self.assertEqual(record['stage'],'test_action');self.assertEqual(record['reason'],'native_nonzero')
        with self.assertRaises(native.NativeFailure) as caught:self.pipeline('readiness','unknown')
        record=self.retained(caught.exception);self.assertEqual(record['stage'],'readiness')

    def test_warnings_success_shape_and_json_caller_counts(self):
        self.assertEqual(self.pipeline('services_up','warning').returncode,0)
        result=native.capture_command([sys.executable,'-c','import sys;print("PRIVATE",file=sys.stderr);print("{}")'],env=dict(os.environ),timeout=2)
        self.assertEqual(result.stdout,'{}\n');self.assertEqual(result.returncode,0)
        with self.assertRaises(native.NativeFailure) as caught:native.json_result(result.stdout,result.native_observation)
        self.assertEqual(caught.exception.record['capture']['stderr']['read_bytes'],8)
        self.assertNotIn('PRIVATE',json.dumps(caught.exception.record))

    def test_wrapped_primary_and_actual_default_json_interface(self):
        from dev import profile_launcher as launcher
        primary=native.NativeFailure(native.base('native_nonzero','services_up'))
        outer=RuntimeError('PRIVATE');outer.__cause__=primary
        self.assertEqual(project(outer,'runtime_profile')['native_failure']['stage'],'services_up')
        spec=importlib.util.spec_from_file_location('native_default_caller',SCRIPTS/'qualify-reference-container.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        result=native.capture_command([sys.executable,'-c','print("not JSON PRIVATE")'],env=dict(os.environ),timeout=2)
        with patch.object(module,'run',return_value=result):
            with self.assertRaises(native.NativeFailure) as caught:module.effigy_json('/private',self.root,self.env,'status')
        self.assertEqual(caught.exception.record['reason'],'native_json_refused')
        self.assertTrue(caught.exception.record['capture']['stdout']['eof'])

class GenuineNativeControls(unittest.TestCase):
    setUpClass=classmethod(NativeControls.setUpClass.__func__)
    setUp=NativeControls.setUp
    retained=NativeControls.retained
    def test_qualified_bounded_renderer_to_exported_launcher_task_parent_outer(self):
        import shutil
        repo=self.root/'backend';repo.mkdir()
        bindir=self.root/'bin';bindir.mkdir();home=self.root/'home';home.mkdir(mode=0o700)
        (repo/'compose.yml').write_text('services:\n  silo_client:\n    image: private-fake-never-executed\n')
        target=repo/'infra/dev/catalog/silo-mc';target.parent.mkdir(parents=True)
        shutil.copytree(SCRIPTS/'dev/catalog/silo-mc',target)
        fake=bindir/'colima'
        fake.write_text('#!'+sys.executable+'\nimport sys,json,signal\nsignal.alarm(5)\nif sys.argv[1:]==["status","--profile","effigy"]:print("colima is running using containerd")\nelif sys.argv[1:]==["list","--json"]:print(json.dumps({"name":"effigy","status":"Running","cpus":2,"memory":4294967296,"disk":34359738368}))\nelse:sys.stdout.write("X"*70000)\n')
        fake.chmod(0o700)
        driver=repo/'failure.py'
        driver.write_text("""import os,sys,signal
from pathlib import Path
signal.alarm(30)
sys.path.insert(0,os.environ['CONTROL_SCRIPTS'])
from dev import profile_launcher as launcher
from dev import startup_evidence as native,silo_client
try:
    native.configure(os.environ,Path.cwd(),'start','hybrid')
    identity=launcher.verify_binary(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE'],os.environ['UNDERLAY_PROFILE_EFFIGY_BIN'])
    command_env=dict(os.environ);command_env.pop('EFFIGY_INTERNAL_SUPPRESS_HEADER',None)
    @native.stage('bootstrap_readguard')
    def invoke():
        return launcher._run_process(identity,[identity.binary,'--repo',str(Path.cwd()),*silo_client.bounded_arguments('silo_client','printf SHOULD_NOT_EXECUTE')],cwd=Path.cwd(),env=command_env,timeout=12,emit_stdout=False,emit_stderr=False)
    invoke()
except Exception as error:
    launcher._cli_failure(error);sys.exit(1)
raise AssertionError('bounded refusal falsely accepted')
""")
        (repo/'effigy.toml').write_text('[tasks.failure]\nrun="python3 failure.py"\nrun_in="host"\n[containers.hybrid_services]\ncompose_file="compose.yml"\nproject_name="native-owned"\nworking_dir="/workspace"\nprimary_service="silo_client"\n')
        env=dict(self.env,HOME=str(home),COLIMA_HOME=str(self.root/'colima'),LIMA_HOME=str(self.root/'lima'),
            EFFIGY_COMPOSE_BACKEND='colima',PATH=str(bindir)+os.pathsep+self.env['PATH'])
        for key in ('DOCKER_HOST','DOCKER_CONTEXT','COLIMA_PROFILE'):env.pop(key,None)
        with self.assertRaises(native.NativeFailure) as caught:
            self.runtime.run([self.binary,'--repo',str(repo),'failure'],cwd=repo,env=env,timeout=30)
        record=self.retained(caught.exception)
        self.assertEqual(record['reason'],'bounded_native_refused',json.dumps(record))
        self.assertEqual(record['stage'],'bootstrap_readguard')
        block=record['native']['bounded']['refusal_observations']
        self.assertEqual(block['stdout']['state'],'overflow')
        self.assertGreater(block['stdout']['read_bytes']['bytes'],65536)
        rows=[json.loads(line) for p in self.root.glob('startup-*.jsonl') for line in p.read_text().splitlines()]
        originals=[r['observation']['native'] for r in rows if r.get('observation') and r['observation']['native'] and r['observation']['native']['bounded']]
        self.assertTrue(originals)
        self.assertTrue(all(value==record['native'] for value in originals))
        self.assertNotIn('SHOULD_NOT_EXECUTE',json.dumps(record))

class MarkerControls(unittest.TestCase):
    setUpClass=classmethod(NativeControls.setUpClass.__func__)
    setUp=NativeControls.setUp
    pipeline=NativeControls.pipeline
    retained=NativeControls.retained
    def test_actual_configured_marker_refusals_and_late_publication(self):
        source="""import os,sys,json,io,contextlib
from pathlib import Path
sys.path.insert(0,os.environ['CONTROL_SCRIPTS'])
from dev import startup_evidence as native
native.configure(os.environ,Path.cwd(),'start','hybrid')
error=native.NativeFailure(native.base('native_nonzero','services_up'))
output=io.StringIO()
with contextlib.redirect_stderr(output):native.cli_failure(error)
line=output.getvalue();mode=os.environ['CONTROL_MARKER']
if mode=='duplicate':line=line+line
elif mode=='truncated':line=line[:-8]
elif mode=='unknown':line=line.replace('services_up','PRIVATE')
elif mode=='foreign':line=line.replace(os.environ['UNDERLAY_PROFILE_COMMAND_NONCE'],'f'*32)
elif mode=='extra':line=line.replace('"exit":null','"exit":null,"PRIVATE":"secret"')
sys.stderr.write(line);sys.exit(1)
"""
        (self.root/'markers.py').write_text(source)
        with (self.root/'effigy.toml').open('a') as f:f.write('\n[tasks.markers]\nrun="python3 markers.py"\nrun_in="host"\n')
        for mode in ('duplicate','truncated','unknown','foreign','extra'):
            with self.assertRaises(native.NativeFailure) as caught:
                self.runtime.run([self.binary,'--repo',str(self.root),'markers'],cwd=self.root,env=dict(self.env,CONTROL_MARKER=mode),timeout=8)
            record=self.retained(caught.exception);self.assertEqual(record['reason'],'marker_refused')
        with self.assertRaises(native.NativeFailure) as caught:self.pipeline('services_up','latepublication')
        record=self.retained(caught.exception)
        self.assertEqual(record['reason'],'native_nonzero');self.assertTrue(record['publication_unavailable'])

from reference_lifecycle_test import PendingIdentityTests,PendingBarrierTests

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(60)
    unittest.main()
