"""Real original-route constructor/transport controls, all in fresh private fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import original_container_route as route
from fresh_backend_admission import FreshBackend, Refusal
import container_identity_observer as observer


def help_output(namespace='default',address='/run/containerd/containerd.sock',config='/etc/nerdctl/nerdctl.toml'):
    return ('nerdctl is a command line interface for containerd\n\nConfig file ($NERDCTL_TOML): '+config+'\n\nUsage: nerdctl [command]\n\nFlags:\n'
        +'      --address string     containerd address, optionally with "unix://" prefix [$CONTAINERD_ADDRESS] (default "'+address+'")\n'
        +'      --namespace string   containerd namespace, such as "moby" for Docker, "k8s.io" for Kubernetes [$CONTAINERD_NAMESPACE] (default "'+namespace+'")\n'
        +"\nRun 'nerdctl COMMAND --help' for more information on a command.\n\n").encode()

class RouteControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.backend=FreshBackend(self.root,{})
        self.checkout=self.backend.paths['HOME']/'main';self.checkout.mkdir(mode=0o700)
        (self.checkout/'effigy.toml').write_text('fixture source config\n');(self.checkout/'effigy.toml').chmod(0o600)
        subprocess.run(['git','init','-q',str(self.checkout)],check=True,env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.scope={'schema':'effigy.container.scope.v1','schema_version':1,'ok':True,'checkout':str(self.checkout),'scope':{'kind':'none','token':None}}
        self.policy={'driver':'colima','profile':'effigy','project_name':'fixture','primary_service':'api','services':{'api':{},'portless':{}}}
        self.config={'ok':True,'result':{'schema':'effigy.config.v1','ok':True,'selected_path':'containers','selected_value':{'path':'containers','value':{'default':'stack','stack':self.policy}}}}
        self.backend.original_scope(self.checkout,b'[containers.default]\n','a'*64)
        self.backend.original_policy(self.checkout,'default',json.dumps(self.config).encode(),json.dumps({'ok':True,'result':self.scope}).encode())
        self.colima=self.root/'colima';self.lima=self.root/'limactl';self.ssh=self.root/'ssh'
        start='''#!INTERPRETER
import sys
from pathlib import Path
r=Path(__file__).parent
expected=['start','--profile','effigy','--runtime','containerd','--activate=false','--ssh-config=false','--ssh-agent=false','--template=false','--mount',str(r)+':w','--cpu','6','--memory','8','--disk','64']
if sys.argv[1:]!=expected:sys.exit(81)
for name in ['lima-home/colima-effigy','colima-home/effigy']:(r/name).mkdir(mode=0o700)
p=r/'lima-home/colima-effigy/lima.yaml';p.write_text('mounts:\\n    - location: '+str(r)+'\\n      writable: true\\n');p.chmod(0o600)
p=r/'colima-home/effigy/colima.yaml';p.write_text('runtime: containerd\\nmounts:\\n  - location: '+str(r)+'/\\n    writable: true\\n');p.chmod(0o600)
'''.replace('INTERPRETER',sys.executable)
        self.colima.write_text(start);self.colima.chmod(0o700)
        source='''#!INTERPRETER
import sys,json,hashlib,os,time
from pathlib import Path
r=Path(__file__).parent;a=sys.argv[1:];v=json.loads((r/'transport.json').read_text())
if a[:4]!=['shell','--workdir',str(r),'colima-effigy']:sys.exit(82)
if os.environ.get('LIMA_HOME')!=str(r/'lima-home') or os.environ.get('COLIMA_HOME')!=str(r/'colima-home') or any(k.startswith(('CONTAINERD_','NERDCTL_')) for k in os.environ):sys.exit(83)
tail=a[4:];mode=v.get('mode');p=r/'calls';calls=json.loads(p.read_text()) if p.exists() else [];calls.append('nonce' if tail[0]=='/bin/cat' else tail[-1] if tail[:2]==['sudo','nerdctl'] else 'metadata');p.write_text(json.dumps(calls));p.chmod(0o600)
if mode=='stall':time.sleep(1)
if mode=='overflow':sys.stdout.write('X'*70000);sys.exit(0)
if mode=='stderr':sys.stderr.write('SYNTHETIC_SECRET_ENV_CONFIG');sys.exit(1)
if mode=='partial':sys.stdout.write('partial');sys.exit(0)
if tail[0]=='/bin/cat':
 p=Path(tail[1]);assert p.parent==r and p.name.startswith('.observer-cwd-')
 sys.stdout.buffer.write(p.read_bytes());sys.exit(0)
if tail[:3]==['sudo','/bin/sh','-c']:
 if len(tail)!=4 or hashlib.sha256(tail[3].encode()).hexdigest()!=v['script_sha']:sys.exit(84)
 digest=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
 if mode=='rootless':sys.stdout.write('underlay.nerdctl-route-metadata.v1\\nrootless\\n'+digest+'\\nabsent\\n-\\n');sys.exit(0)
 if mode=='override':sys.exit(62)
 cfg=v.get('config_sha');state='present' if cfg else 'absent'
 if mode=='changed_config' and calls.count('metadata')>1:cfg='c'*64;state='present'
 print('underlay.nerdctl-route-metadata.v1\\nrootful\\n'+digest+'\\n'+state+'\\n'+(cfg or '-'));sys.exit(0)
if tail==['sudo','nerdctl','--version']:print('nerdctl version '+('2.2.0' if mode=='version' else '2.3.1'));sys.exit(0)
if tail==['sudo','nerdctl','--help']:
 text=v['help']
 if mode=='changed_help' and calls.count('--help')>1:text=text.replace('default "default"','default "changed"')
 sys.stdout.write(text);sys.exit(0)
if tail[:4]==['sudo','nerdctl','--namespace',v['namespace']] and tail[4:6]==['--address',v['address']]:
 args=tail[6:]
 if args==['ps','--all','--no-trunc','--quiet']:sys.stdout.write(''.join(k+'\\n' for k in sorted(v['records'])));sys.exit(0)
 if len(args)==7 and args[:5]==['container','inspect','--mode','dockercompat','--format']:print(json.dumps(v['records'][args[6]]));sys.exit(0)
sys.exit(85)
'''.replace('INTERPRETER',sys.executable)
        self.lima.write_text(source);self.lima.chmod(0o700);self.ssh.write_text('#!/bin/sh\nexit 80\n');self.ssh.chmod(0o700)
        self.backend.bind_tools(self.colima,self.lima,self.ssh);self.env=self.backend.env.copy()
        self.model={'help':help_output().decode(),'namespace':'default','address':'/run/containerd/containerd.sock','config_sha':None,'script_sha':hashlib.sha256(route.METADATA_SCRIPT.encode()).hexdigest(),'records':{}}
        self.write()
    def tearDown(self):self.temp.cleanup()
    def write(self,mode=None):
        self.model['mode']=mode;p=self.root/'transport.json';p.write_text(json.dumps(self.model));p.chmod(0o600)
        p=self.root/'calls'
        if p.exists():p.unlink()
    def start(self):
        args=self.backend.start_command(self.env)
        subprocess.run(args,check=True,env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
    def test_source_receipt_pins_before_effect_and_semantic_original_intent(self):
        source=self.backend.require_read_contract();self.assertEqual(source['owner_receipt_sha256'],route.OWNER_SHA)
        self.assertFalse(source['binary_source_attested']);self.assertEqual(source['source_defaults'],route.SOURCE_DEFAULTS)
        self.assertFalse((self.root/'lima-home/colima-effigy').exists())
        self.assertEqual(self.backend.policies[(str(self.checkout),'default')]['services'],['api','portless'])
        self.assertEqual(self.backend.policies[(str(self.checkout),'default')]['primary'],'api');self.assertIsNone(self.scope['scope']['token'])
    def test_real_constructor_original_route_after_start_before_compose_no_boot_claim(self):
        self.start();result=self.backend.admit_original_route(self.env)
        self.assertEqual(result['namespace'],'default');self.assertEqual(result['config_state'],'absent')
        self.assertFalse(result['vm_signal_authority']);self.assertFalse(result['backend_boot_verified'])
        self.assertEqual(json.loads((self.root/'calls').read_text()),['nonce','metadata','--version','--help','metadata','--help'])
        self.assertEqual(list(self.root.glob('.observer-cwd-*')),[])
        self.assertNotIn('SYNTHETIC_SECRET',json.dumps(result))
    def test_toml_route_does_not_get_normalized_to_source_defaults(self):
        self.model.update(help=help_output('selected','/run/selected.sock').decode(),namespace='selected',address='/run/selected.sock',config_sha='b'*64);self.write()
        self.start();result=self.backend.admit_original_route(self.env)
        self.assertEqual(result['namespace'],'selected');self.assertEqual(result['address'],'/run/selected.sock');self.assertEqual(result['config_sha256'],'b'*64)
    def test_cli_and_host_env_overrides_refuse_before_transport(self):
        self.start();self.backend.bind_generated_profile();reader=route.RouteReader(self.backend,self.env)
        with self.assertRaises(Refusal):reader.read(['sudo','nerdctl','--namespace','forged','--help'],time.monotonic()+1)
        for key in ('CONTAINERD_NAMESPACE','NERDCTL_TOML','LIMA_INSTANCE','SSH','DOCKER_HOST'):
            with self.assertRaises(Refusal):self.backend.admit_original_route(dict(self.env,**{key:''}))
        self.assertFalse((self.root/'calls').exists())
    def test_rootless_guest_override_bad_version_changed_config_and_help_refuse(self):
        self.start()
        for mode in ('rootless','override','version','changed_config','changed_help'):
            self.write(mode)
            with self.assertRaises(Refusal):self.backend.admit_original_route(self.env)
        self.assertIsNone(self.backend.original_route)
    def test_help_parser_actual_shape_duplicate_wrong_config_escaped_unknown_and_eof(self):
        line=help_output().decode().splitlines()[7]
        variants=[help_output()[:-1],help_output(config='/home/foreign/nerdctl.toml'),help_output().replace(b'Flags:',b'Flags: \x1b'),help_output()+b'secret\n',help_output().replace(b'      --namespace string',b'--namespace string'),help_output().replace(b'default "default"',b'default "x\\ny"'),help_output().replace(b'\nFlags:\n',('\nFlags:\n'+line+'\n').encode())]
        for raw in variants:
            with self.subTest(size=len(raw)),self.assertRaises(Refusal):route.help_route(raw)
    def test_actual_capture_caps_incomplete_stderr_deadline_and_privacy(self):
        self.start()
        for mode in ('overflow','partial','stderr'):
            self.write(mode)
            with self.assertRaises(Refusal) as caught:self.backend.admit_original_route(self.env)
            self.assertNotIn('SECRET',str(caught.exception))
        self.write('stall');capture=route.host_capture
        def finite(argv,env,cwd,deadline):return capture(argv,env,cwd,min(deadline,time.monotonic()+.02))
        with patch.object(route,'host_capture',finite),self.assertRaises(Refusal):self.backend.admit_original_route(self.env)
    def test_root_tool_config_mount_policy_mutation_and_preexisting_refuse(self):
        self.start();self.backend.admit_original_route(self.env)
        config=self.root/'lima-home/colima-effigy/lima.yaml';config.write_text('mounts: []\n');config.chmod(0o600)
        with self.assertRaises(Refusal):self.backend.admit_original_route(self.env)
        self.assertEqual(len(json.loads((self.root/'calls').read_text())),6)
    def test_incomplete_original_foreign_policy_holds_constructor_and_cleanup(self):
        self.start();self.backend.admit_original_route(self.env)
        with self.assertRaises(Refusal) as caught:self.backend.observer_for(self.checkout,self.env)
        self.assertEqual(str(caught.exception),'independent_foreign_scope_required')
    def test_factory_full_id_reader_uses_original_route_and_independent_foreign_policy(self):
        other=self.backend.paths['HOME']/'other';other.mkdir(mode=0o700)
        (other/'effigy.toml').write_text('independent foreign source config\n');(other/'effigy.toml').chmod(0o600)
        subprocess.run(['git','init','-q',str(other)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        scope=dict(self.scope,checkout=str(other))
        config=copy.deepcopy(self.config);config['result']['selected_path']='containers.hybrid_services'
        config['result']['selected_value']['path']='containers.hybrid_services'
        config['result']['selected_value']['value']=dict(self.policy,project_name='foreign')
        self.backend.original_policy(other,'hybrid_services',json.dumps(config).encode(),json.dumps({'ok':True,'result':scope}).encode())
        def record(token,project,checkout,service):
            return dict(id=token*64,created='2026-10-14T01:02:03Z',project=project,checkout=str(checkout),service=service,oneoff='false',running=True,status='running')
        records=[record('a','fixture',self.checkout,'api'),record('b','fixture',self.checkout,'portless'),record('c','foreign',other,'api'),record('d','foreign',other,'portless')]
        self.model.update(help=help_output('selected','/run/selected.sock').decode(),namespace='selected',address='/run/selected.sock',config_sha='b'*64,records={r['id']:r for r in records});self.write()
        self.start();reader=self.backend.observer_for(self.checkout,self.env,'default',[(str(other),'hybrid_services')])
        self.assertEqual(reader.context['namespace'],'selected');self.assertEqual(reader.context['address'],'/run/selected.sock')
        self.assertEqual(reader.env['HOME'],self.env['HOME']);self.assertIsNone(reader.context['boot'])
        import importlib.util
        spec=importlib.util.spec_from_file_location('route_scoped_down',Path(__file__).with_name('qualify-reference-container.py'))
        caller=importlib.util.module_from_spec(spec);spec.loader.exec_module(caller)
        fake=self.root/'effigy'
        fake.write_text('#!'+sys.executable+"\n"+"import json,sys\nfrom pathlib import Path\nr=Path(__file__).parent\nif sys.argv[1:]!=['--repo',str(r/'home/main'),'container','down','--json']:sys.exit(89)\nv=json.loads((r/'transport.json').read_text())\nv['records']={k:x for k,x in v['records'].items() if x['project']=='foreign'}\n(r/'transport.json').write_text(json.dumps(v))\n(r/'transport.json').chmod(0o600)\nprint(json.dumps({'ok':True,'result':{}}))\n")
        fake.chmod(0o700);receipts=[]
        self.assertTrue(caller.independently_observe_container_down(str(fake),self.checkout,dict(self.env,UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT=str(self.root)),receipts,reader))
        self.assertEqual(len(reader._baseline['foreign']),2)
        self.assertTrue(receipts[-1]['container_cleanup_verified']);self.assertFalse(receipts[-1]['vm_signal_authority'])
        reader.env['HOME']='/foreign'
        with self.assertRaises(Refusal):reader.guard()
    def test_original_policy_mutation_refuses_before_any_backend_effect(self):
        self.backend.policies[(str(self.checkout),'default')]['services']=[]
        with self.assertRaises(Refusal):self.backend.start_command(self.env)
        self.assertFalse((self.root/'lima-home/colima-effigy').exists())
    def test_metadata_wrong_rootful_duplicate_truncated_and_error_never_absence(self):
        for raw in (b'',b'underlay.nerdctl-route-metadata.v1\nrootless\n'+b'a'*64+b'\nabsent\n-\n',b'underlay.nerdctl-route-metadata.v1\r\nrootful\r\n'+b'a'*64+b'\r\nabsent\r\n-\r\n'):
            with self.assertRaises(Refusal):route.metadata(raw)
    def test_actual_default_entry_semantic_policy_precedes_foreign_hold_and_effects(self):
        import importlib.util
        from types import SimpleNamespace
        spec=importlib.util.spec_from_file_location('route_default_entry',Path(__file__).with_name('qualify-reference-container.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        fixture=Path(tempfile.mkdtemp(dir=self.root)).resolve();fixture.chmod(0o700);calls=[];checkouts=[]
        def instances(source,parent):
            from private_cargo_cache_test import CacheTests
            _, cargo_source, _, _ = CacheTests.fixture(self, root=fixture)
            checkout=parent/'main';checkout.mkdir(mode=0o700)
            api=checkout/'apps/acme-api';api.mkdir(parents=True)
            (api/'Cargo.lock').write_bytes((cargo_source/'apps/acme-api/Cargo.lock').read_bytes())
            subprocess.run(['git','init','-q',str(checkout)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            (checkout/'effigy.toml').write_text('siblings = false\n');checkouts.append(checkout);return [checkout]
        def producer(args,**kwargs):
            calls.append(args)
            checkout=Path(args[args.index('--repo')+1])
            tail=args[args.index(str(checkout))+1:]
            if checkout!=checkouts[0]:raise Refusal('foreign_source_capture_unqualified')
            if tail==['bundle','inspect','--json']:
                value={'result':{'source':{'source_type':'path','source_path':str(module.REPO)}}}
            elif tail==['dev','--plan']:return SimpleNamespace(returncode=0,stdout='workspace-rust-bun',stderr='')
            elif tail==['config','--inspect']:return SimpleNamespace(returncode=0,stdout='"41001:41001" "41002:41002" "41003:41003"',stderr='')
            elif tail==['config','--inspect','--path','containers']:value=self.config
            elif tail==['container','scope']:value={'ok':True,'result':dict(self.scope,checkout=str(checkout))}
            else:raise AssertionError('non-source dispatch forbidden')
            return SimpleNamespace(returncode=0,stdout=json.dumps(value),stderr='')
        real_run=subprocess.run
        def run(args,**kwargs):
            if args==['git','-C',str(self.root),'rev-parse','HEAD']:return SimpleNamespace(returncode=0,stdout='a'*40+'\n')
            return real_run(args,**kwargs)
        from private_cargo_cache import initialize
        def cache(checkout, home, target, env):
            return initialize(checkout,home,target,env,host_cache=fixture/'host')
        with patch.object(module,'initialize_private_cargo',side_effect=cache),patch.dict(os.environ,{'UNDERLAY_PROFILE_EFFIGY_SOURCE':str(self.root)},clear=True),patch.object(module,'require_effigy_binary',return_value=str(self.colima)),patch.object(module,'selected_tools',return_value=(self.colima,self.lima,self.ssh)),patch.object(module.REFERENCE,'reference_source',return_value=self.root),patch.object(module.REFERENCE,'make_reference_instances',instances),patch.object(module.REFERENCE,'point_bundle_at_task_branch',return_value=None),patch.object(module.REFERENCE,'initialize_reference_fixture_secrets',return_value={'vaults':[]}),patch.object(module.RUNTIME,'mktemp_root',return_value=fixture),patch.object(module.RUNTIME,'fixed_default_ports_available',return_value=[]),patch.object(module,'run',producer),patch.object(module.subprocess,'run',run):
            self.assertEqual(module.main(),1)
        receipt=json.loads((fixture/'default-container-receipts.json').read_text())
        self.assertEqual(receipt['refusal_class'],'unknown')
        self.assertFalse(receipt['cleanup_verified']);self.assertFalse((fixture/'backend-start-intent.json').exists())
        self.assertEqual(len(list(fixture.glob('policy-*.json'))),1)
        self.assertEqual(len(calls),6);self.assertFalse((fixture/'lima-home/colima-effigy').exists())
    def test_source_defaults_are_not_a_runtime_route_or_late_policy_authority(self):
        with self.assertRaises(Refusal):route.help_route(b'')
        self.start()
        with self.assertRaises(Refusal):self.backend.original_policy(self.checkout,'hybrid_services',json.dumps(self.config).encode(),json.dumps({'ok':True,'result':self.scope}).encode())
        self.assertIsNone(self.backend.original_route)

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
