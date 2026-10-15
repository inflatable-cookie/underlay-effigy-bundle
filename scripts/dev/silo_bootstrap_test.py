"""Real-shell production bootstrap/capture controls, with no backend effects."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import silo_client as shared
spec=importlib.util.spec_from_file_location('bootstrap_launcher',Path(__file__).with_name('profile_launcher.py'))
launcher=importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name]=launcher
spec.loader.exec_module(launcher)


class BootstrapTests(unittest.TestCase):
    def exercise(self,root,container='hybrid_services',override=None,negative=False,default_caller=False,port=443,suffix=''):
        seen=[]
        identity=launcher.BinaryIdentity('source','/owned/effigy','digest',1,2,3,4)
        context={'routes':{'front':'front'+suffix+'.example.test','admin':'admin'+suffix+'.example.test'},'https_port':port}
        env={'EFFIGY_PROFILE_SILO_BUCKET':'owned-bucket'}
        def transport(args,**kwargs):
            self.assertEqual(args[0],identity.binary)
            for flag,key in (('--deadline-ms','deadline_ms'),('--stdout-limit-bytes','stdout_limit_bytes'),('--stderr-limit-bytes','stderr_limit_bytes')):
                self.assertEqual(int(args[args.index(flag)+1]),shared.BOUNDS[key])
            service=args[args.index('--service')+1];command=args[args.index('--command')+1]
            selected=args[args.index('container')+1];self.assertEqual(selected,container)
            actual={'PATH':'/usr/bin:/bin','HOME':'/tmp'}
            if service=='silo':actual.update(MC_CONFIG_DIR='/tmp/.mc',MC_HOST_local='http://minioadmin:minioadmin@127.0.0.1:9000')
            elif override:actual.update(override)
            # Marked process-entry consumers challenge HOME, global flag order,
            # explicit alias recipe and bucket/ACL/CORS inputs through real sh.
            prefix='mc() { test "$HOME" = /root && test "$1" = --config-dir && test "$2" = /root/.mc || return 91; shift 2; '
            alias={'status':'success','alias':'local','URL':'http://silo:9000','accessKey':'minioadmin','secretKey':'minioadmin','api':'S3v4','path':'auto'}
            prefix+='case "$*" in "--json alias set local http://silo:9000 minioadmin minioadmin --api S3v4 --path auto") printf %s '+__import__('shlex').quote(json.dumps(alias,indent=1))+';; '
            prefix+='"--json alias list local") printf %s '+__import__('shlex').quote(json.dumps({**alias,'src':'/root/.mc/config.json'},indent=1))+';; '
            prefix+='"ready local"|"mb local/owned-bucket --ignore-existing"|"anonymous set download local/owned-bucket") printf stage_pass;; '
            # Independent browser requirements, parsed from the actual shell-produced XML.
            expected=['https://'+role+suffix+'.example.test'+('' if port==443 else ':'+str(port)) for role in ('front','admin')]
            evaluator=('import sys,xml.etree.ElementTree as E; r=E.parse(sys.argv[1]).getroot(); '
                'assert r.tag=="CORSConfiguration" and len(r)==1; q=r[0]; '
                'assert q.tag=="CORSRule"; '
                'assert [x.text for x in q.findall("AllowedOrigin")]=='+repr(expected)+'; '
                'assert {x.text for x in q.findall("AllowedMethod")}=={"GET","HEAD","PUT"}; '
                'assert [x.text for x in q.findall("AllowedHeader")]==["*"]; '
                'assert "https://foreign.invalid" not in [x.text for x in q.findall("AllowedOrigin")]')
            prefix+='"cors set local/owned-bucket "*) test -f "$4" && /usr/bin/python3 -c '+__import__('shlex').quote(evaluator)+' "$4";; *) return 92;; esac; }; '

            # Rehome only the test's in-container temporary path into this fresh
            # owned fixture, while executing the maintained file/trap behavior.
            command=command.replace('/tmp/underlay-profile-cors-',str(root/'cors-'))
            result=subprocess.run(['/bin/sh','-c',prefix+command],env=actual,capture_output=True,text=True,timeout=3)
            seen.append((service,result.returncode))
            value={'schema':'effigy.container.bounded-exec.v1','schema_version':1,'ok':True,'container':container,'service':service,'failure':'complete','code':0,'limits':shared.BOUNDS,'retained':{'stdout_bytes':len(result.stdout.encode()),'stderr_bytes':len(result.stderr.encode())},'preparation':{'captures':0,'retained':{'stdout_bytes':0,'stderr_bytes':0}},'attempts':1,'workspace_user_fallback':False,'remote_cancellation':'unverified','stdout':result.stdout,'stderr':result.stderr,'stdout_bytes':len(result.stdout.encode()),'stderr_bytes':len(result.stderr.encode())}
            code=0
            if negative:
                for key in ('stdout','stderr','stdout_bytes','stderr_bytes'):value.pop(key)
                value.update(ok=False,failure='inner_command_failed',code=1,inner_code=1);code=1
            envelope={'schema':'effigy.command.v1','schema_version':1,'ok':value['ok'],'result':value if value['ok'] else None,'error':None if value['ok'] else {'details':value,'message':'seeded-secret'}}
            return {'outcome':'complete','exit':code,'stdout':json.dumps(envelope).encode(),'stdout_bytes':0,'stderr_bytes':0}
        with patch.object(launcher,'verify_unchanged'),patch.object(shared,'bounded_run',side_effect=transport):
            if default_caller:
                import storage_launcher
                with patch.object(storage_launcher,'profiles',launcher), \
                     patch.object(launcher,'verify_binary',return_value=identity), \
                     patch.object(launcher,'_json_command',return_value={'routes':[{'declared':'front','effective':'front.example.test'},{'declared':'admin','effective':'admin.example.test'}]}), \
                     patch.object(launcher,'_gateway_json',return_value={'https_addr':'127.0.0.1:443','private':True,'running':True}), \
                     patch.dict(os.environ,{**env,'EFFIGY_GATEWAY_PRIVATE_STATE_ROOT':str(root),'EFFIGY_PROFILE_FRONT_DECLARED':'front','EFFIGY_PROFILE_ADMIN_DECLARED':'admin'}), \
                     patch.object(sys,'argv',['storage_launcher','reconcile','--repo',str(root),'--container',container]):
                    self.assertEqual(storage_launcher.main(),0)
            else:launcher._bootstrap_silo(identity,root,env,container,context)
        return seen

    def test_both_profiles_real_shell_recipe_cors_and_exclusive_cleanup(self):
        for container in ('stack','hybrid_services','disposable_test'):
            with tempfile.TemporaryDirectory(prefix='underlay-bootstrap-') as temporary:
                root=Path(temporary).resolve()
                seen=self.exercise(root,container,default_caller=container=="stack")
                self.assertEqual(seen,[('silo',0),('silo_client',0)]+[('silo_client',0)]*7)
                self.assertEqual(list(root.glob('cors-*')),[])
                path=root/'.effigy/runtime/dev-profiles'/container/'silo-bootstrap.jsonl'
                self.assertEqual(path.stat().st_mode&0o777,0o600)
                self.assertNotIn('minioadmin',path.read_text())

    def test_actual_bootstrap_xml_effective_browser_origins_main_and_worktrees(self):
        for container,port,suffix in (('hybrid_services',443,''),('hybrid_services',54321,'-first'),('disposable_test',54322,'-second')):
            with tempfile.TemporaryDirectory(prefix='underlay-cors-policy-') as directory:
                self.exercise(Path(directory).resolve(),container,port=port,suffix=suffix)

    def test_guard_and_native_negative_prevent_mutations_and_secret_output(self):
        for override in ({'MC_HOST_local':''},{'MC_CONFIG_DIR':'seeded-secret'},{'HTTP_PROXY':''}):
            with tempfile.TemporaryDirectory(prefix='underlay-bootstrap-') as temporary:
                root=Path(temporary).resolve()
                with self.assertRaisesRegex(launcher.ProfileError,'readonly guard refused'):
                    self.exercise(root,override=override)
                text=(root/'.effigy/runtime/dev-profiles/hybrid_services/silo-bootstrap.jsonl').read_text()
                self.assertNotIn('seeded-secret',text);self.assertNotIn('"operation":"alias"',text)
        with tempfile.TemporaryDirectory(prefix='underlay-bootstrap-') as temporary:
            root=Path(temporary).resolve()
            with self.assertRaises(launcher.ProfileError):self.exercise(root,negative=True)
            text=(root/'.effigy/runtime/dev-profiles/hybrid_services/silo-bootstrap.jsonl').read_text()
            self.assertIn('unavailable_native_failure_omits_command_bytes',text)
            self.assertNotIn('seeded-secret',text)

    def test_bootstrap_bad_context_and_bucket_emit_before_mc_refusal(self):
        identity=launcher.BinaryIdentity('source','/owned/effigy','digest',1,2,3,4)
        for env,context in (({},{}),({'EFFIGY_PROFILE_SILO_BUCKET':'seeded-secret@bad'},{}),
                            ({'EFFIGY_PROFILE_SILO_BUCKET':'owned-bucket'},{'routes':{'front':'seeded-secret@bad','admin':'admin.example.test'},'https_port':443})):
            with tempfile.TemporaryDirectory(prefix='underlay-bootstrap-input-') as temporary:
                root=Path(temporary).resolve()
                with patch.object(shared,'bounded_run',side_effect=AssertionError('MC must not start')) as run:
                    with self.assertRaisesRegex(launcher.ProfileError,'input contract refused'):
                        launcher._bootstrap_silo(identity,root,env,'hybrid_services',context)
                run.assert_not_called()
                text=(root/'.effigy/runtime/dev-profiles/hybrid_services/silo-bootstrap.jsonl').read_text()
                self.assertNotIn('seeded-secret',text)
                self.assertEqual(len(text.splitlines()),4)
                self.assertTrue(all(json.loads(line)['event']=='bootstrap_input' for line in text.splitlines()))

    def test_pinned_ready_acl_cors_source_interfaces(self):
        import hashlib
        root=Path(os.environ['UNDERLAY_BOOTSTRAP_MC_SOURCE_ROOT'])
        expected={
            'ready-main.go':'445274728b834cf05f02db69e16be165e585f16173cdf3b7bf9c58e3ddf20045',
            'anonymous-main.go':'375df7b8dde81c444c84612baccdf8f58fb70d68af2759a6593ba97cc25d0c2a',
            'cors-main.go':'e9706faf8a7a756d8c823e79fecb791f352792aa7b24cff30966e63332463afd',
            'cors-set.go':'a7b31722c69b362c663d5da1e91b7593482c6a1ae746c0bda652934b94d926f9'}
        for name,digest in expected.items():self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),digest)
        self.assertIn('if healthResult.Healthy',(root/'ready-main.go').read_text())
        self.assertIn('set PERMISSION TARGET',(root/'anonymous-main.go').read_text())
        self.assertIn('ALIAS/BUCKET CORSFILE',(root/'cors-set.go').read_text())
        self.assertIn('len(ctx.Args()) != 2',(root/'cors-set.go').read_text())

    def test_default_admission_refuses_before_native_or_mutation(self):
        import storage_launcher
        with tempfile.TemporaryDirectory(prefix='underlay-bootstrap-') as temporary:
            root=Path(temporary).resolve()
            with patch.object(storage_launcher,'profiles',launcher), \
                 patch.object(launcher,'verify_binary',side_effect=launcher.ProfileError('refused')), \
                 patch.object(launcher,'_json_command') as native, \
                 patch.object(launcher,'_bootstrap_silo') as bootstrap, \
                 patch.object(sys,'argv',['storage_launcher','admit','--repo',str(root),'--container','stack']):
                with self.assertRaises(launcher.ProfileError):storage_launcher.main()
                native.assert_not_called();bootstrap.assert_not_called()

    def test_shared_capture_accounting_rejects_forged_success(self):
        # Native envelope/marker/overflow controls remain covered by the real
        # routing/storage suites; unknown selection cannot gain prefix credit.
        for text in ('{}','{"schema":"effigy.command.v1","ok":true}', 'seeded-secret'):
            with self.assertRaises(ValueError):shared.bounded_payload(text,0,'silo_client')
        with self.assertRaises(ValueError):shared.bounded_arguments('silo_client','ignored','../foreign')

class RefusalObservationTests(unittest.TestCase):
    def observation(self):
        return {'version':1,'operation_elapsed_ms':8001,'remaining_budget_ms':0,
                'preparation_elapsed_ms':4,'attempt_elapsed_ms':7997,'spawn_disposition':'spawned',
                'stdout':{'state':'overflow','retained_prefix_bytes':{'semantics':'exact','bytes':65536},
                          'read_bytes':{'semantics':'lower_bound','bytes':70000}},
                'stderr':{'state':'pending','retained_prefix_bytes':{'semantics':'unknown'},
                          'read_bytes':{'semantics':'unknown'}},'leader_exit_observed':'unknown'}
    def envelope(self, observation):
        value={'schema':'effigy.container.bounded-exec.v1','schema_version':1,'ok':False,
            'container':'hybrid_services','service':'silo_client','failure':'stdout_overflow',
            'limits':shared.BOUNDS,'retained':{'stdout_bytes':65536,'stderr_bytes':0},
            'preparation':{'captures':1,'retained':{'stdout_bytes':0,'stderr_bytes':0}},
            'attempts':1,'workspace_user_fallback':False,'phase':'command_execution',
            'termination_scope':'owned_host_client_group','remote_cancellation':'unverified'}
        if observation is not None:value['refusal_observations']=observation
        return json.dumps({'schema':'effigy.command.v1','schema_version':1,'ok':False,
                           'error':{'details':value,'message':'SEEDED_SECRET'},'result':None})
    def test_native_shape_overflow_and_independent_unknown_counts_never_output(self):
        output,projection=shared.bounded_payload(self.envelope(self.observation()),1,'silo_client')
        self.assertIsNone(output)
        self.assertEqual(projection['refusal_observations'],self.observation())
        self.assertNotIn('SEEDED',json.dumps(projection))
        self.assertEqual(projection['remote_cancellation'],'unverified')
        _,legacy=shared.bounded_payload(self.envelope(None),1,'silo_client')
        self.assertNotIn('refusal_observations',legacy)
    def test_malformed_version_clocks_states_bytes_and_extra_secret_refuse(self):
        import copy
        variants=[]
        for key,value in [('version',2),('version',True),('remaining_budget_ms',8001),
                          ('operation_elapsed_ms',-1),('attempt_elapsed_ms','SECRET'),
                          ('spawn_disposition','executed_in_guest'),('leader_exit_observed','reaped')]:
            v=self.observation();v[key]=value;variants.append(v)
        v=self.observation();v['argv']='SECRET';variants.append(v)
        for key,value in [('state','closed'),('read_bytes',{'semantics':'unknown','bytes':0}),
                          ('retained_prefix_bytes',{'semantics':'exact','bytes':65537}),
                          ('read_bytes',{'semantics':'exact','bytes':0}),
                          ('read_bytes',{'semantics':'exact','bytes':True})]:
            v=self.observation();v['stdout'][key]=value;variants.append(v)
        for v in variants:
            with self.subTest(value=v),self.assertRaises(ValueError):shared.bounded_payload(self.envelope(v),1,'silo_client')
        for failure in ('complete','inner_command_failed'):
            with self.assertRaises(ValueError):shared.refusal_observations(self.observation(),failure)
        text=self.envelope(self.observation()).replace('"version": 1','"version": 1, "version": 1')
        with self.assertRaises(ValueError):shared.bounded_payload(text,1,'silo_client')
    def test_actual_qualified_native_refusal_overflow_with_private_fake_backend(self):
        import shutil
        with tempfile.TemporaryDirectory(prefix='underlay-native-refusal-',dir=Path.home()) as temporary:
            root=Path(temporary).resolve();repo=root/'checkout';repo.mkdir()
            bindir=root/'bin';bindir.mkdir();home=root/'home';home.mkdir(mode=0o700)
            (repo/'compose.yml').write_text('services:\n  silo_client:\n    image: private-fake-never-executed\n')
            (repo/'effigy.toml').write_text('[containers.hybrid_services]\ncompose_file = "compose.yml"\nproject_name = "native-owned"\nworking_dir = "/workspace"\nprimary_service = "silo_client"\n')
            target=repo/'infra/dev/catalog/silo-mc';target.parent.mkdir(parents=True)
            shutil.copytree(Path(__file__).parent/'catalog/silo-mc',target)
            fake=bindir/'colima'
            fake.write_text('#!'+sys.executable+'\nimport sys,json\nif sys.argv[1:]==["status","--profile","effigy"]:print("colima is running using containerd")\nelif sys.argv[1:]==["list","--json"]:print(json.dumps({"name":"effigy","status":"Running","cpus":2,"memory":4294967296,"disk":34359738368}))\nelse:sys.stdout.write("X"*70000)\n')
            fake.chmod(0o700)
            env={**os.environ,'HOME':str(home),'COLIMA_HOME':str(root/'colima'),
                 'EFFIGY_COMPOSE_BACKEND':'colima','PATH':str(bindir)+os.pathsep+os.environ['PATH']}
            for key in ('DOCKER_HOST','DOCKER_CONTEXT','COLIMA_PROFILE'):env.pop(key,None)
            result=shared.bounded_run([os.environ['UNDERLAY_PROFILE_EFFIGY_BIN'],'--repo',str(repo),
                     *shared.bounded_arguments('silo_client','printf SHOULD_NOT_EXECUTE')],env=env,timeout=12)
            self.assertEqual(result['outcome'],'complete');self.assertNotEqual(result['exit'],0)
            envelope=json.loads(result['stdout'])
            output,projection=shared.bounded_payload(result['stdout'].decode(),result['exit'],'silo_client')
            self.assertIsNone(output)
            block=projection['refusal_observations']
            self.assertEqual(block['version'],1)
            self.assertEqual(block['stdout']['state'],'overflow')
            self.assertGreater(block['stdout']['read_bytes']['bytes'],65536)
            self.assertNotIn('SHOULD_NOT_EXECUTE',json.dumps(projection))

    def test_exact_qualified_public_renderer_shape(self):
        import hashlib
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        from qualification_runtime import SUPPORTED_EFFIGY_SOURCE
        source=Path(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE'])
        text=(source/'src/runner/container_command/bounded_exec.rs').read_text()
        self.assertEqual(SUPPORTED_EFFIGY_SOURCE,launcher.SUPPORTED_SOURCE)
        for name,digest in launcher.SUPPORTED_API.items():
            self.assertEqual(hashlib.sha256((source/name).read_bytes()).hexdigest(),digest)
        self.assertIn('"refusal_observations": refusal_observations_json',text)
        self.assertIn('"leader_exit_observed": observations.leader_exit.label()',text)

if __name__=='__main__':unittest.main()
