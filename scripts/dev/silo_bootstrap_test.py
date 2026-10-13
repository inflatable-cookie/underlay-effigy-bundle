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
    def exercise(self,root,container='hybrid_services',override=None,negative=False,default_caller=False):
        seen=[]
        identity=launcher.BinaryIdentity('source','/owned/effigy','digest',1,2,3,4)
        context={'routes':{'front':'front.example.test','admin':'admin.example.test'},'https_port':443}
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
            prefix+='"cors set local/owned-bucket "*) test -f "$4" && '+ '/usr/bin/python3 -c '+__import__('shlex').quote('import sys; from pathlib import Path; s=Path(sys.argv[1]).read_text(); assert s.count("<AllowedOrigin>")==2 and "https://front.example.test" in s and "https://admin.example.test" in s and "<AllowedMethod>PUT</AllowedMethod>" in s')+' "$4";; *) return 92;; esac; }; '
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
            else:
                profile='hybrid' if container=='hybrid_services' else 'disposable_test'
                with patch.object(launcher,'_start_services',return_value={'context':context}), \
                     patch.object(launcher,'_profile_env',return_value=env), \
                     patch.object(launcher,'_profile_root',return_value=root):
                    self.assertEqual(launcher._start_profile(identity,root,env,profile),context)
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

if __name__=='__main__':unittest.main()
