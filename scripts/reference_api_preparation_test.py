import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import reference_api_preparation as api


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ur.api-preparation.')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkout = self.root/'reference'
        self.cwd = self.checkout/'apps/acme-api'
        self.cwd.mkdir(parents=True)
        self.target = self.root/'target'
        (self.target/'debug').mkdir(parents=True)
        self.cargo = self.root/'cargo'; self.cargo.mkdir()
        self.rustup = self.root/'rustup'; self.rustup.mkdir()
        self.env = {'UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT':str(self.root),
                    'CARGO_TARGET_DIR':str(self.target), 'CARGO_HOME':str(self.cargo),
                    'RUSTUP_HOME':str(self.rustup), 'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2'}
        (self.cwd/'effigy.toml').write_text('[tasks]\nbuild = "cd {repo} && cargo build {args}"\napi = "cd {repo} && cargo run -p acme-api {args}"\n')
        (self.cwd/'Cargo.lock').write_text('locked')
        (self.cwd/'Cargo.toml').write_text('[package]\nname="acme-api"\nversion="0.1.0"\n')
        files=[]
        for name in api.PATCH_FILES:
            p=self.checkout/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('instrumented')
            files.append({'path':name,'sha256_after':hashlib.sha256(p.read_bytes()).hexdigest()})
        self.patch={'reference_source_commit':'source','patch_sha256':'patch','cargo_lock_sha256':hashlib.sha256(b'locked').hexdigest(),'files':files}
        self.binary=self.target/'debug/acme-api'
        self.binary.write_bytes(b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01'+b'\0'*4+b'\x02\0\0\0'+b'\0'*16)
        self.binary.chmod(0o700)
        self.events=[]
        self.emit=lambda event,**fields:self.events.append((event,fields))
        self.tool=patch.object(api.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'rustc 1.90.0\nhost: aarch64-apple-darwin\n',b''))
        self.tool.start();self.addCleanup(self.tool.stop)
        self.result={'exit':0,'refusal':None,'identity_admitted':True,'leader_reaped':True,'stdout':{'eof':True},'stderr':{'eof':True}}

    def prepare(self):
        return api.prepare('/qualified/effigy',self.checkout,self.env,self.patch,self.emit)

    def test_actual_configured_build_and_launch_match(self):
        with patch.object(api,'capture',return_value=self.result) as runner:
            prepared=self.prepare()
        args=runner.call_args.args[0]
        self.assertEqual(args[3:],['build','--','-p','acme-api','--locked','--offline'])
        self.assertEqual(runner.call_args.kwargs['env'],self.env)
        self.assertEqual(runner.call_args.kwargs['cwd'],self.cwd)
        api.admit_launch(prepared,self.checkout,self.env,self.patch,self.emit)
        self.assertEqual(self.events[-1][1]['listener_timeout_seconds'],480)
        self.assertEqual(self.events[-1][1]['outer_readiness_seconds'],540)
        self.assertEqual(prepared['inputs']['features'],'default')

    def test_build_failure_even_after_check_success_is_published(self):
        for change in ({'exit':1},{'refusal':'deadline'},{'identity_admitted':False},{'stderr':{'eof':False}}):
            self.events.clear()
            with patch.object(api,'capture',return_value=dict(self.result,**change)):
                with self.assertRaisesRegex(RuntimeError,'configured_build_refused'):self.prepare()
            self.assertEqual([e[0] for e in self.events],['reference_api_link_capture'])
            self.assertEqual(self.events[0][1]['capture'],dict(self.result,**change))

    def test_success_without_linked_platform_refuses(self):
        with patch.object(api,'capture',return_value=self.result):
            self.binary.write_bytes(b'not an executable')
            with self.assertRaisesRegex(RuntimeError,'linked_platform'):self.prepare()
            self.binary.unlink()
            with self.assertRaises(FileNotFoundError):self.prepare()

    def test_lock_patch_and_target_mismatch_precede_build(self):
        with patch.object(api,'capture') as runner:
            for key,value in (('cargo_lock_sha256','wrong'),('files',[])):
                with self.assertRaisesRegex(RuntimeError,'changed'):
                    api.prepare('/qualified',self.checkout,self.env,dict(self.patch,**{key:value}),self.emit)
            with self.assertRaisesRegex(RuntimeError,'private_target'):
                api.prepare('/qualified',self.checkout,dict(self.env,CARGO_TARGET_DIR='/'),self.patch,self.emit)
            runner.assert_not_called()

    def test_package_feature_and_environment_refuse_before_build(self):
        with patch.object(api,'capture') as runner:
            original=(self.cwd/'effigy.toml').read_text()
            (self.cwd/'effigy.toml').write_text(original.replace('cargo build {args}','cargo build --all-features {args}'))
            with self.assertRaisesRegex(RuntimeError,'configured_caller'):self.prepare()
            (self.cwd/'effigy.toml').write_text(original)
            for env in (dict(self.env,CARGO_NET_OFFLINE='false'),dict(self.env,RUSTFLAGS='SECRET')):
                with self.assertRaisesRegex(RuntimeError,'refused'):
                    api.prepare('/qualified',self.checkout,env,self.patch,self.emit)
            runner.assert_not_called()

    def test_late_publication_never_grants_build_credit(self):
        def failed(*args,**kwargs):raise RuntimeError('journal_unavailable')
        with patch.object(api,'capture',return_value=dict(self.result,exit=1)):
            with self.assertRaisesRegex(RuntimeError,'build_refused_publication_unavailable'):
                api.prepare('/qualified',self.checkout,self.env,self.patch,failed)
        self.assertEqual(self.events,[])

    def test_launch_changed_source_or_artifact_refuses(self):
        with patch.object(api,'capture',return_value=self.result):prepared=self.prepare()
        self.binary.write_bytes(self.binary.read_bytes()+b'changed')
        with self.assertRaisesRegex(RuntimeError,'launch_inputs_changed'):
            api.admit_launch(prepared,self.checkout,self.env,self.patch,self.emit)
        self.assertNotIn('SECRET',json.dumps(self.events))

    def test_actual_runtime_caller_publishes_failed_exit_without_payload(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('api_runtime_caller',Path(__file__).with_name('qualify-reference-runtime.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        class Journal:
            def append(inner,event,**fields):self.events.append((event,fields))
        module.COMMAND_DIAGNOSTICS=Journal()
        # The setup's rustc stub must not intercept the maintained identity reader.
        self.tool.stop()
        import sys
        with self.assertRaisesRegex(RuntimeError,'native_nonzero'):
            module.run([sys.executable,'-c','import sys;sys.stdout.write("SECRET");sys.stderr.write("SECRET");sys.exit(3)'],env=dict(os.environ))
        observation=self.events[-1][1]['observation']
        self.assertEqual(observation['exit'],3)
        self.assertEqual(observation['capture']['stdout']['read_bytes'],6)
        self.assertEqual(observation['effect_state'],'unknown')
        self.assertNotIn('SECRET',json.dumps(self.events))


if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(60)
    unittest.main()
