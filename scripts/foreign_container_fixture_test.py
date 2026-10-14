"""Independent pre-effect genuine catalog/intent controls with fake transport."""
import copy
import json
import os
from pathlib import Path
import signal
import sys
import subprocess
import unittest
from original_container_route_test import RouteControls
from foreign_container_fixture import ForeignFixture
from container_identity_observer import Refusal

class ForeignControls(RouteControls):
    def prepare_foreign(self):
        fixture=ForeignFixture(self.backend)
        policy=dict(self.policy,project_name='qualified-foreign-silo',primary_service='silo',services={'silo':{}})
        config=copy.deepcopy(self.config);config['result']['selected_value']['value']={'default':'witness','witness':policy}
        scope=dict(self.scope,checkout=str(fixture.checkout))
        self.backend.original_policy(fixture.checkout,'default',json.dumps(config).encode(),json.dumps({'ok':True,'result':scope}).encode())
        return fixture
    def test_original_independent_intent_and_genuine_recipe_before_any_effect(self):
        fixture=self.prepare_foreign();fragment=(fixture.checkout/'infra/dev/catalog/silo/compose.fragment.yml').read_text()
        source=Path(__file__).parent/'dev/catalog/silo/compose.fragment.yml'
        self.assertEqual(fragment,source.read_text().replace('    ports:\n      - "{{ api_port }}:9000"\n      - "{{ console_port }}:9001"\n',''))
        self.assertNotIn('ports:',fragment);self.assertIn('command: ["server", "/data"',fragment)
        self.assertFalse(fixture.up_attempted);fixture.guard()
        self.assertEqual(fixture.intent['startup_intent_sha256'],self.backend.intent_sha256)
        self.assertNotEqual(self.backend.policies[(str(fixture.checkout),'default')]['project'],self.backend.policies[(str(self.checkout),'default')]['project'])
        self.assertFalse((self.root/'backend-start-intent.json').exists())
    def test_exact_source_scoped_start_complete_ids_state_and_reuse_refusal(self):
        fixture=self.prepare_foreign();self.start();calls=[]
        def dispatch(binary,checkout,env,*args,**kw):
            self.assertEqual(checkout,fixture.checkout);self.assertEqual(args,('container','up','--detach','--json'))
            self.assertEqual(kw,dict(timeout=600,private=True));calls.append(args)
            row=dict(id='c'*64,created='2026-10-14T01:02:03Z',project='qualified-foreign-silo',checkout=str(checkout),service='silo',oneoff='false',running=True,status='running')
            self.model['records']={row['id']:row};self.write();return {'ok':True}
        fixture.start('/qualified/effigy',self.env,dispatch)
        reader=self.backend.observer_for(fixture.checkout,self.env,foreign_fixture=fixture)
        before=reader.baseline();self.assertEqual(list(before['owned']),['c'*64])
        self.assertEqual(before['owned']['c'*64]['created'],'2026-10-14T01:02:03Z')
        with self.assertRaises(Refusal):fixture.start('/qualified/effigy',self.env,dispatch)
        self.assertEqual(len(calls),1)
        self.model['records']['c'*64]['created']='2026-10-14T01:02:04Z';self.write()
        with self.assertRaises(Refusal):reader.after(before)
    def test_actual_qualified_assembly_policy_before_backend_start(self):
        import tempfile
        from fresh_backend_admission import FreshBackend,selected_tools
        from qualification_runtime import require_effigy_binary
        binary=require_effigy_binary()
        with tempfile.TemporaryDirectory(prefix='underlay-foreign-assembly-',dir=Path.home()) as name:
            root=Path(name).resolve();root.chmod(0o700);backend=FreshBackend(root,{})
            fixture=ForeignFixture(backend)
            env={**os.environ,**backend.env,'HOME':str(backend.paths['HOME'])}
            captures=[]
            for tail in (['config','--inspect','--path','containers'],['container','scope']):
                result=subprocess.run([binary,'--json','--repo',str(fixture.checkout),*tail],env=env,capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,'closed_source_assembly_refusal')
                captures.append(result.stdout)
            backend.original_policy(fixture.checkout,'default',*captures)
            policy=backend.policies[(str(fixture.checkout),'default')]
            self.assertEqual(policy['services'],['silo']);self.assertEqual(policy['primary'],'silo')
            self.assertEqual(policy['project'],'qualified-foreign-silo')
            self.assertFalse((root/'backend-start-intent.json').exists())

    def test_changed_unknown_project_catalog_or_creation_intent_refuses(self):
        fixture=self.prepare_foreign()
        for name in ('intent','catalog'):
            path=fixture.path if name=='intent' else fixture.checkout/'infra/dev/catalog/silo/service.toml'
            original=path.read_bytes();path.write_bytes(original+b'\n')
            with self.assertRaises(Refusal):fixture.guard()
            path.write_bytes(original)
        self.start()
        with self.assertRaises(Refusal):self.backend.observer_for(fixture.checkout,self.env,foreign_fixture=object())
        with self.assertRaises(Refusal):self.backend.observer_for(fixture.checkout,self.env,foreign_fixture=fixture)

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
