"""Private caller construction, real guards/callers and sealed-wrapper controls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch
from private_caller_environment import construct,verify_context,CLASSES
from fresh_backend_admission import FreshBackend,Refusal

class EnvironmentControls(unittest.TestCase):
    def test_ambient_classes_excluded_before_root_creation_without_mutation(self):
        ambient={k:'SEEDED_SECRET' for k in ('SSH_AUTH_SOCK','SSH_CONNECTION','SSH_ASKPASS','SSH_UNKNOWN',
            'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG','LIMA_HOME','COLIMA_HOME',
            'CONTAINERD_NAMESPACE','NERDCTL_TOML','XDG_CONFIG_HOME','UNCLASSIFIED_SECRET')}
        ambient.update(PATH='/usr/bin:/bin',HOME='/operator',RUSTUP_HOME='/trusted/toolchain',
                       UNDERLAY_PROFILE_EFFIGY_SOURCE='/source',UNDERLAY_PROFILE_EFFIGY_BIN='/binary')
        original=copy.deepcopy(ambient);operator=dict(os.environ)
        env,receipt=construct(ambient)
        self.assertEqual(ambient,original);self.assertEqual(dict(os.environ),operator)
        self.assertFalse(any(k.startswith(CLASSES) for k in env));self.assertNotIn('HOME',env)
        self.assertNotIn('UNCLASSIFIED_SECRET',env);self.assertEqual(env['RUSTUP_HOME'],'/trusted/toolchain')
        self.assertNotIn('SEEDED',json.dumps(receipt));self.assertTrue(receipt['ambient_unchanged'])
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();root.chmod(0o700)
            backend=FreshBackend(root,env)
            self.assertEqual(backend.env['HOME'],str(root/'home'))
            self.assertEqual(backend.env['LIMA_HOME'],str(root/'lima-home'))
            self.assertEqual(backend.env['COLIMA_HOME'],str(root/'colima-home'))
            self.assertFalse((root/'lima-home/colima-effigy').exists())
    def test_explicit_late_overrides_refuse_without_stripping_or_rebase(self):
        env,_=construct({'PATH':'/usr/bin:/bin'})
        for key in ('SSH_AUTH_SOCK','SSH_UNKNOWN','CONTAINERD_NAMESPACE','CONTAINERD_ADDRESS','LIMA_HOME','DOCKER_HOST'):
            with tempfile.TemporaryDirectory() as name:
                root=Path(name).resolve();root.chmod(0o700)
                with self.assertRaises(Refusal):FreshBackend(root,{**env,key:'SEEDED_SECRET'})
                self.assertEqual(list(root.iterdir()),[])
        context={'private_home':'/owned/home','colima_home':'/owned/colima','lima_home':'/owned/lima'}
        admitted={'HOME':'/owned/home','COLIMA_HOME':'/owned/colima','LIMA_HOME':'/owned/lima'}
        self.assertTrue(verify_context(admitted,context))
        for key in ('HOME','COLIMA_HOME','LIMA_HOME','SSH_AUTH_SOCK','CONTAINERD_NAMESPACE','CONTAINERD_ADDRESS'):
            late={**admitted,key:'SEEDED_SECRET'}
            with self.assertRaises(Refusal) as caught:verify_context(late,context)
            self.assertNotIn('SEEDED',str(caught.exception));self.assertEqual(late[key],'SEEDED_SECRET')
    def test_both_actual_entrypoints_construct_same_private_context_before_effects(self):
        for filename in ('qualify-reference-optin.py','qualify-reference-container.py'):
            with tempfile.TemporaryDirectory() as name:
                root=Path(name).resolve();root.chmod(0o700)
                fixture=root/'fixture';fixture.mkdir(mode=0o700)
                tools=[]
                for label in ('colima','lima','ssh'):
                    path=root/label;path.write_text('#!/bin/sh\nexit 17\n');path.chmod(0o700);tools.append(path)
                spec=importlib.util.spec_from_file_location('private_'+filename.replace('-','_'),Path(__file__).with_name(filename))
                q=importlib.util.module_from_spec(spec);sys.modules[spec.name]=q;spec.loader.exec_module(q)
                seen=[]
                class Boundary(Exception):pass
                class ActualBackend(FreshBackend):
                    def require_read_contract(self):
                        self.guard();self.verify_environment(self.env)
                        self_env=self.env.copy();seen.append(self_env)
                        if any(k.startswith('SSH') for k in self_env):raise AssertionError('private agent reattached')
                        raise Boundary()
                supplied={'UNDERLAY_PROFILE_STORAGE_DIAGNOSTICS_DIR':str(root),
                          'UNDERLAY_PROFILE_EFFIGY_SOURCE':str(root),'UNDERLAY_PROFILE_EFFIGY_BIN':str(tools[0]),
                          'PATH':'/usr/bin:/bin','SSH_AUTH_SOCK':'SEEDED_SECRET','SSH_UNKNOWN':'SEEDED_SECRET'}
                with patch.dict(os.environ,supplied,clear=True),patch.object(q,'FreshBackend',ActualBackend), \
                     patch.object(q,'require_effigy_binary',return_value=str(tools[0])) as gate, \
                     patch.object(q.REFERENCE,'reference_source',return_value=root), \
                     patch.object(q.RUNTIME,'mktemp_root',return_value=fixture), \
                     patch.object(q,'selected_tools',return_value=tuple(tools)), \
                     patch.object(q.RUNTIME,'run',side_effect=AssertionError('native effects forbidden')):
                    before=dict(os.environ)
                    with self.assertRaises(Boundary):q.main()
                    self.assertEqual(dict(os.environ),before)
                    self.assertFalse(any(k.startswith('SSH') for k in gate.call_args.kwargs['env']))
                self.assertEqual(len(seen),1)
                self.assertEqual(seen[0]['HOME'],str(fixture/'home'))
                self.assertTrue((fixture/'backend-intent.json').is_file())
                self.assertFalse((fixture/'lima-home/colima-effigy').exists())
    def test_reference_helper_uses_private_environment_when_env_omitted(self):
        spec=importlib.util.spec_from_file_location('private_reference',Path(__file__).with_name('qualify-reference-profiles.py'))
        q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
        env,_=construct({'SSH_AUTH_SOCK':'SEEDED_SECRET','PATH':'/usr/bin:/bin'})
        q.PRIVATE_CHILD_ENV=env
        from types import SimpleNamespace
        with patch.object(q.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')) as run:
            q.run(['/owned/tool'],show_output=False)
        self.assertEqual(run.call_args.kwargs['env'],env)
        self.assertIsNot(run.call_args.kwargs['env'],env)
        self.assertNotIn('SSH_AUTH_SOCK',run.call_args.kwargs['env'])

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
