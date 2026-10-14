"""Original-startup caller controls; unsupported boot input never becomes authority."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch
from fresh_backend_admission import FreshBackend, Refusal, MISSING

class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
    def tearDown(self):self.temp.cleanup()
    def prepared(self):
        backend=FreshBackend(self.root,{})
        checkout=backend.paths['HOME']/'main';checkout.mkdir(mode=0o700)
        backend.original_scope(checkout,b'[containers.default]\nproject_name = "fixture"\n', 'a'*64)
        tools=[]
        for name in ('colima','lima','ssh'):
            path=self.root/name;path.write_text('#!/bin/sh\nexit 19\n');path.chmod(0o700);tools.append(path)
        backend.bind_tools(*tools)
        return backend,checkout,tools
    def test_original_intent_roots_before_effect_and_fixed_isolation_recipe(self):
        backend,checkout,tools=self.prepared()
        original=json.loads(backend.path.read_text());prepared=json.loads(backend.prepared_path.read_text())
        self.assertFalse(original['startup_attempted']);self.assertEqual(original['scope_inputs'],[])
        self.assertEqual(prepared['scope_inputs'][0]['captured_config_sha256'],hashlib.sha256(b'[containers.default]\nproject_name = "fixture"\n').hexdigest())
        self.assertNotEqual(backend.env['COLIMA_HOME'],backend.env['LIMA_HOME'])
        args=backend.planned_start_command(backend.env)
        for flag in ('--activate=false','--ssh-config=false','--ssh-agent=false','--template=false'):self.assertIn(flag,args)
        self.assertEqual(args[args.index('--mount')+1],str(self.root)+':w')
        self.assertNotIn('/Users/operator',str(args))
        with self.assertRaises(Refusal) as caught:backend.start_command(backend.env)
        self.assertEqual(str(caught.exception),MISSING)
    def test_operator_environment_never_inherited_and_no_partial_creation(self):
        for name in ('DOCKER_CONTEXT','CONTAINERD_ADDRESS','NERDCTL_CONFIG','LIMA_HOME','SSH','COLIMA_HOME','XDG_CONFIG_HOME'):
            with self.subTest(name=name):
                with self.assertRaises(Refusal):FreshBackend(self.root,{name:''})
                self.assertEqual(list(self.root.iterdir()),[])
    def test_preexisting_fixture_profile_or_scope_refuses(self):
        (self.root/'existing').write_text('held')
        with self.assertRaises(Refusal):FreshBackend(self.root,{})
        (self.root/'existing').unlink();backend,checkout,tools=self.prepared()
        (backend.paths['LIMA_HOME']/'colima-effigy').mkdir(mode=0o700)
        with self.assertRaises(Refusal) as caught:backend.planned_start_command(backend.env)
        self.assertEqual(str(caught.exception),'profile_preexisting')
    def test_wrong_root_tool_config_input_and_mutated_intent(self):
        backend,checkout,tools=self.prepared()
        wrong=dict(backend.env,LIMA_HOME='/Users/operator/.lima')
        with self.assertRaises(Refusal):backend.planned_start_command(wrong)
        tools[0].write_text('changed');tools[0].chmod(0o700)
        with self.assertRaises(Refusal):backend.planned_start_command(backend.env)
        with self.assertRaises(Refusal):backend.original_scope(checkout,b'', 'a'*64)
        backend.path.write_text('{}')
        with self.assertRaises(Refusal):backend.guard()
    def test_permissions_symlink_or_reused_root_refuse(self):
        self.root.chmod(0o755)
        with self.assertRaises(Refusal):FreshBackend(self.root,{})
        self.root.chmod(0o700);backend,checkout,tools=self.prepared()
        old=backend.paths['LIMA_HOME'];old.rmdir();old.mkdir(mode=0o700)
        with self.assertRaises(Refusal):backend.guard()
    def test_late_running_names_directory_and_injected_boot_are_not_authority(self):
        backend,checkout,tools=self.prepared()
        for model in ({'name':'colima-effigy','status':'Running','dir':str(backend.paths['LIMA_HOME'])},
                      {'name':'colima-effigy','status':'Stopped'},{}):
            with self.assertRaises(Refusal) as caught:backend.consume_instance_projection(json.dumps(model).encode())
            self.assertEqual(str(caught.exception),MISSING)
        with self.assertRaises(Refusal) as caught:backend.consume_instance_projection(b'{"name":"colima-effigy","boot":"12345678-1234-1234-1234-123456789ABC"}')
        self.assertEqual(str(caught.exception),'unsupported_instance_field')
    def test_observer_and_scoped_down_cannot_use_owner_boolean_or_late_inventory(self):
        backend,checkout,tools=self.prepared()
        with self.assertRaises(Refusal) as caught:backend.observer_for(checkout,backend.env)
        self.assertEqual(str(caught.exception),MISSING)
        self.assertFalse((backend.paths['LIMA_HOME']/'colima-effigy').exists())
        self.assertEqual(backend.observation_requirements()['late_inventory_authority'],False)
    def test_actual_both_qualifier_entrypoints_refuse_before_query_or_runtime(self):
        for filename in ('qualify-reference-container.py','qualify-reference-optin.py'):
            with self.subTest(filename=filename),tempfile.TemporaryDirectory(dir=self.root) as directory:
                fixture=Path(directory).resolve();fixture.chmod(0o700)
                spec=importlib.util.spec_from_file_location('admission_'+filename.replace('-','_'),Path(__file__).with_name(filename))
                module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
                tools=[]
                for name in ('colima','lima','ssh'):
                    p=self.root/(filename+name);p.write_text('#!/bin/sh\nexit 18\n');p.chmod(0o700);tools.append(p)
                env={'UNDERLAY_PROFILE_STORAGE_DIAGNOSTICS_DIR':str(self.root),'UNDERLAY_PROFILE_EFFIGY_SOURCE':str(self.root)}
                with patch.dict(os.environ,env,clear=True),patch.object(module,'require_effigy_binary',return_value=str(tools[0])),patch.object(module.REFERENCE,'reference_source',return_value=self.root),patch.object(module.RUNTIME,'mktemp_root',return_value=fixture),patch.object(module,'selected_tools',return_value=tuple(tools)),patch.object(module.RUNTIME,'fixed_default_ports_available',side_effect=AssertionError('native query forbidden')),patch.object(module.RUNTIME,'run',side_effect=AssertionError('runtime forbidden')):
                    with self.assertRaises(Refusal) as caught:module.main()
                self.assertEqual(str(caught.exception),MISSING)
                self.assertTrue((fixture/'backend-intent.json').is_file())
                self.assertTrue((fixture/'backend-prepared.json').is_file())
                self.assertFalse((fixture/'lima-home'/'colima-effigy').exists())

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
