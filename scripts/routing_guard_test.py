"""No runtime: real shell predicates through the production bounded decoder."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

import routing_guard as guard
import storage_correlation as native
from reference_storage_probe import StorageDiagnosticJournal


class GuardTests(unittest.TestCase):
    def base(self,service):
        env={'PATH':'/usr/bin:/bin','HOME':'/root'}
        if service=='silo':
            env['MC_HOST_local']='http://minioadmin:minioadmin@127.0.0.1:9000'
            env['MC_CONFIG_DIR']='/tmp/.mc'
            env['HOME']='/tmp'
        return env

    def transport(self,env,mode='complete'):
        def call(label,checkout,args,timeout):
            self.assertEqual(args[-1],'--json')
            for flag,key in (('--deadline-ms','deadline_ms'),('--stdout-limit-bytes','stdout_limit_bytes'),('--stderr-limit-bytes','stderr_limit_bytes')):
                self.assertEqual(int(args[args.index(flag)+1]),native.BOUNDS[key])
            service=args[args.index('--service')+1]
            command=args[args.index('--command')+1]
            completed=subprocess.run(['/bin/sh','-c',command],env=env,capture_output=True,text=True,timeout=3)
            stdout=completed.stdout
            if mode=='duplicate_marker':stdout+=stdout
            if mode=='unknown_record':stdout=stdout.replace('GUARD|MC_RESOLVE|absent|1','GUARD|seeded-secret|present|0')
            value=dict(schema='effigy.container.bounded-exec.v1',schema_version=1,ok=True,
                       container='hybrid_services',service=service,failure='complete',code=0,
                       limits=native.BOUNDS,retained={'stdout_bytes':len(stdout.encode()),'stderr_bytes':len(completed.stderr.encode())},
                       preparation={'captures':0,'retained':{'stdout_bytes':0,'stderr_bytes':0}},attempts=1,
                       workspace_user_fallback=False,remote_cancellation='unverified',stdout=stdout,
                       stderr=completed.stderr,stdout_bytes=len(stdout.encode()),stderr_bytes=len(completed.stderr.encode()))
            outer=0
            if mode=='negative':
                for key in ('stdout','stderr','stdout_bytes','stderr_bytes'):value.pop(key)
                value.update(ok=False,failure='inner_command_failed',code=1,inner_code=1);outer=1
            if mode=='malformed':return 'seeded-secret',1
            return json.dumps(dict(schema='effigy.command.v1',schema_version=1,ok=value['ok'],
                                   result=value if value['ok'] else None,error=None if value['ok'] else {'details':value,'message':'seeded-secret'})),outer
        return call

    def invoke(self,service,env,journal,mode='complete'):
        def shell(label,command,service=service):
            return guard.finite_shell(self.transport(env,mode),journal,label,command,service)
        return guard.evaluate_guard(shell,journal,service)

    def test_all_predicates_absent_empty_present_and_exact_alias(self):
        for service in ('silo','silo_client'):
            env=self.base(service);journal=Mock()
            self.assertTrue(self.invoke(service,env,journal)['guard_passed'])
            for name,rule in guard.predicates(service):
                if name=='HOME':continue  # Inherited HOME is observational; shared input owns HOME.
                for value in ('','seeded-secret'):
                    changed={**env,name:value};journal=Mock()
                    original=subprocess.run(['/bin/sh','-c',native.environment_guard(service)],env=changed,capture_output=True,timeout=3)
                    self.assertNotEqual(original.returncode,0)  # Older guard remains a historical refusal control.
                    with self.assertRaisesRegex(ValueError,'routing_guard_refused'):self.invoke(service,changed,journal)
                    projection=journal.append.call_args.kwargs
                    record=next(r for r in projection['predicates'] if r['predicate']==name)
                    self.assertEqual(record['presence'],'empty' if value=='' else 'present')
                    self.assertFalse(record['agreement']);self.assertNotIn('seeded-secret',str(journal.mock_calls))
            if service=='silo':
                changed=dict(env);changed.pop('MC_HOST_local');journal=Mock()
                with self.assertRaises(ValueError):self.invoke(service,changed,journal)
                self.assertEqual(next(r for r in journal.append.call_args.kwargs['predicates'] if r['predicate']=='MC_HOST_local')['presence'],'absent')

    def test_server_exact_default_replaces_absence_without_other_exceptions(self):
        for value in (None,'','relative','.mc','/tmp/.mc/','/other','seeded-secret'):
            env=self.base('silo')
            if value is None:env.pop('MC_CONFIG_DIR')
            else:env['MC_CONFIG_DIR']=value
            journal=Mock()
            with self.assertRaisesRegex(ValueError,'routing_guard_refused'):self.invoke('silo',env,journal)
            self.assertNotIn('seeded-secret',str(journal.mock_calls))
        self.assertEqual(dict(guard.predicates('silo'))['MC_CONFIG_DIR'],'expected_server_configdir')
        self.assertEqual(dict(guard.predicates('silo_client'))['MC_CONFIG_DIR'],'absent')
        effects=[];journal=Mock()
        def observe_then_bootstrap(env):
            self.invoke('silo',env,journal)
            effects.append('alias_bootstrap')
        with self.assertRaises(ValueError):observe_then_bootstrap({**self.base('silo'),'MC_CONFIG_ENV_FILE':''})
        self.assertEqual(effects,[])

    def test_source_image_compose_native_layering_and_mount_boundary(self):
        from service_defaults import baseline
        image={'MC_CONFIG_DIR':'/tmp/.mc','HOME':'/tmp'}
        compose={'MC_HOST_local':'http://minioadmin:minioadmin@127.0.0.1:9000'}
        self.assertTrue(baseline(image,compose,'silo',('/data',))['baseline_passed'])
        self.assertFalse(baseline(image,{**compose,'MC_CONFIG_DIR':'relative'},'silo')['baseline_passed'])
        client=baseline({}, {}, 'silo_client')
        self.assertFalse(client['baseline_passed'])
        self.assertEqual(client['predicates'][-1]['resolution'],'unknown_shell_default')
        self.assertTrue(baseline({}, {}, 'silo_client',command_input=guard.OWNER_CLIENT_COMMAND_INPUT)['baseline_passed'])
        self.assertFalse(baseline({'MC_CONFIG_DIR':''},{},'silo_client',command_input=guard.OWNER_CLIENT_COMMAND_INPUT)['baseline_passed'])
        for path in ('/','/tmp','/tmp/.mc','/tmp/../other','relative'):
            with self.assertRaises(ValueError):baseline(image,compose,'silo',(path,))
        self.assertNotIn('minioadmin',json.dumps(baseline(image,compose,'silo')))

    def test_shared_client_input_before_every_environment_consumer(self):
        # Every MC operation uses this same transport, including readonly guard.
        for inherited in (None,'','seeded-secret','/root'):
            env=self.base('silo_client')
            if inherited is None:env.pop('HOME')
            else:env['HOME']=inherited
            journal=Mock()
            self.assertTrue(self.invoke('silo_client',env,journal)['guard_passed'])
            for operation in ('alias_bootstrap','alias_list','bucket_create','producer_file','client_write',
                              'client_stat','client_reverse_read','client_own_read'):
                output=guard.finite_shell(self.transport(env),journal,operation,
                    "test \"$HOME\" = /root && /bin/sh -c 'test \"$HOME\" = /root && printf consumer_pass'",
                    'silo_client')
                self.assertEqual(output,'consumer_pass')
            observations=[c.kwargs for c in journal.append.call_args_list if c.args[0]=='client_command_input']
            self.assertEqual(len(observations),9)
            self.assertEqual(observations[0]['inherited_expected_agreement'],inherited=='/root')
            self.assertTrue(all(r['provenance']=='owner_command_input' and not r['default_home_qualified'] for r in observations))
            self.assertNotIn('seeded-secret',str(journal.mock_calls))
        journal=Mock()
        output=guard.finite_shell(self.transport({**self.base('silo'),'HOME':'/tmp'}),journal,
                                'server_read','printf "%s" "$HOME"','silo')
        self.assertEqual(output,'/tmp')
        self.assertNotIn('client_command_input',str(journal.mock_calls))

    def test_image_interface_callers_use_same_input_before_mc(self):
        import importlib.util
        from unittest.mock import patch
        spec=importlib.util.spec_from_file_location('home_image_control',Path(__file__).with_name('qualify-storage-correlation.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        from silo_fixture import CLIENT_IMAGE
        invocations=[]
        def capture(args,env,timeout):
            command=args[-1];image=args[args.index('--entrypoint')+2]
            # A real shell MC function models an environment consumer at process
            # entry, not an assertion against the emitted assignment text.
            expected='/root' if image==CLIENT_IMAGE else '/tmp'
            prefix='mc() { test "$HOME" = '+expected+' || return 91; printf interface_ok; }; '
            result=subprocess.run(['/bin/sh','-c',prefix+command],env={'PATH':'/usr/bin:/bin','HOME':'/tmp'},capture_output=True,timeout=3)
            invocations.append((image,result.returncode))
            return {'exit':result.returncode,'outcome':'complete','stdout':result.stdout,
                    'stdout_bytes':len(result.stdout),'stderr_bytes':len(result.stderr)}
        journal=Mock()
        with patch.object(module,'bound_colima',return_value='/owned/colima'),patch.object(module,'bounded_run',side_effect=capture),patch.object(module,'file_producer',return_value=':'),patch.object(native,'stat_projection'),patch.object(module,'offline_client_interface'):
            module.image_interfaces({},journal,'a'*32)
        self.assertEqual(len(invocations),12)
        self.assertTrue(all(code==0 for _,code in invocations))
        inputs=[c.kwargs for c in journal.append.call_args_list if c.args[0]=='client_command_input']
        self.assertEqual(len(inputs),6)
        self.assertTrue(all(not r['inherited_expected_agreement'] and r['input_expected_agreement'] for r in inputs))

    def test_offline_recipe_actual_shell_flags_guard_and_phase_decode(self):
        import importlib.util,shlex
        from unittest.mock import patch
        spec=importlib.util.spec_from_file_location('offline_recipe_control',Path(__file__).with_name('qualify-storage-correlation.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        alias={'status':'success','alias':'local','URL':'http://silo:9000','accessKey':'minioadmin','secretKey':'minioadmin','api':'S3v4','path':'auto'}
        listed={**alias,'src':'/root/.mc/config.json'}
        stat={'status':'success','name':'underlay-'+'a'*32,'lastModified':'2026-10-12T00:00:00Z','size':9,'etag':'','type':'file'}
        prefix='mc() { test "$HOME" = /root && test "$1" = --config-dir && test "$2" = /root/.mc || return 91; shift 2; '
        prefix+='case "$*" in "--json alias set local http://silo:9000 minioadmin minioadmin --api S3v4 --path auto") printf %s '+shlex.quote(json.dumps(alias,indent=1))+';; '
        prefix+='"--json alias list local") printf %s '+shlex.quote(json.dumps(listed,indent=1))+';; '
        prefix+='"--json stat /root/underlay-'+'a'*32+'") printf %s '+shlex.quote(json.dumps(stat,indent=1))+';; '
        prefix+='"cat /root/underlay-'+'a'*32+'") printf challenge;; "--version") printf version_control;; *) return 92;; esac; }; '
        def capture(args,env,timeout):
            self.assertIn('--network',args);self.assertEqual(args[args.index('--network')+1],'none')
            result=subprocess.run(['/bin/sh','-c',prefix+args[-1]],env={'PATH':'/usr/bin:/bin','HOME':'seeded-secret'},capture_output=True,timeout=3)
            return {'exit':result.returncode,'outcome':'complete','stdout':result.stdout,'stdout_bytes':len(result.stdout),'stderr_bytes':len(result.stderr)}
        journal=Mock()
        with patch.object(module,'bound_colima',return_value='/owned/colima'),patch.object(module,'bounded_run',side_effect=capture),patch.object(module,'file_producer',return_value=':'):
            module.offline_client_interface({},journal,'a'*32)
            self.assertEqual(module.client_image_provenance({},journal,False),'version_control')
        self.assertNotIn('seeded-secret',str(journal.mock_calls))
        self.assertNotIn('minioadmin',str(journal.mock_calls))
        phases=[c.kwargs['operation'] for c in journal.append.call_args_list if c.args[0]=='offline_mc_phase']
        self.assertEqual(phases,['guard','alias_set','alias_list','producer','stat','cat'])

    def test_input_authority_and_framing_refuse_without_normalizing_overrides(self):
        from service_defaults import baseline
        for supplied in ('/root',{},object()):
            with self.assertRaisesRegex(ValueError,'client_command_input_refused'):
                baseline({}, {}, 'silo_client',command_input=supplied)
        with self.assertRaises(TypeError):baseline({}, {}, 'silo_client',native_home='/root')
        for text in ('M_HOME|present|0|0\nbody','M_HOME|absent|1|1\nbody',
                     'M_HOME|empty|0|1','M_HOME|seeded-secret|0|1\nbody','body'):
            with self.assertRaises(ValueError):guard.client_input_projection(text,'M')
        for name in ('MC_CONFIG_DIR','MC_CONFIG_ENV_FILE','MC_HOST_local','HTTP_PROXY'):
            effects=[];journal=Mock()
            with self.assertRaisesRegex(ValueError,'routing_guard_refused'):
                self.invoke('silo_client',{**self.base('silo_client'),name:''},journal)
                effects.append('alias_write')
            self.assertEqual(effects,[])
        for home in ({},{'HOME':'seeded-secret'}):
            record=baseline(home,{},'silo_client',command_input=guard.OWNER_CLIENT_COMMAND_INPUT)
            self.assertTrue(record['baseline_passed'])
            self.assertEqual(record['predicates'][-1]['resolution'],'owner_command_input')
            self.assertFalse(record['home_input_observation']['default_home_qualified'])
            self.assertNotIn('seeded-secret',json.dumps(record))
        for path in ('/root','/root/.mc','/'):
            with self.assertRaises(ValueError):baseline({}, {}, 'silo_client',(path,),command_input=guard.OWNER_CLIENT_COMMAND_INPUT)

    def test_full_path_refusal_markers_native_negative_and_secret_exclusion(self):
        for mode,classification in (('duplicate_marker','marker_refused'),('negative','inner_command_failed'),
                                    ('malformed','native_envelope_refused'),('unknown_record','malformed_predicate_evidence')):
            journal=Mock()
            with self.assertRaises(ValueError):self.invoke('silo',self.base('silo'),journal,mode)
            self.assertIn(classification,str(journal.mock_calls));self.assertNotIn('seeded-secret',str(journal.mock_calls))
        for error,expected in ((OSError('seeded-secret'),'spawn_refused'),(TimeoutError('seeded-secret'),'timeout'),(ValueError('seeded-secret'),'dispatch_refused')):
            journal=Mock()
            def fail(*args,**kwargs):raise error
            with self.assertRaises(ValueError):guard.finite_shell(fail,journal,'routing_environment_guard','ignored','silo')
            self.assertEqual(journal.append.call_args.kwargs['classification'],expected)
            self.assertNotIn('seeded-secret',str(journal.mock_calls))

    def test_decoder_duplicates_order_missing_oversize_and_false_agreement(self):
        text=subprocess.run(['/bin/sh','-c',guard.guard_command('silo')],env=self.base('silo'),capture_output=True,text=True,timeout=3).stdout
        for changed in (text+text,text.replace('GUARD|MC_RESOLVE','GUARD|HOME'),text.replace('|absent|1','|absent|0',1),'x'*4097,text.splitlines()[0]):
            with self.assertRaises(ValueError):guard.guard_projection(changed,'silo')
        with self.assertRaises(ValueError):guard.predicates('foreign')

    def test_durable_production_journal_before_refusal(self):
        with tempfile.TemporaryDirectory(prefix='underlay-guard-') as temporary:
            root=Path(temporary);fixture=root/'fixture';fixture.mkdir(mode=0o700)
            path=root/'storage-diagnostics.jsonl';journal=StorageDiagnosticJournal(path,fixture)
            try:
                with self.assertRaises(ValueError):self.invoke('silo',{**self.base('silo'),'MC_CONFIG_DIR':'seeded-secret'},journal)
            finally:journal.close()
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertNotIn('seeded-secret',path.read_text())
            rows=[json.loads(l) for l in path.read_text().splitlines()]
            self.assertFalse(rows[-1]['guard_passed']);self.assertEqual(rows[-1]['classification'],'predicates_complete')


if __name__=='__main__':unittest.main()
