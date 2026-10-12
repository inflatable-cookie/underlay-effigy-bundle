"""Hermetic production correlation controls; no container or network effects."""
import json
import unittest
from unittest.mock import Mock
import storage_correlation as probe


class CorrelationTests(unittest.TestCase):
    def test_inner_pipeline_exit_survives_outer_error_without_output_leak(self):
        import subprocess
        result = subprocess.run(['/bin/sh', '-c', probe.shell_command('printf seeded-secret >/dev/null; exit 57')], capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 57)
        self.assertEqual(probe.nested_exit(result.stdout), {'inner_exit':57, 'inner_exit_evidence':'shell_marker'})
        for value in ('seeded-secret', 'UNDERLAY_STORAGE_EXIT=999', 'UNDERLAY_STORAGE_EXIT=0\nUNDERLAY_STORAGE_EXIT=1'):
            self.assertEqual(probe.nested_exit(value)['inner_exit_evidence'], 'unknown')

    def test_exact_gateway_invocation_and_rejected_repo_have_no_effect(self):
        import os
        import subprocess
        import tempfile
        from pathlib import Path
        self.assertEqual(probe.invocation('/qualified', '/owned', ['gateway','status','--private-state-root','/private','--json']), ['/qualified','--json','gateway','status','--private-state-root','/private'])
        self.assertEqual(probe.invocation('/qualified', '/owned', ['container','hybrid_services','status','--json'])[:4], ['/qualified','--json','--repo','/owned'])
        with self.assertRaises(ValueError): probe.invocation('/qualified', '/owned', ['gateway','status'])
        binary = os.environ.get('UNDERLAY_PROFILE_EFFIGY_BIN')
        if not binary:
            raise RuntimeError('exact-source gateway parser control requires the qualified binary')
        from qualification_runtime import require_effigy_binary
        self.assertEqual(binary, require_effigy_binary())
        with tempfile.TemporaryDirectory(prefix='underlay-storage-cli-') as directory:
            root = Path(directory)
            import ast
            tree = ast.parse(Path(__file__).with_name('qualify-storage-correlation.py').read_text())
            calls = []
            for node in ast.walk(tree):
                if not isinstance(node, ast.List) or not node.elts or not isinstance(node.elts[0], ast.Constant) or node.elts[0].value != 'gateway':
                    continue
                values = []
                for item in node.elts:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str):
                        values.append(item.value)
                    elif isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id == 'str' and len(item.args) == 1 and isinstance(item.args[0], ast.Name) and item.args[0].id == 'gateway':
                        values.append(directory)
                    else:
                        self.fail('unclassified gateway argument in actual selector')
                calls.append(values)
            self.assertEqual(sorted(call[1] for call in calls), ['down','setup-tls','status','up'])
            for arguments in calls:
                actual = probe.invocation(binary, root, arguments)
                self.assertNotIn('--repo', actual)
                self.assertEqual(actual[actual.index('--private-state-root') + 1], directory)
                # All actual arguments must parse successfully before the
                # deliberate global --repo rejection. No command is executed.
                refused = [binary, '--repo', directory, *actual[1:]]
                process = subprocess.run(refused, capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, 2)
                envelope = json.loads(process.stdout)
                self.assertEqual(envelope['error']['kind'], 'CliParseError')
                self.assertEqual(envelope['error']['message'], 'unknown argument: --repo')
                self.assertEqual(list(root.iterdir()), [])

    def test_secret_free_error_projection_and_unknowns(self):
        body = b'<Error><Code>NoSuchKey</Code><RequestId>ABC-123</RequestId><Message>seeded-secret</Message><Key>secret</Key></Error>'
        result = probe.s3_error(body)
        self.assertEqual(result['error_code'], 'NoSuchKey')
        self.assertEqual(len(result['request_id_sha256']), 64)
        self.assertNotIn('seeded-secret', json.dumps(result))
        for body in (b'bad', b'<!DOCTYPE a><Error/>', b'<Error><Code>seeded-secret</Code></Error>', b'x' * 16385):
            self.assertEqual(probe.s3_error(body), {'error_code': 'unknown'})

    @staticmethod
    def alias():
        return json.dumps({'status':'success','alias':'local','URL':'http://silo:9000',
                           'accessKey':'minioadmin','secretKey':'minioadmin','api':'S3v4',
                           'path':'auto','src':'/root/.mc/config.json'},indent=1)

    @staticmethod
    def stat(key,size):
        return json.dumps({'status':'success','name':key,'lastModified':'2026-10-11T00:00:00Z',
                           'size':size,'etag':'digest','type':'file'},indent=1)

    def test_pretty_multiline_and_duplicate_json_refusal(self):
        self.assertEqual(probe.alias_projection(self.alias())['endpoint'],'http://silo:9000')
        for change in ({'URL':'http://user:secret@silo:9000'}, {'src':'env'}, {'path':'on'}, {'api':'S3v2'}, {'secretKey':'seeded-secret'}):
            with self.assertRaises(ValueError):probe.alias_projection(json.dumps({**json.loads(self.alias()),**change}))
        for value in (self.alias()+self.alias(),self.alias()+'secret', '{"status":"success","status":"error"}', '[{}]', 'bad'):
            with self.assertRaises(ValueError):probe.json_records(value)
        self.assertEqual(probe.stat_projection(self.stat('owned',7),'owned',7)['size'],7)
        for key,size in (('foreign',7),('owned',8)):
            with self.assertRaises(ValueError):probe.stat_projection(self.stat('owned',7),key,size)

    def test_full_correspondence_and_reverse_bytes_refusal(self):
        nonce='a'*32; key='main-known.txt';client_key=nonce+'-'+key;host_key=nonce+'-host-'+key
        payload=('client:'+client_key).encode();reverse=('host:'+host_key).encode();calls=[]
        def shell(label,command,**kwargs):
            calls.append(label)
            if label=='alias':return self.alias()
            if label=='stat':return self.stat(client_key,len(payload))
            if label=='server_read_client_write':return payload.decode()
            if label in ('server_read_host_write','client_read_host_write'):return reverse.decode()
            return ''
        request=Mock(side_effect=[(200,{},payload),(200,{},b'')])
        outcome=probe.correlate(shell,request,Mock(),8140,key,nonce)
        self.assertEqual(outcome['payloads'],[payload,reverse]);self.assertLess(calls.index('producer'),calls.index('consumer'))
        request=Mock(return_value=(404,{},b'<Error><Code>NoSuchKey</Code></Error>'))
        with self.assertRaisesRegex(ValueError,'host_byte'):probe.correlate(shell,request,Mock(),8140,key,nonce)
        self.assertEqual(request.call_count,1)
        def stale(label,command,**kwargs):
            if label=='client_read_host_write':return payload.decode()
            return shell(label,command,**kwargs)
        with self.assertRaisesRegex(ValueError,'byte_correspondence'):
            probe.correlate(stale,Mock(side_effect=[(200,{},payload),(200,{},b'')]),Mock(),8140,key,nonce)
        def failed(label,command,**kwargs):
            if label=='producer':raise ValueError('producer_refused')
            return shell(label,command,**kwargs)
        calls.clear()
        with self.assertRaisesRegex(ValueError,'producer_refused'):probe.correlate(failed,Mock(),Mock(),8140,key,nonce)
        self.assertNotIn('consumer',calls)

    def test_cross_scope_requires_own_survival_and_exact_no_such_key(self):
        own={'port':1,'bucket':'owned','keys':['a','b'],'payloads':[b'one',b'two']}
        foreign={'keys':['c','d']}
        for error in ('NoSuchBucket','unknown',None):
            body=b'generic' if error is None else ('<Error><Code>'+error+'</Code></Error>').encode()
            with self.assertRaises(ValueError):
                probe.cross_scope(Mock(side_effect=[(200,{},b'one'),(200,{},b'two'),(404,{},body)]),Mock(),own,foreign)
        probe.cross_scope(Mock(side_effect=[(200,{},b'one'),(200,{},b'two'),(404,{},b'<Error><Code>NoSuchKey</Code></Error>'),(404,{},b'<Error><Code>NoSuchKey</Code></Error>')]),Mock(),own,foreign)

    def test_presence_guards_and_marker_boundaries(self):
        import os,subprocess
        base={k:v for k,v in os.environ.items() if k not in probe.ROUTING_OVERRIDES and k!='MC_HOST_local'}
        base['HOME']='/root'
        for name in ('MC_HOST_local',*probe.ROUTING_OVERRIDES):
            for value in ('','seeded-secret'):
                result=subprocess.run(['/bin/sh','-c',probe.environment_guard('silo_client')],env={**base,name:value},capture_output=True,timeout=2)
                self.assertNotEqual(result.returncode,0);self.assertNotIn(b'seeded-secret',result.stdout+result.stderr)
        marker='UNDERLAY_ABC12345'
        result=subprocess.run(['/bin/sh','-c',probe.shell_command('printf %s bytes',marker)],capture_output=True,text=True,timeout=2)
        self.assertEqual(probe.shell_region(result.stdout,marker),('bytes',0))
        for value in (result.stdout+result.stdout,result.stdout.replace('_END=0','_END=999'),result.stdout.replace('_BEGIN','_OTHER')):
            with self.assertRaises(ValueError):probe.shell_region(value,marker)

    def test_native_status_identity_live_ports_and_unavailable_cleanup(self):
        identity={'project':'owned'}
        status=dict(schema='effigy.container.status.v1',schema_version=1,ok=True,container='hybrid_services',driver='colima',manifest_driver='colima',backend='containerd',profile='effigy',project_name='owned',primary_service='silo',runtime_running=True,services=[{'name':'silo','container_name':'opaque server','status':'Up 1 second','ports':['127.0.0.1:8140->9000/tcp']},{'name':'silo_client','container_name':'opaque client','status':'running','ports':[]}])
        binding=[('silo',8140,9000)]
        self.assertEqual(probe.status_projection(status,identity,binding)['port'],8140)
        for change in ({'runtime_running':False},{'services':None},{'backend':'foreign'},{'project_name':'foreign'},{'services':status['services']*2}):
            with self.assertRaises(ValueError):probe.status_projection({**status,**change},identity,binding)
        with self.assertRaises(ValueError):probe.status_projection(status,identity,[('silo',8540,9000)])
        probe.status_projection({**status,'services':[]},identity,[],after_down=True)
        with self.assertRaises(ValueError):probe.status_projection({**status,'runtime_running':False,'services':[]},identity,[],after_down=True)

    def test_real_process_caps_timeout_and_nested_capture_counterexample(self):
        import sys,os
        result=probe.bounded_run([sys.executable,'-c','import os; os.write(1,b"seeded-secret"*10000)'],cap=64,timeout=2)
        self.assertEqual(result['outcome'],'truncated');self.assertLessEqual(len(result['stdout']),64)
        # An inner collector allocates output before emitting. The outer reader
        # sees zero bytes and cannot demonstrate an inner byte bound.
        code='import sys,time; value=b"x"*65536; time.sleep(1); sys.stdout.buffer.write(value)'
        result=probe.bounded_run([sys.executable,'-c',code],cap=4096,timeout=.1)
        self.assertEqual(result['outcome'],'timeout');self.assertEqual(result['stdout_bytes'],0)
        evidence=probe.capture_contract(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE'])
        self.assertFalse(evidence['outer_pipe_cap_sufficient']);self.assertTrue(evidence['inner_byte_cap_demonstrated'])

    def test_real_file_producer_noclobber_and_independent_consumer(self):
        import tempfile,subprocess
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix='underlay-file-producer-') as name:
            path=Path(name)/'owned-file'
            payload=b'known challenge'
            producer=subprocess.run(['/bin/sh','-c',probe.file_producer(path,payload)],capture_output=True,timeout=2)
            self.assertEqual(producer.returncode,0);self.assertEqual(path.read_bytes(),payload)
            # A successful producer grants no consumer credit: preserve a
            # consumer refusal independently without rewriting the file.
            consumer=subprocess.run(['/bin/sh','-c','read -r value < "$1"; test "$value" = wrong','sh',str(path)],capture_output=True,timeout=2)
            self.assertNotEqual(consumer.returncode,0)
            refused=subprocess.run(['/bin/sh','-c',probe.file_producer(path,b'replacement')],capture_output=True,timeout=2)
            self.assertNotEqual(refused.returncode,0);self.assertEqual(path.read_bytes(),payload)

    def test_bounded_native_accounting_and_secret_projection(self):
        import copy
        marker='UNDERLAY_TEST1234'
        command=probe.shell_command('printf seeded-secret',marker)
        import subprocess
        executed=subprocess.run(['/bin/sh','-c',command],capture_output=True,text=True,timeout=2)
        stdout=executed.stdout
        value=dict(schema='effigy.container.bounded-exec.v1',schema_version=1,ok=True,
                   container='hybrid_services',service='silo_client',failure='complete',code=0,
                   limits=dict(probe.BOUNDS),retained={'stdout_bytes':len(stdout.encode())+17,'stderr_bytes':3},
                   preparation={'captures':2,'retained':{'stdout_bytes':17,'stderr_bytes':3}},
                   attempts=1,workspace_user_fallback=False,remote_cancellation='unverified',
                   stdout=stdout,stderr='',stdout_bytes=len(stdout.encode()),stderr_bytes=0)
        def envelope(v):return json.dumps(dict(schema='effigy.command.v1',schema_version=1,ok=v['ok'],result=v if v['ok'] else None,error=None if v['ok'] else {'details':v,'message':'seeded-secret'}))
        output,projection=probe.bounded_payload(envelope(value),0,'silo_client')
        self.assertEqual(probe.shell_region(output,marker),('seeded-secret',0))
        self.assertNotIn('seeded-secret',json.dumps(projection))
        for change in ({'stdout_bytes':0},{'retained':{'stdout_bytes':0,'stderr_bytes':3}}, {'preparation':{'captures':2,'retained':{'stdout_bytes':100000,'stderr_bytes':3}}}, {'code':1},{'limits':{**probe.BOUNDS,'deadline_ms':9000}}, {'attempts':2},{'schema_version':2}):
            with self.assertRaises(ValueError):probe.bounded_payload(envelope({**value,**change}),0,'silo_client')
        for failure in probe.BOUND_FAILURES:
            negative={k:v for k,v in value.items() if k not in ('stdout','stderr','stdout_bytes','stderr_bytes')}
            negative.update(ok=False,failure=failure,phase='command_execution',termination_scope='owned_host_client_group',inner_code=17,code=17)
            output,projection=probe.bounded_payload(envelope(negative),1,'silo_client')
            self.assertIsNone(output);self.assertEqual(projection['failure'],failure)
            self.assertNotIn('seeded-secret',json.dumps(projection))
        for failure in ('unknown','seeded-secret','complete'):
            bad={**value,'ok':False,'failure':failure}
            with self.assertRaises(ValueError):probe.bounded_payload(envelope(bad),1,'silo_client')
        with self.assertRaises(ValueError):probe.bounded_payload(envelope(value),1,'silo_client')

    def test_bounded_actual_parser_shapes_have_no_runtime_effect(self):
        import tempfile,subprocess
        from pathlib import Path
        from qualification_runtime import require_effigy_binary
        binary=require_effigy_binary()
        with tempfile.TemporaryDirectory(prefix='underlay-bounded-cli-') as name:
            root=Path(name)
            args=probe.bounded_arguments('silo_client','printf challenge')
            for field in ('--bounded','--deadline-ms','--stdout-limit-bytes','--stderr-limit-bytes'):
                broken=list(args);i=broken.index(field)
                del broken[i:i+(1 if field=='--bounded' else 2)]
                result=probe.bounded_run(probe.invocation(binary,root,broken),timeout=5)
                self.assertEqual(result['exit'],2)
                payload=probe.strict_json(result['stdout'].decode());self.assertEqual(payload['error']['kind'],'CliParseError')
            # Valid flags pass parsing, then the owned empty repository refuses
            # missing policy before runtime discovery; no manifest or backend.
            result=probe.bounded_run(probe.invocation(binary,root,args),timeout=5)
            self.assertNotEqual(result['exit'],0)
            payload=probe.strict_json(result['stdout'].decode())
            self.assertNotEqual(payload['error']['kind'],'CliParseError')
            self.assertEqual(list(root.iterdir()),[])

    def test_minimal_policy_has_no_apps_dns_or_other_services(self):
        policy = dict(driver='colima', profile='effigy', startup='detached', project_name='owned', working_dir='/', host={'publish_address':'127.0.0.1'}, host_processes=[{'secret':'x'}], dns={'routes':['secret']}, services={'silo':{'catalog':'silo'}, 'silo_client':{'catalog':'silo-mc'}, 'postgres':{}})
        result = probe.minimal_policy(policy)
        self.assertEqual(list(result['services']), ['silo', 'silo_client'])
        self.assertEqual(result['host_processes'], [])
        self.assertNotIn('dns', result)
        with self.assertRaises(ValueError): probe.minimal_policy({**policy, 'driver':'foreign'})
        for changed in ({'host':{'publish_address':'0.0.0.0'}}, {'project_name':'seeded-secret?'}, {'working_dir':'/foreign'}, {'startup':'attached'}):
            with self.assertRaises(ValueError): probe.minimal_policy({**policy, **changed})

    def test_native_minimal_manifest_load_and_refusals(self):
        import subprocess
        import tempfile
        import shutil
        from pathlib import Path
        from qualification_runtime import require_effigy_binary
        binary = require_effigy_binary()
        policy = probe.minimal_policy(dict(driver='colima', profile='effigy', startup='detached', project_name='owned', working_dir='/', host={'publish_address':'127.0.0.1'}, services={'silo':{'catalog':'silo'}, 'silo_client':{'catalog':'silo-mc'}}))
        with tempfile.TemporaryDirectory(prefix='underlay-storage-schema-') as directory:
            for scope in ('main', 'worktree'):
                root = Path(directory) / scope
                root.mkdir()
                for alias in ('silo', 'silo-mc'):
                    shutil.copytree(Path(__file__).parent / 'dev/catalog' / alias, root / 'infra/dev/catalog' / alias)
                manifest = root / 'effigy.toml'
                valid = probe.minimal_manifest(policy)
                def inspect(text):
                    manifest.write_text(text)
                    process = subprocess.run(probe.invocation(binary, root, ['config','--inspect','--path','containers.hybrid_services','--json']), capture_output=True, text=True, timeout=10)
                    return process.returncode, json.loads(process.stdout)
                code, envelope = inspect(valid)
                self.assertEqual(code, 0)
                selected = envelope['result']['selected_value']
                self.assertEqual(selected['path'], 'containers.hybrid_services')
                self.assertEqual(selected['value'], policy)
                # Native schema refusal, not a text assertion that mirrors output.
                for invalid in ('[sources]\nsiblings=false\n' + valid,
                                valid.replace('"driver" = "colima"', '"driver" = 17'),
                                valid + '"unknown_fixture_field" = true\n', 'not valid toml ['):
                    code, envelope = inspect(invalid)
                    self.assertNotEqual(code, 0)
                    self.assertFalse(envelope['ok'])
                inspect(valid)
                hosts = subprocess.run(probe.invocation(binary, root, ['container','hybrid_services','hosts','--json']), capture_output=True, text=True, timeout=10)
                self.assertEqual(hosts.returncode, 0)
                actual_hosts = json.loads(hosts.stdout)['result']
                probe.hosts_projection(actual_hosts, root)
                for changed in ({'checkout':'/foreign'}, {'routes':[{'kind':'http','service':'front'}]}, {'routes':'malformed'}):
                    with self.assertRaises(ValueError): probe.hosts_projection({**actual_hosts, **changed}, root)
                self.assertEqual(list(root.rglob('*.listener.json')), [])
                self.assertEqual(list(root.rglob('*.pid')), [])

    def test_native_primary_worktree_identity_and_compose_refusals(self):
        import subprocess
        import tempfile
        from pathlib import Path
        from qualification_runtime import require_effigy_binary
        binary = require_effigy_binary()
        with tempfile.TemporaryDirectory(prefix='underlay-storage-identity-') as directory:
            fixture = Path(directory).resolve()
            main = fixture / 'main'
            main.mkdir()
            def git(root, *args):
                return subprocess.run(['git','-C',str(root),*args], check=True, capture_output=True, text=True, timeout=10).stdout.strip()
            git(main, 'init')
            (main / 'owned.txt').write_text('fixture')
            git(main, 'add', 'owned.txt')
            git(main, '-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','-m','fixture')
            revision = git(main, 'rev-parse','HEAD')
            first = fixture / 'first'
            git(main, 'worktree','add','--detach',str(first),'HEAD')
            policy = probe.minimal_policy(dict(driver='colima', profile='effigy', startup='detached', project_name='owned', working_dir='/', host={'publish_address':'127.0.0.1'}, services={'silo':{'catalog':'silo'}, 'silo_client':{'catalog':'silo-mc'}}))
            for checkout, kind in ((main,'none'),(first,'worktree')):
                (checkout / 'effigy.toml').write_text(probe.minimal_manifest(policy))
                process = subprocess.run(probe.invocation(binary, checkout, ['container','scope','--json']), capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode,0)
                report = json.loads(process.stdout)['result']
                identity = probe.scope_identity(report, checkout, fixture, kind, revision, policy)
                self.assertEqual(identity['kind'], kind)
                labels = '  com.effigy.project: ' + identity['project'] + '\n'
                if kind == 'worktree': labels += '  com.effigy.scope: ' + identity['token'] + '\n'
                status = {'project_name':identity['project']}
                self.assertEqual(probe.compose_identity(labels.encode(),status,identity)['scope_kind'], kind)
                for bad in (b'', b'\xffseeded-secret', labels.encode()+b'  com.effigy.project: foreign\n', labels.encode()+b'  com.effigy.scope: malformed\n', labels.encode()+b'  com.effigy.scope: ffffffffffffffffffffffffffffffff\n'):
                    with self.assertRaises(ValueError): probe.compose_identity(bad,status,identity)
                if kind == 'worktree':
                    with self.assertRaises(ValueError): probe.compose_identity(('  com.effigy.project: '+identity['project']+'\n').encode(),status,identity)
                with self.assertRaises(ValueError): probe.compose_identity(labels.encode(),{'project_name':'foreign'},identity)
                for bad in ({**report,'checkout':str(fixture/'foreign')}, {**report,'scope':{'kind':'unknown','token':None}}, {**report,'scope':{'kind':kind}}, {**report,'scope':{'kind':kind,'token':None if kind=='worktree' else 'a'*32}}):
                    with self.assertRaises(ValueError): probe.scope_identity(bad,checkout,fixture,kind,revision,policy)
                with self.assertRaises(ValueError): probe.scope_identity(report,checkout,fixture,kind,'0'*40,policy)
                with self.assertRaises(ValueError): probe.scope_identity(report,checkout,fixture,kind,revision,{**policy,'share_runtime_identity':True})
                hosts = {'schema':'effigy.container.hosts.v1','ok':True,'checkout':str(checkout),'scope':{'kind':'primary' if kind=='none' else kind,'token':identity['token'],'shared_runtime_identity':kind=='none'},'routes':[]}
                probe.hosts_projection(hosts,checkout,identity)
                with self.assertRaises(ValueError): probe.hosts_projection({**hosts,'scope':{'kind':'primary','token':'foreign'}},checkout,identity)

    def test_actual_signed_request_retains_safe_framing_and_error(self):
        import importlib.util
        from pathlib import Path
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('correlation_request_runtime', Path(__file__).with_name('qualify-reference-runtime.py'))
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        response = Mock(status=404)
        response.getheader.side_effect = lambda name: {'Content-Length':'99', 'Content-Type':'application/xml'}.get(name)
        response.getheaders.return_value = []
        response.read.return_value = b'<Error><Code>NoSuchKey</Code><Message>seeded-secret</Message></Error>'
        connection = Mock()
        connection.getresponse.return_value = response
        journal = Mock()
        journal.begin.return_value = 'storage-01'
        with patch.object(runtime.http.client, 'HTTPConnection', return_value=connection):
            status, _, _ = runtime._s3_request(8540, 'GET', '/bucket/key', diagnostics=journal, diagnostic_operation='known_get', diagnostic_path_template='/<bucket>/<object>')
        self.assertEqual(status, 404)
        phases = [call.args[4] for call in journal.phase.call_args_list]
        self.assertEqual(phases, ['request_sent', 'before_response_headers', 'response_headers_received', 'before_response_body', 'response_body_received'])
        self.assertNotIn('seeded-secret', str(journal.mock_calls))
        self.assertEqual(journal.append.call_args.kwargs['error_code'], 'NoSuchKey')
        connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
