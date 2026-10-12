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

    def test_mc_per_field_before_refusal_and_exact_recipe(self):
        import tempfile
        from pathlib import Path
        from reference_storage_probe import StorageDiagnosticJournal
        with tempfile.TemporaryDirectory(prefix='underlay-mc-fields-') as temporary:
            root=Path(temporary);fixture=root/'fixture';fixture.mkdir(mode=0o700)
            p=root/'storage-diagnostics.jsonl';journal=StorageDiagnosticJournal(p,fixture)
            alias=json.loads(self.alias())
            for field in alias:
                for change in (None,False,'seeded-secret'):
                    altered={**alias,field:change}
                    with self.assertRaises(ValueError):probe.alias_projection(json.dumps(altered),journal)
                    record=json.loads(p.read_text().splitlines()[-1])
                    self.assertFalse(next(f for f in record['fields'] if f['field']==field)['expected_agreement'])
                altered=dict(alias);altered.pop(field)
                with self.assertRaises(ValueError):probe.alias_projection(json.dumps(altered),journal)
            with self.assertRaises(ValueError):probe.alias_projection(json.dumps({**alias,'seeded-secret':'secret'}),journal)
            self.assertEqual(json.loads(p.read_text().splitlines()[-1])['unknown_field_count'],1)
            set_record=dict(alias);set_record.pop('src')
            probe.alias_projection(json.dumps(set_record),journal,'alias_set')
            with self.assertRaises(ValueError):probe.alias_projection(json.dumps(set_record),journal,'alias_list')
            for field in json.loads(self.stat('owned',9)):
                altered={**json.loads(self.stat('owned',9)),field:False}
                with self.assertRaises(ValueError):probe.stat_projection(json.dumps(altered),'owned',9,journal)
            for op,body in (('bucket',{'status':'success','bucket':'local/owned','region':''}),
                            ('pipe',{'status':'success','target':'local/owned','size':9})):
                probe.operation_projection(json.dumps(body),op,'local/owned',9,journal)
                for field in body:
                    with self.assertRaises(ValueError):probe.operation_projection(json.dumps({**body,field:'seeded-secret'}),op,'local/owned',9,journal)
            journal.close()
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertNotIn('seeded-secret',p.read_text())
        import shlex
        for args in (['alias','list','local'],['mb','local/owned'],['pipe','local/owned'],['stat','local/owned'],['cat','local/owned']):
            words=shlex.split(probe.mc_command(args))
            self.assertEqual(words[:3],['mc','--config-dir','/root/.mc'])
            self.assertEqual(words[3:],args)
            self.assertEqual(shlex.split(probe.mc_command(args,'silo')),['mc']+args)

    def test_pinned_emitted_struct_source_contract(self):
        import os,re,hashlib
        from pathlib import Path
        root=Path(os.environ['UNDERLAY_MC_SOURCE_ROOT'])
        facts={'alias-main.go':('54ef9abc015f0be1bc4481f9e903097bf8ddb2b0bba57ef22e7accdd3d125ebd','aliasMessage'),
               'stat.go':('335b9f8a197955ed97003e4130e82804eb9f41288c0fdeebf8edf8003ec3be95','statMessage'),
               'mb-main.go':('b2e98ac646ce4604725d3b8119241d1211116835f92db7c027a2af3d0d86cdd6','makeBucketMessage'),
               'pipe-main.go':('8f0fff4597e8c872214dbe7f2ce68be17ab6fe6a8c1c4d8f8cc8e7f1c910765b','pipeMessage')}
        for filename,(digest,struct) in facts.items():
            raw=(root/filename).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
            source=raw.decode();block=source.split('type '+struct+' struct {',1)[1].split('}',1)[0]
            fields=re.findall(r'json:"([^"]+)"',block)
            values={name.split(',')[0]:('' if ',omitempty' in name else 'required') for name in fields}
            if struct=='aliasMessage':
                self.assertEqual(set(values),set(json.loads(self.alias()))|{'lookup'})
                self.assertEqual(values['src'],'');self.assertEqual(values['status'],'required')
            elif struct=='statMessage':self.assertEqual(values['type'],'')
            else:self.assertTrue(all(v=='required' for v in values.values()))
            self.assertIn('json.MarshalIndent',source)

    def test_full_correspondence_and_reverse_bytes_refusal(self):
        nonce='a'*32; key='main-known.txt';client_key=nonce+'-'+key;host_key=nonce+'-host-'+key
        payload=('client:'+client_key).encode();reverse=('host:'+host_key).encode();calls=[]
        def shell(label,command,**kwargs):
            calls.append(label)
            if label=='alias':return self.alias()
            if label=='stat':return self.stat(client_key,len(payload))
            if label=='bucket':return json.dumps({'status':'success','bucket':'local/underlay-storage-correlation','region':''})
            if label=='consumer':return json.dumps({'status':'success','target':'local/underlay-storage-correlation/'+client_key,'size':len(payload)})
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

    def test_port_classes_and_before_rejection_evidence(self):
        import copy
        identity={'project':'owned'}
        status=dict(schema='effigy.container.status.v1',schema_version=1,ok=True,container='hybrid_services',driver='colima',manifest_driver='colima',backend='containerd',profile='effigy',project_name='owned',primary_service='silo',runtime_running=True,services=[{'name':'silo','container_name':'opaque server','status':'Up 1 second','ports':['127.0.0.1:8140->9000/tcp','9000/tcp']},{'name':'silo_client','container_name':'opaque client','status':'running','ports':[]}])
        bindings=[('silo',8140,9000)]
        self.assertEqual(probe.status_projection(status,identity,bindings)['port'],8140)
        for token in ('9000/udp','1234/tcp','0.0.0.0:8140->9000/tcp','[::]:8140->9000/tcp','127.0.0.2:8140->9000/tcp','127.0.0.1:8140->9000/udp','127.0.0.1:8140-8141->9000/tcp','seeded-secret-http://user:password@foreign','x'*300,None):
            changed=copy.deepcopy(status);changed['services'][0]['ports'].append(token)
            journal=Mock()
            with self.assertRaises(ValueError):probe.status_projection(changed,identity,bindings,diagnostics=journal)
            evidence=journal.append.call_args.kwargs
            self.assertEqual(evidence['evidence'],'current_input_before_validation')
            self.assertEqual(evidence['rows'][0]['ports'][-1]['input_sha256'],probe.input_fingerprint(token)['input_sha256'])
            self.assertNotIn('seeded-secret',json.dumps(evidence));self.assertNotIn('password',json.dumps(evidence))
            self.assertLess(len(json.dumps(evidence)),12000)
        for tokens in (['9000/tcp'], ['127.0.0.1:8140->9000/tcp']*2, ['127.0.0.1:8140->9000/tcp','127.0.0.1:8540->9000/tcp']):
            changed=copy.deepcopy(status);changed['services'][0]['ports']=tokens
            with self.assertRaises(ValueError):probe.status_projection(changed,identity,bindings,diagnostics=Mock())
        changed=copy.deepcopy(status);changed['project_name']='seeded-secret';changed['services'][0]['container_name']='credential-string';changed['services'][0]['status']='seeded-secret'
        journal=Mock()
        with self.assertRaises(ValueError):probe.status_projection(changed,identity,bindings,diagnostics=journal)
        self.assertNotIn('seeded-secret',json.dumps(journal.append.call_args.kwargs))
        self.assertNotIn('credential-string',json.dumps(journal.append.call_args.kwargs))
        changed=copy.deepcopy(status);changed['services'][0]['ports']=['9000/tcp']*65
        journal=Mock()
        with self.assertRaisesRegex(ValueError,'projection_truncated'):probe.status_projection(changed,identity,bindings,diagnostics=journal)
        self.assertTrue(journal.append.call_args.kwargs['projection_truncated'])

    def test_rejected_status_is_durable_secret_free_mode0600(self):
        import tempfile,stat
        from pathlib import Path
        from reference_storage_probe import StorageDiagnosticJournal
        with tempfile.TemporaryDirectory(prefix='underlay-port-evidence-') as name:
            root=Path(name).resolve();fixture=root/'fixture';fixture.mkdir(mode=0o700)
            evidence=root/'evidence';evidence.mkdir(mode=0o700)
            path=evidence/'storage-diagnostics.jsonl';journal=StorageDiagnosticJournal(path,fixture)
            status={'schema':'seeded-secret','compose_file':'/seeded-secret/path','services':[{'name':'silo','container_name':'seeded-secret','status':'seeded-secret','ports':['seeded-secret']} ]}
            try:
                with self.assertRaises(ValueError):probe.status_projection(status,{'project':'owned'},[],diagnostics=journal)
                persisted=path.read_text()
                self.assertNotIn('seeded-secret',persisted)
                record=json.loads(persisted)
                self.assertEqual(record['event'],'native_status_observation')
                self.assertEqual(record['rows'][0]['ports'][0]['class'],'unknown')
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            finally:journal.close()

    def test_native_private_backend_formatter_rows_both_checkouts(self):
        import tempfile,subprocess,os,shutil
        from pathlib import Path
        from qualification_runtime import require_effigy_binary
        binary=require_effigy_binary()
        with tempfile.TemporaryDirectory(prefix='underlay-native-port-parser-',dir=Path.home()) as name:
            fixture=Path(name).resolve();bin_dir=fixture/'bin';bin_dir.mkdir();home=fixture/'home';home.mkdir()
            fake=bin_dir/'colima'
            fake.write_text("#!/bin/sh\ncase \"$*\" in\n 'status --profile effigy') printf '%s\\n' 'colima is running using containerd';;\n 'list --json') printf '%s\\n' '{\"name\":\"effigy\",\"status\":\"Running\",\"cpus\":2,\"memory\":4294967296,\"disk\":34359738368}';;\n 'nerdctl --profile effigy -- ps --format '*|'nerdctl --profile effigy -- ps --all --format '*) printf '%s' \"$FAKE_PORT_ROWS\";;\n 'nerdctl --profile effigy -- exec '*) exit 0;;\n *) exit 93;;\nesac\n")
            fake.chmod(0o700)
            env={**os.environ,'PATH':str(bin_dir)+os.pathsep+os.environ['PATH'],'HOME':str(home),'COLIMA_HOME':str(fixture/'colima'),'EFFIGY_COMPOSE_BACKEND':'colima'}
            for key in ('DOCKER_HOST','DOCKER_CONTEXT'):env.pop(key,None)
            main=fixture/'main';main.mkdir()
            def git(root,*args):return subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True,text=True,timeout=10).stdout.strip()
            git(main,'init');(main/'owned').write_text('fixture');git(main,'add','owned');git(main,'-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','-m','fixture')
            revision=git(main,'rev-parse','HEAD');first=fixture/'first';git(main,'worktree','add','--detach',str(first),'HEAD')
            policy=probe.minimal_policy(dict(driver='colima',profile='effigy',startup='detached',project_name='owned',working_dir='/',host={'publish_address':'127.0.0.1'},services={'silo':{'catalog':'silo'},'silo_client':{'catalog':'silo-mc'}}))
            projects=[]
            for checkout,kind in ((main,'none'),(first,'worktree')):
                for alias in ('silo','silo-mc'):shutil.copytree(Path(__file__).parent/'dev/catalog'/alias,checkout/'infra/dev/catalog'/alias)
                (checkout/'effigy.toml').write_text(probe.minimal_manifest(policy))
                captured=probe.bounded_run(probe.invocation(binary,checkout,['container','scope','--json']),env=env,timeout=10)
                self.assertEqual(captured['exit'],0)
                scope=probe.strict_json(captured['stdout'].decode())['result']
                identity=probe.scope_identity(scope,checkout,fixture,kind,revision,policy)
                project=identity['project'];projects.append(project)
                # This is a source-representative formatter double, not a live
                # backend receipt. The actual pinned native parser/serializer runs.
                port=8140 if kind=='none' else 8540
                rows=f'opaque-server-{kind}\tUp 1 second\t127.0.0.1:{port}->9000/tcp, 9000/tcp\t{project}\t{checkout}\tsilo\tFalse\nopaque-client-{kind}\trunning\t\t{project}\t{checkout}\tsilo_client\tFalse\n'
                captured=probe.bounded_run(probe.invocation(binary,checkout,['container','hybrid_services','status','--json']),env={**env,'FAKE_PORT_ROWS':rows},timeout=10)
                self.assertEqual(captured['exit'],0,{'stderr_bytes':captured['stderr_bytes'],'stdout_bytes':captured['stdout_bytes']})
                envelope=probe.strict_json(captured['stdout'].decode());self.assertEqual(envelope['schema'],'effigy.command.v1');self.assertTrue(envelope['ok'])
                native=envelope['result'];self.assertEqual(native['schema_version'],1)
                server=next(row for row in native['services'] if row['name']=='silo')
                self.assertEqual(server['ports'],[f'127.0.0.1:{port}->9000/tcp','9000/tcp'])
                self.assertEqual(probe.status_projection(native,identity,[('silo',port,9000)],diagnostics=Mock())['port'],port)
                with self.assertRaises(ValueError):probe.status_projection(native,{**identity,'project':'foreign'},[('silo',8140,9000)],diagnostics=Mock())
                from qualification.formatter_cases import format_ports,maintained_cases
                variants=[
                    ([('127.0.0.1',port,9000,'tcp'),('127.0.0.1',port+1,9001,'tcp')],[('silo',port,9000),('silo',port+1,9001)],True),
                    ([('127.0.0.1',port+30,9001,'tcp'),('127.0.0.1',port,9000,'tcp')],[('silo',port,9000),('silo',port+30,9001)],True),
                    ([('0.0.0.0',port+1,9001,'udp'),('127.0.0.1',port,9000,'tcp')],[('silo',port,9000)],False)]
                for _,mappings,expected in maintained_cases():
                    variants.append((mappings,[('silo',port,9000)],False))
                for mappings,declared,accepted in variants:
                    rendered=format_ports(mappings)
                    rows=f'opaque-server-{kind}\tUp 1 second\t{rendered}\t{project}\t{checkout}\tsilo\tFalse\nopaque-client-{kind}\trunning\t\t{project}\t{checkout}\tsilo_client\tFalse\n'
                    captured=probe.bounded_run(probe.invocation(binary,checkout,['container','hybrid_services','status','--json']),env={**env,'FAKE_PORT_ROWS':rows},timeout=10)
                    self.assertEqual(captured['exit'],0)
                    native=probe.strict_json(captured['stdout'].decode())['result']
                    journal=Mock()
                    if accepted:self.assertEqual(probe.status_projection(native,identity,declared,diagnostics=journal)['port'],port)
                    else:
                        with self.assertRaises(ValueError):probe.status_projection(native,identity,declared,diagnostics=journal)
                    self.assertEqual(journal.append.call_args.kwargs['evidence'],'current_input_before_validation')

                for rendered in (f'127.0.0.1:{port}-{port+2}->9000-9001/tcp',
                                 f'127.0.0.1:{port}-{port+1}->9000-9001/udp',
                                 f'127.0.0.1:{port}->9000, {port}->9001/tcp',
                                 f'127.0.0.1:{port}->9000, 9001/tcp',
                                 f'{port}->9000/tcp', 'seeded-secret-http://password@foreign'):
                    rows=f'opaque-server-{kind}\tUp 1 second\t{rendered}\t{project}\t{checkout}\tsilo\tFalse\nopaque-client-{kind}\trunning\t\t{project}\t{checkout}\tsilo_client\tFalse\n'
                    captured=probe.bounded_run(probe.invocation(binary,checkout,['container','hybrid_services','status','--json']),env={**env,'FAKE_PORT_ROWS':rows},timeout=10)
                    self.assertEqual(captured['exit'],0)
                    native=probe.strict_json(captured['stdout'].decode())['result'];journal=Mock()
                    with self.assertRaises(ValueError):probe.status_projection(native,identity,[('silo',port,9000),('silo',port+1,9001)],diagnostics=journal)
                    self.assertNotIn('seeded-secret',str(journal.mock_calls));self.assertNotIn('password',str(journal.mock_calls))
                    self.assertEqual(journal.append.call_args.kwargs['evidence'],'current_input_before_validation')
            self.assertEqual(len(set(projects)),2)

    def test_231_maintained_source_goldens_and_complete_group_refusals(self):
        from qualification.formatter_cases import format_ports, maintained_cases
        from formatter_provenance import formatter_projection
        from pathlib import Path
        formatter_projection((Path(__file__).parent/'qualification/fixtures/nerdctl-231-formatter.go').read_bytes())
        for name,mappings,expected in maintained_cases():
            self.assertEqual(format_ports(mappings),expected,name)
        bindings=[('silo',8140,9000),('silo',8141,9001)]
        text=format_ports([('127.0.0.1',8141,9001,'tcp'),('127.0.0.1',8140,9000,'tcp')])
        self.assertEqual(text,'127.0.0.1:8140-8141->9000-9001/tcp')
        self.assertEqual(probe.grouped_published(text.split(', '),'silo',bindings),bindings)
        nonadj=[('silo',8140,9000),('silo',8170,9001)]
        grouped=format_ports([('127.0.0.1',8170,9001,'tcp'),('127.0.0.1',8140,9000,'tcp')])
        self.assertEqual(probe.grouped_published(grouped.split(', '),'silo',nonadj),nonadj)
        for text in ('127.0.0.1:8140-8142->9000-9001/tcp','127.0.0.1:8141-8140->9001-9000/tcp',
                     '127.0.0.1:0-1->9000-9001/tcp','127.0.0.1:65535-65536->9000-9001/tcp',
                     '127.0.0.1:08140-8141->9000-9001/tcp','127.0.0.1:8140-8140->9000-9000/tcp',
                     '127.0.0.1:1-65535->1-65535/tcp','127.0.0.1:8140->9000, 8141->9001/tcp',
                     '127.0.0.1:8140-8141->9000-9001/udp','0.0.0.0:8140-8141->9000-9001/tcp',
                     '127.0.0.2:8140-8141->9000-9001/tcp','8140-8141->9000-9001/tcp',
                     '127.0.0.1:8140->9000, 9001/tcp','127.0.0.1:8140->9000',
                     '127.0.0.1:8140->9000/tcp, 127.0.0.1:8141->9001/tcp',
                     '127.0.0.1:8140-8141->9000-9001/tcp, 127.0.0.1:8140->9000/tcp',
                     'seeded-secret', '127.0.0.1:8140->9000/unknown'):
            with self.assertRaises(ValueError,msg=text):probe.grouped_published(text.split(', '),'silo',bindings)
        with self.assertRaises(ValueError):probe.grouped_published([text],'silo',bindings*9)

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
