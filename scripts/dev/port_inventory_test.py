"""Whole production inventory controls; native backend is a finite private double."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import port_inventory as ports
import profile_launcher as launcher
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from qualification.formatter_cases import format_ports, maintained_cases
from formatter_provenance import formatter_projection

TARGETS=ports.PROFILE_TARGETS
BINDINGS=[('postgres',25432,5432),('mailpit',21025,1025),('mailpit',28025,8025),('silo',29000,9000),('silo',29001,9001),('dbgate',23000,3000)]


def compose(bindings=BINDINGS, project='owned',token=None):
    text='services:\n'
    for name in TARGETS:
        text+='  '+name+':\n    image: fixture\n    labels:\n      com.effigy.project: '+project+'\n'
        if token:text+='      com.effigy.scope: '+token+'\n'
        mappings=[(h,t) for n,h,t in bindings if n==name]
        if mappings:text+='    ports:\n'+''.join(f'    - 127.0.0.1:{h}:{t}\n' for h,t in mappings)
    return text.encode()


def status(bindings=BINDINGS):
    rows=[]
    for name in TARGETS:
        rendered=format_ports([('127.0.0.1',h,t,'tcp') for n,h,t in bindings if n==name])
        rows.append(dict(name=name,container_name='opaque-'+name,status='Up 1 second',ports=rendered.split(', ') if rendered else []))
    return dict(services=rows,ports=[f'{h}:{t}' for n,h,t in bindings],project_name='owned')


class InventoryTests(unittest.TestCase):
    def test_maintained_formatter_and_canonical_six_port_inventory(self):
        formatter_projection((Path(__file__).resolve().parents[1]/'qualification/fixtures/nerdctl-231-formatter.go').read_bytes())
        for _,mappings,expected in maintained_cases():self.assertEqual(format_ports(mappings),expected)
        for bindings in (BINDINGS,[(n,h+23 if t==9001 else h,t) for n,h,t in BINDINGS],[(n,1 if t==9000 else 2 if t==9001 else h,t) for n,h,t in BINDINGS],[(n,65534 if t==9000 else 65535 if t==9001 else h,t) for n,h,t in BINDINGS]):
            with self.subTest(bindings=bindings):
                declared=ports.compose_bindings(compose(bindings),TARGETS);s=status(bindings)
                self.assertEqual(ports.admit_inventory(s,declared,TARGETS),{(n,t):h for n,h,t in bindings})
                for row in s['services']:row['ports']+= [str(t)+'/tcp' for t in TARGETS[row['name']]]
                self.assertEqual(len(ports.admit_inventory(s,declared,TARGETS)),6)

    def test_whole_inventory_negative_before_and_after_requested_target(self):
        s=status();variants=[]
        for name in ('postgres','silo','dbgate'):
            i=next(i for i,r in enumerate(s['services']) if r['name']==name)
            base=s['services'][i]['ports'][0]
            bads=[base.replace('127.0.0.1','0.0.0.0'),base.replace('127.0.0.1','127.0.0.2'),base.replace('/tcp','/udp'),base.replace('/tcp','/sctp'),base.replace('/tcp','/unknown'),'[::1]:29000->9000/tcp','9000/tcp','029000->9000/tcp','127.0.0.1:65536->9000/tcp','127.0.0.1:29001-29000->9000-9001/tcp','127.0.0.1:29000-29002->9000-9001/tcp','127.0.0.1:29000->9000','127.0.0.1:29000->9000, 29001->9001/tcp','x'*129]
            for bad in bads:
                x=copy.deepcopy(s);x['services'][i]['ports']=[bad];variants.append(x)
            x=copy.deepcopy(s);x['services'][i]['ports']*=2;variants.append(x)
        for field in ('ports','services'):
            x=copy.deepcopy(s);x[field]=[];variants.append(x)
            x=copy.deepcopy(s);x[field]+=x[field][:1];variants.append(x)
        for alloc in ('0.0.0.0:29000:9000','29000:9000/udp','29000:9002','029000:9000','SEEDED_SECRET'):
            x=copy.deepcopy(s);x['ports'].append(alloc);variants.append(x)
        x=copy.deepcopy(s);x['services'][-1]['name']='foreign';variants.append(x)
        x=copy.deepcopy(s);x['services'][1]['ports']=['127.0.0.1:21025-21026->1025-1026/tcp'];variants.append(x)
        x=copy.deepcopy(s);x['services'][2]['ports']=['127.0.0.1:29000->9000','29001->9001/tcp'];variants.append(x) # mergeable adjacency
        for x in variants:
            with self.subTest(index=variants.index(x)):
                with self.assertRaises(ValueError):ports.admit_inventory(x,BINDINGS,TARGETS)
        with self.assertRaises(ValueError):ports.admit_inventory(s,[(n,h+1,t) for n,h,t in BINDINGS],TARGETS)

    def test_compose_every_unsupported_entry_is_a_refusal(self):
        raw=compose()
        for replacement in ('0.0.0.0:25432:5432','127.0.0.1:025432:5432','127.0.0.1:65536:5432','127.0.0.1:25432:5432/udp','25432:5432','{target: 5432, published: 25432}','127.0.0.1:25432:5432\n    - 127.0.0.1:25432:5432'):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):ports.compose_bindings(raw.replace(b'127.0.0.1:25432:5432',replacement.encode()),TARGETS)
        for bad in (raw.replace(b'  postgres:',b'  foreign:'),raw.replace(b'    ports:',b'    ports: []',1),raw.replace(b'    image: fixture',b'    image: fixture\n    image: other',1),raw.replace(b'    - 127.0.0.1:25432:5432\n',b''),raw+b'x'*131073):
            with self.assertRaises(ValueError):ports.compose_bindings(bad,TARGETS)
        with self.assertRaises(ValueError):ports.compose_identity(raw,{'project_name':'foreign'},{'project':'owned','kind':'none','token':None})
        with self.assertRaises(ValueError):ports.compose_identity(raw.replace(b'com.effigy.project: owned',b'com.effigy.project: foreign',1),status(),{'project':'owned','kind':'none','token':None})


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='underlay-inventory-snapshot-');self.addCleanup(self.temp.cleanup)
        self.repo=Path(self.temp.name).resolve();self.path=self.repo/'compose.yml';self.path.write_bytes(compose())
        self.status=launcher._status_source(self.repo,{**status(), 'schema':'effigy.container.status.v1','schema_version':1,'ok':True,'container':'hybrid_services','compose_file':str(self.path)},'hybrid_services')
    def test_missing_source_never_depends_on_journal(self):
        self.path.unlink()
        for journal in (None,launcher._silo_journal(self.repo,'hybrid_services','service-port-context.jsonl')):
            token=launcher._PORT_EVIDENCE.set(journal)
            try:
                with self.assertRaises(launcher.ProfileError):launcher._compose_loopback_port_bindings(self.repo,self.status)
            finally:launcher._PORT_EVIDENCE.reset(token)
    def test_changed_before_during_and_unsafe_source(self):
        self.path.write_bytes(compose()+b'\n')
        with self.assertRaises(launcher.ProfileError):launcher._compose_loopback_port_bindings(self.repo,self.status)
        self.path.write_bytes(compose());s=launcher._status_source(self.repo,self.status,'hybrid_services')
        original=ports._compose_identity;calls=[]
        def observed(repo,status):
            calls.append(1)
            if len(calls)==2:self.path.write_bytes(compose()+b'\n')
            return original(repo,status)
        with patch.object(ports,'_compose_identity',side_effect=observed),self.assertRaises(launcher.ProfileError):launcher._compose_loopback_port_bindings(self.repo,s)
        for kind in ('symlink','hardlink','oversize'):
            self.path.unlink();other=self.repo/'other';other.write_bytes(compose())
            if kind=='symlink':self.path.symlink_to(other)
            elif kind=='hardlink':os.link(other,self.path)
            else:self.path.write_bytes(b'x'*131073)
            with self.subTest(kind=kind),self.assertRaises(launcher.ProfileError):launcher._compose_loopback_port_bindings(self.repo,self.status)
            other.unlink()
    def test_finite_native_capture_duplicate_schema_overflow_and_seed_privacy(self):
        backend=self.repo/'local-reader';journal=launcher._silo_journal(self.repo,'hybrid_services','service-port-context.jsonl')
        token=launcher._PORT_EVIDENCE.set(journal)
        try:
            for payload in ("SEEDED_SECRET", "x"*300000, '{"schema":"effigy.command.v1","schema":"effigy.command.v1"}', '{"schema":"unknown","schema_version":1,"ok":true}'):
                code="print("+repr(payload)+")"
                backend.write_text('#!'+sys.executable+'\n'+code+'\n');backend.chmod(0o700)
                binary=launcher.BinaryIdentity('source',str(backend),'digest',1,2,3,4)
                with patch.object(launcher,'verify_unchanged'),self.assertRaises(launcher.ProfileError):launcher._json_command(binary,self.repo,{},'container','hybrid_services','status')
            with patch.object(launcher,'verify_unchanged',side_effect=launcher.ProfileError('SEEDED_ADMISSION')),self.assertRaises(launcher.ProfileError):launcher._json_command(binary,self.repo,{},'container','hybrid_services','status')
        finally:launcher._PORT_EVIDENCE.reset(token)
        p=self.repo/'.effigy/runtime/dev-profiles/hybrid_services/service-port-context.jsonl';text=p.read_text()
        self.assertNotIn('SEEDED',text);self.assertNotIn(str(backend),text);self.assertEqual(p.stat().st_mode&0o777,0o600)

    def test_unreadable_and_schema_routing_sources_refuse(self):
        with patch.object(ports.os,'open',side_effect=PermissionError('SEEDED_PRIVATE')),self.assertRaises(launcher.ProfileError):launcher._compose_loopback_port_bindings(self.repo,self.status)
        for field,value in (('schema','unknown'),('schema_version',True),('container','foreign'),('project_name',None)):
            changed={**self.status,field:value}
            with self.subTest(field=field),self.assertRaises(launcher.ProfileError):launcher._status_source(self.repo,changed,'hybrid_services')

    def test_safe_journal_full_payload_digest_only(self):
        journal=launcher._silo_journal(self.repo,'hybrid_services','service-port-context.jsonl');token=launcher._PORT_EVIDENCE.set(journal)
        try:
            s=launcher._status_source(self.repo,{**self.status,'compose_ps':'SEEDED_CREDENTIAL_ENV_ARGV'},'hybrid_services');b=launcher._compose_loopback_port_bindings(self.repo,s);launcher._resolved_service_ports(s,b)
        finally:launcher._PORT_EVIDENCE.reset(token)
        p=self.repo/'.effigy/runtime/dev-profiles/hybrid_services/service-port-context.jsonl';text=p.read_text()
        self.assertNotIn('SEEDED',text);self.assertNotIn('25432',text);self.assertEqual(p.stat().st_mode&0o777,0o600)
        self.assertTrue(any(json.loads(l).get('live_compose_equal') for l in text.splitlines()))

class NativeInventoryTests(unittest.TestCase):
    def test_native_formatter_complete_context_primary_two_worktrees_profiles(self):
        from storage_correlation import toml_value
        identity=launcher.verify_binary(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE'],os.environ['UNDERLAY_PROFILE_EFFIGY_BIN'])
        with tempfile.TemporaryDirectory(prefix='underlay-complete-native-',dir=Path.home()) as directory:
            root=Path(directory).resolve();home=root/'home';home.mkdir();bindir=root/'bin';bindir.mkdir()
            fake=bindir/'colima';fake.write_text('''#!/bin/sh
case "$*" in
 'status --profile effigy') printf '%s\\n' 'colima is running using containerd';;
 'list --json') printf '%s\\n' '{"name":"effigy","status":"Running","cpus":2,"memory":4294967296,"disk":34359738368}';;
 'nerdctl --profile effigy -- ps '*) printf '%s' "$FAKE_PORT_ROWS";;
 'nerdctl --profile effigy -- exec '*) exit 0;;
 'nerdctl --profile effigy -- compose '*) last=''; for word in "$@"; do last="$word"; done; test "$last" = ps || exit 93; exit 0;;
 *) for word in "$@"; do case "$word" in status|list|nerdctl|--profile|effigy|--|compose|ps|--all|--format|--filter|inspect|--json|version) printf '%s ' "$word" >&2;; *) printf 'redacted ' >&2;; esac; done; exit 93;;
esac
''');fake.chmod(0o700)
            docker=bindir/'docker';docker.write_text('#!/bin/sh\nexit 94\n');docker.chmod(0o700)
            env={**os.environ,'PATH':str(bindir)+os.pathsep+os.environ['PATH'],'HOME':str(home),'COLIMA_HOME':str(root/'colima'),'EFFIGY_COMPOSE_BACKEND':'colima','FAKE_PORT_ROWS':'','PYTHONDONTWRITEBYTECODE':'1'}
            for key in ('DOCKER_HOST','DOCKER_CONTEXT','COLIMA_PROFILE'):env.pop(key,None)
            main=root/'main';main.mkdir()
            def git(*args):subprocess.run(['git','-C',str(main),*args],capture_output=True,check=True,timeout=10)
            git('init');(main/'owned').write_text('fixture');git('add','owned');git('-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','-m','fixture')
            checkouts=[main,root/'first',root/'second']
            for checkout in checkouts[1:]:git('worktree','add','--detach',str(checkout),'HEAD')
            for checkout in checkouts:
                catalog=checkout/'infra/dev/catalog';catalog.mkdir(parents=True)
                for name,targets in TARGETS.items():
                    path=catalog/name;path.mkdir();(path/'service.toml').write_text('[service]\nname = '+json.dumps(name)+'\n[ports]\ndefault = '+json.dumps(list(targets))+'\n')
                    (path/'compose.fragment.yml').write_text('services:\n  {{ service_name }}:\n    image: fixture\n'+('    ports:\n'+''.join('      - \"'+str(t)+':'+str(t)+'\"\n' for t in targets) if targets else ''))
                # Genuine bundle-owned Silo fragments; pure rendering never pulls images.
                for name,alias in (('silo','silo'),('silo_client','silo-mc')):
                    shutil.rmtree(catalog/name);shutil.copytree(Path(__file__).parent/'catalog'/alias,catalog/name)
                for container in ('hybrid_services','disposable_test'):
                    policy=dict(driver='colima',profile='effigy',startup='detached',project_name='owned-'+container.replace('_','-'),working_dir='/',primary_service='silo',host={'publish_address':'127.0.0.1'},services={n:{'catalog':n} for n in TARGETS},host_processes=[])
                    (checkout/'effigy.toml').write_text('[containers.'+container+']\n'+'\n'.join(json.dumps(k)+' = '+toml_value(v) for k,v in policy.items())+'\n')
                    source=launcher._json_command(identity,checkout,env,'container',container,'status')
                    source=launcher._status_source(checkout,source,container)
                    bindings=launcher._compose_loopback_port_bindings(checkout,source)
                    scope=launcher._json_command(identity,checkout,env,'container','scope');owned=ports.checkout_identity(scope,checkout,policy)
                    for variant in ('canonical',):
                        # Native rendering decides declaration ports. Only formatter row grammar is doubled.
                        rows=[]
                        for n,ts in TARGETS.items():
                            pairs=[('127.0.0.1',h,t,'tcp') for name,h,t in bindings if name==n]
                            rendered=format_ports(pairs)
                            if pairs:rendered+=', '+', '.join(str(t)+'/tcp' for t in ts)
                            rows.append(f'opaque-{n}\tUp 1 second\t{rendered}\t{owned["project"]}\t{checkout}\t{n}\tFalse\n')
                        declared_routes={name.lower():name.lower()+'.fixture.test' for name in ('API','FRONT','ADMIN','S3','DBGATE','MAILPIT','SILO')}
                        native_env={**env,'FAKE_PORT_ROWS':''.join(rows),'EFFIGY_GATEWAY_PRIVATE_STATE_ROOT':str(root/'private'),**{'EFFIGY_PROFILE_'+name.upper()+'_DECLARED':domain for name,domain in declared_routes.items()}}
                        journal=launcher._silo_journal(checkout,container,'service-port-context.jsonl')
                        token=launcher._PORT_EVIDENCE.set(journal)
                        try:
                            live=launcher._status_source(checkout,launcher._json_command(identity,checkout,native_env,'container',container,'status'),container)
                            declared=launcher._compose_loopback_port_bindings(checkout,live)
                            ports.compose_identity(declared.raw,live,owned)
                            self.assertEqual(len(launcher._resolved_service_ports(live,declared)),6)
                            original=launcher._json_command
                            def query(i,r,e,*args,**kw):
                                if 'hosts' in args:return {'routes':[{'declared':domain,'effective':domain} for domain in declared_routes.values()]}
                                return original(i,r,e,*args,**kw)
                            with patch.object(launcher,'_json_command',side_effect=query),patch.object(launcher,'_gateway_json',return_value={'https_addr':'127.0.0.1:44321','private':True,'running':True}):
                                context=launcher.profile_context(identity,checkout,native_env,container)
                            child_env=launcher.profile_environment(context,native_env)
                            self.assertEqual(child_env['SMTP_PORT'],str(context['ports']['smtp']))
                            decoded=subprocess.run(['node','--input-type=module','-e','import {decodeContext} from '+json.dumps((Path(__file__).parent/'context-diagnostic.mjs').as_uri())+'; const value=decodeContext({status:0,stdout:process.env.CONTROL_CONTEXT}); if(Object.keys(value.ports).length!==6) process.exit(1);'],env={**env,'CONTROL_CONTEXT':json.dumps(context)},capture_output=True,timeout=10)
                            self.assertEqual(decoded.returncode,0)
                            # Execute the actual Vite bounded subprocess/decode expressions
                            # against the production CLI, with only route/gateway inputs doubled.
                            cli=root/'cli';cli.mkdir(exist_ok=True)
                            driver=cli/'profile_launcher.py'
                            driver.write_text("import sys,os\nsys.path.insert(0,"+repr(str(Path(__file__).parent))+")\nimport profile_launcher as p\noriginal=p._json_command\ndef query(i,r,e,*args,**kw):\n if 'hosts' in args:\n  if os.environ.get('CALLER_EXPECT_REFUSAL'):raise AssertionError('invalid inventory reached hosts')\n  return {'routes':[{'declared':v,'effective':v} for k,v in e.items() if k.startswith('EFFIGY_PROFILE_') and k.endswith('_DECLARED')]}\n return original(i,r,e,*args,**kw)\np._json_command=query\ndef gateway(*a,**k):\n if os.environ.get('CALLER_EXPECT_REFUSAL'):raise AssertionError('invalid inventory reached gateway')\n return {'https_addr':'127.0.0.1:44321','private':True,'running':True}\np._gateway_json=gateway\ntry:sys.exit(p.main())\nexcept Exception as e:p._cli_failure(e);sys.exit(1)\n")
                            vite=(Path(__file__).parent/'managed-vite-listener.mjs').read_text()
                            start=vite.index('  const contextResult = spawnSync(')
                            stop=vite.index('  const hmrPort',start)
                            expressions=vite[start:stop]
                            node="import {spawnSync} from 'node:child_process'; import {join} from 'node:path'; import {decodeContext} from "+json.dumps((Path(__file__).parent/'context-diagnostic.mjs').as_uri())+"; const adapterDirectory="+json.dumps(str(cli))+"; const repo="+json.dumps(str(checkout))+"; const selected={profile:"+json.dumps('hybrid' if container=='hybrid_services' else 'disposable_test')+"}; try {"+expressions+" if(process.env.CALLER_EXPECT_REFUSAL||Object.keys(context.ports).length!==6) process.exit(2); } catch(error) {if(!process.env.CALLER_EXPECT_REFUSAL||!error.message.includes('inventory'))process.exit(3);}"
                            caller=subprocess.run(['node','--input-type=module','-e',node],env=native_env,capture_output=True,timeout=20)
                            self.assertEqual(caller.returncode,0)
                            # Complete unrelated-target corruption refuses before hosts/gateway publication.
                            bad_env={**native_env,'FAKE_PORT_ROWS':''.join(rows).replace('127.0.0.1:','0.0.0.0:',1)}
                            rejected=subprocess.run(['node','--input-type=module','-e',node],env={**bad_env,'CALLER_EXPECT_REFUSAL':'1'},capture_output=True,timeout=20)
                            self.assertEqual(rejected.returncode,0)
                            with patch.object(launcher,'_gateway_json',side_effect=AssertionError('gateway after invalid inventory')):
                                with self.assertRaises(launcher.ProfileError):launcher.profile_context(identity,checkout,bad_env,container)
                        finally:launcher._PORT_EVIDENCE.reset(token)
