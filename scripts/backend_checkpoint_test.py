"""Real constructor/route transport and separate-process checkpoint guards."""
import copy
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import time
import unittest
from original_container_route_test import RouteControls
from fresh_backend_admission import FreshBackend
from container_identity_observer import Refusal
import backend_checkpoint as checkpoint

class CheckpointControls(RouteControls):
    def ready_checkpoint(self):
        self.start();self.backend.admit_original_route(self.env)
        return self.backend.save_checkpoint('route_bound')

    def test_complete_backend_roundtrip_in_another_process_and_actual_guard(self):
        ref=self.ready_checkpoint()
        code="""import json,sys
from fresh_backend_admission import FreshBackend
b,r=FreshBackend.restore_checkpoint(json.loads(sys.argv[1]),{})
b.guard();b.verify_tools();assert r is None
assert len(b.policies)==1 and b.start_record and b.profile_binding and b.original_route
assert b.original_route['namespace']=='default'
assert b.reader_environment()['LIMA_HOME']!=b.reader_environment()['COLIMA_HOME']
assert b.original_config_digests and b.manifest_identities and b.policy_records
print('restored')
"""
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(Path(__file__).parent))
        result=subprocess.run([sys.executable,'-c',code,json.dumps(ref)],env=env,capture_output=True,timeout=8)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,b'restored\n')
        b,_=FreshBackend.restore_checkpoint(ref,{})
        self.assertEqual(b.original_route,self.backend.original_route)
        self.assertEqual(b.policies,self.backend.policies)
        self.assertEqual(b.original_config_digests,self.backend.original_config_digests)
        self.assertEqual(b.profile_binding,self.backend.profile_binding)
        self.assertEqual(b.prepared,json.loads(json.dumps(self.backend.prepared)))
        self.assertFalse(list(self.root.glob('.observer-cwd-*')))

    def test_source_root_tool_config_schema_epoch_and_content_fail_closed(self):
        ref=self.ready_checkpoint();value=checkpoint.load_record(ref)
        cases=[]
        for field in ('source','root','history','unknown','config'):
            bad=copy.deepcopy(value)
            if field=='source':bad['sources']['backend_checkpoint.py']='0'*64
            if field=='root':bad['state']['root']=str(self.root/'other')
            if field=='history':bad['historical_route_config_known']=False
            if field=='unknown':bad['state']['environment']={'SECRET':'never admitted'}
            if field=='config':bad['state']['profile_binding']['config_sha256']='0'*64
            path=self.root/('bad-'+field+'.json');cases.append(checkpoint.write(path,bad))
        for badref in cases:
            with self.assertRaises((Refusal,FileNotFoundError)):FreshBackend.restore_checkpoint(badref,{})
        target=Path(self.backend.profile_binding['config']);target.write_text('changed')
        with self.assertRaises(Refusal):FreshBackend.restore_checkpoint(ref,{})

    def test_exclusive_publication_capacity_partial_identity_and_pending_effect(self):
        ref=self.ready_checkpoint()
        with self.assertRaises(FileExistsError):checkpoint.write(Path(ref['path']),{})
        with self.assertRaises(Refusal):checkpoint.write(self.root/'large.json',{'data':'x'*checkpoint.CAP})
        with self.assertRaises(Refusal):checkpoint.consume(ref)
        value={'checkouts':['a','b','c'],'api_preparation':{},'auth_patch':{},'cargo_admission':{},'original_host_facts':{},'prospective_services':{},'partial_ledger':{'main_started':True,'main_idempotent':True,'first_unperformed':'policy_readback','dispatch_state':'unknown'},'input_references':[ref],'deadline_at':time.time()+100,'started_at':time.time()-14300}
        with self.assertRaises(Refusal):checkpoint.validate_resume(value)
        p=Path(ref['path']);p.chmod(0o644)
        with self.assertRaises(Refusal):checkpoint.load_record(ref)

    def test_read_only_binding_does_not_repair_permissions_or_mount(self):
        self.start()
        config=self.root/'lima-home/colima-effigy/lima.yaml';config.chmod(0o644)
        with self.assertRaises(Refusal):self.backend._bind_generated_profile(read_only=True)
        self.assertEqual(config.stat().st_mode&0o777,0o644)
        config.chmod(0o600);config.write_text('mounts:\n    - location: /foreign\n      writable: true\n')
        with self.assertRaises(Refusal):self.backend._bind_generated_profile(read_only=True)


    def prospective_fixture(self):
        from original_container_route_test import startup_carrier
        from datetime import datetime,timezone
        root=self.root/'prospective';root.mkdir(mode=0o700);b=FreshBackend(root,{})
        base=b.paths['HOME']/'reference';base.mkdir(mode=0o700)
        members=[]
        for index,name in enumerate(('main','first','second')):
            checkout=base/name;checkout.mkdir(mode=0o700);members.append(checkout)
            (checkout/'effigy.toml').write_text('fixture source config\n');(checkout/'effigy.toml').chmod(0o600)
            subprocess.run(['git','init','-q',str(checkout)],check=True,capture_output=True)
            b.original_scope(checkout,b'fixture','a'*64)
            scope=dict(self.scope,checkout=str(checkout))
            for kind in ('hybrid_services','disposable_test'):
                policy=dict(self.policy,project_name='fixture'+str(index))
                config={'ok':True,'result':{'schema':'effigy.config.v1','selected_path':'containers.'+kind,'selected_value':{'path':'containers.'+kind,'value':policy}}}
                b.original_policy(checkout,kind,json.dumps(config).encode(),json.dumps({'ok':True,'result':scope}).encode())
        tools=[]
        for name,source in (('colima',startup_carrier(root)),('limactl',self.lima.read_text()),('ssh',self.ssh.read_text())):
            p=root/name;p.write_text(source);p.chmod(0o700);tools.append(p)
        b.bind_tools(*tools);model=copy.deepcopy(self.model)
        model['records']={token*64:dict(id=token*64,created=datetime.now(timezone.utc).isoformat(),project='fixture0',checkout=str(members[0]),service=service,oneoff='false',running=True,status='running') for token,service in (('a','api'),('b','portless'))}
        p=root/'transport.json';p.write_text(json.dumps(model));p.chmod(0o600)
        args=b.start_command(b.env);subprocess.run(args,check=True,env=b.env,capture_output=True,timeout=2)
        started=time.time()-60;deadline=started+14400
        product={'runtime_head':'a'*40,'preserved_hold':{'current_fixture':str(root),'exception_type':'UncertainProfileOwnership','stage':'current_browser_context'},'known_source_counterexample':{'new_runtime_policy_readback_dispatched':False,'new_runtime_object_http_dispatched':False},'runtime_outer':{'capture':{'refusal':None,'leader_reaped':True,'stdout':{'eof':True},'stderr':{'eof':True}}}}
        product_ref=checkpoint.write(self.root/'product.json',product)
        batch_ref=checkpoint.write(self.root/'batch.json',{'head':'a'*40,'started_at':started,'deadline_at':deadline})
        auth={'schema':'underlay.metadata-hold-prospective-authorization.v1','run_id':'11111111-2222-4333-8444-555555555555','brief_version':78,'root':str(root),'product':product_ref,'batch':batch_ref,'started_at':started,'deadline_at':deadline}
        path=self.root/'authorization.json';checkpoint.write(path,auth)
        with self.assertRaises(Refusal):FreshBackend.prospective_from_metadata_hold(path,{})
        from unittest.mock import patch
        selected=patch.object(checkpoint,'SELECTED_AUTHORIZATION',(auth['run_id'],auth['root'],product_ref['sha256'],started,deadline))
        selected.start();self.addCleanup(selected.stop)
        return b,path,members,model,auth

    def test_actual_prospective_epoch_nonce_inventory_and_foreign_refusal(self):
        b,path,members,model,auth=self.prospective_fixture()
        restored,_=FreshBackend.prospective_from_metadata_hold(path,{})
        self.assertEqual(restored.checkpoint_epoch,'prospective');self.assertIsNone(restored.original_route)
        restored.admit_original_route(restored.env)
        reader,baseline=checkpoint.prospective_inventory(restored,members[0],started_at=auth['started_at'],captured_at=time.time())
        self.assertEqual(len(baseline['owned']),2);self.assertEqual(baseline['foreign'],{})
        self.assertFalse(list(restored.root.glob('.observer-cwd-*')))
        ref=restored.save_checkpoint('route_bound');value=checkpoint.load_record(ref)
        self.assertFalse(value['historical_route_config_known'])
        row=copy.deepcopy(next(iter(model['records'].values())));row.update(id='f'*64,project='unknown')
        model['records']['f'*64]=row;(restored.root/'transport.json').write_text(json.dumps(model))
        with self.assertRaises(Refusal):checkpoint.prospective_inventory(restored,members[0],started_at=auth['started_at'],captured_at=time.time())
        # No write/start/down action is delegated to the reader.
        calls=json.loads((restored.root/'calls').read_text())
        self.assertTrue(all(c in ('nonce','metadata','--version','--help','--quiet') or (len(c)==64 and all(x in '0123456789abcdef' for x in c)) for c in calls))

    def test_dispatch_pending_or_publication_failure_never_replays(self):
        directory=self.root/'ledger';directory.mkdir(mode=0o700)
        ledger=checkpoint.DispatchLedger(directory)
        ledger.event('storage','main','dispatch',mutating=True)
        with self.assertRaises(Refusal):ledger.event('storage','main','dispatch',mutating=True)
        with self.assertRaises(Refusal):checkpoint.DispatchLedger(directory)
        ledger.event('storage','main','effect_unknown',mutating=True)
        with self.assertRaises(Refusal):ledger.event('auth_media','main','dispatch',mutating=True)
        raw=''.join(p.read_text() for p in directory.iterdir())
        self.assertNotIn('SECRET',raw);self.assertIn('effect_unknown',raw)


    def test_ready_checkpoint_complete_payload_single_consumption_and_false_stage(self):
        from qualification_cleanup_test import World
        b,path,members,model,auth=self.prospective_fixture()
        b,_=FreshBackend.prospective_from_metadata_hold(path,{})
        b.admit_original_route(b.env)
        _,baseline=checkpoint.prospective_inventory(b,members[0],started_at=auth['started_at'],captured_at=time.time())
        inputs=dict(schema='underlay.reference.api-inputs.v1',checkout=str(members[0]),target=str(b.paths['HOME']/'.cargo-target'),package='acme-api',features='default',profile='debug',locked=True,offline=True,jobs=2,cargo_home=str(b.paths['HOME']/'.cargo'),rustup_home=str(self.root/'rustup'),source='a'*40,patch_sha256='b'*64,lock_sha256='c'*64,instrumented_files={},manifest_sha256='d'*64,cargo_manifest_sha256='e'*64,toolchain_sha256='f'*64)
        api=dict(inputs=inputs,artifact=dict(sha256='a'*64,device=1,inode=2,bytes=32,path=inputs['target']+'/debug/acme-api',platform='darwin-arm64',package='acme-api',profile='debug'),capture=dict(exit=0,refusal=None,identity_admitted=True,leader_reaped=True,stdout={'eof':True},stderr={'eof':True}))
        resume=dict(checkouts=list(map(str,members)),api_preparation=api,auth_patch=dict(files=[],patch_sha256='b'*64,cargo_lock_sha256='c'*64,reference_source_commit='a'*40,patch_bytes=1),cargo_admission=checkpoint.reference(path),original_host_facts=World().capture(),prospective_services=baseline,partial_ledger=dict(main_started=True,main_idempotent=True,first_unperformed='policy_readback',dispatch_state='not_dispatched'),input_references=[checkpoint.reference(path)],deadline_at=auth['deadline_at'],started_at=auth['started_at'])
        for field,value in (('first_unperformed','storage'),('dispatch_state','effect_unknown'),('main_started',False)):
            bad=copy.deepcopy(resume);bad['partial_ledger'][field]=value
            with self.assertRaises(Refusal):b.save_checkpoint('continuation_ready',resume=bad)
        ref=b.save_checkpoint('continuation_ready',resume=resume)
        restored,actual=FreshBackend.restore_checkpoint(ref,{})
        self.assertEqual(actual,json.loads(json.dumps(resume)));self.assertEqual(actual['partial_ledger']['first_unperformed'],'policy_readback')
        self.assertFalse(checkpoint.load_record(ref)['historical_route_config_known'])
        checkpoint.consume(ref)
        with self.assertRaises(FileExistsError):checkpoint.consume(ref)
        self.assertNotIn('DO_NOT_PERSIST',Path(ref['path']).read_text())


    def test_actual_host_gate_rejects_original_generation_and_kernel_start_changes(self):
        from types import SimpleNamespace
        from qualification_cleanup_test import World
        from qualification_cleanup import CleanupUnknown
        from profile_resume import current_hosts
        import hashlib
        world=World();old={};files={}
        for role,state in world.states.items():
            state['public_url']='https://'+state['route_domain']
            path=self.root/(role+'.json');path.write_text(json.dumps(state));path.chmod(0o600);files[role]=path
            snap=dict(state)
            for owner in ('supervisor','child','listener'):snap[owner+'_start']=state[owner+'_start_identity']
            old[role]=dict(state=snap,provenance=dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),device=path.stat().st_dev,inode=path.stat().st_ino))
        q=SimpleNamespace(listener_state=lambda c,r,e:(files[r],world.states[r]),pending_start_identity=world)
        for field,value in (('generation','f'*32),('child_pid',999),('listener_start',{'start_seconds':2,'start_microseconds':0})):
            bad=copy.deepcopy(old);bad['api']['state'][field]=value
            with self.assertRaises(Refusal):current_hosts(q,self.root,{},bad)
        world.processes[101]['start_identity']=dict(platform='macos',start_seconds=999,start_microseconds=0)
        with self.assertRaises(CleanupUnknown):current_hosts(q,self.root,{},old)

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *unused:os._exit(124));signal.alarm(60)
    unittest.main()
