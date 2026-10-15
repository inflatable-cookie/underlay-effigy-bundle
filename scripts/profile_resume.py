"""Exact metadata-hold prospective admission and one-use operation continuation."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import backend_checkpoint as cp
from container_identity_observer import Refusal, identity, file_sha
from original_container_route import read_small
from fresh_backend_admission import FreshBackend
from reference_storage_probe import StorageDiagnosticJournal,decode_journal_rows
from private_caller_environment import construct
import qualification_batch


def qualifier():
    path=Path(__file__).with_name('qualify-reference-optin.py')
    spec=importlib.util.spec_from_file_location('resume_qualifier',path);q=importlib.util.module_from_spec(spec);sys.modules[spec.name]=q;spec.loader.exec_module(q)
    return q


def original_inputs(auth,backend):
    product=cp.private_read(cp.verify_reference(auth['product']))
    packet=Path(auth['product']['path']).parent
    raw=read_small(packet/'runtime-diagnostics/storage-diagnostics.jsonl',131072)
    if hashlib.sha256(raw).hexdigest()!=product['main_journal']['sha256']:raise Refusal('resume_original_journal_changed')
    rows=decode_journal_rows(raw.decode());events={}
    for row in rows:events[row['event']]=row
    patch_fields={'reference_source_commit','patch_sha256','patch_bytes','cargo_lock_sha256','files','patch_artifact'}
    patch={k:v for k,v in events['reference_auth_fixture_patched'].items() if k in patch_fields}
    linked=events['reference_api_linked'];capture=events['reference_api_link_capture']['capture']
    artifact=events.get('reference_api_launch_artifact',{}).get('artifact',linked['artifact'])
    prepared={'inputs':linked['inputs'],'artifact':artifact,'capture':capture}
    if capture['exit']!=0 or capture['refusal'] is not None or not capture['leader_reaped'] or not all(capture[k]['eof'] for k in ('stdout','stderr')):raise Refusal('resume_build_unqualified')
    check=events['reference_auth_fixture_compile']['capture']
    if check['exit']!=0 or check['refusal'] is not None or not check['leader_reaped'] or not all(check[k]['eof'] for k in ('stdout','stderr')):raise Refusal('resume_check_unqualified')
    current={}
    for row in rows:
        if row['event']=='listener_probe_snapshot':
            snap=row['snapshot']
            if snap['document']=='state' and snap.get('state',{}).get('status')=='ready':current[snap['role']]=snap
    if set(current)!={'api','front','admin'}:raise Refusal('resume_original_host_missing')
    checkouts=sorted({k[0] for k in backend.policies})
    main=[p for p in checkouts if Path(p).name=='main']
    if len(main)!=1:raise Refusal('resume_primary_checkout')
    checkouts=main+[p for p in checkouts if p not in main]
    return checkouts,prepared,patch,current,events


def bind(q,backend,prepared,auth,packet):
    env=backend.env.copy();inputs=prepared['inputs']
    env.update(CARGO_HOME=inputs['cargo_home'],CARGO_TARGET_DIR=inputs['target'],RUSTUP_HOME=inputs['rustup_home'],CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='2',UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT=str(backend.root))
    env.update(UNDERLAY_PROFILE_BATCH_INTENT=os.environ['UNDERLAY_PROFILE_BATCH_INTENT'],UNDERLAY_PROFILE_BATCH_INTENT_SHA256=os.environ['UNDERLAY_PROFILE_BATCH_INTENT_SHA256'])
    current_batch=cp.private_read(Path(env['UNDERLAY_PROFILE_BATCH_INTENT']))
    if current_batch['started_at']!=auth['started_at'] or current_batch['deadline_at']!=auth['deadline_at']:raise Refusal('resume_clock_changed')
    qualification_batch.INTENT=current_batch;qualification_batch.ROOT=Path(env['UNDERLAY_PROFILE_BATCH_INTENT']).parent
    q.EFFIGY=q.require_effigy_binary(env=env);q.REFERENCE.EFFIGY=q.RUNTIME.EFFIGY=q.RUNTIME.REFERENCE.EFFIGY=q.EFFIGY
    q.REFERENCE.PRIVATE_CHILD_ENV=q.RUNTIME.REFERENCE.PRIVATE_CHILD_ENV=env
    journal=StorageDiagnosticJournal(packet/'storage-diagnostics.jsonl',backend.root)
    q.ACTIVE_DIAGNOSTICS=q.RUNTIME.COMMAND_DIAGNOSTICS=journal
    import route_observation,storage_observation
    route_observation.configure(journal.append);storage_observation.configure(journal.append)
    q.listener_snapshot.configure(journal.append);q.transition_snapshot.configure(journal.append,backend.root)
    return env,journal


def current_hosts(q,checkout,env,old):
    """The original file digest binds full state, including kernel boot/start data."""
    states={}
    for role in ('api','front','admin'):
        path,state=q.listener_state(checkout,role,env)
        before=old[role]['provenance']
        if file_sha(path,1048576)!=before['sha256'] or identity(path)[:2]!=(before['device'],before['inode']):raise Refusal('resume_original_host_state_changed')
        prior=old[role]['state']
        for key in ('generation','runtime_generation','address','route_domain'):
            if state.get(key)!=prior.get(key):raise Refusal('resume_host_generation_changed')
        for owner in ('supervisor','child','listener'):
            if state.get(owner+'_pid')!=prior.get(owner+'_pid'):raise Refusal('resume_host_pid_changed')
            start=state.get(owner+'_start_identity') or {};prior_start=prior.get(owner+'_start') or {}
            if any(start.get(k)!=prior_start.get(k) for k in ('start_seconds','start_microseconds')):raise Refusal('resume_host_start_changed')
        states[role]=state
    import qualification_cleanup
    from qualification_cleanup_action import ListenerObserver
    qualified=qualification_cleanup.capture(states,ListenerObserver(q,checkout,env,container='hybrid_services',profile='hybrid'))
    root,port,gateway=q.gateway_context(checkout,env)
    q.RUNTIME.observe_routes(checkout,root,env,states,port)
    import route_observation as routes
    routes.context_gate(gateway,root,port,states,states)
    for role in ('front','admin'):
        parsed=q.urlsplit(states[role]['public_url'])
        if parsed.scheme!='https' or parsed.hostname!=states[role]['route_domain'] or parsed.port is not None:raise Refusal('resume_browser_metadata')
    return qualified


def admission(authorization):
    backend,auth=FreshBackend.prospective_from_metadata_hold(authorization,os.environ)
    packet=Path(authorization).parent
    checkouts,prepared,patch,hosts,events=original_inputs(auth,backend)
    q=qualifier();env,journal=bind(q,backend,prepared,auth,packet)
    try:
        # Required immutable production assets remain byte-identical to the original run.
        original=events['attempt_started']['cleanup_sources']
        for name in ('dev/profile_launcher.py','dev/startup_evidence.py','dev/owned_capture.py','dev/host_identity.py','dev/silo_client.py','dev/storage_launcher.py','generated_profile.py'):
            if hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()!=original[name]:raise Refusal('resume_production_source_changed')
        from private_cargo_cache import verify_environment,summary
        cargo=verify_environment(env)
        if summary(cargo)!=events['private_cargo_inputs']['receipt']:raise Refusal('resume_cargo_admission_changed')
        for checkout in checkouts:q.reference_api_preparation.admit_launch(prepared,Path(checkout),env,patch,lambda event,**fields:journal.append(event,**fields))
        backend.admit_original_route(env)
        _,services=cp.prospective_inventory(backend,checkouts[0],started_at=auth['started_at'],captured_at=time.time())
        qualified=current_hosts(q,Path(checkouts[0]),env,hosts)
        refs=[cp.reference(Path(prepared['inputs']['cargo_home'])/'admission.json'),auth['product'],auth['batch']]
        for checkout in checkouts:
            refs.extend(cp.reference(Path(checkout)/name) for name in ('effigy.toml','apps/acme-api/Cargo.lock','apps/acme-api/effigy.toml'))
        resume={'checkouts':checkouts,'api_preparation':prepared,'auth_patch':patch,'cargo_admission':refs[0],
            'original_host_facts':qualified,'prospective_services':services,
            'partial_ledger':{'main_started':True,'main_idempotent':True,'first_unperformed':'policy_readback','dispatch_state':'not_dispatched'},
            'input_references':refs,'deadline_at':auth['deadline_at'],'started_at':auth['started_at']}
        ref=backend.save_checkpoint('continuation_ready',resume=resume,directory=packet)
        # Restore the actual whole state and guards before allowing the hold disposition.
        restored,roundtrip=FreshBackend.restore_checkpoint(ref,os.environ)
        if roundtrip!=json.loads(json.dumps(resume)):raise Refusal('resume_roundtrip_changed')
        restored.guard();cp.write(packet/'admission-passed.json',{'schema':'underlay.metadata-hold-read-admission.v1','captured_at':time.time(),'historical_route_config_container_ids':'unknown','hold_retired_for_future_only':True,'checkpoint':ref})
        print(json.dumps({'stage':'prospective_admission','passed':True,'historical_identity_known':False}),flush=True)
    finally:journal.close()


def continuation(reference_path):
    ref=cp.private_read(reference_path);backend,resume=FreshBackend.restore_checkpoint(ref,os.environ)
    packet=Path(reference_path).parent;admitted=cp.private_read(packet/'admission-passed.json')
    if admitted['checkpoint']!=ref or admitted.get('hold_retired_for_future_only') is not True:raise Refusal('resume_admission_missing')
    auth={'deadline_at':resume['deadline_at'],'started_at':resume['started_at']}
    q=qualifier();diagnostics=packet/'continuation';diagnostics.mkdir(mode=0o700)
    env,journal=bind(q,backend,resume['api_preparation'],auth,diagnostics)
    try:
        cp.consume(ref)
        q.API_PREPARATION=resume['api_preparation'];q.CHECKPOINT_LEDGER=cp.DispatchLedger(packet)
        # Main start/idempotency/bootstrap/check/build are retained, never dispatched here.
        receipts=q.verify_profile_runtime([Path(p) for p in resume['checkouts']],env,backend_admission=backend,storage_only=False,diagnostics=journal,auth_patch_receipt=resume['auth_patch'],resume_main=True)
        q.qualification_cleanup.require_product_cleanup(receipts.get('dev_test_cleanup'))
        path=packet/'runtime-completed.json';cp.write(path,receipts)
        qualification_batch.passed('runtime',path)
        print(json.dumps({'stage':'runtime_continuation','passed':True}),flush=True)
    finally:journal.close()


def main():
    if os.environ.get('UNDERLAY_PROFILE_RESUME_CHECKPOINT'):
        return continuation(Path(os.environ['UNDERLAY_PROFILE_RESUME_CHECKPOINT']))
    path=os.environ.get('UNDERLAY_PROFILE_RESUME_AUTHORIZATION')
    if not path:raise Refusal('resume_authorization_missing')
    return admission(Path(path))

if __name__=='__main__':
    try:main()
    except BaseException as error:
        from qualification_refusal import project
        print(json.dumps(project(error,'runtime_profile')),file=sys.stderr);sys.exit(1)
