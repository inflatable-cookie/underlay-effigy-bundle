"""Private typed backend associations and one-use continuation checkpoints.

State audit: roots/intents/tools/policy/manifests are retained creation inputs;
profile/config/route can be a separately authorized prospective epoch. API build,
Cargo, patch, checkout and listener receipts remain explicit input references.
Environment and credentials are reconstructed by their private factories, never
serialized. A pending mutating dispatch is not a resumable completed stage.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import time
from container_identity_observer import Refusal, Observer, identity, file_sha, strict_json
from original_container_route import read_small

CAP=65536
SCHEMA='underlay.backend-checkpoint.v1'
SELECTED_AUTHORIZATION=('c9a21399-ca9b-4d76-99dc-851ec18a8226','/Users/tom/ur.IOTh8d',
 '636b2ca3116363293e560491d6105070aebad588d9f9294e7d940430d3dda117',1792039072.979,1792053472.979)
SOURCES=('profile_resume.py','backend_checkpoint.py','fresh_backend_admission.py','original_container_route.py',
         'container_identity_observer.py','generated_profile.py','qualify-reference-optin.py','qualify-reference-runtime.py','qualify-reference-profiles.py','private_caller_environment.py','reference_api_preparation.py','private_cargo_cache.py','qualification_cleanup.py','qualification_cleanup_action.py','service_baseline_handoff.py','route_observation.py','storage_observation.py','reference_storage_probe.py','qualification_batch.py')
STATE_KEYS={'root','root_identity','paths','identities','intent_sha256','prepared_sha256',
 'manifest_identities','original_config_digests','policies','policy_records','profile_binding',
 'profile_binding_sha256','start_record','original_route','route_source'}
RESUME_KEYS={'checkouts','api_preparation','auth_patch','cargo_admission','original_host_facts',
 'prospective_services','partial_ledger','input_references','deadline_at','started_at'}
STAGES=('policy_readback','storage','auth_media','remaining_profiles','lifecycle','dev_test','runtime_cleanup','container')


def sources():
    return {name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest() for name in SOURCES}


def private_read(path):
    stamp=identity(path)
    if stamp[2]&0o777!=0o600:raise Refusal('checkpoint_permissions')
    raw=read_small(path,CAP)
    if not raw or len(raw)>CAP:raise Refusal('checkpoint_bound')
    return strict_json(raw)


def write(path,value):
    path=Path(path);identity(path.parent,True)
    raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    if len(raw)>CAP:raise Refusal('checkpoint_capacity')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        view=memoryview(raw)
        while view:
            count=os.write(fd,view)
            if count<=0:raise Refusal('checkpoint_short_write')
            view=view[count:]
        os.fsync(fd)
    finally:os.close(fd)
    return reference(path)


def reference(path,limit=1048576):
    return {'path':str(path),'identity':identity(path,executable=limit>1048576),
            'sha256':file_sha(path,limit),'limit':limit}


def verify_reference(value):
    if type(value) is not dict or set(value)!={'path','identity','sha256','limit'}:raise Refusal('checkpoint_reference_schema')
    if value['limit'] not in (1048576,268435456):raise Refusal('checkpoint_reference_bound')
    p=Path(value['path'])
    if identity(p,executable=value['limit']>1048576)!=tuple(value['identity']) or file_sha(p,value['limit'])!=value['sha256']:raise Refusal('checkpoint_input_changed')
    return p


def snapshot(backend):
    backend.guard();backend.verify_tools()
    state={k:copy.deepcopy(getattr(backend,k,None)) for k in STATE_KEYS}
    state['root']=str(backend.root);state['paths']={k:str(p) for k,p in backend.paths.items()}
    state['policies']=[{'key':list(k),'value':v} for k,v in backend.policies.items()]
    state['policy_records']=[{'key':list(k),'path':str(v[0]),'sha256':v[1],'policy':v[2],'manifest_sha256':v[3]} for k,v in getattr(backend,'policy_records',{}).items()]
    state['start_record']=[str(backend.start_record[0]),backend.start_record[1]] if backend.start_record else None
    refs=[reference(backend.path),reference(backend.prepared_path)]
    if backend.start_record:refs.append(reference(backend.start_record[0]))
    for value in getattr(backend,'policy_records',{}).values():refs.append(reference(value[0]))
    for path in backend.manifest_identities:refs.append(reference(path))
    if backend.profile_binding:
        for k in ('config','colima_config'):refs.append(reference(backend.profile_binding[k]))
    for tool in backend.prepared['tool_provenance'].values():refs.append(reference(tool['path'],268435456))
    return state,refs


def validate_resume(value):
    if type(value) is not dict or set(value)!=RESUME_KEYS:raise Refusal('checkpoint_resume_schema')
    if type(value['checkouts']) is not list or len(value['checkouts'])!=3 or len(set(value['checkouts']))!=3:raise Refusal('checkpoint_checkouts')
    if value['deadline_at']-value['started_at']!=14400 or not value['started_at']<=time.time()<value['deadline_at']:raise Refusal('checkpoint_deadline')
    ledger=value['partial_ledger']
    if type(ledger) is not dict or set(ledger)!={'main_started','main_idempotent','first_unperformed','dispatch_state'}:raise Refusal('checkpoint_ledger_schema')
    if ledger!={'main_started':True,'main_idempotent':True,'first_unperformed':'policy_readback','dispatch_state':'not_dispatched'}:raise Refusal('checkpoint_unresumable_effect')
    if type(value['input_references']) is not list or not value['input_references']:raise Refusal('checkpoint_inputs_missing')
    for ref in value['input_references']:verify_reference(ref)
    # These are source-owned public build/identity structures, not ambient data.
    if type(value['api_preparation']) is not dict or set(value['api_preparation'])!={'inputs','artifact','capture'}:raise Refusal('checkpoint_api_schema')
    capture=value['api_preparation']['capture']
    if type(capture) is not dict or set(capture)-{'schema','exit','refusal','identity_admitted','original_child_identity','leader_reaped','group_absence','remote_cancellation','elapsed_ms','stdout','stderr','diagnostics'} or capture.get('exit')!=0 or capture.get('refusal') is not None or capture.get('identity_admitted') is not True or capture.get('leader_reaped') is not True or not all(capture.get(k,{}).get('eof') is True for k in ('stdout','stderr')):raise Refusal('checkpoint_build_capture')
    inputs=value['api_preparation']['inputs'];artifact=value['api_preparation']['artifact']
    if set(inputs)!={'schema','checkout','target','package','features','profile','locked','offline','jobs','cargo_home','rustup_home','source','patch_sha256','lock_sha256','instrumented_files','manifest_sha256','cargo_manifest_sha256','toolchain_sha256'}:raise Refusal('checkpoint_api_input_schema')
    if set(artifact)!={'sha256','device','inode','bytes','path','platform','package','profile'}:raise Refusal('checkpoint_artifact_schema')
    if inputs['package']!='acme-api' or inputs['features']!='default' or inputs['profile']!='debug' or inputs['locked'] is not True or inputs['offline'] is not True or inputs['jobs']!=2:raise Refusal('checkpoint_api_input_policy')
    if type(value['auth_patch']) is not dict or not {'files','patch_sha256','cargo_lock_sha256','reference_source_commit','patch_bytes'}<=set(value['auth_patch']) or set(value['auth_patch'])-{'files','patch_sha256','cargo_lock_sha256','reference_source_commit','patch_bytes','patch_artifact'}:raise Refusal('checkpoint_patch_schema')
    if type(value['original_host_facts']) is not dict or set(value['original_host_facts'])!={'api','front','admin'}:raise Refusal('checkpoint_host_baseline')
    if type(value['prospective_services']) is not dict or not value['prospective_services'].get('owned'):raise Refusal('checkpoint_service_baseline')
    services=value['prospective_services']
    if set(services)!={'binding','owned','foreign'}:raise Refusal('checkpoint_services_schema')
    for identifier,row in {**services['owned'],**services['foreign']}.items():
        from container_identity_observer import projection
        if projection((json.dumps(row)+'\n').encode(),identifier)!=row:raise Refusal('checkpoint_service_projection')
    for role,state in value['original_host_facts'].items():
        if not all(state.get(k) is not None for k in ('generation','runtime_generation','supervisor_pid','child_pid','listener_pid')):raise Refusal('checkpoint_host_baseline')


def save(backend,phase,*,epoch='creation',resume=None,directory=None):
    if phase not in ('profile_bound','route_bound','continuation_ready'):raise Refusal('checkpoint_phase')
    if epoch not in ('creation','prospective'):raise Refusal('checkpoint_epoch')
    if phase=='continuation_ready':validate_resume(resume)
    elif resume is not None:raise Refusal('checkpoint_premature_resume')
    state,refs=snapshot(backend)
    directory=Path(directory) if directory else backend.root/'backend-checkpoints'
    if not directory.exists():directory.mkdir(mode=0o700)
    identity(directory,True)
    value={'schema':SCHEMA,'phase':phase,'epoch':epoch,'observed_at':time.time(),
           'historical_route_config_known':epoch=='creation','sources':sources(),
           'state':state,'references':refs,'resume':resume}
    import secrets
    return write(directory/('checkpoint-'+secrets.token_hex(16)+'.json'),value)


def load_record(ref):
    path=verify_reference(ref);v=private_read(path)
    if type(v) is not dict or set(v)!={'schema','phase','epoch','observed_at','historical_route_config_known','sources','state','references','resume'} or v['schema']!=SCHEMA:raise Refusal('checkpoint_schema')
    if v['sources']!=sources() or set(v['state'])!=STATE_KEYS:raise Refusal('checkpoint_source_or_state')
    validate_state(v['state'])
    if v['epoch'] not in ('creation','prospective') or v['historical_route_config_known']!=(v['epoch']=='creation'):raise Refusal('checkpoint_history')
    if v['phase'] not in ('profile_bound','route_bound','continuation_ready'):raise Refusal('checkpoint_phase')
    for item in v['references']:verify_reference(item)
    if v['phase']=='continuation_ready':
        validate_resume(v['resume'])
        root=Path(v['state']['root']);inputs=v['resume']['api_preparation']['inputs']
        if inputs['cargo_home']!=str(root/'home/.cargo') or inputs['target']!=str(root/'home/.cargo-target'):raise Refusal('checkpoint_private_build_inputs')
        for checkout in v['resume']['checkouts']:Path(checkout).relative_to(root/'home/reference')
    elif v['resume'] is not None:raise Refusal('checkpoint_premature_resume')
    return v


def restore(cls,ref,inherited):
    from private_caller_environment import construct
    value=load_record(ref);s=value['state'];backend=object.__new__(cls)
    backend.root=Path(s['root']);backend.root_identity=tuple(s['root_identity'])
    backend.paths={k:Path(p) for k,p in s['paths'].items()};backend.identities={k:tuple(v) for k,v in s['identities'].items()}
    backend.env=construct(inherited)[0];backend.env.update({k:str(p) for k,p in backend.paths.items()})
    backend.path=backend.root/'backend-intent.json';backend.intent=private_read(backend.path);backend.intent_sha256=s['intent_sha256']
    backend.prepared_path=backend.root/'backend-prepared.json';backend.prepared=private_read(backend.prepared_path);backend.prepared_sha256=s['prepared_sha256']
    for key in ('original_config_digests','manifest_identities','profile_binding','profile_binding_sha256','original_route','route_source'):setattr(backend,key,s[key])
    backend.manifest_identities={p:tuple(stamp) for p,stamp in backend.manifest_identities.items()}
    if backend.profile_binding:
        backend.profile_binding['identities']={k:tuple(v) for k,v in backend.profile_binding['identities'].items()}
    backend.policies={tuple(r['key']):r['value'] for r in s['policies']}
    backend.policy_records={tuple(r['key']):(Path(r['path']),r['sha256'],r['policy'],r['manifest_sha256']) for r in s['policy_records']}
    backend.start_record=(Path(s['start_record'][0]),s['start_record'][1]) if s['start_record'] else None
    backend.guard();backend.verify_tools();backend.verify_environment(backend.env)
    backend.require_read_contract()
    if backend.route_source!=s['route_source']:raise Refusal('checkpoint_route_source_changed')
    backend.checkpoint_epoch=value['epoch']
    return backend,value['resume']


def consume(ref):
    value=load_record(ref)
    if value['phase']!='continuation_ready':raise Refusal('checkpoint_not_ready')
    return write(Path(ref['path']+'.consumed'),{'schema':'underlay.checkpoint-consumption.v1',
        'checkpoint_sha256':ref['sha256'],'at':time.time(),'first_unperformed':'policy_readback'})


def prospective(cls,authorization,inherited):
    """Exact retained failed-metadata operation only; no general adoption API.

    Original root/tool/start/policy links are required. Unrecorded configuration
    and route are explicitly new observations. This performs no guest request.
    """
    from private_caller_environment import construct
    from fresh_backend_admission import PROFILE,INSTANCE
    auth=private_read(authorization)
    required={'schema','run_id','brief_version','root','product','batch','deadline_at','started_at'}
    if set(auth)!=required or auth['schema']!='underlay.metadata-hold-prospective-authorization.v1' or auth['brief_version']!=78:raise Refusal('prospective_authorization')
    if not re.fullmatch('[0-9a-f-]{36}',auth['run_id']):raise Refusal('prospective_run_binding')
    if (auth['run_id'],auth['root'],auth['product'].get('sha256'),auth['started_at'],auth['deadline_at'])!=SELECTED_AUTHORIZATION:raise Refusal('prospective_selected_operation')
    product=private_read(verify_reference(auth['product']));batch=private_read(verify_reference(auth['batch']))
    if auth['deadline_at']!=batch['deadline_at'] or auth['started_at']!=batch['started_at'] or auth['deadline_at']-auth['started_at']!=14400 or not auth['started_at']<=time.time()<auth['deadline_at']:raise Refusal('prospective_deadline')
    if product['runtime_head']!=batch['head'] or product['preserved_hold']['current_fixture']!=auth['root'] or product['preserved_hold']['exception_type']!='UncertainProfileOwnership' or product['preserved_hold']['stage']!='current_browser_context':raise Refusal('prospective_original_operation')
    known=product['known_source_counterexample']
    if known.get('new_runtime_policy_readback_dispatched') is not False or known.get('new_runtime_object_http_dispatched') is not False:raise Refusal('prospective_prior_effect_unknown')
    capture=product['runtime_outer']['capture']
    if capture['refusal'] is not None or not capture['leader_reaped'] or not all(capture[k]['eof'] for k in ('stdout','stderr')):raise Refusal('prospective_capture_unknown')
    root=Path(auth['root']);identity(root,True)
    backend=object.__new__(cls);backend.root=root;backend.root_identity=identity(root,True)
    backend.path=root/'backend-intent.json';backend.intent=private_read(backend.path);backend.intent_sha256=file_sha(backend.path,1048576)
    backend.prepared_path=root/'backend-prepared.json';backend.prepared=private_read(backend.prepared_path);backend.prepared_sha256=file_sha(backend.prepared_path,1048576)
    start=root/'backend-start-intent.json';start_value=private_read(start)
    if backend.intent['root']!=str(root) or backend.intent['profile']!=PROFILE or backend.intent['instance']!=INSTANCE or backend.intent['runtime']!='containerd' or backend.prepared['original_intent_sha256']!=backend.intent_sha256 or start_value['intent_sha256']!=backend.intent_sha256:raise Refusal('prospective_original_intent')
    backend.paths={k:Path(v) for k,v in backend.intent['roots'].items()};backend.identities={k:tuple(v) for k,v in backend.intent['root_identities'].items()}
    if set(backend.paths)!={'HOME','COLIMA_HOME','LIMA_HOME'} or set(backend.identities)!=set(backend.paths):raise Refusal('prospective_roots')
    expected={'HOME':root/'home','COLIMA_HOME':root/'colima-home','LIMA_HOME':root/'lima-home'}
    if backend.paths!=expected:raise Refusal('prospective_root_layout')
    for key,path in backend.paths.items():
        if identity(path,True)[:4]!=backend.identities[key][:4]:raise Refusal('prospective_original_root_changed')
    backend.env=construct(inherited)[0];backend.env.update({k:str(p) for k,p in backend.paths.items()})
    backend.start_record=(start,file_sha(start,1048576));backend.manifest_identities={};backend.original_config_digests=[];backend.policies={};backend.policy_records={};backend.profile_binding=None;backend.original_route=None;backend.checkpoint_epoch='prospective'
    backend.verify_tools()
    args=[backend.prepared['tool_provenance']['colima']['path'],'start','--profile',PROFILE,'--runtime','containerd','--activate=false','--ssh-config=false','--ssh-agent=false','--template=false','--mount',str(root)+':w','--cpu','6','--memory','8','--disk','64']
    if start_value['startup_recipe_sha256']!=hashlib.sha256(json.dumps(args).encode()).hexdigest():raise Refusal('prospective_start_recipe')
    records=list(root.glob('policy-*.json'))
    if len(records)!=6:raise Refusal('prospective_policy_set')
    checkouts=set()
    for path in records:
        record=private_read(path)
        if set(record)!={'intent_sha256','config_sha256','scope_sha256','manifest_sha256','policy'} or record['intent_sha256']!=backend.intent_sha256:raise Refusal('prospective_policy_binding')
        policy=record['policy'];checkout=Path(policy['checkout']);checkout.relative_to(root/'home/reference')
        if checkout.resolve(strict=True)!=checkout or set(policy)!={'project','checkout','services','primary','oneoffs'}:raise Refusal('prospective_policy_schema')
        # Filename is the original closed key hash, not a late selected scope.
        kinds=[kind for kind in ('hybrid_services','disposable_test') if path.name=='policy-'+hashlib.sha256(repr((str(checkout),kind)).encode()).hexdigest()+'.json']
        if len(kinds)!=1:raise Refusal('prospective_policy_name')
        key=(str(checkout),kinds[0]);manifest=checkout/'effigy.toml'
        if file_sha(manifest,1048576)!=record['manifest_sha256']:raise Refusal('prospective_manifest_changed')
        backend.manifest_identities[str(manifest)]=identity(manifest)[:4]
        backend.policies[key]=policy;backend.policy_records[key]=(path,file_sha(path,1048576),copy.deepcopy(policy),record['manifest_sha256']);checkouts.add(str(checkout))
    if len(checkouts)!=3:raise Refusal('prospective_checkout_set')
    for path in root.glob('scope-source-*.json'):
        record=private_read(path)
        if record['original_intent_sha256']!=backend.intent_sha256 or record['checkout'] not in checkouts:raise Refusal('prospective_scope_source')
        backend.original_config_digests.append(record)
    if len(backend.original_config_digests)!=3:raise Refusal('prospective_scope_inputs')
    backend.require_read_contract();backend.guard();backend.verify_environment(backend.env)
    backend._bind_generated_profile(read_only=True)
    return backend,auth


def prospective_inventory(backend,checkout,*,started_at,captured_at):
    """A current before-operation baseline; never evidence of startup IDs."""
    from datetime import datetime
    from fresh_backend_admission import INSTANCE
    backend.guard();backend.verify_tools()
    key=(str(Path(checkout).resolve(strict=True)),'hybrid_services')
    if backend.checkpoint_epoch!='prospective' or key not in backend.policies or not backend.original_route:raise Refusal('prospective_route_not_admitted')
    route=backend.original_route;tools=backend.prepared['tool_provenance']
    context={**backend.route_context(),'schema':'underlay.container-observer-context.v2',
        'private_home':str(backend.paths['HOME']),'startup_intent_sha256':backend.intent_sha256,
        'limactl_sha256':tools['limactl']['sha256'],'ssh_sha256':tools['ssh']['sha256'],
        'namespace':route['namespace'],'address':route['address'],'boot':None,
        'scopes':[copy.deepcopy(backend.policies[key])],'foreign':{}}
    reader=Observer(context,backend.env,backend.root,{k:copy.deepcopy(v) for k,v in context.items() if k!='schema'})
    reader.original_admission=backend
    baseline=reader.baseline()
    for value in baseline['owned'].values():
        try:created=datetime.fromisoformat(value['created'].replace('Z','+00:00')).timestamp()
        except (ValueError,TypeError):raise Refusal('prospective_creation_unknown') from None
        if not started_at<=created<=captured_at:raise Refusal('prospective_creation_chronology')
    return reader,baseline


class DispatchLedger:
    """Lossless, exclusive stage events; failed publication is sticky."""
    def __init__(self,directory):
        self.directory=Path(directory);identity(self.directory,True);self.sequence=0;self.pending=None;self.sticky=False
        if list(self.directory.glob('dispatch-*.json')):raise Refusal('checkpoint_dispatch_already_started')
    def event(self,stage,member,state,*,mutating):
        if self.sticky:raise Refusal('checkpoint_publication_sticky')
        if stage not in STAGES+('profile_start',) or member not in ('main','first','second','all') or state not in ('dispatch','completed','effect_unknown') or type(mutating) is not bool:raise Refusal('checkpoint_dispatch_schema')
        tag=(stage,member,mutating)
        if state=='dispatch':
            if self.pending is not None:raise Refusal('checkpoint_unsettled_dispatch')
            self.pending=tag
        elif self.pending!=tag:raise Refusal('checkpoint_dispatch_binding')
        self.sequence+=1
        try:
            write(self.directory/('dispatch-%04d.json'%self.sequence),{'schema':'underlay.checkpoint-dispatch.v1','stage':stage,'member':member,'state':state,'mutating':mutating,'sequence':self.sequence,'at':time.time()})
        except BaseException:
            self.sticky=True
            raise
        if state=='completed':self.pending=None
        elif state=='effect_unknown':self.sticky=True


def validate_state(s):
    from original_container_route import admit_sources,CONFIG_PATH
    root=Path(s['root']);identity(root,True)
    expected={'HOME':str(root/'home'),'COLIMA_HOME':str(root/'colima-home'),'LIMA_HOME':str(root/'lima-home')}
    if s['paths']!=expected or set(s['identities'])!=set(expected):raise Refusal('checkpoint_root_layout')
    binding=s['profile_binding']
    if binding is not None:
        if set(binding)!={'config_dir','colima_dir','config','colima_config','identities','config_sha256','colima_config_sha256'}:raise Refusal('checkpoint_config_schema')
        for key in ('config','colima_config','config_dir','colima_dir'):Path(binding[key]).relative_to(root)
    route=s['original_route']
    if route is not None:
        keys={'namespace','address','help_sha256','binary_sha256','config_selection','config_state','config_sha256','rootful','source','reported_version','captures','cwd_correspondence','atomic_config_route_snapshot','backend_boot_verified','vm_signal_authority','remote_memory_bounded','remote_cancellation_verified'}
        if set(route)!=keys or route['source']!=admit_sources() or route['reported_version']!='2.3.1' or route['config_selection']!=CONFIG_PATH or route['rootful'] is not True:raise Refusal('checkpoint_route_schema')
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',route['namespace']) or not re.fullmatch('/[A-Za-z0-9_./-]+\\.sock',route['address']):raise Refusal('checkpoint_route_identity')
        for name in ('help_sha256','binary_sha256'):
            if not re.fullmatch('[0-9a-f]{64}',route[name]):raise Refusal('checkpoint_route_hash')
        if route['config_state'] not in ('present','absent') or (route['config_sha256'] is not None and not re.fullmatch('[0-9a-f]{64}',route['config_sha256'])):raise Refusal('checkpoint_route_config')
        if any(route[k] is not False for k in ('atomic_config_route_snapshot','backend_boot_verified','vm_signal_authority','remote_memory_bounded','remote_cancellation_verified')):raise Refusal('checkpoint_unsupported_authority')
    if s['route_source']!=admit_sources():raise Refusal('checkpoint_route_source_changed')
