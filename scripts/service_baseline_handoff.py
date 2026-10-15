"""Private ready-action transfer of original association and live service IDs.

This supplies no VM/process signal authority. It never discovers an owner from
late status, and never turns an absent handoff into an empty baseline.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
from container_identity_observer import Observer, Refusal, identity, file_sha, projection, MAX_IDS
from original_container_route import read_small

SCHEMA='underlay.ready-service-association.v1'
BASELINE='underlay.ready-service-baseline.v1'
SOURCES=('service_baseline_handoff.py','qualification_cleanup_action.py','qualification_cleanup.py',
         'container_identity_observer.py','fresh_backend_admission.py','original_container_route.py',
         'qualification_runtime.py','qualify-reference-optin.py','qualification_batch.py','qualify-reference-runtime.py','private_caller_environment.py','private_cargo_cache.py','reference_api_preparation.py','route_observation.py','storage_observation.py','dev/startup_evidence.py','dev/owned_capture.py','dev/host_identity.py','dev/profile_launcher.py','dev/silo_client.py','dev/storage_launcher.py','generated_profile.py','qualification_refusal.py','auth_operation.py','qualify-reference-profiles.py')


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def write(path, root, value):
    root=Path(root);identity(root,True);path=Path(path)
    if path.parent!=root:raise Refusal('handoff_boundary')
    raw=json.dumps(value,sort_keys=True).encode()
    if len(raw)>1048576:raise Refusal('handoff_cap')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)
    return identity(path),file_sha(path,1048576)


def read(path, root, expected=None):
    try:return _read(path,root,expected)
    except Refusal:raise
    except Exception:raise Refusal("handoff_unavailable") from None


def _read(path, root, expected=None):
    from container_identity_observer import strict_json
    path=Path(path);identity(root,True)
    if path.parent!=Path(root):raise Refusal('handoff_boundary')
    before=identity(path)
    if stat.S_IMODE(before[2])!=0o600:raise Refusal('handoff_permissions')
    raw=read_small(path);sha=hashlib.sha256(raw).hexdigest()
    if expected is not None and (before!=tuple(expected[0]) or sha!=expected[1]):raise Refusal('handoff_changed')
    return strict_json(raw),(before,sha)


class Association:
    def __init__(self, record, fixture):
        self.record=copy.deepcopy(record);self.fixture=Path(fixture)
        required={'schema','context','directories','files','sources','original_route','ready_manifest','tools'}
        if type(record) is not dict or set(record)!=required or record['schema']!=SCHEMA:raise Refusal('handoff_association_schema')
        self.sha=digest(record)
        self.guard()

    def guard(self):
        if digest(self.record)!=self.sha:raise Refusal('handoff_association_changed')
        if type(self.record['directories']) is not dict or not self.record['directories']:raise Refusal('handoff_roots')
        for name,stamp in self.record['directories'].items():
            path=Path(name);path.relative_to(self.fixture)
            if identity(path,True)[:4]!=tuple(stamp):raise Refusal('handoff_root_changed')
        for name,entry in self.record['files'].items():
            path=Path(name);path.relative_to(self.fixture)
            if type(entry) is not dict or set(entry)!={'identity','sha256'}:raise Refusal('handoff_file_schema')
            if identity(path)!=tuple(entry['identity']) or file_sha(path,1048576)!=entry['sha256']:raise Refusal('handoff_file_changed')
        expected={str(Path(__file__).parent/name) for name in SOURCES}
        if set(self.record['sources'])!=expected:raise Refusal('handoff_sources')
        for name,sha in self.record['sources'].items():
            if hashlib.sha256(Path(name).read_bytes()).hexdigest()!=sha:raise Refusal('handoff_source_changed')
        manifest=self.record['ready_manifest']
        if type(manifest) is not dict or set(manifest)!={'path','sha256'}:raise Refusal('handoff_manifest_schema')
        Path(manifest['path']).relative_to(self.fixture)
        if file_sha(manifest['path'],1048576)!=manifest['sha256']:raise Refusal('handoff_manifest_changed')
        self.verify_tools()

    def verify_tools(self):
        c=self.record['context']
        if type(self.record['tools']) is not dict or set(self.record['tools'])!={'colima','limactl','ssh'}:raise Refusal('handoff_tools_schema')
        for tool in self.record['tools'].values():
            if identity(tool['path'],executable=True)!=tuple(tool['identity']) or file_sha(tool['path'],268435456)!=tool['sha256']:raise Refusal('handoff_original_tool_changed')
        for name in ('limactl','ssh'):
            if file_sha(c[name],268435456)!=c[name+'_sha256']:raise Refusal('handoff_tool_changed')

    def reader_environment(self):
        import shlex
        c=self.record['context']
        return {'HOME':c['private_home'],'COLIMA_HOME':c['colima_home'],'LIMA_HOME':c['lima_home'],
                'SSH':shlex.join([c['ssh'],'-o','ControlMaster=no','-o','ControlPersist=no']),
                'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}

    def observer(self, env):
        self.guard();c=self.record['context']
        observer=Observer(c,env,self.fixture,{k:copy.deepcopy(v) for k,v in c.items() if k!='schema'})
        observer.original_admission=self
        return observer


def prepare(observer, root, manifest, ready_bytes, *, cargo_env=None):
    """Called by the ORIGINAL creator before dev:test, never by a late reader."""
    backend=getattr(observer,'original_admission',None)
    if backend is None or backend.original_route is None:raise Refusal('handoff_original_factory_required')
    backend.guard();backend.verify_tools()
    if observer._baseline is not None:raise Refusal('handoff_owned_baseline_too_early')
    files={}
    paths=[backend.path,backend.prepared_path,backend.start_record[0],
           backend.profile_binding['config'],backend.profile_binding['colima_config']]
    paths += [row[0] for row in backend.policy_records.values()]
    if cargo_env is not None:
        from private_cargo_cache import verify_environment
        verify_environment(cargo_env)
        paths.append(Path(cargo_env['CARGO_HOME'])/'admission.json')
    for path in paths:
        files[str(path)]={'identity':identity(path),'sha256':file_sha(path,1048576)}
    # The ready wrapper task is the ONLY predeclared manifest edit. The child
    # binds its exact bytes; the parent restores the original before post-proof.
    manifest=Path(manifest)
    if type(ready_bytes) is not bytes or not ready_bytes or len(ready_bytes)>1048576:raise Refusal('handoff_ready_manifest')
    directories={str(path):identity(path,True)[:4] for path in [backend.root,*backend.paths.values(),
                 Path(backend.profile_binding['config_dir']),Path(backend.profile_binding['colima_dir'])]}
    record={'schema':SCHEMA,'context':copy.deepcopy(observer.context),'directories':directories,'files':files,
            'sources':{str(Path(__file__).parent/name):hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest() for name in SOURCES},
            'original_route':copy.deepcopy(backend.original_route),
            'tools':copy.deepcopy(backend.prepared['tool_provenance']),
            'ready_manifest':{'path':str(manifest),'sha256':hashlib.sha256(ready_bytes).hexdigest()}}
    return write(Path(root)/'association.json',root,record)


def capture_ready(root, fixture, env):
    record,stamp=read(Path(root)/'association.json',root)
    association=Association(record,fixture);observer=association.observer(env)
    baseline=observer.baseline()
    value={'schema':BASELINE,'association_sha256':stamp[1],
           'context_sha256':digest(record['context']),'baseline':baseline}
    write(Path(root)/'services.json',root,value)
    return observer,baseline


def accept(parent, root, association_stamp):
    # Source-qualified wrapper captured LIVE IDs before the configured action.
    # Private identity/content are checked; no status/name/Boolean substitution.
    association,_=read(Path(root)/'association.json',root,association_stamp)
    record,stamp=read(Path(root)/'services.json',root)
    if type(record) is not dict or set(record)!={'schema','association_sha256','context_sha256','baseline'} or record['schema']!=BASELINE:
        raise Refusal('handoff_baseline_schema')
    if record['association_sha256']!=association_stamp[1] or record['context_sha256']!=digest(parent.context) or association['context']!=parent.context:
        raise Refusal('handoff_original_context_changed')
    baseline=record['baseline']
    if type(baseline) is not dict or set(baseline)!={'binding','owned','foreign'} or baseline['binding']!=parent.binding or baseline['foreign']!=parent.context['foreign']:
        raise Refusal('handoff_baseline_binding')
    if type(baseline['owned']) is not dict or not 1<=len(baseline['owned'])<=MAX_IDS:raise Refusal('handoff_baseline_cardinality')
    seen=set()
    for full_id,row in baseline['owned'].items():
        projection((json.dumps(row)+'\n').encode(),full_id)
        scopes=[s for s in parent.context['scopes'] if s['project']==row['project']]
        if len(scopes)!=1:raise Refusal('handoff_owned_project')
        s=scopes[0]
        if row['checkout'] not in (None,'',s['checkout']) or row['service'] not in s['services'] or not row['running'] or row['oneoff'] not in (None,'','false','False') or (row['oneoff'] in (None,'') and s['oneoffs']):
            raise Refusal('handoff_live_scope')
        token=(row['project'],row['service'])
        if token in seen:raise Refusal('handoff_duplicate_service')
        seen.add(token)
    if seen!={(s['project'],name) for s in parent.context['scopes'] for name in s['services']}:raise Refusal('handoff_missing_service')
    if parent._baseline is not None:raise Refusal('handoff_baseline_already_bound')
    parent._baseline=copy.deepcopy(baseline)
    proof=parent.after(baseline)
    read(Path(root)/'services.json',root,stamp)
    return proof
