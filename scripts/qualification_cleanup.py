"""Qualification-only immutable listener baselines; never signal/cleanup authority."""
import copy
import json
import os
from pathlib import Path
import re
import stat

CAP = 65536
ROLES = ('supervisor', 'child', 'listener')
FIELDS = ('owner','runtime_generation','generation','address','route_domain','route_owner') + tuple(
    role + suffix for role in ROLES for suffix in ('_pid','_boot_identity','_start_identity'))

class CleanupUnknown(RuntimeError):
    """Closed refusal: omit observer exceptions and any payload."""


def validate(states):
    if type(states) is not dict or set(states) != {'api','front','admin'}:
        raise CleanupUnknown('listener_inventory')
    result = {}
    for name, state in states.items():
        if type(state) is not dict or state.get('status') != 'ready':
            raise CleanupUnknown('listener_not_ready')
        if any(not re.fullmatch('[0-9a-f]{32}', str(state.get(k,''))) for k in ('generation','runtime_generation')):
            raise CleanupUnknown('generation')
        if not isinstance(state.get('owner'),str) or not 0<len(state['owner'])<=512:
            raise CleanupUnknown('owner')
        address=state.get('address');domain=state.get('route_domain');route=state.get('route_owner')
        if (not isinstance(address,str) or not re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}',address)
                or int(address.rsplit(':',1)[1])>65535 or not isinstance(domain,str)
                or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',domain)
                or not isinstance(route,dict) or route.get('address')!=address):
            raise CleanupUnknown('endpoint_route')
        projected={k:copy.deepcopy(state.get(k)) for k in FIELDS}
        # Only the known route address is needed; arbitrary state/env fields never persist.
        projected['route_owner']={'address':address}
        for role in ROLES:
            pid=projected[role+'_pid'];start=projected[role+'_start_identity'];boot=projected[role+'_boot_identity']
            if (type(pid) is not int or pid<=1 or type(start) is not dict or start.get('platform')!='macos'
                    or type(start.get('start_seconds')) is not int or start['start_seconds']<=0
                    or type(start.get('start_microseconds')) is not int or not 0<=start['start_microseconds']<1000000
                    or not isinstance(boot,str) or not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',boot)):
                raise CleanupUnknown('precise_identity')
            projected[role+'_start_identity']={k:start[k] for k in ('platform','start_seconds','start_microseconds')}
        result[name]=projected
    if len({s['address'] for s in result.values()})!=3 or len({s['route_domain'] for s in result.values()})!=3:
        raise CleanupUnknown('duplicate_endpoint')
    return result


def capture(states, observer):
    baseline=validate(states)
    try:
        for name,state in baseline.items():
            live={role:observer.match_role(state,role) for role in ROLES}
            child=live['child']
            if any(x is None for x in live.values()):raise CleanupUnknown('role_unknown')
            if child['pgid']!=state['child_pid'] or child['ppid']!=state['supervisor_pid']:
                raise CleanupUnknown('ancestry_group')
            members=observer.group_members(child['pgid'])
            if state['child_pid'] not in members or state['listener_pid'] not in members:
                raise CleanupUnknown('group_members')
            if len(members)>64 or len(set(members))!=len(members):raise CleanupUnknown('group_cap_or_duplicate')
            identities=[observer.kernel_identity(pid) for pid in members]
            if any(x is None or x['pgid']!=child['pgid'] or x['boot_identity']!=child['boot_identity'] for x in identities):
                raise CleanupUnknown('group_identity')
            if observer.socket_pids(state['address']) != [state['listener_pid']] or not observer.route_matches(state):
                raise CleanupUnknown('socket_route')
            by_pid={x['pid']:x for x in identities}
            for item in identities:
                if item['uid']!=child['uid']:raise CleanupUnknown('foreign_group_member')
                parent=item['pid'];seen=set()
                while parent!=child['pid']:
                    if parent in seen or parent not in by_pid:raise CleanupUnknown('foreign_ancestry')
                    seen.add(parent);parent=by_pid[parent]['ppid']
            state['group_members']=[{k:copy.deepcopy(x[k]) for k in ('pid','ppid','pgid','uid','boot_identity','start_identity')} for x in identities]
    except CleanupUnknown:raise
    except Exception:raise CleanupUnknown('observation_unavailable') from None
    return baseline


def verify_absent(baseline, observer, foreign_check):
    # Baseline must come from successful capture; terminal state/inventory is no substitute.
    try:
        validate({name:dict(state,status='ready') for name,state in baseline.items()})
        if set(baseline)!= {'api','front','admin'}:raise CleanupUnknown('missing_baseline')
        for state in baseline.values():
            if not state.get('group_members'):raise CleanupUnknown('missing_group_baseline')
            for role in ROLES:
                if observer.boot_identity()!=state[role+'_boot_identity'].upper():raise CleanupUnknown('boot_changed')
                if observer.kernel_identity(state[role+'_pid']) is not None:raise CleanupUnknown('process_present_or_reused')
            if len(state['group_members'])>64:raise CleanupUnknown('group_cap')
            for identity in state['group_members']:
                if (type(identity) is not dict or set(identity)!={'pid','ppid','pgid','uid','boot_identity','start_identity'}
                        or type(identity['pid']) is not int or identity['pid']<=1
                        or identity['pgid']!=state['child_pid'] or identity['boot_identity'].upper()!=state['child_boot_identity'].upper()
                        or type(identity['start_identity']) is not dict
                        or set(identity['start_identity'])!={'platform','start_seconds','start_microseconds'}
                        or identity['start_identity']['platform']!='macos'
                        or type(identity['start_identity']['start_seconds']) is not int or identity['start_identity']['start_seconds']<=0
                        or type(identity['start_identity']['start_microseconds']) is not int
                        or not 0<=identity['start_identity']['start_microseconds']<1000000):
                    raise CleanupUnknown('group_baseline_identity')
                if observer.kernel_identity(identity['pid']) is not None:raise CleanupUnknown('group_member_present_or_reused')
            if observer.group_members(state['child_pid']):raise CleanupUnknown('group_present')
            if observer.socket_pids(state['address']) or observer.address_accepts(state['address']):raise CleanupUnknown('socket_present')
            if not observer.route_absent(state):raise CleanupUnknown('route_present_or_unknown')
        foreign_check()
    except CleanupUnknown:raise
    except Exception:raise CleanupUnknown('absence_or_foreign_unknown') from None
    return {'host_listener_cleanup_verified':True,'listeners':3,'foreign_preservation_verified':True,
            'container_cleanup_verified':False,'retirement_verified':False}


def action_once(capture_baseline, action, save):
    baseline=capture_baseline();save({'schema':'underlay.qualification-cleanup.v1','baseline':baseline,'action':'pending'})
    code=action()  # exactly one configured action; no retry or hidden QA.
    current=capture_baseline()
    if current!=baseline:raise CleanupUnknown('baseline_changed_during_action')
    save({'schema':'underlay.qualification-cleanup.v1','baseline':baseline,'action':'passed' if code==0 else 'failed'})
    return code


def write_private(path, root, record):
    root=Path(root).resolve(strict=True);path=Path(path)
    info=root.stat()
    if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise CleanupUnknown('receipt_root')
    if path.parent.resolve(strict=True)!=root or path.is_symlink():raise CleanupUnknown('receipt_boundary')
    data=json.dumps(record,sort_keys=True).encode()
    if len(data)>CAP:raise CleanupUnknown('receipt_cap')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data)


def read_private(path, root):
    path=Path(path);root=Path(root).resolve(strict=True)
    if path.parent.resolve(strict=True)!=root:raise CleanupUnknown('receipt_boundary')
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            before=os.fstat(f.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o600:raise CleanupUnknown('receipt_identity')
            raw=f.read(CAP+1);after=os.fstat(f.fileno())
        if len(raw)>CAP or len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise CleanupUnknown('receipt_cap_or_change')
        def pairs(items):
            d={}
            for k,v in items:
                if k in d:raise CleanupUnknown('receipt_duplicate')
                d[k]=v
            return d
        record=json.loads(raw,object_pairs_hook=pairs)
        if set(record)!= {'schema','baseline','action'} or record['schema']!='underlay.qualification-cleanup.v1' or record['action'] not in ('pending','passed','failed'):
            raise CleanupUnknown('receipt_schema')
        return record
    except CleanupUnknown:raise
    except Exception:raise CleanupUnknown('receipt_unavailable') from None


def container_cleanup_credit(status):
    # Admitted status.v1 exposes names/status/ports, not immutable IDs or independent absence.
    raise CleanupUnknown('immutable_container_identity_surface_unqualified')


def require_product_cleanup(proof):
    if type(proof) is not dict or proof.get("host_listener_cleanup_verified") is not True or proof.get("container_cleanup_verified") is not True or proof.get("foreign_preservation_verified") is not True:
        raise CleanupUnknown("whole_product_cleanup_unqualified")
