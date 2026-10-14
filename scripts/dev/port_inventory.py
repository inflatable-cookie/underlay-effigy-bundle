"""Production port inventory admission; observations grant no ownership authority."""
import hashlib
import json
import re
import os
import stat
import time
from pathlib import Path

PROFILE_TARGETS = {"postgres": (5432,), "mailpit": (1025,8025), "silo": (9000,9001), "dbgate": (3000,), "silo_client": ()}
STORAGE_TARGETS = {"silo": (9000,9001), "silo_client": ()}

def port_facts(value):
    import ipaddress
    facts={"input_type": "string" if isinstance(value,str) else "wrong_type", "input_bytes":len(value.encode()) if isinstance(value,str) else None}
    if not isinstance(value,str):return {**facts,'class':'wrong_type'}
    if len(value.encode())>128:return {**facts,'class':'oversized'}
    exposed=re.fullmatch(r'([0-9]{1,5})/(tcp|udp|sctp)',value)
    published=re.fullmatch(r'(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]{1,5})->([0-9]{1,5})/(tcp|udp|sctp)',value)
    if exposed:
        target=int(exposed[1])
        if not 1<=target<=65535 or str(target)!=exposed[1]:return {**facts,'class':'malformed_numeric'}
        return {**facts,'class':'exposed_only','target':target,'protocol':exposed[2]}
    if published:
        try: address=ipaddress.ip_address(published[1].strip('[]'))
        except ValueError:return {**facts,'class':'malformed_address'}
        host,target=int(published[2]),int(published[3])
        if not (1<=host<=65535 and 1<=target<=65535 and str(host)==published[2] and str(target)==published[3]):return {**facts,'class':'malformed_numeric'}
        kind='loopback_exact' if str(address)=='127.0.0.1' else 'wildcard' if address.is_unspecified else 'other_loopback' if address.is_loopback else 'foreign'
        return {**facts,'class':'published','host_port':host,'target':target,'protocol':published[4],'address_kind':kind}
    grouped=re.fullmatch(r'(127\.0\.0\.1:)?([0-9]{1,5})(?:-([0-9]{1,5}))?->([0-9]{1,5})(?:-([0-9]{1,5}))?(/tcp)?',value)
    if grouped:
        return {**facts,'class':'grouped_numeric_fragment','loopback_prefix_present':bool(grouped[1]),
                'host_start':int(grouped[2]),'host_end':int(grouped[3] or grouped[2]),
                'target_start':int(grouped[4]),'target_end':int(grouped[5] or grouped[4]),
                'tcp_suffix_present':bool(grouped[6])}
    if re.fullmatch(r'[0-9a-fA-F:.\[\]>/tcpudsh-]{1,128}',value) and '-' in value:
        return {**facts,'class':'range_or_malformed'}
    return {**facts,'class':'unknown'}


MAX_PUBLISHED_MAPPINGS = 16


def grouped_published(tokens, service, bindings, emit=None):
    """Decode only source-qualified 2.3.1 grouping; declarations cap expansion."""
    if (not isinstance(bindings,list) or len(bindings)>MAX_PUBLISHED_MAPPINGS
            or any(not isinstance(item,tuple) or len(item)!=3 or not isinstance(item[0],str)
                   or type(item[1]) is not int or type(item[2]) is not int
                   or not 1<=item[1]<=65535 or not 1<=item[2]<=65535 for item in bindings)
            or len({h for n,h,t in bindings}) != len(bindings)):
        raise ValueError('live_compose_disagreement')
    emit = emit or (lambda *a,**kw:None)
    expected = {(h,t) for n,h,t in bindings if n == service}
    result=[]; group=[]; seen=set()
    for token in tokens:
        facts=port_facts(token)
        if not isinstance(token,str):raise ValueError("live_port_representation_unknown")
        if token in seen:raise ValueError('live_port_duplicate')
        seen.add(token)
        if facts['class']=='exposed_only':
            if group or facts['protocol']!='tcp' or facts['target'] not in {t for h,t in expected}:
                raise ValueError('unexpected_exposed_port')
            continue
        if not isinstance(token,str) or len(token.encode())>128:
            raise ValueError('live_port_representation_unknown')
        # Only exact loopback can establish group context. No context is inferred
        # from a later fragment, exposure, or independent declaration.
        match=re.fullmatch(r'(127\.0\.0\.1:)?([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?->([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?(/tcp)?',token)
        if not match or bool(match[1]) == bool(group) or (match[1] and result):
            raise ValueError('live_port_representation_unknown')
        hs,he,ts,te=int(match[2]),int(match[3] or match[2]),int(match[4]),int(match[5] or match[4])
        span=he-hs+1
        emit('port_group_predicates',service=service,open_group_count=int(bool(group)),
             expanded_before_count=len(result)+len(group),paired_range=bool(match[3]) and bool(match[5]),
             span_count=span if 1<=span<=MAX_PUBLISHED_MAPPINGS else None,
             span_bounded=1<=span<=MAX_PUBLISHED_MAPPINGS,span_equal=he-hs==te-ts,
             range_order_agrees=he>=hs and te>=ts,group_closed=bool(match[6]))
        if (any(v>65535 for v in (hs,he,ts,te)) or he<hs or te<ts or he-hs!=te-ts
                or bool(match[3])!=bool(match[5]) or (match[3] and he==hs)
                or he-hs+1>len(expected) or len(result)+len(group)+he-hs+1>len(expected)):
            raise ValueError('live_port_invalid')
        expanded=[(h,ts+h-hs) for h in range(hs,he+1)]
        if any(item not in expected for item in expanded):raise ValueError('live_compose_disagreement')
        if group and (hs<=group[-1][0] or (hs==group[-1][0]+1 and ts==group[-1][1]+1)):
            # The source sorts and would compress adjacent equalspan segments.
            raise ValueError('live_port_invalid')
        group.extend(expanded)
        if match[6]:
            result.extend(group);group=[]
    if group:raise ValueError('live_port_representation_unknown')
    if len(set(result))!=len(result):raise ValueError('live_port_duplicate')
    return [(service,h,t) for h,t in result]


def checkout_identity(report, checkout, policy):
    """Compare supported scope report with local Git kind and explicit policy."""
    import subprocess
    checkout=Path(checkout)
    def git(*args):
        p=subprocess.run(['git','-C',str(checkout),*args],capture_output=True,text=True,timeout=10)
        if p.returncode:raise ValueError('git_identity_unavailable')
        return p.stdout.strip()
    if checkout.resolve(strict=True)!=checkout or checkout.stat().st_uid!=os.getuid() or git('rev-parse','--show-toplevel')!=str(checkout):raise ValueError('checkout_identity_mismatch')
    if not isinstance(report,dict) or report.get('schema')!='effigy.container.scope.v1' or type(report.get('schema_version')) is not int or report['schema_version']!=1 or report.get('ok') is not True or report.get('checkout')!=str(checkout):raise ValueError('scope_contract_mismatch')
    scope=report.get('scope');kind=scope.get('kind') if isinstance(scope,dict) else None;token=scope.get('token') if isinstance(scope,dict) else None
    gitdir=Path(git('rev-parse','--absolute-git-dir')).resolve(strict=True)
    base=policy.get('project_name')
    if not isinstance(base,str) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,100}',base) or policy.get('share_runtime_identity',False) is not False:raise ValueError('project_policy_unavailable')
    if kind=='none' and token is None and gitdir==checkout/'.git' and (checkout/'.git').is_dir():project=base
    elif kind=='worktree' and isinstance(token,str) and re.fullmatch('[a-f0-9]{32}',token) and (checkout/'.git').is_file() and gitdir.parent.name=='worktrees':project=base+'-wt-'+token[:12]
    else:raise ValueError('scope_kind_mismatch')
    return dict(project=project,kind=kind,token=token,checkout=str(checkout))


def compose_identity(raw,status,identity,diagnostics=None):
    try:text=raw.decode('utf-8')
    except UnicodeError:raise ValueError('malformed_compose_encoding') from None
    projects=re.findall(r'(?m)^\s*com\.effigy\.project:\s*([a-z0-9-]+)\s*$',text)
    scopes=re.findall(r'(?m)^\s*com\.effigy\.scope:\s*([a-f0-9]{32})\s*$',text)
    if not projects or len(projects)!=text.count('com.effigy.project') or set(projects)!={identity['project']} or status.get('project_name')!=identity['project']:raise ValueError('project_label_mismatch')
    # Generated volume labels can also carry this project. Check each service
    # independently rather than equating all label occurrences with row count.
    service_text=re.split(r'(?m)^\S',text.split('services:\n',1)[1],maxsplit=1)[0] if 'services:\n' in text else ''
    blocks=re.findall(r'(?ms)^  ([a-z][a-z0-9_-]*):\n(.*?)(?=^  [a-z][a-z0-9_-]*:|^\S|\Z)',service_text)
    if isinstance(status.get('services'),list) and status['services']:
        if {name for name,body in blocks}!={r.get('name') for r in status['services']}:raise ValueError('project_label_mismatch')
        for name,body in blocks:
            count=len(re.findall(r'(?m)^\s*com\.effigy\.project:',body))
            if count>1 or (identity['kind']=='worktree' and count!=1):raise ValueError('project_label_mismatch')
            if identity['kind']=='worktree' and len(re.findall(r'(?m)^\s*com\.effigy\.scope:',body))!=1:raise ValueError('scoped_label_mismatch')
    if identity['kind']=='none':
        if identity['token'] is not None or text.count('com.effigy.scope'):raise ValueError('primary_foreign_scope_label')
    elif identity['kind']=='worktree':
        if not scopes or len(scopes)!=text.count('com.effigy.scope') or set(scopes)!={identity['token']}:raise ValueError('scoped_label_mismatch')
    else:raise ValueError('unknown_identity_kind')
    return dict(project=identity['project'],scope_kind=identity['kind'],scope=identity['token'])


def compose_bindings(raw,targets):
    """Read the generated block service/short-port schema, refusing skipped entries."""
    if not isinstance(raw,bytes) or len(raw)>131072:raise ValueError('compose_size_refused')
    try:lines=raw.decode('utf-8').splitlines()
    except UnicodeError:raise ValueError('malformed_compose_encoding') from None
    inside=False;service=None;in_ports=False;rows=[];names=[];keys=set();port_seen=set()
    service_fields={'image','build','command','entrypoint','environment','ports','volumes','healthcheck','labels','networks','depends_on','working_dir','user','restart','init','stdin_open','tty','extra_hosts','expose','container_name'}
    nested_keys={}

    for line in lines:
        if '\t' in line or re.search(r'(?:^ *[A-Za-z0-9_.-]+: +|^ *- +)[&*!][A-Za-z]',line):raise ValueError('unsupported_compose_shape')
        if not line.strip():continue
        indent=len(line)-len(line.lstrip(' '))
        if indent==0:
            if line=='services:':
                if inside or names:raise ValueError('duplicate_compose_services')
                inside=True
            else:inside=False
            service=None;in_ports=False;continue
        if not inside:continue
        if indent==2:
            match=re.fullmatch(r'  ([a-z][a-z0-9_-]*):',line)
            if not match or match[1] in names or match[1] not in targets:raise ValueError('compose_service_ambiguity')
            service=match[1];names.append(service);keys=set();nested_keys={};in_ports=False;continue
        if service is None:raise ValueError('unsupported_compose_shape')
        if indent==4 and not line.lstrip().startswith('-'):
            match=re.fullmatch(r'    ([a-z][a-z0-9_]*):(?: .*|)',line)
            if not match or match[1] in keys or match[1] not in service_fields:raise ValueError('duplicate_or_unknown_compose_field')
            keys.add(match[1]);nested_keys={};in_ports=match[1]=='ports'
            if in_ports and line!='    ports:':raise ValueError('unsupported_compose_ports')
            continue
        if indent>4 and not line.lstrip().startswith('-'):
            nested=re.fullmatch(r' +([A-Za-z_][A-Za-z0-9_.-]*):(?: .*|)',line)
            if nested:
                for level in tuple(nested_keys):
                    if level>indent:del nested_keys[level]
                seen=nested_keys.setdefault(indent,set())
                if nested[1] in seen:raise ValueError('duplicate_or_unknown_compose_field')
                seen.add(nested[1])
        if in_ports:
            match=re.fullmatch(r'''    - (?:(['"])(127\.0\.0\.1:[1-9][0-9]{0,4}:[1-9][0-9]{0,4}(?:/tcp)?)\1|(127\.0\.0\.1:[1-9][0-9]{0,4}:[1-9][0-9]{0,4}(?:/tcp)?))''',line)
            if not match:raise ValueError('unsupported_compose_port_entry')
            host,target=map(int,(match[2] or match[3]).removesuffix('/tcp').split(':')[1:])
            row=(service,host,target)
            if host>65535 or target>65535 or target not in targets[service] or row in port_seen:raise ValueError('compose_binding_refused')
            port_seen.add(row);rows.append(row)
    expected={(n,t) for n,ports in targets.items() for t in ports}
    if set(names)!=set(targets) or len(rows)!=len(expected) or {(n,t) for n,h,t in rows}!=expected or len({h for n,h,t in rows})!=len(rows):raise ValueError('compose_inventory_incomplete')
    return rows


def declaration_bindings(tokens,bindings):
    if not isinstance(tokens,list) or len(tokens)>MAX_PUBLISHED_MAPPINGS:raise ValueError('declaration_inventory_unavailable')
    result=[]
    by_target={t:(n,h,t) for n,h,t in bindings}
    for token in tokens:
        if not isinstance(token,str):raise ValueError('declaration_tuple_unknown')
        m=re.fullmatch(r'(?:127\.0\.0\.1:)?([1-9][0-9]{0,4}):([1-9][0-9]{0,4})(?:/tcp)?',token)
        if not m or int(m[1])>65535 or int(m[2]) not in by_target:raise ValueError('declaration_tuple_unknown')
        n,h,t=by_target[int(m[2])];row=(n,int(m[1]),t)
        if row in result:raise ValueError('declaration_duplicate')
        result.append(row)
    if sorted(result)!=sorted(bindings):raise ValueError('declaration_compose_disagreement')
    return result


def admit_inventory(status,bindings,targets,emit=None):
    """Whole live inventory equals captured Compose; status.ports is declaration only."""
    emit=emit or (lambda *a,**kw:None)
    required={(n,t) for n,ts in targets.items() for t in ts}
    if not isinstance(bindings,list) or len(bindings)>MAX_PUBLISHED_MAPPINGS or any(not isinstance(b,tuple) or len(b)!=3 or not isinstance(b[0],str) or type(b[1]) is not int or type(b[2]) is not int or not 1<=b[1]<=65535 or not 1<=b[2]<=65535 for b in bindings):raise ValueError('compose_binding_refused')
    if len(bindings)!=len(required) or len(set(bindings))!=len(bindings) or len({h for n,h,t in bindings})!=len(bindings) or {(n,t) for n,h,t in bindings}!=required:raise ValueError('compose_inventory_incomplete')
    raw=json.dumps(status,sort_keys=True,separators=(',',':')).encode()
    emit('port_inventory_input',payload_bytes=len(raw),payload_sha256=hashlib.sha256(raw).hexdigest(),required_binding_count=len(required),atomic_association=False)
    rows=status.get('services') if isinstance(status,dict) else None
    if not isinstance(rows,list) or len(rows)!=len(targets):raise ValueError('live_inventory_incomplete')
    names=[];containers=[];live=[]
    for row in rows:
        if not isinstance(row,dict) or set(row)!={'name','container_name','status','ports'} or not isinstance(row['name'],str) or row['name'] not in targets or row['name'] in names:raise ValueError('live_service_ambiguity')
        name=row['name'];names.append(name)
        c=row['container_name'];state=row['status']
        if not isinstance(c,str) or not 0<len(c.encode())<=256 or c in containers or not isinstance(state,str) or not re.fullmatch(r'(?:Up|running|Running)(?: .*)?',state):raise ValueError('live_service_not_running')
        containers.append(c)
        ports=row['ports']
        if not isinstance(ports,list) or len(ports)>64:raise ValueError('live_ports_unavailable')
        histogram={}
        for value in ports:
            kind=port_facts(value)['class'];histogram[kind]=histogram.get(kind,0)+1
        emit('port_inventory_row',service=name,token_count=len(ports),class_counts=histogram)
        live.extend(grouped_published(ports,name,bindings,emit))
    if len(live)!=len(set(live)) or sorted(live)!=sorted(bindings):raise ValueError('live_compose_disagreement')
    declaration_bindings(status.get('ports'),bindings)
    emit('port_inventory_agreement',service_count=len(rows),binding_count=len(live),live_compose_equal=True,declaration_compose_equal=True,atomic_association=False)
    return {(n,t):h for n,h,t in live}

class StatusSource(dict):
    pass


class ComposeBindings(list):
    def __init__(self, values, snapshot):
        super().__init__(values)
        self.snapshot = snapshot


def _file_identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size,
            "mtime_ns": info.st_mtime_ns, "uid": info.st_uid, "links": info.st_nlink}


def _compose_identity(repo, status):
    value = status.get("compose_file")
    if not isinstance(value, str) or not value:
        return None, {"state": "missing_source"}
    candidate = Path(value)
    candidate = candidate if candidate.is_absolute() else repo / candidate
    # Validate lexical components before canonicalization can erase a symlink.
    try:
        relative = candidate.relative_to(repo)
        if ".." in relative.parts:
            return None, {"state": "foreign_source"}
        current = repo
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return None, {"state": "unsafe_source"}
        path = candidate.resolve(strict=True)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            return None, {"state": "unsafe_source"}
        if info.st_size > 131072:
            return None, {"state": "oversized_source", "bytes": info.st_size}
        return path, {"state": "observed", **_file_identity(info)}
    except (OSError, ValueError):
        return None, {"state": "unavailable_source"}



def read_compose(repo, status, targets, emit=None):
    emit = emit or (lambda *a, **kw: None)
    path, identity = _compose_identity(repo, status)
    initial = getattr(status, "initial_identity", identity)
    emit("compose_source_before_read", source=identity, initial_agrees=identity == initial,
               read_started_ns=time.monotonic_ns(), path_inside_checkout=path is not None)
    if path is None or identity != initial:
        emit("compose_source_refusal", reason="source_changed_before_read" if identity != initial else identity["state"])
        raise ValueError("compose_association_unavailable")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            before = _file_identity(os.fstat(stream.fileno()))
            raw = stream.read(131073)
            after = _file_identity(os.fstat(stream.fileno()))
        _, current = _compose_identity(repo, status)
        stable = before == after == {k:identity[k] for k in before} and current == identity and len(raw) <= 131072
        snapshot = {"source": identity, "sha256": hashlib.sha256(raw).hexdigest(),
                    "read_bytes": len(raw), "unchanged_during_read": stable,
                    "read_finished_ns": time.monotonic_ns(), "atomic_association": False}
        emit("compose_source_consumed", **snapshot)
        if not stable:
            raise ValueError("source_changed_during_read")
        lines = raw.decode("utf-8").splitlines()
    except (OSError, UnicodeError):
        emit("compose_source_refusal", reason="source_unreadable")
        raise ValueError("compose_association_unavailable")

    result = ComposeBindings(compose_bindings(raw, targets), snapshot)
    result.raw = raw
    return result

REFUSAL_REASONS = frozenset(('checkout_identity_mismatch', 'compose_association_unavailable', 'compose_binding_refused', 'compose_inventory_incomplete', 'compose_service_ambiguity', 'compose_size_refused', 'declaration_compose_disagreement', 'declaration_duplicate', 'declaration_inventory_unavailable', 'declaration_tuple_unknown', 'duplicate_compose_services', 'duplicate_or_unknown_compose_field', 'git_identity_unavailable', 'live_compose_disagreement', 'live_inventory_incomplete', 'live_port_duplicate', 'live_port_invalid', 'live_port_representation_unknown', 'live_ports_unavailable', 'live_service_ambiguity', 'live_service_not_running', 'malformed_compose_encoding', 'primary_foreign_scope_label', 'project_label_mismatch', 'project_policy_unavailable', 'scope_contract_mismatch', 'scope_kind_mismatch', 'scoped_label_mismatch', 'source_changed_during_read', 'unexpected_exposed_port', 'unknown_identity_kind', 'unsupported_compose_port_entry', 'unsupported_compose_ports', 'unsupported_compose_shape'))
