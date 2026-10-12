"""Finite, secret-free projections for the owned Silo write/read diagnosis."""
import hashlib
import json
import re
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

ERROR_CODES = {"NoSuchKey", "NoSuchBucket", "AccessDenied", "SignatureDoesNotMatch",
               "InvalidAccessKeyId", "InvalidRequest", "InternalError", "SlowDown"}


def safe_framing(response):
    patterns = {"Content-Length": r"[0-9]{1,12}", "Transfer-Encoding": r"chunked",
                "Connection": r"close|keep-alive", "Content-Type": r"(?:application/(?:xml|json|octet-stream)|text/plain)(?:; charset=utf-8)?"}
    result = {}
    for name, pattern in patterns.items():
        value = response.getheader(name)
        if value is not None:
            result[name.lower()] = value.lower() if re.fullmatch(pattern, value.lower()) else "unclassified"
    return result


def s3_error(body):
    result = {"error_code": "unknown"}
    if len(body) > 16384 or b"<!" in body:
        return result
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return result
    if root.tag != "Error":
        return result
    code = root.findtext("Code")
    if code in ERROR_CODES:
        result["error_code"] = code
    request = root.findtext("RequestId")
    if request and re.fullmatch(r"[A-Za-z0-9-]{1,128}", request):
        result["request_id_sha256"] = hashlib.sha256(request.encode()).hexdigest()
    return result


CAPTURE_LIMIT = 262144


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=pairs)
    except (ValueError, TypeError):
        raise ValueError('malformed_json') from None


def json_records(output):
    # Callers pass exactly the unique shell-framed region, never human headers.
    if len(output.encode()) > CAPTURE_LIMIT:
        raise ValueError('mc_output_truncated')
    record = strict_json(output)
    if not isinstance(record, dict):
        raise ValueError('invalid_mc_record')
    return [record]


from dev.silo_client import mc_command


def mc_record(output, expected, diagnostics, operation, optional=None):
    optional=optional or {}
    try:record=json_records(output)[0]
    except ValueError:
        if diagnostics:diagnostics.append('mc_fields',operation=operation,classification='malformed_or_duplicate',input_bytes=len(output.encode()),fields=[])
        raise
    fields=[]
    for name,(kind,value) in {**expected,**optional}.items():
        present=name in record;typed=present and type(record[name]) is kind
        agreement=typed and (value is None or record[name]==value)
        fields.append({'field':name,'present':present,'type_agreement':typed,
                       'expected_agreement':agreement,'required':name in expected})
    extra=set(record)-set(expected)-set(optional)
    if diagnostics:diagnostics.append('mc_fields',operation=operation,classification='decoded',
        input_bytes=len(output.encode()),record_count=1,unknown_field_count=len(extra),fields=fields)
    if extra or any((f['required'] and not f['expected_agreement']) or (not f['required'] and f['present'] and not f['expected_agreement']) for f in fields):
        raise ValueError('alias_config_refused' if operation.startswith('alias') else 'stat_shape_refused' if operation=='stat' else 'mc_operation_refused')
    return record


def alias_projection(output, diagnostics=None, operation='alias_list'):
    expected={'status':(str,'success'),'alias':(str,'local'),'URL':(str,'http://silo:9000'),
              'accessKey':(str,'minioadmin'),'secretKey':(str,'minioadmin'),'api':(str,'S3v4'),'path':(str,'auto')}
    if operation=='alias_list':expected['src']=(str,'/root/.mc/config.json')
    elif operation!='alias_set':raise ValueError('alias_shape_refused')
    mc_record(output,expected,diagnostics,operation)
    return {'alias':'local', 'endpoint':'http://silo:9000',
            'config_scope':'client-container:/root/.mc', 'credentials_recorded':False,
            'recipe_provenance':'explicit_probe_input_not_production_default'}


def stat_projection(output, key=None, size=None, diagnostics=None):
    expected={'status':(str,'success'),'name':(str,key),'lastModified':(str,None),
              'size':(int,size),'etag':(str,None),'type':(str,'file')}
    optional={name:(str,None) for name in ('expires','expiration','expirationRuleID','replicationStatus','versionID')}
    optional.update({name:(dict,None) for name in ('metadata','restore','checksum')})
    optional['deleteMarker']=(bool,None)
    record=mc_record(output,expected,diagnostics,'stat',optional)
    if not 0<=record['size']<=1048576:raise ValueError('stat_shape_refused')
    return {'status':'success','size':record['size'],'type':'file'}


def operation_projection(output, operation, target, size=None, diagnostics=None):
    if operation=='bucket':expected={'status':(str,'success'),'bucket':(str,target),'region':(str,'')}
    elif operation=='pipe':expected={'status':(str,'success'),'target':(str,target),'size':(int,size)}
    else:raise ValueError('mc_operation_refused')
    mc_record(output,expected,diagnostics,operation)
    return {'operation':operation,'success':True}


def running(status):
    if not isinstance(status, str): return False
    lowered = status.lower()
    return not any(x in lowered for x in ('exited','created','dead','paused')) and any(x in lowered for x in ('up','running'))


def input_fingerprint(value):
    # Native JSON is externally bounded. Only byte counts/digests leave memory.
    if isinstance(value,str): raw=value.encode('utf-8')
    else:
        try: raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        except (ValueError,TypeError):return {'input_type':'unsupported','input_bytes':None,'input_sha256':None}
    kind='string' if isinstance(value,str) else ('object' if isinstance(value,dict) else 'list' if isinstance(value,list) else 'boolean' if type(value) is bool else 'integer' if type(value) is int else 'null' if value is None else 'other')
    return {'input_type':kind,'input_bytes':len(raw),'input_sha256':hashlib.sha256(raw).hexdigest()}


def port_facts(value):
    import ipaddress
    facts=input_fingerprint(value)
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


def grouped_published(tokens, service, bindings):
    """Decode only source-qualified 2.3.1 grouping; declarations cap expansion."""
    if (not isinstance(bindings,list) or len(bindings)>MAX_PUBLISHED_MAPPINGS
            or any(not isinstance(item,tuple) or len(item)!=3 or item[0] not in ('silo','silo_client')
                   or type(item[1]) is not int or type(item[2]) is not int
                   or not 1<=item[1]<=65535 or not 1<=item[2]<=65535 for item in bindings)
            or len({h for n,h,t in bindings}) != len(bindings)):
        raise ValueError('live_compose_disagreement')
    expected = {(h,t) for n,h,t in bindings if n == service}
    result=[]; group=[]; seen=set()
    for token in tokens:
        facts=port_facts(token)
        if facts['input_sha256'] in seen:raise ValueError('live_port_duplicate')
        seen.add(facts['input_sha256'])
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


def native_identity_observation(value):
    result={'evidence':'current_input_before_validation','root_type':input_fingerprint(value)['input_type'],'fields':[],'ownership_credit':False}
    if isinstance(value,dict):
        for field in ('schema','schema_version','ok','checkout','scope','routes','selected_value','project_name','compose_file','ports','container','primary_service','driver','manifest_driver','backend','profile','runtime_running'):
            if field in value:result['fields'].append({'field':field,**input_fingerprint(value[field])})
    return result


def native_status_observation(status):
    result={'evidence':'current_input_before_validation','root_type':input_fingerprint(status)['input_type'],
            'fields':[],'rows':[],'projection_truncated':False,'ownership_credit':False}
    if not isinstance(status,dict):return result
    for field in ('schema','schema_version','ok','container','driver','manifest_driver','backend','profile','project_name','primary_service','runtime_running'):
        result['fields'].append({'field':field,'present':field in status,**input_fingerprint(status.get(field))})
    rows=status.get('services');result['service_inventory']=input_fingerprint(rows)
    if not isinstance(rows,list):return result
    result['row_count']=len(rows);result['projection_truncated']=len(rows)>16
    for index,row in enumerate(rows[:16]):
        projection={'index':index,'service':'unknown','fields':[],'ports':[]}
        if not isinstance(row,dict):
            projection['row']=input_fingerprint(row);result['rows'].append(projection);continue
        if row.get('name') in ('silo','silo_client'):projection['service']=row['name']
        for field in ('name','container_name','status','ports'):
            projection['fields'].append({'field':field,'present':field in row,**input_fingerprint(row.get(field))})
        # Unknown key names are never printed either.
        projection['extra_field_count']=len(set(row)-{'name','container_name','status','ports'})
        ports=row.get('ports')
        if isinstance(ports,list):
            projection['port_count']=len(ports)
            if len(ports)>64:result['projection_truncated']=True
            projection['ports']=[{'index':i,**port_facts(token)} for i,token in enumerate(ports[:64])]
        result['rows'].append(projection)
    return result


def status_projection(status, identity, bindings, after_down=False, diagnostics=None):
    observation=native_status_observation(status)
    if diagnostics is not None: diagnostics.append("native_status_observation", **observation)
    if observation["projection_truncated"]:raise ValueError("status_projection_truncated")
    if not isinstance(status,dict):raise ValueError("status_identity_unavailable")
    expected = {'schema':'effigy.container.status.v1','schema_version':1,'ok':True,
                'container':'hybrid_services','driver':'colima','manifest_driver':'colima',
                'backend':'containerd','profile':'effigy','project_name':identity['project'],
                'primary_service':'silo','runtime_running':True}
    if any(type(status.get(k)) is not type(v) or status.get(k) != v for k,v in expected.items()):
        raise ValueError('status_identity_unavailable')
    rows = status.get('services')
    if not isinstance(rows,list): raise ValueError('status_inventory_unavailable')
    if after_down:
        if rows: raise ValueError('post_down_inventory_not_empty')
        return {'available':True,'service_count':0}
    if len(rows) != 2 or any(not isinstance(r,dict) or not isinstance(r.get('name'),str) for r in rows) or {r['name'] for r in rows} != {'silo','silo_client'}:
        raise ValueError('status_service_ambiguity')
    names=[]; published=[]
    for row in rows:
        if set(row) != {'name','container_name','status','ports'} or not running(row['status']):
            raise ValueError('status_not_running')
        name=row['container_name']
        if not isinstance(name,str) or not 0 < len(name.encode()) <= 256:
            raise ValueError('status_container_unknown')
        names.append(name)
        if not isinstance(row['ports'],list): raise ValueError('status_ports_unknown')
        published.extend(grouped_published(row['ports'],row['name'],bindings))
    if len(set(names)) != 2 or len(set(published)) != len(published) or sorted(published) != sorted(bindings):
        raise ValueError('live_compose_disagreement')
    api=[h for name,h,t in published if name=='silo' and t==9000]
    if len(api)!=1: raise ValueError('live_api_port_ambiguity')
    return {'project':identity['project'],'port':api[0],
            'selected_container_sha256':[hashlib.sha256(x.encode()).hexdigest() for x in names],
            'dns_addresses_observed':False,'container_ids_observed':False}


def bounded_run(args, *, cwd=None, env=None, timeout=180, cap=CAPTURE_LIMIT):
    # Drain both pipes without retaining beyond the cap. Only our exact child
    # PID is stopped on a violated diagnostic bound; no pattern signalling.
    import selectors, subprocess, time, os
    process=subprocess.Popen(args,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    streams=selectors.DefaultSelector(); buffers={'stdout':bytearray(),'stderr':bytearray()}; counts=dict.fromkeys(buffers,0)
    for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
        streams.register(stream,selectors.EVENT_READ,name)
    deadline=time.monotonic()+timeout; outcome='complete'
    try:
        while streams.get_map():
            if time.monotonic() >= deadline:
                outcome='timeout';process.kill();break
            for entry,_ in streams.select(min(.1,max(0,deadline-time.monotonic()))):
                data=os.read(entry.fileobj.fileno(),8192)
                if not data: streams.unregister(entry.fileobj);continue
                name=entry.data;counts[name]+=len(data)
                remaining=cap-len(buffers[name]);buffers[name].extend(data[:max(0,remaining)])
                if counts[name]>cap:
                    outcome='truncated';process.kill();break
            if outcome!='complete':break
        process.wait(timeout=5)
    finally:
        streams.close();process.stdout.close();process.stderr.close()
    return {'exit':process.returncode,'stdout':bytes(buffers['stdout']),'stderr':bytes(buffers['stderr']),
            'stdout_bytes':counts['stdout'],'stderr_bytes':counts['stderr'],'outcome':outcome}


ROUTING_OVERRIDES = ('MC_RESOLVE','MC_INSECURE','MC_DEBUG','MC_JSON','MC_QUIET','MC_NO_COLOR','MC_DISABLE_PAGER','MC_LIMIT_UPLOAD','MC_LIMIT_DOWNLOAD','MC_PROFILER','MC_ENC_KMS','MC_ENC_S3','MC_CONFIG_DIR','MC_CONFIG_ENV_FILE','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY',
                     'http_proxy','https_proxy','all_proxy','NO_PROXY','no_proxy')


def environment_guard(service):
    names=ROUTING_OVERRIDES + (() if service=='silo' else ('MC_HOST_local',))
    checks='; '.join('test "${'+name+'+present}" != present' for name in names)
    if service=='silo':
        checks += '; test "${MC_HOST_local+present}" = present; test "$MC_HOST_local" = "http://minioadmin:minioadmin@127.0.0.1:9000"'
    else: checks += '; test "$HOME" = /root'
    return 'set -eu; '+checks


def minimal_policy(policy):
    if not isinstance(policy, dict) or policy.get("driver") != "colima" or policy.get("profile") != "effigy":
        raise ValueError("unsupported production service policy")
    if policy.get('share_runtime_identity', False) is not False:
        raise ValueError('shared runtime identity is forbidden')
    services = policy.get("services")
    if not isinstance(services, dict) or services.get("silo") != {"catalog": "silo"} or services.get("silo_client") != {"catalog": "silo-mc"}:
        raise ValueError("production Silo declarations changed")
    if (policy.get('host') != {'publish_address':'127.0.0.1'}
            or policy.get('working_dir') != '/' or policy.get('startup') != 'detached'
            or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,100}', policy.get('project_name', ''))):
        raise ValueError('unsafe production service scope')
    result = {key: policy[key] for key in ("driver", "profile", "startup", "project_name", "working_dir", "host")}
    result.update(primary_service="silo", services={name: services[name] for name in ("silo", "silo_client")}, host_processes=[])
    return result


def scope_identity(report, checkout, fixture, expected_kind, revision, policy, diagnostics=None):
    if diagnostics is not None:diagnostics.append("native_scope_observation", **native_identity_observation(report))
    """Bind one native query to a caller-created Git checkout before effects."""
    import os
    import subprocess
    from pathlib import Path
    checkout, fixture = Path(checkout), Path(fixture)
    if checkout.resolve(strict=True) != checkout or fixture.resolve(strict=True) != fixture:
        raise ValueError('noncanonical_fixture')
    checkout.relative_to(fixture)
    for path in (checkout, *checkout.parents):
        if path.stat().st_uid != os.getuid() or path.is_symlink():
            raise ValueError('foreign_fixture_owner')
        if path == fixture: break
    def git(*args):
        process = subprocess.run(['git', '-C', str(checkout), *args], capture_output=True, text=True, timeout=10)
        if process.returncode: raise ValueError('git_identity_unavailable')
        return process.stdout.strip()
    if git('rev-parse', '--show-toplevel') != str(checkout) or git('rev-parse', 'HEAD') != revision:
        raise ValueError('git_source_mismatch')
    git_dir = Path(git('rev-parse', '--absolute-git-dir')).resolve(strict=True)
    git_dir.relative_to(fixture)
    if expected_kind == 'none':
        if git_dir != checkout / '.git' or not (checkout / '.git').is_dir():
            raise ValueError('primary_git_identity_mismatch')
    elif expected_kind == 'worktree':
        if not (checkout / '.git').is_file() or git_dir.parent.name != 'worktrees':
            raise ValueError('worktree_git_identity_mismatch')
    else:
        raise ValueError('unsupported_fixture_kind')
    if (not isinstance(report, dict) or report.get('schema') != 'effigy.container.scope.v1'
            or report.get('schema_version') != 1 or report.get('ok') is not True
            or report.get('checkout') != str(checkout)):
        raise ValueError('scope_contract_mismatch')
    scope = report.get('scope')
    if not isinstance(scope, dict) or scope.get('kind') != expected_kind or 'token' not in scope:
        raise ValueError('scope_kind_mismatch')
    token = scope['token']
    if expected_kind == 'none':
        if token is not None: raise ValueError('primary_token_mismatch')
        project = policy['project_name']
    else:
        if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{32}', token):
            raise ValueError('scoped_token_missing')
        project = policy['project_name'] + '-wt-' + token[:12]
    if policy.get('share_runtime_identity', False) is not False:
        raise ValueError('shared_identity_forbidden')
    return {'checkout':str(checkout), 'kind':expected_kind, 'token':token,
            'project':project, 'reference_source':revision}


def compose_identity(raw, status, identity, diagnostics=None):
    if diagnostics is not None:diagnostics.append("compose_identity_input", input_bytes=len(raw),input_sha256=hashlib.sha256(raw).hexdigest(),status=native_identity_observation(status),ownership_credit=False)
    """Strict branch-specific labels; observations confer no cleanup authority."""
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('malformed_compose_encoding') from None
    projects = re.findall(r'(?m)^\s*com\.effigy\.project:\s*([a-z0-9-]+)\s*$', text)
    scopes = re.findall(r'(?m)^\s*com\.effigy\.scope:\s*([a-f0-9]{32})\s*$', text)
    if (len(projects) != text.count('com.effigy.project') or not projects
            or set(projects) != {identity['project']} or status.get('project_name') != identity['project']):
        raise ValueError('project_label_mismatch')
    if identity['kind'] == 'none':
        if identity['token'] is not None or text.count('com.effigy.scope'):
            raise ValueError('primary_foreign_scope_label')
    elif identity['kind'] == 'worktree':
        if (not scopes or len(scopes) != text.count('com.effigy.scope')
                or set(scopes) != {identity['token']}):
            raise ValueError('scoped_label_mismatch')
    else:
        raise ValueError('unknown_identity_kind')
    return {'project':identity['project'], 'scope_kind':identity['kind'], 'scope':identity['token']}


def hosts_projection(hosts, checkout, identity=None, diagnostics=None):
    if diagnostics is not None:diagnostics.append("native_hosts_observation", **native_identity_observation(hosts))
    from pathlib import Path
    if (not isinstance(hosts, dict) or hosts.get('schema') != 'effigy.container.hosts.v1'
            or hosts.get('ok') is not True or hosts.get('checkout') != str(Path(checkout).resolve())):
        raise ValueError('foreign or unsupported hosts contract')
    if identity is not None:
        scope = hosts.get('scope', {})
        expected_host_kind = 'primary' if identity['kind'] == 'none' else identity['kind']
        if (scope.get('kind') != expected_host_kind or scope.get('token') != identity['token']
                or (identity['kind'] != 'none' and scope.get('shared_runtime_identity') is not False)):
            raise ValueError('hosts_scope_mismatch')
    routes = hosts.get('routes')
    if not isinstance(routes, list):
        raise ValueError('malformed hosts inventory')
    safe = []
    for route in routes:
        if not isinstance(route, dict) or route.get('kind') != 'tcp' or route.get('service') != 'silo':
            raise ValueError('unexpected service or application route')
        names = {key: route.get(key) for key in ('declared', 'effective')}
        if any(not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,200}', value) for value in names.values()):
            raise ValueError('unsafe effective hostname')
        safe.append({'kind':'tcp', 'service':'silo', **names})
    return safe


def toml_value(value):
    if isinstance(value, str):
        return json.dumps(value)
    if type(value) is bool:
        return str(value).lower()
    if type(value) is int:
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(json.dumps(key) + " = " + toml_value(item) for key, item in value.items()) + " }"
    raise ValueError("unsupported service policy value")


def invocation(binary, checkout, args):
    arguments = list(args)
    prefix = [binary]
    if '--json' in arguments:
        arguments.remove('--json')
        prefix.append('--json')
    # Exact-source global CLI rejects --repo for Gateway before execution.
    # Gateway ownership is selected explicitly by its private state root.
    if arguments and arguments[0] == 'gateway':
        if '--private-state-root' not in arguments:
            raise ValueError('gateway diagnosis requires explicit private state')
    else:
        prefix.extend(['--repo', str(checkout)])
    return prefix + arguments


def minimal_manifest(policy):
    return ('[containers.hybrid_services]\n'
            + '\n'.join(json.dumps(key) + ' = ' + toml_value(value) for key, value in policy.items()) + '\n')


def shell_command(command, marker='UNDERLAY_STORAGE'):
    if not re.fullmatch(r'[A-Z0-9_]{8,80}',marker): raise ValueError('invalid_shell_marker')
    return ('printf "'+marker+'_BEGIN\\n"; set +e; ( '+command+' ); storage_code=$?; '
            'printf "\\n'+marker+'_END=%s\\n" "$storage_code"; exit "$storage_code"')


def shell_region(output, marker):
    begin=marker+'_BEGIN\n'; end_pattern=r'(?m)^'+re.escape(marker)+r'_END=([0-9]{1,3})$'
    ends=list(re.finditer(end_pattern,output))
    if output.count(begin)!=1 or len(ends)!=1 or int(ends[0].group(1))>255:
        raise ValueError('shell_framing_unknown')
    start=output.index(begin)+len(begin);end=ends[0].start()
    if end<start or not output[start:end].endswith('\n'): raise ValueError('shell_framing_unknown')
    return output[start:end-1], int(ends[0].group(1))


def nested_exit(output):
    try:
        _,code=shell_region(output,'UNDERLAY_STORAGE')
        return {'inner_exit':code,'inner_exit_evidence':'shell_marker'}
    except ValueError: return {'inner_exit':None,'inner_exit_evidence':'unknown'}


def file_producer(path,payload):
    import shlex
    return 'set -eu; set -C; printf %s '+shlex.quote(payload.decode('ascii'))+' > '+shlex.quote(str(path))


def correlate(shell, request, journal, port, key, nonce):
    import shlex
    if key not in ('main-known.txt','first-known.txt') or not re.fullmatch(r'[a-f0-9]{32}',nonce):
        raise ValueError('unknown_correlation_challenge')
    bucket='underlay-storage-correlation'
    client_key=nonce+'-'+key;host_key=nonce+'-host-'+key
    payload=('client:'+client_key).encode();reverse=('host:'+host_key).encode()
    journal.append('mc_alias',**alias_projection(shell('alias',mc_command(['alias','list','local'],json_output=True)),journal))
    # No ignore-existing: this attempt must own fresh storage.
    operation_projection(shell('bucket',mc_command(['mb',f'local/{bucket}'],json_output=True)),'bucket',f'local/{bucket}',diagnostics=journal)
    file='/tmp/underlay-correlation-'+nonce+'-'+key
    shell('producer',file_producer(file,payload))
    operation_projection(shell('consumer',mc_command(['pipe',f'local/{bucket}/{client_key}'],json_output=True)+' < '+shlex.quote(file)),'pipe',f'local/{bucket}/{client_key}',len(payload),journal)
    journal.append('mc_stat',**stat_projection(shell('stat',mc_command(['stat',f'local/{bucket}/{client_key}'],json_output=True)),client_key,len(payload),journal))
    def read_exact(service, alias, object_key, expected, label):
        value=shell(label,mc_command(['cat',f'{alias}/{bucket}/{object_key}'],service),service=service).encode()
        journal.append(label,body_bytes=len(value),bytes_match=value==expected,body_sha256=hashlib.sha256(value).hexdigest())
        if value!=expected: raise ValueError('byte_correspondence_refused')
    read_exact('silo','local',client_key,payload,'server_read_client_write')
    status,_,body=request(port,'GET',f'/{bucket}/{client_key}',diagnostics=journal,
                          diagnostic_operation='client_write_host_get',diagnostic_path_template='/<bucket>/<known-object>')
    journal.append('host_get',status=status,body_bytes=len(body),bytes_match=body==payload,**(s3_error(body) if status>=400 else {}))
    if status!=200 or body!=payload: raise ValueError('host_byte_correspondence_refused')
    status,_,body=request(port,'PUT',f'/{bucket}/{host_key}',reverse,diagnostics=journal,
                          diagnostic_operation='host_put',diagnostic_path_template='/<bucket>/<host-object>')
    if status!=200: raise ValueError('host_write_refused')
    read_exact('silo','local',host_key,reverse,'server_read_host_write')
    read_exact('silo_client','local',host_key,reverse,'client_read_host_write')
    return {'port':port,'bucket':bucket,'keys':[client_key,host_key],
            'payloads':[payload,reverse]}


def cross_scope(request,journal,own,foreign):
    for key,payload in zip(own['keys'],own['payloads']):
        status,_,body=request(own['port'],'GET',f"/{own['bucket']}/{key}",diagnostics=journal,
                             diagnostic_operation='own_key_survival',diagnostic_path_template='/<bucket>/<own-object>')
        if status!=200 or body!=payload: raise ValueError('own_key_survival_refused')
    for key in foreign['keys']:
        status,_,body=request(own['port'],'GET',f"/{own['bucket']}/{key}",diagnostics=journal,
                             diagnostic_operation='cross_scope_get',diagnostic_path_template='/<bucket>/<foreign-object>')
        error=s3_error(body);journal.append('cross_scope_result',status=status,**error)
        if status!=404 or error.get('error_code')!='NoSuchKey':raise ValueError('cross_scope_isolation_unproven')


def capture_contract(source):
    from pathlib import Path
    snippets={
      'src/runner/container_command/bounded_exec.rs':('effigy.container.bounded-exec.v1','"preparation"','"remote_cancellation"'),
      'src/runner/exec_command/bounded.rs':('BoundedCommandBudget','preparation_stdout_retained','stdout_remaining'),
    }
    digests={}
    for relative,required in snippets.items():
        raw=(Path(source)/relative).read_bytes();text=raw.decode()
        if any(part not in text for part in required):raise ValueError('capture_source_unrecognized')
        digests[relative]=hashlib.sha256(raw).hexdigest()
    return {'classification':'reviewed_native_bounded_capture','inner_byte_cap_demonstrated':True,
            'outer_pipe_cap_sufficient':False,'source_files_sha256':digests}


from dev.silo_client import BOUNDS, BOUND_FAILURES, bounded_arguments, bounded_payload
