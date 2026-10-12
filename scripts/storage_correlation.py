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


def alias_projection(output):
    record = json_records(output)[0]
    allowed = {'status','alias','URL','accessKey','secretKey','api','path','src'}
    if set(record) != allowed or record.get('status') != 'success' or record.get('alias') != 'local':
        raise ValueError('alias_shape_refused')
    if (record['URL'] != 'http://silo:9000' or record['api'] != 'S3v4'
            or record['path'] != 'auto' or record['src'] != '/root/.mc/config.json'
            or record['accessKey'] != 'minioadmin' or record['secretKey'] != 'minioadmin'):
        raise ValueError('alias_config_refused')
    return {'alias':'local', 'endpoint':'http://silo:9000',
            'config_scope':'client-container:/root/.mc', 'credentials_recorded':False}


def stat_projection(output, key=None, size=None):
    record = json_records(output)[0]
    allowed = {'status','name','lastModified','size','etag','type','expires',
               'expiration','expirationRuleID','replicationStatus','metadata',
               'versionID','deleteMarker','restore','checksum'}
    if (not set(record) <= allowed or not {'status','name','lastModified','size','etag','type'} <= set(record)
            or record['status'] != 'success' or record['type'] != 'file'
            or type(record['size']) is not int or not 0 <= record['size'] <= 1048576
            or not isinstance(record['name'], str)
            or (key is not None and record['name'] != key)
            or (size is not None and record['size'] != size)):
        raise ValueError('stat_shape_refused')
    return {'status':'success', 'size':record['size'], 'type':'file'}


def running(status):
    if not isinstance(status, str): return False
    lowered = status.lower()
    return not any(x in lowered for x in ('exited','created','dead','paused')) and any(x in lowered for x in ('up','running'))


def status_projection(status, identity, bindings, after_down=False):
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
    if len(rows) != 2 or {r.get('name') for r in rows if isinstance(r,dict)} != {'silo','silo_client'}:
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
        for port in row['ports']:
            # Pinned backend preserves docker/nerdctl .Ports strings; no ranges,
            # wildcard binds or unknown representations receive credit.
            match=re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})->([0-9]{1,5})/tcp',port) if isinstance(port,str) else None
            if not match: raise ValueError('live_port_representation_unknown')
            host,target=map(int,match.groups())
            if not 1 <= host <= 65535 or not 1 <= target <= 65535: raise ValueError('live_port_invalid')
            published.append((row['name'],host,target))
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


def scope_identity(report, checkout, fixture, expected_kind, revision, policy):
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


def compose_identity(raw, status, identity):
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


def hosts_projection(hosts, checkout, identity=None):
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
    journal.append('mc_alias',**alias_projection(shell('alias','mc alias list --json local')))
    # No ignore-existing: this attempt must own fresh storage.
    shell('bucket',f'mc mb local/{bucket}')
    file='/tmp/underlay-correlation-'+nonce+'-'+key
    shell('producer',file_producer(file,payload))
    shell('consumer',f'mc pipe local/{bucket}/{client_key} < '+shlex.quote(file))
    journal.append('mc_stat',**stat_projection(shell('stat',f'mc stat --json local/{bucket}/{client_key}'),client_key,len(payload)))
    def read_exact(service, alias, object_key, expected, label):
        value=shell(label,f'mc cat {alias}/{bucket}/{object_key}',service=service).encode()
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


BOUNDS={'deadline_ms':8000,'stdout_limit_bytes':65536,'stderr_limit_bytes':16384}
BOUND_FAILURES={'deadline','stdout_overflow','stderr_overflow','read_failure','incomplete_output',
                'launch_failed','inner_command_failed','runtime_identity_mismatch','workspace_preparation_failed'}


def bounded_arguments(service,command):
    if service not in ('silo','silo_client'):raise ValueError('bounded_service_refused')
    return ['container','hybrid_services','shell','--service',service,'--command',command,'--bounded',
            '--deadline-ms',str(BOUNDS['deadline_ms']),'--stdout-limit-bytes',str(BOUNDS['stdout_limit_bytes']),
            '--stderr-limit-bytes',str(BOUNDS['stderr_limit_bytes']),'--json']


def bounded_payload(output,outer_exit,service):
    envelope=strict_json(output)
    if (not isinstance(envelope,dict) or envelope.get('schema')!='effigy.command.v1'
            or envelope.get('schema_version')!=1 or type(envelope.get('ok')) is not bool):
        raise ValueError('bounded_envelope_refused')
    value=envelope.get('result') if envelope['ok'] else envelope.get('error',{}).get('details')
    if (not isinstance(value,dict) or value.get('schema')!='effigy.container.bounded-exec.v1'
            or value.get('schema_version')!=1 or type(value.get('ok')) is not bool
            or value['ok'] != envelope['ok'] or value.get('remote_cancellation')!='unverified'):
        raise ValueError('bounded_schema_refused')
    failure=value.get('failure');success=failure=='complete'
    if (failure not in BOUND_FAILURES and not success) or success!=value['ok'] or (outer_exit==0)!=success:
        raise ValueError('bounded_status_refused')
    if value.get('container')!='hybrid_services' or value.get('service')!=service:
        if not (failure=='launch_failed' and value.get('container')==value.get('service')=='[redacted]'):
            raise ValueError('bounded_selection_refused')
    limits=value.get('limits') if success else value.get('limits',BOUNDS)
    if limits!=BOUNDS:raise ValueError('bounded_limits_refused')
    retained=value.get('retained');preparation=value.get('preparation')
    if not isinstance(retained,dict) or not isinstance(preparation,dict) or not isinstance(preparation.get('retained'),dict):
        raise ValueError('bounded_accounting_refused')
    attempts=value.get('attempts');captures=preparation.get('captures')
    if type(attempts) is not int or not 0<=attempts<=2 or type(captures) is not int or not 0<=captures<=100:
        raise ValueError('bounded_accounting_refused')
    if type(value.get('workspace_user_fallback')) is not bool or value['workspace_user_fallback']!=(attempts>1):
        raise ValueError('bounded_accounting_refused')
    projection={'failure':failure,'attempts':attempts,'preparation_captures':captures,'remote_cancellation':'unverified','bounds':dict(BOUNDS)}
    for stream in ('stdout','stderr'):
        count=retained.get(stream+'_bytes');prep=preparation['retained'].get(stream+'_bytes');limit=BOUNDS[stream+'_limit_bytes']
        if type(count) is not int or type(prep) is not int or not 0<=prep<=count<=limit:
            raise ValueError('bounded_accounting_refused')
        projection[stream+'_retained_bytes']=count;projection['preparation_'+stream+'_bytes']=prep
        if success:
            raw=value.get(stream);command_count=value.get(stream+'_bytes')
            if not isinstance(raw,str) or type(command_count) is not int or len(raw.encode())!=command_count or count!=prep+command_count:
                raise ValueError('bounded_accounting_refused')
            projection['command_'+stream+'_bytes']=command_count
    if success:
        if value.get('code')!=0 or attempts<1:raise ValueError('bounded_status_refused')
        return value['stdout'],projection
    phase=value.get('phase')
    if failure!='inner_command_failed':
        if phase not in ('runtime_discovery','workspace_preparation','command_execution') or value.get('termination_scope')!='owned_host_client_group':
            raise ValueError('bounded_phase_refused')
        projection['phase']=phase
    elif type(value.get('inner_code')) is not int or value['inner_code']==0:
        raise ValueError('bounded_status_refused')
    else:projection['inner_code']=value['inner_code']
    return None,projection
