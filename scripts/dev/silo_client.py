"""Production-owned finite Silo recipe and native bounded command contract."""
import json
import re
import secrets
import shlex

CAPTURE_LIMIT=262144


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



ROUTING_OVERRIDES = ('MC_RESOLVE','MC_INSECURE','MC_DEBUG','MC_JSON','MC_QUIET','MC_NO_COLOR','MC_DISABLE_PAGER','MC_LIMIT_UPLOAD','MC_LIMIT_DOWNLOAD','MC_PROFILER','MC_ENC_KMS','MC_ENC_S3','MC_CONFIG_DIR','MC_CONFIG_ENV_FILE','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY',
                     'http_proxy','https_proxy','all_proxy','NO_PROXY','no_proxy')


BOUNDS={'deadline_ms':8000,'stdout_limit_bytes':65536,'stderr_limit_bytes':16384}
BOUND_FAILURES={'deadline','stdout_overflow','stderr_overflow','read_failure','incomplete_output',
                'launch_failed','inner_command_failed','runtime_identity_mismatch','workspace_preparation_failed'}


def bounded_arguments(service,command,container="hybrid_services"):
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}",container):raise ValueError("bounded_container_refused")
    if service not in ('silo','silo_client'):raise ValueError('bounded_service_refused')
    return ['container',container,'shell','--service',service,'--command',command,'--bounded',
            '--deadline-ms',str(BOUNDS['deadline_ms']),'--stdout-limit-bytes',str(BOUNDS['stdout_limit_bytes']),
            '--stderr-limit-bytes',str(BOUNDS['stderr_limit_bytes']),'--json']


def refusal_observations(value, failure):
    """Exact bd259769 additive host diagnostics; never remote effect authority."""
    if value is None:
        return None  # legacy absence is unavailable, never an observed zero
    fields={'version','operation_elapsed_ms','remaining_budget_ms','preparation_elapsed_ms',
            'attempt_elapsed_ms','spawn_disposition','stdout','stderr','leader_exit_observed'}
    if type(value) is not dict or set(value)!=fields or type(value['version']) is not int or value['version']!=1:
        raise ValueError('bounded_observations_refused')
    if failure in ('complete','inner_command_failed'):
        raise ValueError('bounded_observations_phase_refused')
    for key in ('operation_elapsed_ms','remaining_budget_ms','preparation_elapsed_ms','attempt_elapsed_ms'):
        count=value[key]
        if count is None and key in ('preparation_elapsed_ms','attempt_elapsed_ms'):continue
        if type(count) is not int or not 0<=count<=2**64-1:raise ValueError('bounded_observation_clock_refused')
    if value['remaining_budget_ms']>BOUNDS['deadline_ms']:
        raise ValueError('bounded_observation_clock_refused')
    if value['spawn_disposition'] not in ('not_attempted','attempted_not_confirmed','spawned','unknown') or value['leader_exit_observed'] not in ('alive','unknown'):
        raise ValueError('bounded_observation_spawn_refused')
    for stream in ('stdout','stderr'):
        entry=value[stream]
        if type(entry) is not dict or set(entry)!={'state','retained_prefix_bytes','read_bytes'} or entry['state'] not in ('pending','eof','overflow','read_error','unknown'):
            raise ValueError('bounded_observation_stream_refused')
        counts={}
        for key in ('retained_prefix_bytes','read_bytes'):
            item=entry[key]
            if type(item) is not dict:raise ValueError('bounded_observation_bytes_refused')
            if item=={'semantics':'unknown'}:continue
            if set(item)!={'semantics','bytes'} or item['semantics'] not in ('exact','lower_bound') or type(item['bytes']) is not int or not 0<=item['bytes']<=2**64-1:
                raise ValueError('bounded_observation_bytes_refused')
            counts[key]=item
        retained=counts.get('retained_prefix_bytes');read=counts.get('read_bytes')
        if retained and retained['bytes']>BOUNDS[stream+'_limit_bytes']:
            raise ValueError('bounded_observation_retention_refused')
        # A read witness can exceed retention. It is diagnostic, never usable output.
        if retained and read and read['semantics']=='exact' and retained['bytes']>read['bytes']:
            raise ValueError('bounded_observation_bytes_refused')
    return value


def bounded_payload(output,outer_exit,service,container="hybrid_services"):
    envelope=strict_json(output)
    if (not isinstance(envelope,dict) or envelope.get('schema')!='effigy.command.v1'
            or type(envelope.get('schema_version')) is not int or envelope.get('schema_version')!=1 or type(envelope.get('ok')) is not bool):
        raise ValueError('bounded_envelope_refused')
    value=envelope.get('result') if envelope['ok'] else envelope.get('error',{}).get('details')
    if (not isinstance(value,dict) or value.get('schema')!='effigy.container.bounded-exec.v1'
            or type(value.get('schema_version')) is not int or value.get('schema_version')!=1 or type(value.get('ok')) is not bool
            or value['ok'] != envelope['ok'] or value.get('remote_cancellation')!='unverified'):
        raise ValueError('bounded_schema_refused')
    failure=value.get('failure');success=failure=='complete'
    observed=refusal_observations(value.get('refusal_observations'),failure)
    if 'refusal_observations' in value and observed is None:raise ValueError('bounded_observations_refused')
    if (failure not in BOUND_FAILURES and not success) or success!=value['ok'] or (outer_exit==0)!=success:
        raise ValueError('bounded_status_refused')
    if value.get('container')!=container or value.get('service')!=service:
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
    if observed is not None:projection['refusal_observations']=observed
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


def mc_command(arguments, service='silo_client', json_output=False):
    import shlex
    if service not in ('silo_client','silo'):raise ValueError('guard_service_refused')
    # Trusted diagnostic recipe only; HOME binding still precedes initialization.
    prefix=['mc']+(['--config-dir','/root/.mc'] if service=='silo_client' else [])
    if json_output:prefix.append('--json')
    return ' '.join(shlex.quote(x) for x in prefix+list(arguments))


# This private capability names the shared command binding, not native/image
# HOME provenance. Baselines cannot authorize arbitrary supplied HOME values.
OWNER_CLIENT_COMMAND_INPUT = object()


def client_command_input(command, marker):
    return ('if test "${HOME+present}" != present; then underlay_home_state=absent; '
            'elif test -z "$HOME"; then underlay_home_state=empty; else underlay_home_state=present; fi; '
            'if test "${HOME-}" = /root; then underlay_home_agreement=1; else underlay_home_agreement=0; fi; '
            'HOME=/root; export HOME; '
            'if test "$HOME" = /root; then underlay_home_bound=1; else underlay_home_bound=0; fi; '
            "printf '"+marker+"_HOME|%s|%s|%s\\n' "+
            '"$underlay_home_state" "$underlay_home_agreement" "$underlay_home_bound"; '
            'test "$underlay_home_bound" = 1 || exit 1; '+command)


def client_input_projection(region, marker):
    line, separator, remainder = region.partition('\n')
    match = re.fullmatch(re.escape(marker)+r'_HOME\|(absent|empty|present)\|([01])\|1', line)
    if not separator or not match or (match[1]!='present' and match[2]!='0'):
        raise ValueError('client_command_input_refused')
    return remainder, {'inherited_presence':match[1], 'inherited_expected_agreement':match[2]=='1',
                       'input_presence':'present', 'input_expected_agreement':True,
                       'provenance':'owner_command_input', 'default_home_qualified':False}


def predicates(service):
    if service not in ('silo','silo_client'):
        raise ValueError('guard_service_refused')
    result=[(name,'expected_server_configdir' if service=='silo' and name=='MC_CONFIG_DIR' else 'absent') for name in ROUTING_OVERRIDES]
    result.append(('MC_HOST_local','expected_loopback_alias' if service=='silo' else 'absent'))
    result.append(('HOME','expected_home' if service=='silo_client' else 'expected_server_home'))
    return result


def guard_command(service):
    commands=['set -u']
    for name,rule in predicates(service):
        commands.append('if test "${'+name+'+present}" != present; then underlay_guard_state=absent; '
                        'elif test -z "$'+name+'"; then underlay_guard_state=empty; else underlay_guard_state=present; fi')
        condition=('test "${'+name+'+present}" != present' if rule=='absent' else
                   'test "${'+name+'+present}" = present && test "$'+name+'" = "'+
                   ('http://minioadmin:minioadmin@127.0.0.1:9000' if rule=='expected_loopback_alias' else '/tmp/.mc' if rule=='expected_server_configdir' else '/tmp' if rule=='expected_server_home' else '/root')+'"')
        commands.append('if '+condition+'; then underlay_guard_match=1; else underlay_guard_match=0; fi')
        commands.append("printf 'GUARD|"+name+"|%s|%s\\n' \"$underlay_guard_state\" \"$underlay_guard_match\"")
    # This finite diagnostic transport succeeds only to preserve all predicate
    # records in native bounded-exec success. Python still refuses any mismatch.
    return '; '.join(commands)


def guard_projection(region,service):
    expected=predicates(service)
    if len(region.encode())>4096:raise ValueError('guard_framing_refused')
    lines=region.splitlines()
    if len(lines)!=len(expected):raise ValueError('guard_framing_refused')
    result=[]
    for line,(name,rule) in zip(lines,expected):
        match=re.fullmatch('GUARD\\|'+re.escape(name)+r'\|(absent|empty|present)\|([01])',line)
        if not match:raise ValueError('guard_framing_refused')
        state,agreement=match.groups();passed=agreement=='1'
        if (rule=='absent' and passed!=(state=='absent')) or (rule!='absent' and passed and state!='present'):
            raise ValueError('guard_record_refused')
        result.append({'predicate':name,'rule':rule,'presence':state,'agreement':passed})
    return {'service':service,'predicates':result,'guard_passed':all(r['agreement'] for r in result),
            'evidence':'readonly_predicate_evaluation_not_environment_dump'}


def finite_shell(call,journal,label,command,service='silo_client',container='hybrid_services'):
    marker='UNDERLAY_'+secrets.token_hex(16).upper()
    if service not in ('silo','silo_client'):raise ValueError('guard_service_refused')
    if service=='silo_client':command=client_command_input(command,marker)
    try:
        output,outer=call(label,None,bounded_arguments(service,shell_command(command,marker),container),timeout=10)
    except Exception as error:
        classification=('timeout' if isinstance(error,TimeoutError) else 'spawn_refused' if isinstance(error,OSError)
                        else {'command_spawn_refused':'spawn_refused','command_capture_timeout':'timeout','command_capture_truncated':'truncated'}.get(str(error),'dispatch_refused'))
        journal.append('shell_dispatch',operation=label,service=service,classification=classification,
                       guard_evidence='not_reached')
        raise ValueError('guard_dispatch_refused') from None
    try:
        output,projection=bounded_payload(output,outer,service,container)
    except (ValueError,TypeError,KeyError):
        journal.append('shell_dispatch',operation=label,service=service,classification='native_envelope_refused',
                       outer_exit=outer if type(outer) is int and -255<=outer<=255 else None,guard_evidence='not_reached')
        raise ValueError('bounded_envelope_refused') from None
    journal.append('native_bounded_completion',operation=label,service=service,**projection)
    if output is None:
        journal.append('shell_dispatch',operation=label,service=service,classification=projection['failure'],
                       guard_evidence='unavailable_native_failure_omits_command_bytes')
        raise ValueError('native_bounded_refusal')
    try:region,inner=shell_region(output,marker)
    except ValueError:
        journal.append('shell_dispatch',operation=label,service=service,classification='marker_refused',guard_evidence='not_reached')
        raise ValueError('guard_framing_refused') from None
    journal.append('shell_completion',operation=label,service=service,inner_exit=inner,outer_exit=outer,
                   region_bytes=len(region.encode()),framing='unique_marker')
    if outer!=0 or inner!=0:raise ValueError('shell_operation_refused')
    if service=='silo_client':
        try:region,input_record=client_input_projection(region,marker)
        except ValueError:
            journal.append('client_command_input',operation=label,classification='input_framing_refused')
            raise
        journal.append('client_command_input',operation=label,service=service,**input_record)
    return region


def evaluate_guard(shell,journal,service):
    region=shell('routing_environment_guard',guard_command(service),service=service)
    try:projection=guard_projection(region,service)
    except ValueError:
        journal.append('routing_guard',service=service,classification='malformed_predicate_evidence')
        raise
    journal.append('routing_guard',classification='predicates_complete',**projection)
    if not projection['guard_passed']:raise ValueError('routing_guard_refused')
    return projection


def json_records(output):
    # Callers pass exactly the unique shell-framed region, never human headers.
    if len(output.encode()) > CAPTURE_LIMIT:
        raise ValueError('mc_output_truncated')
    record = strict_json(output)
    if not isinstance(record, dict):
        raise ValueError('invalid_mc_record')
    return [record]




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
            'recipe_provenance':'explicit_recipe_not_inherited_default'}
