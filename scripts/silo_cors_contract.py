"""One source-admitted, service-only CORS observation. Never starts applications."""
import hashlib,json,os,re,sys,time
from pathlib import Path
import xml.etree.ElementTree as ET
from qualification_runtime import require_effigy_binary,SUPPORTED_EFFIGY_SOURCE,SUPPORTED_EFFIGY_SHA256
from original_container_route import read_small
from container_identity_observer import Refusal,identity
from service_baseline_handoff import write
from storage_correlation import minimal_policy,minimal_manifest,strict_json
from private_caller_environment import construct
from fresh_backend_admission import FreshBackend,selected_tools
from reference_storage_probe import StorageDiagnosticJournal
import storage_observation as storage

DEADLINE=None # Bound once by the immutable caller/control intent, never renewed.
SIGNED_HEADERS=('authorization','x-amz-content-sha256','x-amz-date')
NS='http://s3.amazonaws.com/doc/2006-03-01/'


def policy_facts(raw,origins):
    """Strict bounded MC cors get XML; only closed facts escape memory."""
    if type(raw) is not str or len(raw.encode())>65536 or '<!' in raw or len(origins)!=2 or len(set(origins))!=2:
        raise Refusal('cors_policy_schema')
    raw=re.sub(r'^\s*<\?xml version="1.0" encoding="UTF-8"\?>\s*','',raw)
    if '<?' in raw:raise Refusal('cors_policy_schema')
    try:root=ET.fromstring(raw)
    except (ET.ParseError,ValueError):raise Refusal('cors_policy_schema') from None
    prefix='{'+NS+'}' if root.tag=='{'+NS+'}CORSConfiguration' else ''
    def tag(node):
        if node.attrib or not isinstance(node.tag,str) or not node.tag.startswith(prefix):raise Refusal('cors_policy_schema')
        return node.tag[len(prefix):]
    if tag(root)!='CORSConfiguration' or not 1<=len(root)<=100 or (root.text or '').strip():raise Refusal('cors_policy_schema')
    rows=[]
    def match(pattern,value):
        if pattern.count('*')>1 or '?' in pattern:raise Refusal('cors_policy_schema')
        if '*' not in pattern:return pattern==value
        first,last=pattern.split('*');return len(value)>=len(first)+len(last) and value.startswith(first) and value.endswith(last)
    for rule in root:
        if tag(rule)!='CORSRule' or (rule.text or '').strip() or (rule.tail or '').strip() or not 1<=len(rule)<=128:raise Refusal('cors_policy_schema')
        fields={}
        for node in rule:
            name=tag(node)
            if name not in ('ID','AllowedOrigin','AllowedMethod','AllowedHeader','ExposeHeader','MaxAgeSeconds') or len(node) or (node.tail or '').strip():raise Refusal('cors_policy_schema')
            value=node.text or ''
            if not value or len(value)>2048:raise Refusal('cors_policy_schema')
            fields.setdefault(name,[]).append(value)
        if any(len(fields.get(k,[]))>1 for k in ('ID','MaxAgeSeconds')):raise Refusal('cors_policy_schema')
        if 'MaxAgeSeconds' in fields and (not re.fullmatch('[0-9]+',fields['MaxAgeSeconds'][0]) or int(fields['MaxAgeSeconds'][0])>2147483647):raise Refusal('cors_policy_schema')
        allowed=fields.get('AllowedOrigin',[]);methods=fields.get('AllowedMethod',[]);headers=fields.get('AllowedHeader',[])
        if not allowed or not methods or any(m not in ('GET','HEAD','PUT','POST','DELETE') for m in methods):raise Refusal('cors_policy_schema')
        origins_ok=[any(match(p,o) for p in allowed) for o in origins]
        header_ok=[any(match(p.lower(),h) for p in headers) for h in SIGNED_HEADERS]
        foreign=any(match(p,'https://foreign.invalid') for p in allowed)
        rows.append(dict(origin_count=len(allowed),front_matches=origins_ok[0],admin_matches=origins_ok[1],
            intended_origin_set_equal=set(allowed)==set(origins),method_count=len(methods),
            get_allowed='GET' in methods,head_allowed='HEAD' in methods,put_allowed='PUT' in methods,
            header_rule_count=len(headers),header_wildcard='*' in headers,signed_header_matches=header_ok,
            request_matches=origins_ok[0] and 'PUT' in methods and all(header_ok),
            foreign_request_matches=foreign and 'PUT' in methods and all(header_ok)))
    return dict(schema='underlay.cors-policy-facts.v1',rule_count=len(rows),rules=rows,
                request_matches=any(r['request_matches'] for r in rows),foreign_matches=any(r['foreign_request_matches'] for r in rows))


def read_policy(client,call,journal,bucket,origins,container="hybrid_services"):
    if not re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',bucket):raise Refusal('cors_bucket_input')
    xml=client.finite_shell(call,journal,'cors_get',client.mc_command(['cors','get','local/'+bucket]),container=container)
    facts=policy_facts(xml,origins)
    journal.append('cors_policy_readback',observation=facts)
    return facts


def require_policy(client,call,journal,bucket,origins,container='hybrid_services'):
    o=storage.Operation('observe_silo_policy','cors_policy_readback',emit=journal.append)
    try:facts=read_policy(client,call,journal,bucket,origins,container)
    except Refusal:
        o.fail('cors_policy_schema',policy_schema_valid=False)
    rules=facts['rules']
    predicates=dict(policy_schema_valid=True,
        policy_origin_matches=facts['rule_count']==1 and all(r['intended_origin_set_equal'] and r['origin_count']==2 for r in rules),
        policy_methods_match=all(r['get_allowed'] and r['head_allowed'] and r['put_allowed'] for r in rules),
        policy_headers_match=all(all(r['signed_header_matches']) for r in rules),
        policy_foreign_ungranted=not facts['foreign_matches'])
    o.check(all(predicates.values()),'cors_policy',**predicates);o.finish()
    return facts


def preflight(port,bucket,origin,journal):
    response,o=storage.request('prove_silo','cors_allowed','127.0.0.1',port,'/'+bucket+'/cors-probe',method='OPTIONS',
        headers={'Origin':origin,'Access-Control-Request-Method':'PUT','Access-Control-Request-Headers':','.join(SIGNED_HEADERS)},emit=journal.append)
    status,headers,body=response;o.facts.update(storage.cors_facts(headers,origin));o.publish('status');o.finish()
    result=dict(status=status,facts=dict(o.facts),positive=status==200 and all(o.facts[k] for k in ('origin_matches','method_allowed','headers_allowed')))
    journal.append('cors_preflight_result',**result)
    if status==403:
        response,f=storage.request('prove_silo','cors_foreign','127.0.0.1',port,'/'+bucket+'/foreign-probe',method='OPTIONS',
            headers={'Origin':'https://foreign.invalid','Access-Control-Request-Method':'PUT','Access-Control-Request-Headers':','.join(SIGNED_HEADERS)},emit=journal.append)
        code,h,_=response;f.facts.update(storage.cors_facts(h,'https://foreign.invalid'));f.finish()
        journal.append('cors_foreign_result',status=code,facts=dict(f.facts))
    return result


def main():
    global DEADLINE
    import importlib.util
    def load(name,file):
        spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
    old=load('cors_service_helpers','qualify-storage-correlation.py');OPT=old.OPT;DEV=old.DEV;R=OPT.RUNTIME
    binary=require_effigy_binary();OPT.EFFIGY=OPT.REFERENCE.EFFIGY=R.EFFIGY=binary
    intent_path=Path(os.environ['UNDERLAY_SILO_CORS_INTENT']);raw=read_small(intent_path);intent=strict_json(raw)
    DEADLINE=intent.get('deadline_at')
    if type(DEADLINE) not in (int,float) or not time.time()<DEADLINE<=time.time()+14400:raise Refusal('cors_clock_refused')
    if hashlib.sha256(raw).hexdigest()!=os.environ['UNDERLAY_SILO_CORS_INTENT_SHA256'] or intent.get('schema')!='underlay.service-cors-intent.v1' or intent.get('source')!=SUPPORTED_EFFIGY_SOURCE or intent.get('binary_sha256')!=SUPPORTED_EFFIGY_SHA256:raise Refusal('cors_intent_refused')
    clock_raw=read_small(Path(os.environ['UNDERLAY_PROFILE_BATCH_INTENT']));clock=strict_json(clock_raw)
    if (hashlib.sha256(clock_raw).hexdigest()!=os.environ['UNDERLAY_PROFILE_BATCH_INTENT_SHA256']
        or clock.get('schema')!='underlay.product-batch-intent.v1' or clock.get('stages')!=['runtime','container']
        or clock.get('head')!=intent['head'] or clock.get('source')!=intent['source']
        or clock.get('binary_sha256')!=intent['binary_sha256'] or clock.get('controls_sha256')!=intent['controls_sha256']
        or clock.get('deadline_at')!=DEADLINE or clock.get('started_at')!=DEADLINE-14400):raise Refusal('cors_clock_refused')
    repo=Path(__file__).resolve().parents[1]
    def git(*args):return __import__('subprocess').run(['git',*args],cwd=repo,capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    if git('rev-parse','HEAD')!=intent['head'] or git('status','--porcelain'):raise Refusal('cors_source_changed')
    packet=intent_path.parent;identity(packet,True)
    controls_raw=read_small(packet/'controls.json')
    if hashlib.sha256(controls_raw).hexdigest()!=intent['controls_sha256'] or strict_json(controls_raw).get('deadline_at')!=DEADLINE:raise Refusal('cors_controls_changed')
    write(packet/'service-cors.started.json',packet,{'intent_sha256':hashlib.sha256(raw).hexdigest()})
    fixture=packet/'fixture';fixture.mkdir(mode=0o700)
    private,env_receipt=construct(os.environ);backend=FreshBackend(fixture,private);backend.bind_tools(*selected_tools());backend.require_read_contract()
    env=dict(backend.env,EFFIGY_COMPOSE_BACKEND='colima');OPT.REFERENCE.PRIVATE_CHILD_ENV=env;R.REFERENCE.PRIVATE_CHILD_ENV=env
    journal=StorageDiagnosticJournal(packet/'storage-diagnostics.jsonl',fixture);storage.configure(journal.append);backend.refusal_emit=journal.append;R.COMMAND_DIAGNOSTICS=journal
    gateway=fixture/'gateway';gateway.mkdir(mode=0o700);env['EFFIGY_GATEWAY_PRIVATE_STATE_ROOT']=str(gateway)
    checkout=backend.paths['HOME']/'reference';started=False;gateway_started=False;vm=False;phase='assembly';failure=None;observations={}
    def run(args,timeout=120,cwd=None):return R.run(args,cwd=cwd,env=env,timeout=min(timeout,max(.01,DEADLINE-time.time())),print_output=False)
    def native(*args):return run([binary,'--json','--repo',str(checkout),*args],cwd=checkout)
    def result(*args):
        x=strict_json(native(*args).stdout)
        if x.get('schema')!='effigy.command.v1' or x.get('ok') is not True or type(x.get('result')) is not dict:raise Refusal('cors_native_schema')
        return x['result']
    def gate_time(reserve=180):
        if time.time()+reserve>=DEADLINE:raise Refusal('cors_remaining_time')
    try:
        journal.append('cors_environment',observation=env_receipt);gate_time(480)
        source=OPT.REFERENCE.reference_source();run(['git','clone','--no-hardlinks','--local',str(source),str(checkout)])
        run(['git','-C',str(checkout),'checkout','--detach','fa6a5e89ad83db460a5506b7fa3f915fa767d72a'])
        OPT.REFERENCE.point_bundle_at_task_branch(checkout);OPT.enable_profiles(checkout,Path(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE']))
        selected=result('config','--inspect','--path','containers.hybrid_services')['selected_value']['value']
        # Supported original hosts supplies effective declared origin names only; no listeners start.
        hosts=result('container','hybrid_services','hosts');routes={}
        for role,declared in (('front','acme.test'),('admin','admin.acme.test')):
            matches=[r['effective'] for r in hosts['routes'] if r.get('declared')==declared]
            if len(matches)!=1:raise Refusal('cors_origin_context')
            routes[role]=matches[0]
        policy=minimal_policy(selected);(checkout/'effigy.toml').write_text(minimal_manifest(policy));DEV._prepare_silo_override(checkout)
        config=native('config','--inspect','--path','containers.hybrid_services');scope=native('container','scope')
        if strict_json(config.stdout)['result']['selected_value']['value']!=policy:raise Refusal('cors_composition')
        backend.original_scope(checkout,config.stdout.encode(),hashlib.sha256((repo/'export.toml').read_bytes()).hexdigest())
        backend.original_policy(checkout,'hybrid_services',config.stdout.encode(),scope.stdout.encode())
        journal.append('cors_service_composition',service_count=2,host_process_count=0,origin_count=len(routes),origin_distinct=len(set(routes.values()))==2)
        from service_defaults import baseline,image_defaults
        from routing_guard import OWNER_CLIENT_COMMAND_INPUT
        defaults=[baseline(image_defaults('pgsty/silo'),{'MC_HOST_local':'http://minioadmin:minioadmin@127.0.0.1:9000'},'silo',('/data',)),
                  baseline(image_defaults('pgsty/mc'),{},'silo_client',command_input=OWNER_CLIENT_COMMAND_INPUT)]
        for record in defaults:journal.append('service_default_baseline',**record)
        if not all(r['baseline_passed'] for r in defaults):raise Refusal('cors_image_defaults')
        phase='backend_start';gate_time(480);run(backend.start_command(env),timeout=1200);vm=True;backend.admit_original_route(env)
        # Retain source-qualified image pins; pull precisely those content-addressed
        # artifacts. No optional package/interface/provenance acquisition matrix.
        from silo_fixture import IMAGE,CLIENT_IMAGE
        colima=backend.prepared['tool_provenance']['colima']['path']
        arch=run([colima,'ssh','--profile','effigy','--','uname','-m'],timeout=8).stdout.strip()
        platform={'aarch64':'linux/arm64','x86_64':'linux/amd64'}.get(arch)
        if platform is None:raise Refusal('cors_image_platform')
        for image in (IMAGE,CLIENT_IMAGE):
            gate_time();run([colima,'nerdctl','--profile','effigy','--','pull','--platform',platform,image],timeout=min(600,DEADLINE-time.time()-180))
        journal.append('cors_pinned_images',platform=platform,digest_selected=True)

        phase='gateway_start';gate_time();
        run([binary,'--json','gateway','setup-tls','--private-state-root',str(gateway)])
        gateway_started=True
        run([binary,'--json','gateway','up','--private-state-root',str(gateway),'--dns-addr','127.0.0.1:0','--proxy-addr','127.0.0.1:0','--https-addr','127.0.0.1:0'])
        phase='service_up';result('container','hybrid_services','up');started=True
        status=result('container','hybrid_services','status')
        bindings=DEV._compose_loopback_port_bindings(checkout,status,targets=DEV.port_inventory.STORAGE_TARGETS)
        ports=[p for s,p,t in bindings if s=='silo' and t==9000]
        if len(ports)!=1:raise Refusal('cors_service_port')
        gs=strict_json(run([binary,'--json','gateway','status','--private-state-root',str(gateway)]).stdout)['result']
        context={'routes':routes,'https_port':DEV._gateway_https_port(gs)}
        origins=[DEV._public_url(routes[r],context['https_port']) for r in ('front','admin')]
        phase='production_bootstrap';gate_time();ident=DEV.verify_binary(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE'],binary)
        import secrets
        boot_env=dict(env,EFFIGY_PROFILE_SILO_BUCKET='acme-media',UNDERLAY_PROFILE_COMMAND_NONCE=secrets.token_hex(16))
        # Reuse the original source-qualified startup evidence clock carrier.
        # No runtime/container stage is entered; separate service-only intent is
        # the authority. Both bind the same immutable original deadline/head.
        session=DEV.startup_evidence.configure(boot_env,checkout,'start','hybrid')
        try:DEV._bootstrap_silo(ident,checkout,boot_env,'hybrid_services',context)
        finally:
            if session is not None:session.close()
            DEV.startup_evidence.ACTIVE.set(None)
        journal.append('cors_bootstrap_completed',origin_count=2,origins_distinct=len(set(origins))==2,application_listeners_started=False)
        def call(label,unused,args,timeout):
            x=run([binary,'--repo',str(checkout),*args],timeout=timeout,cwd=checkout);return x.stdout,x.returncode
        phase='policy_readback';gate_time()
        facts=read_policy(DEV.silo_client,call,journal,'acme-media',origins);observations['policy']=facts
        phase='browser_preflight';observations['preflight']=preflight(ports[0],'acme-media',origins[0],journal)
        observations['policy_predicts_preflight']=facts['request_matches'];phase='diagnostic_complete'
    except BaseException as error:
        failure=type(error).__name__;journal.append('cors_diagnostic_refused',phase=phase,exception_type=failure,policy_schema_refused=type(error) is Refusal and error.args==('cors_policy_schema',))
        from qualification_refusal import project
        journal.append('qualification_refusal',projection=project(error,'runtime_profile'))
    finally:
        journal.enter_cleanup()
        if started and time.time()+30<DEADLINE:
            try:result('container','hybrid_services','down');journal.append('cors_scoped_down',completed=True,independent_cleanup_verified=False)
            except BaseException as error:journal.append('cors_scoped_down',completed=False,exception_type=type(error).__name__,independent_cleanup_verified=False)
        # Existing source-qualified route evidence explicitly lacks VM kernel/agent
        # ownership. Do not convert private paths or a successful start into stop authority.
        journal.append('cors_backend_disposition',backend_started=vm,backend_suspended=False,disks_held=True,
                       vm_kernel_agent_ownership='unverified',independent_cleanup_verified=False,old_resources_touched=False)
        journal.close();storage.configure(None)
        write(packet/'service-cors-result.json',packet,dict(schema='underlay.service-cors-result.v1',phase=phase,failure_class=failure,
            observations=observations,backend_started=vm,backend_suspended=False,independent_cleanup_verified=False,whole_profile_acceptance=False))
    print('SERVICE CORS PACKET: '+str(packet),flush=True)
    return 1 if failure else 0

if __name__=='__main__':raise SystemExit(main())
