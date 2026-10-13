#!/usr/bin/env python3
"""One service-only Reference Silo correlation; never starts application tasks."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import secrets

from qualification_runtime import require_effigy_binary, SUPPORTED_EFFIGY_SOURCE, SUPPORTED_EFFIGY_SHA256
from reference_storage_probe import StorageDiagnosticJournal
from storage_correlation import correlate, minimal_policy, minimal_manifest, s3_error, invocation, shell_command, nested_exit, hosts_projection, scope_identity, compose_identity, bounded_run, shell_region, status_projection, environment_guard, cross_scope, strict_json, capture_contract, bounded_arguments, bounded_payload, file_producer, native_identity_observation, native_status_observation, mc_command, alias_projection
from silo_fixture import prepare_published_images
from routing_guard import finite_shell, evaluate_guard, OWNER_CLIENT_COMMAND_INPUT, client_command_input, client_input_projection, guard_command, guard_projection
from service_defaults import baseline, image_defaults
from formatter_provenance import bind_host, bound_colima, version_arguments, observe
import importlib.util


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


OPT = load('storage_optin', 'qualify-reference-optin.py')
DEV = load('storage_launcher', 'dev/profile_launcher.py')


SAFE_REASONS = {'status_projection_truncated','live_port_duplicate','unexpected_exposed_port','live_port_not_owned_loopback','native_bounded_refusal','bounded_envelope_refused','bounded_schema_refused','bounded_status_refused','bounded_selection_refused','bounded_limits_refused','bounded_accounting_refused','bounded_phase_refused','container_capture_boundary_unqualified','capture_source_unrecognized','byte_correspondence_refused','host_byte_correspondence_refused','host_write_refused','shell_operation_refused','status_identity_unavailable','status_inventory_unavailable','status_service_ambiguity','status_not_running','status_container_unknown','status_ports_unknown','live_port_representation_unknown','live_port_invalid','live_compose_disagreement','live_api_port_ambiguity','alias_shape_refused','alias_config_refused','stat_shape_refused','mc_operation_refused','cross_scope_isolation_unproven','own_key_survival_refused','cross_checkout_identity_conflict','command_capture_timeout','command_capture_truncated','native_result_schema_refused','gateway_identity_unknown','image_interface_refused','routing_guard_refused','service_default_baseline_unqualified','guard_framing_refused','guard_record_refused','guard_dispatch_refused','client_command_input_refused','formatter_host_identity_refused','formatter_private_scope_refused','formatter_version_unknown','formatter_source_unknown','formatter_capture_refused','formatter_source_unavailable'}

def client_image_provenance(env,journal,shape):
    from silo_fixture import CLIENT_IMAGE
    marker='UNDERLAY_'+secrets.token_hex(16).upper()
    command=environment_guard('silo_client')+'; '+mc_command(['--version'])
    if shape:command='command -v sh; command -v mc; '+command+'; sha256sum /usr/bin/mc'
    command=shell_command(client_command_input(command,marker),marker)
    capture=bounded_run([bound_colima(env),'nerdctl','--profile','effigy','--','run','--rm','--network','none','--entrypoint','/bin/sh',CLIENT_IMAGE,'-c',command],env=env,timeout=60)
    journal.append('client_image_provenance',shape=shape,exit=capture['exit'],outcome=capture['outcome'],stdout_bytes=capture['stdout_bytes'],stderr_bytes=capture['stderr_bytes'])
    if capture['exit'] or capture['outcome']!='complete':raise ValueError('image_interface_refused')
    region,inner=shell_region(capture['stdout'].decode(),marker)
    if inner:raise ValueError('image_interface_refused')
    region,input_record=client_input_projection(region,marker)
    journal.append('client_command_input',operation='image_provenance',service='silo_client',**input_record)
    return region


def offline_client_recipe(nonce, markers):
    path='/root/underlay-'+nonce
    return [guard_command('silo_client')+'; '+environment_guard('silo_client'),
            'set -eu; command -v rm >/dev/null; set -C; printf %s private > /tmp/underlay-tools-'+nonce+'; trap '+__import__('shlex').quote('rm -f /tmp/underlay-tools-'+nonce)+' EXIT; test -f /tmp/underlay-tools-'+nonce,
            mc_command(['alias','set','local','http://silo:9000','minioadmin','minioadmin','--api','S3v4','--path','auto'],json_output=True),
            mc_command(['alias','list','local'],json_output=True),
            file_producer(path,b'challenge'),
            mc_command(['stat',path],json_output=True),mc_command(['cat',path])]


def offline_client_interface(env,journal,nonce):
    from silo_fixture import CLIENT_IMAGE
    from storage_correlation import stat_projection
    labels=('guard','tools','alias_set','alias_list','producer','stat','cat')
    markers=['UNDERLAY_'+secrets.token_hex(16).upper() for _ in labels]
    commands=offline_client_recipe(nonce,markers)
    outer='UNDERLAY_'+secrets.token_hex(16).upper()
    # Each independent phase must succeed before the next, inside one fresh
    # network-none container. No host/shared mounts or signature autodetection.
    command='; '.join('( '+shell_command(c,m)+' ) || exit $?' for c,m in zip(commands,markers))
    command=shell_command(client_command_input(command,outer),outer)
    capture=bounded_run([bound_colima(env),'nerdctl','--profile','effigy','--','run','--rm','--network','none','--entrypoint','/bin/sh',CLIENT_IMAGE,'-c',command],env=env,timeout=60)
    journal.append('offline_client_recipe',exit=capture['exit'],outcome=capture['outcome'],stdout_bytes=capture['stdout_bytes'],stderr_bytes=capture['stderr_bytes'],network='none')
    if capture['exit'] or capture['outcome']!='complete':raise ValueError('image_interface_refused')
    region,inner=shell_region(capture['stdout'].decode(),outer)
    if inner:raise ValueError('image_interface_refused')
    region,input_record=client_input_projection(region,outer)
    journal.append('client_command_input',operation='offline_client_recipe',service='silo_client',**input_record)
    for label,marker in zip(labels,markers):
        output,inner=shell_region(region,marker)
        journal.append('offline_mc_phase',operation=label,inner_exit=inner,output_bytes=len(output.encode()))
        if inner:raise ValueError('image_interface_refused')
        if label=='guard':
            record=guard_projection(output,'silo_client');journal.append('routing_guard',**record)
            if not record['guard_passed']:raise ValueError('routing_guard_refused')
        elif label in ('alias_set','alias_list'):alias_projection(output,journal,label)
        elif label=='stat':stat_projection(output,'underlay-'+nonce,9,journal)
        elif label=='cat':
            journal.append('offline_cat',bytes_match=output=='challenge',body_bytes=len(output.encode()))
            if output!='challenge':raise ValueError('byte_correspondence_refused')


def image_interfaces(env,journal,nonce):
    from silo_fixture import IMAGE,CLIENT_IMAGE
    from storage_correlation import stat_projection
    # Source stat.go uses parseStat/MarshalIndent for both local and S3 content;
    # only the shared message shape is qualified by this no-network file control.
    for image in (IMAGE,CLIENT_IMAGE):
        marker='UNDERLAY_'+secrets.token_hex(16).upper()
        command='set -eu; command -v mc >/dev/null; command -v sh >/dev/null; '+file_producer('/root/underlay-'+nonce,b'challenge')+'; '+mc_command(['stat','/root/underlay-'+nonce], 'silo_client' if image==CLIENT_IMAGE else 'silo',json_output=True)
        if image==CLIENT_IMAGE:command=client_command_input(command,marker)
        command=shell_command(command,marker)
        capture=bounded_run([bound_colima(env),'nerdctl','--profile','effigy','--','run','--rm','--network','none','--entrypoint','/bin/sh',image,'-c',command],env=env,timeout=60)
        journal.append('image_interface',exit=capture['exit'],outcome=capture['outcome'],stdout_bytes=capture['stdout_bytes'],stderr_bytes=capture['stderr_bytes'],network='none')
        if capture['exit'] or capture['outcome']!='complete':raise ValueError('image_interface_refused')
        region,inner=shell_region(capture['stdout'].decode(),marker)
        if inner!=0:raise ValueError('image_interface_refused')
        if image==CLIENT_IMAGE:
            region,input_record=client_input_projection(region,marker)
            journal.append('client_command_input',operation='image_local_stat',service='silo_client',**input_record)
        stat_projection(region, 'underlay-'+nonce,9,journal)
        # Help exercises genuine flags/builtins without alias signature probes.
        for operation in ('alias list','pipe','cat','mb','stat','ready','anonymous','cors set'):
            marker='UNDERLAY_'+secrets.token_hex(16).upper()
            command=mc_command(operation.split()+['--help'],'silo_client' if image==CLIENT_IMAGE else 'silo')
            if image==CLIENT_IMAGE:command=client_command_input(command,marker)
            capture=bounded_run([bound_colima(env),'nerdctl','--profile','effigy','--','run','--rm','--network','none','--entrypoint','/bin/sh',image,'-c',shell_command(command,marker)],env=env,timeout=10)
            journal.append('image_flag_interface',operation=operation.replace(' ','_'),exit=capture['exit'],outcome=capture['outcome'],stdout_bytes=capture['stdout_bytes'],stderr_bytes=capture['stderr_bytes'],network='none')
            if capture['exit'] or capture['outcome']!='complete':raise ValueError('image_interface_refused')
            region,inner=shell_region(capture['stdout'].decode(),marker)
            if inner!=0:raise ValueError('image_interface_refused')
            if image==CLIENT_IMAGE:
                _,input_record=client_input_projection(region,marker)
                journal.append('client_command_input',operation='image_help_'+operation.replace(' ','_'),service='silo_client',**input_record)
    offline_client_interface(env,journal,nonce)


def main():
    binary = require_effigy_binary()
    OPT.EFFIGY = OPT.REFERENCE.EFFIGY = OPT.RUNTIME.EFFIGY = binary
    packet = Path(subprocess.run(['mktemp', '-d', str(Path.home() / 'ur.005-storage.XXXXXX')], check=True, capture_output=True, text=True).stdout.strip())
    fixture = packet / 'fixture'
    fixture.mkdir(mode=0o700)
    home = fixture / 'home'
    home.mkdir(mode=0o700)
    colima = fixture / 'colima'
    colima.mkdir(mode=0o700)
    gateway = fixture / 'gateway'
    gateway.mkdir(mode=0o700)
    env = dict(os.environ, HOME=str(home), COLIMA_HOME=str(colima), EFFIGY_COMPOSE_BACKEND='colima', EFFIGY_GATEWAY_PRIVATE_STATE_ROOT=str(gateway))
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT'): env.pop(key, None)
    journal = StorageDiagnosticJournal(packet / 'storage-diagnostics.jsonl', fixture)
    started = []
    results = []
    identities = {}
    print(f'STORAGE CORRELATION PACKET: {packet}', flush=True)

    def call(label, checkout, args, timeout=180):
        if require_effigy_binary() != binary:
            raise RuntimeError('verified executable changed')
        if 'UNDERLAY_CORRELATION_COLIMA_BIN' in env:
            bound_colima(env)
        journal.append('command', operation=label, phase='before_process')
        try:
            captured = bounded_run(invocation(binary, checkout, args), cwd=checkout, env=env, timeout=timeout)
        except OSError:
            journal.append('command_exception', operation=label, outcome='spawn_refused')
            raise ValueError('command_spawn_refused') from None
        journal.append('command_exit',operation=label,exit=captured['exit'],
                       stdout_bytes=captured['stdout_bytes'],stderr_bytes=captured['stderr_bytes'],
                       outcome=captured['outcome'])
        if captured['outcome'] != 'complete': raise ValueError('command_capture_'+captured['outcome'])
        try: output=captured['stdout'].decode('utf-8')
        except UnicodeDecodeError: raise ValueError('command_encoding_unknown') from None
        if captured['exit'] != 0 and '--bounded' not in args:
            raise ValueError('command_exit_refused')
        return output, captured['exit']

    def result(label, checkout, args):
        output,_=call(label,checkout,args)
        journal.append('native_envelope_input',operation=label,input_bytes=len(output.encode()),input_sha256=hashlib.sha256(output.encode()).hexdigest(),evidence='current_input_before_validation',ownership_credit=False)
        envelope=strict_json(output)
        if (not isinstance(envelope,dict) or envelope.get('schema')!='effigy.command.v1'
                or envelope.get('schema_version')!=1 or envelope.get('ok') is not True
                or not isinstance(envelope.get('result'),dict)):
            raise ValueError('command_envelope_refused')
        value=envelope['result']
        journal.append('native_identity_input',operation=label,**native_identity_observation(value))
        if label in ('service-only-status','new-owned-after-down'):journal.append('native_status_input',operation=label,**native_status_observation(value))
        if args[0]=='config': expected='effigy.config.v1'
        elif args[0]=='gateway': expected='effigy.gateway.status.v1' if args[1]=='status' else 'effigy.gateway.command.v1'
        else: expected='effigy.container.'+args[1 if args[1]=='scope' else 2]+'.v1'
        if value.get('schema')!=expected or value.get('schema_version')!=1 or value.get('ok') is not True:
            raise ValueError('native_result_schema_refused')
        return value

    failure = None
    formatter = None
    vm_started = False
    gateway_started = False
    nonce=secrets.token_hex(16)
    try:
        # Read only the specifically retained generated manifest. The old VM,
        # containers, alias database and uncertain resources are never queried.
        retained = Path('/Users/tom/ur.X2VdNA/home/reference/worktrees/first/.effigy/runtime/compose/.effigy-compose.generated.yml')
        raw = retained.read_bytes()
        text = raw.decode()
        journal.append('retained_configuration', compose_sha256=hashlib.sha256(raw).hexdigest(),
                       projects=sorted(set(re.findall(r'com\.effigy\.project:\s*([a-z0-9-]+)', text))),
                       scopes=sorted(set(re.findall(r'com\.effigy\.scope:\s*([a-f0-9]{32})', text))),
                       expected_host_endpoint='127.0.0.1:8540', mc_runtime_alias_observed=False,
                       cause_established=False)
        root = home / 'reference'
        root.mkdir(mode=0o700)
        source = OPT.REFERENCE.reference_source()
        main_checkout = root / 'main'
        subprocess.run(['git', 'clone', '--no-hardlinks', '--local', str(source), str(main_checkout)], check=True, capture_output=True, timeout=120)
        revision = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'], check=True, capture_output=True, text=True).stdout.strip()
        subprocess.run(['git', '-C', str(main_checkout), 'checkout', '--detach', revision], check=True, capture_output=True)
        first = root / 'first'
        subprocess.run(['git', '-C', str(main_checkout), 'worktree', 'add', '--detach', str(first), 'HEAD'], check=True, capture_output=True)
        for checkout in (main_checkout, first):
            OPT.REFERENCE.point_bundle_at_task_branch(checkout)
            OPT.enable_profiles(checkout, Path(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE']))
            inspection = result('effective-production-policy', checkout, ['config', '--inspect', '--path', 'containers.hybrid_services', '--json'])
            selected = inspection.get('selected_value', {})
            if inspection.get('schema') != 'effigy.config.v1' or inspection.get('ok') is not True or selected.get('path') != 'containers.hybrid_services':
                raise RuntimeError('unsupported selected configuration contract')
            if '[bundle.sources]\nsiblings = false' not in inspection.get('effective_manifest', ''):
                raise RuntimeError('production assembly lost bundle source isolation')
            policy = minimal_policy(selected.get('value'))
            original = (checkout / 'effigy.toml').read_bytes()
            journal.append('service_only_composition', checkout=str(checkout), original_manifest_sha256=hashlib.sha256(original).hexdigest(), service_names=list(policy['services']), host_process_count=0, dns_route_count=0, declared_project=policy['project_name'])
            # Bounded disposable fixture replaces only its root manifest. Values
            # come from the actual production export; no service recipes copied.
            manifest = minimal_manifest(policy)
            (checkout / 'effigy.toml').write_text(manifest)
            DEV._prepare_silo_override(checkout)
            verified = result('minimal-policy-inspection', checkout, ['config', '--inspect', '--path', 'containers.hybrid_services', '--json'])['selected_value']['value']
            if verified != policy:
                raise RuntimeError('minimal service policy changed during composition')
            native_scope = result('checkout-scope', checkout, ['container', 'scope', '--json'])
            identity = scope_identity(native_scope, checkout, fixture, 'none' if checkout == main_checkout else 'worktree', revision, policy, diagnostics=journal)
            identities[checkout] = identity
            journal.append('checkout_identity_gate', **identity, runtime_effects=False)
            # Native hosts loads the effective catalog capabilities without
            # starting a gateway or service; its scope marker stays fixture-owned.
            hosts = result('minimal-effective-hosts', checkout, ['container', 'hybrid_services', 'hosts', '--json'])
            # Pinned load_container_policy, used by native hosts, renders this
            # maintained generated path without starting a backend. Inspect only
            # the freshly owned file; post-up status/labels are checked again.
            generated = checkout / '.effigy/runtime/compose/.effigy-compose.generated.yml'
            if generated.exists():
                if generated.is_symlink() or not generated.is_file():
                    raise ValueError('unsafe_generated_compose')
                generated.resolve(strict=True).relative_to(checkout)
                raw_preflight = generated.read_bytes()
                compose_identity(raw_preflight, {'project_name':identity['project']}, identity, diagnostics=journal)
                journal.append('no_backend_compose_identity_gate', **identity,
                               compose_sha256=hashlib.sha256(raw_preflight).hexdigest(),
                               provenance='native_hosts_generated_configuration', runtime_effects=False)
            journal.append('minimal_policy_gate', checkout=str(checkout), policy_preserved=True,
                           catalog_files_sha256={alias: hashlib.sha256((checkout / 'infra/dev/catalog' / alias / 'service.toml').read_bytes()).hexdigest() for alias in ('silo', 'silo-mc')},
                           effective_hosts=hosts_projection(hosts, checkout, identity, diagnostics=journal), runtime_effects=False)

        # Both real identities are retained. Output captured inside core cannot
        # be bounded by our external pipe reader. Stop before any runtime effect.
        if len(identities)!=2 or identities[main_checkout]['kind']!='none' or identities[first]['kind']!='worktree':
            raise ValueError('checkout_orchestration_refused')
        evidence=capture_contract(Path(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE']))
        journal.append('capture_contract_gate',**evidence,runtime_effects=False)


        # No VM/image/service effect until BOTH image/exec baselines agree.
        # Client HOME is a shared command-local owner input. Image/inherited
        # defaults remain unqualified; server inputs are unchanged.
        server_default=baseline(image_defaults('pgsty/silo'),
            {'MC_HOST_local':'http://minioadmin:minioadmin@127.0.0.1:9000'},'silo',('/data',))
        client_default=baseline(image_defaults('pgsty/mc'),{},'silo_client',
                                command_input=OWNER_CLIENT_COMMAND_INPUT)
        journal.append('service_default_baseline',**server_default)
        journal.append('service_default_baseline',**client_default)
        if not server_default['baseline_passed'] or not client_default['baseline_passed']:
            raise ValueError('service_default_baseline_unqualified')

        host = bind_host(env)
        version_arguments(env, fixture)  # Pure private-root/argv gate before effects.
        journal.append('formatter_host_gate', **host, runtime_effects=False)

        # No service starts until both typed production/minimal compositions agree.
        journal.append('start_intents', fixture=str(fixture), gateway=str(gateway), checkouts=[str(main_checkout),str(first)], private_vm_held=True)
        process = bounded_run([bound_colima(env), 'start', '--profile', 'effigy', '--runtime', 'containerd', '--cpu', '2', '--memory', '4', '--disk', '32'], env=env, timeout=1200)
        journal.append('private_vm_start', exit=process['exit'], outcome=process['outcome'])
        if process['exit'] or process['outcome']!='complete': raise ValueError('private_vm_start_unknown')
        vm_started = True
        formatter = observe(env, fixture, journal)
        prepare_published_images(fixture, env,client_probe=lambda shape:client_image_provenance(env,journal,shape))
        image_interfaces(env, journal, nonce)
        # The production Silo catalog declares a TCP alias; pinned core starts
        # its gateway for that catalog capability even without explicit DNS.
        # Use only reviewed private TLS and ephemeral loopback listeners.
        gateway_started = True
        result('private-tls', main_checkout, ['gateway', 'setup-tls', '--private-state-root', str(gateway), '--json'])
        result('private-service-gateway', main_checkout, ['gateway', 'up', '--private-state-root', str(gateway), '--dns-addr', '127.0.0.1:0', '--proxy-addr', '127.0.0.1:0', '--https-addr', '127.0.0.1:0', '--json'])
        gateway_started = True
        for checkout, key in ((main_checkout, 'main-known.txt'), (first, 'first-known.txt')):
            started.append(checkout)
            result('service-only-up', checkout, ['container', 'hybrid_services', 'up', '--json'])
            status = result('service-only-status', checkout, ['container', 'hybrid_services', 'status', '--json'])
            compose = Path(status['compose_file'])
            if not compose.is_absolute(): compose = checkout / compose
            compose = compose.resolve(strict=True)
            compose.relative_to(checkout.resolve())
            bindings = DEV._compose_loopback_port_bindings(checkout, status)
            matches = [port for service, port, target in bindings if service == 'silo' and target == 9000]
            if len(matches) != 1: raise RuntimeError('ambiguous Silo loopback map')
            identity = identities[checkout]
            selected = status_projection(status, identity, bindings, diagnostics=journal)
            port = selected['port']
            for previous in results:
                if previous['port']==port or previous['project']==selected['project'] or set(previous['selected_container_sha256']) & set(selected['selected_container_sha256']):
                    raise ValueError('cross_checkout_identity_conflict')
            journal.append('selected_services', **selected)
            raw = compose.read_bytes()
            identity = identities[checkout]
            journal.append('compose_identity_observation', checkout=str(checkout),
                           compose_sha256=hashlib.sha256(raw).hexdigest(),
                           project_label_count=raw.count(b'com.effigy.project'),
                           scope_label_count=raw.count(b'com.effigy.scope'),
                           expected_project=identity['project'], expected_kind=identity['kind'],
                           expected_token=identity['token'], loopback_port=port)
            try:
                observed = compose_identity(raw, status, identity, diagnostics=journal)
            except ValueError as error:
                journal.append('compose_identity_rejected', reason=str(error))
                raise
            journal.append('executed_scope', checkout=str(checkout), **observed,
                           compose_sha256=hashlib.sha256(raw).hexdigest(), loopback_port=port,
                           service_names=['silo','silo_client'])

            def shell(label, command, service='silo_client'):
                # Same production bounded transport; checkout is explicitly bound.
                def selected_call(operation, unused, args, timeout):
                    return call(operation, checkout, args, timeout=timeout)
                return finite_shell(selected_call,journal,label,command,service)
            for service in ('silo','silo_client'):
                evaluate_guard(shell,journal,service)
            alias_projection(shell('alias-bootstrap',mc_command(['alias','set','local','http://silo:9000','minioadmin','minioadmin','--api','S3v4','--path','auto'],json_output=True)),journal,'alias_set')
            outcome=correlate(shell,OPT.RUNTIME._s3_request,journal,port,key,nonce)
            outcome.update(selected)
            results.append(outcome)
        for own,foreign in ((results[0],results[1]),(results[1],results[0])):
            cross_scope(OPT.RUNTIME._s3_request,journal,own,foreign)

    except Exception as error:
        failure = type(error).__name__
        journal.append('diagnosis_failed', exception_type=failure, reason=str(error) if isinstance(error,ValueError) and str(error) in SAFE_REASONS else 'unknown')
        print(f'STOP: storage correlation {failure}; see sanitized journal', flush=True)
    finally:
        for checkout in reversed(started):
            journal.append('service_log_unavailable',reason='no_qualified_bounded_log_surface')
            try:
                result('new-owned-scoped-down', checkout, ['container', 'hybrid_services', 'down', '--json'])
                status = result('new-owned-after-down', checkout, ['container', 'hybrid_services', 'status', '--json'])
                observation=status_projection(status,identities[checkout],[],after_down=True,diagnostics=journal)
                journal.append('cleanup_status',checkout=str(checkout),**observation,retirement_proven=False)
            except Exception as error:
                journal.append('cleanup_unknown', exception_type=type(error).__name__)
                failure = failure or 'CleanupUnknown'
        if gateway_started:
            try:
                status = result('new-private-gateway-status', main_checkout, ['gateway', 'status', '--private-state-root', str(gateway), '--json'])
                if status.get('private') is not True or status.get('gateway_dir')!=str(gateway) or not isinstance(status.get('routes'),list):
                    raise ValueError('gateway_identity_unknown')
                if status.get('routes'):
                    raise RuntimeError('private routes remain held')
                result('new-private-gateway-down', main_checkout, ['gateway', 'down', '--private-state-root', str(gateway), '--json'])
            except Exception as error:
                journal.append('gateway_cleanup_unknown', exception_type=type(error).__name__)
                failure = failure or 'CleanupUnknown'
        journal.append('disposition', private_vm_started=vm_started, private_vm_held=vm_started, volume_retirement_proven=False, old_resources_touched=False)
        journal.close()
        summary = {'source':SUPPORTED_EFFIGY_SOURCE, 'binary_sha256':SUPPORTED_EFFIGY_SHA256, 'failure_class':failure, 'formatter':formatter, 'results':[{k:v for k,v in r.items() if k!='payloads'} for r in results], 'whole_profile_acceptance':False, 'old_resources_touched':False}
        path = packet / 'result.json'
        path.write_text(json.dumps(summary, indent=2)+'\n')
        path.chmod(0o600)
    return 1 if failure else 0


if __name__ == '__main__':
    raise SystemExit(main())
