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
from storage_correlation import correlate, minimal_policy, minimal_manifest, s3_error, invocation, shell_command, nested_exit, hosts_projection, scope_identity, compose_identity, bounded_run, shell_region, status_projection, environment_guard, cross_scope, strict_json, capture_contract
from silo_fixture import prepare_published_images
import importlib.util


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


OPT = load('storage_optin', 'qualify-reference-optin.py')
DEV = load('storage_launcher', 'dev/profile_launcher.py')


SAFE_REASONS = {'container_capture_boundary_unqualified','capture_source_unrecognized','byte_correspondence_refused','host_byte_correspondence_refused','host_write_refused','shell_operation_refused','status_identity_unavailable','status_inventory_unavailable','status_service_ambiguity','status_not_running','status_container_unknown','status_ports_unknown','live_port_representation_unknown','live_port_invalid','live_compose_disagreement','live_api_port_ambiguity','alias_shape_refused','alias_config_refused','stat_shape_refused','cross_scope_isolation_unproven','own_key_survival_refused','cross_checkout_identity_conflict','command_capture_timeout','command_capture_truncated','native_result_schema_refused','gateway_identity_unknown','image_interface_refused'}

def image_interfaces(env,journal,nonce):
    from silo_fixture import IMAGE,CLIENT_IMAGE
    from storage_correlation import stat_projection
    # Source stat.go uses parseStat/MarshalIndent for both local and S3 content;
    # only the shared message shape is qualified by this no-network file control.
    for image in (IMAGE,CLIENT_IMAGE):
        marker='UNDERLAY_'+secrets.token_hex(16).upper()
        command=shell_command('set -eu; command -v mc >/dev/null; command -v sh >/dev/null; set -C; printf %s challenge > /root/underlay-'+nonce+'; mc stat --json /root/underlay-'+nonce,marker)
        capture=bounded_run(['colima','nerdctl','--profile','effigy','--','run','--rm','--network','none','--entrypoint','/bin/sh',image,'-c',command],env=env,timeout=60)
        journal.append('image_interface',exit=capture['exit'],outcome=capture['outcome'],stdout_bytes=capture['stdout_bytes'],stderr_bytes=capture['stderr_bytes'],network='none')
        if capture['exit'] or capture['outcome']!='complete':raise ValueError('image_interface_refused')
        region,inner=shell_region(capture['stdout'].decode(),marker)
        if inner!=0:raise ValueError('image_interface_refused')
        stat_projection(region, 'underlay-'+nonce,9)

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
        if captured['exit'] != 0 and '--command' not in args:
            raise ValueError('command_exit_refused')
        return output, captured['exit']

    def result(label, checkout, args):
        output,_=call(label,checkout,args)
        envelope=strict_json(output)
        if (not isinstance(envelope,dict) or envelope.get('schema')!='effigy.command.v1'
                or envelope.get('schema_version')!=1 or envelope.get('ok') is not True
                or not isinstance(envelope.get('result'),dict)):
            raise ValueError('command_envelope_refused')
        value=envelope['result']
        if args[0]=='config': expected='effigy.config.v1'
        elif args[0]=='gateway': expected='effigy.gateway.status.v1' if args[1]=='status' else 'effigy.gateway.command.v1'
        else: expected='effigy.container.'+args[1 if args[1]=='scope' else 2]+'.v1'
        if value.get('schema')!=expected or value.get('schema_version')!=1 or value.get('ok') is not True:
            raise ValueError('native_result_schema_refused')
        return value

    failure = None
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
            identity = scope_identity(native_scope, checkout, fixture, 'none' if checkout == main_checkout else 'worktree', revision, policy)
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
                compose_identity(raw_preflight, {'project_name':identity['project']}, identity)
                journal.append('no_backend_compose_identity_gate', **identity,
                               compose_sha256=hashlib.sha256(raw_preflight).hexdigest(),
                               provenance='native_hosts_generated_configuration', runtime_effects=False)
            journal.append('minimal_policy_gate', checkout=str(checkout), policy_preserved=True,
                           catalog_files_sha256={alias: hashlib.sha256((checkout / 'infra/dev/catalog' / alias / 'service.toml').read_bytes()).hexdigest() for alias in ('silo', 'silo-mc')},
                           effective_hosts=hosts_projection(hosts, checkout, identity), runtime_effects=False)

        # Both real identities are retained. Output captured inside core cannot
        # be bounded by our external pipe reader. Stop before any runtime effect.
        if len(identities)!=2 or identities[main_checkout]['kind']!='none' or identities[first]['kind']!='worktree':
            raise ValueError('checkout_orchestration_refused')
        evidence=capture_contract(Path(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE']))
        journal.append('capture_contract_gate',**evidence,runtime_effects=False)
        raise ValueError('container_capture_boundary_unqualified')

        # No service starts until both typed production/minimal compositions agree.
        journal.append('start_intents', fixture=str(fixture), gateway=str(gateway), checkouts=[str(main_checkout),str(first)], private_vm_held=True)
        process = bounded_run(['colima', 'start', '--profile', 'effigy', '--runtime', 'containerd', '--cpu', '2', '--memory', '4', '--disk', '32'], env=env, timeout=1200)
        journal.append('private_vm_start', exit=process['exit'], outcome=process['outcome'])
        if process['exit'] or process['outcome']!='complete': raise ValueError('private_vm_start_unknown')
        vm_started = True
        prepare_published_images(fixture, env)
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
            selected = status_projection(status, identity, bindings)
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
                observed = compose_identity(raw, status, identity)
            except ValueError as error:
                journal.append('compose_identity_rejected', reason=str(error))
                raise
            journal.append('executed_scope', checkout=str(checkout), **observed,
                           compose_sha256=hashlib.sha256(raw).hexdigest(), loopback_port=port,
                           service_names=['silo','silo_client'])

            def shell(label, command, service='silo_client'):
                marker='UNDERLAY_'+secrets.token_hex(16).upper()
                output,outer=call(label,checkout,['container','hybrid_services','shell','--service',service,'--command',shell_command(command,marker)])
                region,inner=shell_region(output,marker)
                journal.append('shell_completion',operation=label,service=service,inner_exit=inner,
                               outer_exit=outer,region_bytes=len(region.encode()),framing='unique_marker')
                if outer!=0 or inner!=0:raise ValueError('shell_operation_refused')
                return region
            # Presence (including empty) refuses before persisted alias bootstrap.
            for service in ('silo','silo_client'):
                shell('routing_environment_guard',environment_guard(service),service=service)
            shell('alias-bootstrap','set -eu; mc alias set local http://silo:9000 minioadmin minioadmin')
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
            for service in ('silo', 'silo_client'):
                try:
                    output, _ = call('finite-service-log', checkout, ['container', 'hybrid_services', 'logs', '--service', service], timeout=10)
                    journal.write_log(f'{checkout.name}-{service.replace("_", "-")}.log', output.splitlines()[-80:])
                    journal.append('service_log_evidence',service=service,availability='unavailable_until_sanitized_lines_verified')
                except Exception as error:
                    journal.append('service_log_unavailable', service=service, exception_type=type(error).__name__)
            try:
                result('new-owned-scoped-down', checkout, ['container', 'hybrid_services', 'down', '--json'])
                status = result('new-owned-after-down', checkout, ['container', 'hybrid_services', 'status', '--json'])
                observation=status_projection(status,identities[checkout],[],after_down=True)
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
        summary = {'source':SUPPORTED_EFFIGY_SOURCE, 'binary_sha256':SUPPORTED_EFFIGY_SHA256, 'failure_class':failure, 'results':[{k:v for k,v in r.items() if k!='payloads'} for r in results], 'whole_profile_acceptance':False, 'old_resources_touched':False}
        path = packet / 'result.json'
        path.write_text(json.dumps(summary, indent=2)+'\n')
        path.chmod(0o600)
    return 1 if failure else 0


if __name__ == '__main__':
    raise SystemExit(main())
