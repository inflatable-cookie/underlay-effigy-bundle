#!/usr/bin/env python3
"""One service-only Reference Silo correlation; never starts application tasks."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from qualification_runtime import require_effigy_binary, SUPPORTED_EFFIGY_SOURCE, SUPPORTED_EFFIGY_SHA256
from reference_storage_probe import StorageDiagnosticJournal
from storage_correlation import correlate, minimal_policy, minimal_manifest, s3_error, invocation, shell_command, nested_exit
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
    print(f'STORAGE CORRELATION PACKET: {packet}', flush=True)

    def call(label, checkout, args, timeout=180):
        if require_effigy_binary() != binary:
            raise RuntimeError('verified executable changed')
        journal.append('command', operation=label, phase='before_process')
        try:
            process = subprocess.run(invocation(binary, checkout, args), cwd=checkout, env=env, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            journal.append('command_exception', operation=label, exception_type=type(error).__name__)
            raise RuntimeError('bounded service command failed') from None
        journal.append('command_exit', operation=label, exit=process.returncode, stdout_bytes=len(process.stdout.encode()), stderr_bytes=len(process.stderr.encode()),
                       **(nested_exit(process.stdout) if '--command' in args else {}))
        if process.returncode != 0:
            raise RuntimeError(f'{label} exit {process.returncode}')
        return process.stdout

    def result(label, checkout, args):
        envelope = json.loads(call(label, checkout, args))
        if envelope.get('ok') is not True or not isinstance(envelope.get('result'), dict):
            raise RuntimeError('negative or malformed Effigy envelope')
        return envelope['result']

    failure = None
    vm_started = False
    gateway_started = False
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
        # No service starts until both typed production/minimal compositions agree.
        process = subprocess.run(['colima', 'start', '--profile', 'effigy', '--runtime', 'containerd', '--cpu', '2', '--memory', '4', '--disk', '32'], env=env, capture_output=True, timeout=1200)
        journal.append('private_vm_start', exit=process.returncode)
        if process.returncode: raise RuntimeError('private VM startup failed')
        vm_started = True
        prepare_published_images(fixture, env)
        # The production Silo catalog declares a TCP alias; pinned core starts
        # its gateway for that catalog capability even without explicit DNS.
        # Use only reviewed private TLS and ephemeral loopback listeners.
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
            port = matches[0]
            raw = compose.read_bytes()
            projects = set(re.findall(r'com\.effigy\.project:\s*([a-z0-9-]+)', raw.decode()))
            scopes = set(re.findall(r'com\.effigy\.scope:\s*([a-f0-9]{32})', raw.decode()))
            if len(projects) != 1 or len(scopes) != 1: raise RuntimeError('ambiguous executed Compose ownership')
            journal.append('executed_scope', checkout=str(checkout), project=next(iter(projects)), scope=next(iter(scopes)), compose_sha256=hashlib.sha256(raw).hexdigest(), loopback_port=port, service_names=['silo','silo_client'])

            def shell(label, command, service='silo_client'):
                return call(label, checkout, ['container', 'hybrid_services', 'shell', '--service', service, '--command', shell_command(command)])
            # Same persistent alias/config setup as production bootstrap; no app,
            # gateway, CORS or authentication task is invoked here.
            shell('alias-bootstrap', 'set -eu; mc alias set local http://silo:9000 minioadmin minioadmin >/dev/null 2>&1')
            shell('client-env-check', 'set -eu; test -z "${MC_HOST_local:-}"; test -z "${MC_CONFIG_DIR:-}"; test -z "${MC_CONFIG_ENV_FILE:-}"; test "$HOME" = /root')
            for service in ('silo', 'silo_client'):
                output = shell('container-identity', 'hostname', service=service)
                identities = re.findall(r'(?m)^([a-f0-9]{12,64})$', output)
                if len(identities) != 1: raise RuntimeError('missing exact selected container identity')
                journal.append('selected_container', service=service, container_hostname=identities[0])
            outcome = correlate(shell, OPT.RUNTIME._s3_request, journal, port, key)
            results.append(outcome)
        for own, foreign in ((results[0], results[1]), (results[1], results[0])):
            status, _, body = OPT.RUNTIME._s3_request(own['port'], 'GET', f"/{foreign['bucket']}/{foreign['key']}", diagnostics=journal, diagnostic_operation='cross_scope_get', diagnostic_path_template='/<bucket>/<foreign-object>')
            journal.append('cross_scope_result', status=status, **s3_error(body))
            if status != 404: raise RuntimeError('cross-scope object isolation failed')
    except Exception as error:
        failure = type(error).__name__
        journal.append('diagnosis_failed', exception_type=failure)
        print(f'STOP: storage correlation {failure}; see sanitized journal', flush=True)
    finally:
        for checkout in reversed(started):
            for service in ('silo', 'silo_client'):
                try:
                    output = call('finite-service-log', checkout, ['container', 'hybrid_services', 'logs', '--service', service], timeout=10)
                    journal.write_log(f'{checkout.name}-{service.replace("_", "-")}.log', output.splitlines()[-80:])
                except Exception as error:
                    journal.append('service_log_unavailable', service=service, exception_type=type(error).__name__)
            try:
                result('new-owned-scoped-down', checkout, ['container', 'hybrid_services', 'down', '--json'])
                status = result('new-owned-after-down', checkout, ['container', 'hybrid_services', 'status', '--json'])
                rows = status.get('services', [])
                journal.append('cleanup_status', checkout=str(checkout), service_states=[{'name': row.get('name') if row.get('name') in ('silo','silo_client') else 'unknown', 'status': row.get('status') if row.get('status') in ('running','stopped','exited','missing','healthy') else 'unknown'} for row in rows if isinstance(row,dict)])
            except Exception as error:
                journal.append('cleanup_unknown', exception_type=type(error).__name__)
                failure = failure or 'CleanupUnknown'
        if gateway_started:
            try:
                status = result('new-private-gateway-status', main_checkout, ['gateway', 'status', '--private-state-root', str(gateway), '--json'])
                if status.get('routes'):
                    raise RuntimeError('private routes remain held')
                result('new-private-gateway-down', main_checkout, ['gateway', 'down', '--private-state-root', str(gateway), '--json'])
            except Exception as error:
                journal.append('gateway_cleanup_unknown', exception_type=type(error).__name__)
                failure = failure or 'CleanupUnknown'
        journal.append('disposition', private_vm_started=vm_started, private_vm_held=vm_started, volume_retirement_proven=False, old_resources_touched=False)
        journal.close()
        summary = {'source':SUPPORTED_EFFIGY_SOURCE, 'binary_sha256':SUPPORTED_EFFIGY_SHA256, 'failure_class':failure, 'results':results, 'whole_profile_acceptance':False, 'old_resources_touched':False}
        path = packet / 'result.json'
        path.write_text(json.dumps(summary, indent=2)+'\n')
        path.chmod(0o600)
    return 1 if failure else 0


if __name__ == '__main__':
    raise SystemExit(main())
