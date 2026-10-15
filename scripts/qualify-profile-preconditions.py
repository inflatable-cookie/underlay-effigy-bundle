#!/usr/bin/env python3
"""No-backend current-source default and opt-in Silo assembly gate."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback

from qualification_runtime import require_effigy_binary, SUPPORTED_EFFIGY_SOURCE, SUPPORTED_EFFIGY_SHA256
from dev.silo_client import bounded_run, strict_json


def load(name, filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def generated_storage_contract(checkout, image, client_image, emit):
    path=checkout/'.effigy/runtime/compose/.effigy-compose.generated.yml'
    if path.is_symlink() or checkout.resolve() not in path.resolve(strict=True).parents:raise ValueError('compose_boundary_refused')
    raw=path.read_bytes()
    if len(raw)>1048576:raise ValueError('compose_bound_refused')
    return generated_storage_projection(raw,image,client_image,emit)


def generated_storage_projection(raw, image, client_image, emit):
    text=raw.decode('utf-8')
    def block(name):
        match=re.search(r'(?ms)^  '+name+r':\n(.*?)(?=^  [A-Za-z0-9_-]+:|^volumes:|\Z)',text)
        if match is None:raise ValueError('compose_service_refused')
        return match[1]
    server=block('silo');client=block('silo_client')
    tests=re.findall(r'(?m)^ +test:\n((?: +- [^\n]*\n)+)',server)
    ready_items=[line.strip()[2:] for line in tests[0].splitlines()] if len(tests)==1 else []
    fields={
        'server_pin':f'image: {image}' in server,
        'client_pin':f'image: {client_image}' in client,
        'ready_health':'healthcheck:' in server and ready_items==['CMD','mc','ready','local'],
        'server_loopback_alias':'@127.0.0.1:9000' in server,
        'distinct_silo_data':'-silo-data:/data' in server and '-minio-data' not in text,
        'client_config_mount_absent':'volumes:' not in client,
        'client_overrides_absent':all(name not in client for name in ('MC_CONFIG_DIR','MC_CONFIG_ENV_FILE','MC_HOST_local','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')),
        'obsolete_service_absent':re.search(r'(?m)^  minio:',text) is None,
    }
    # The actual generated native Compose is inspected in memory. Never retain
    # its environment/config envelope, only fixed predicates and a digest.
    receipt={'compose_sha256':hashlib.sha256(raw).hexdigest(),'predicates':fields}
    emit(receipt)
    if not all(fields.values()):raise ValueError('compose_contract_refused')
    return receipt

def rendered_launcher_controls(checkout, base_env, tasks, launcher, emit):
    from unittest.mock import patch
    class EffectsBoundaryReached(Exception):pass
    identity=launcher.verify_binary(base_env['UNDERLAY_PROFILE_EFFIGY_SOURCE'],base_env['UNDERLAY_PROFILE_EFFIGY_BIN'])
    for task,profile in (('dev:hybrid','hybrid'),('dev:test','disposable_test')):
        declaration=tasks.get(task)
        if not isinstance(declaration,dict) or not isinstance(declaration.get('env'),dict):raise ValueError('launcher_task_schema_refused')
        import shlex
        command=declaration.get('run')
        if not isinstance(command,str):raise ValueError('launcher_asset_command_unavailable')
        words=shlex.split(command)
        if len(words)<2 or Path(words[1]).name!='profile_launcher.py':raise ValueError('launcher_asset_command_unavailable')
        asset=Path(words[1]).parent/'port_inventory.py'
        current=Path(__file__).parent/'dev/port_inventory.py'
        if not asset.is_file() or hashlib.sha256(asset.read_bytes()).digest()!=hashlib.sha256(current.read_bytes()).digest():raise ValueError('port_inventory_asset_mismatch')
        for name in ('startup_evidence.py','owned_capture.py','host_identity.py'):
            copied=Path(words[1]).parent/name
            source=Path(__file__).parent/'dev'/name
            if not copied.is_file() or copied.read_bytes()!=source.read_bytes():raise ValueError('startup_asset_mismatch')
        emit({'task':task,'exported_startup_assets':True})
        emit({'task':task,'exported_port_inventory_asset':True,'port_inventory_sha256':hashlib.sha256(asset.read_bytes()).hexdigest()})
        env={**base_env,**declaration['env']}
        container=launcher.PROFILE_CONTAINERS[profile][0]
        journal_path=checkout/'.effigy/runtime/dev-profiles'/container/'silo-bootstrap.jsonl'
        def before_effects(candidate, accepted):
            with patch.object(launcher,'_start_services',side_effect=EffectsBoundaryReached) as services, \
                 patch.object(launcher,'_bootstrap_silo',side_effect=AssertionError('MC effects forbidden')) as bootstrap:
                try:launcher._start_profile(identity,checkout,candidate,profile)
                except EffectsBoundaryReached:
                    if not accepted:raise ValueError('launcher_control_false_pass')
                except launcher.ProfileError:
                    if accepted:raise
                else:raise ValueError('launcher_control_no_boundary')
                if services.call_count!=int(accepted):raise ValueError('launcher_control_false_pass')
                bootstrap.assert_not_called()
        before_effects(env,True)
        emit({'task':task,'valid_rendered_environment':True,'backend_effects':False})
        count=0
        for name in launcher._LAUNCHER_FIELDS:
            for kind in ('missing','empty','wrong_type','malformed','foreign_valid'):
                candidate=dict(env)
                if kind=='missing':candidate.pop(name,None)
                else:candidate[name]={'empty':'','wrong_type':[], 'malformed':'https://seeded-secret@foreign.invalid/path',
                                      'foreign_valid':'seeded-secret' if name.endswith('BUCKET') else 'seeded-secret.invalid'}[kind]
                before_effects(candidate,False);count+=1
        source_path='containers.'+container+'.host_processes'
        genuine=bounded_run([identity.binary,'--repo',str(checkout),'--json','config','--inspect','--path',source_path],env=base_env,timeout=120)
        if genuine['outcome']!='complete' or genuine['exit']:raise ValueError('launcher_source_control_unavailable')
        for kind in ('wrong_schema','wrong_path','missing_api_env','duplicate_json','native_failure'):
            value=strict_json(genuine['stdout'].decode())
            if kind=='wrong_schema':value['result']['schema']='unknown'
            elif kind=='wrong_path':value['result']['selected_path']='foreign'
            elif kind=='missing_api_env':
                for process in value['result']['selected_value']['value']:
                    if process.get('name')=='api':process.pop('env',None)
            output=json.dumps(value).encode()
            if kind=='duplicate_json':output=b'{"schema":"seeded-secret","schema":"duplicate"}'
            capture={**genuine,'stdout':output,'stdout_bytes':len(output)}
            if kind=='native_failure':capture['exit']=1
            with patch.object(launcher.silo_client,'bounded_run',return_value=capture):before_effects(env,False)
        with patch.object(launcher.silo_client,'bounded_run',side_effect=OSError('seeded-secret')):before_effects(env,False)
        emit({'task':task,'native_schema_refusals':5,'capture_launch_refusals':1,'backend_effects':False})
        text=journal_path.read_text()
        if 'seeded-secret' in text:raise ValueError('launcher_control_privacy_refused')
        records=[strict_json(line) for line in text.splitlines()]
        if journal_path.stat().st_mode&0o777!=0o600 or not all(isinstance(r,dict) for r in records):raise ValueError('launcher_journal_refused')
        emit({'task':task,'refusal_count':count,'safe_field_record_count':len(records),'journal_sha256':hashlib.sha256(text.encode()).hexdigest(),'secret_excluded':True,'backend_effects':False})

def main():
    binary=require_effigy_binary()
    reference=load('precondition_reference','qualify-reference-profiles.py')
    opt=load('precondition_optin','qualify-reference-optin.py')
    opt.EFFIGY=opt.REFERENCE.EFFIGY=opt.RUNTIME.EFFIGY=binary
    reference.EFFIGY=binary
    root=Path(subprocess.run(['mktemp','-d',str(Path.home()/'ur.005-preconditions.XXXXXX')],check=True,capture_output=True,text=True).stdout.strip()).resolve()
    print('PROFILE PRECONDITION PACKET: '+str(root),flush=True)
    env={**os.environ,'HOME':str(root/'home'),'COLIMA_HOME':str(root/'colima')}
    for path in (root/'home',root/'colima',root/'reference'):path.mkdir(mode=0o700)
    receipt={'source':SUPPORTED_EFFIGY_SOURCE,'binary_sha256':SUPPORTED_EFFIGY_SHA256,'runtime_effects':False,'assemblies':[]}
    def call(checkout,*args):
        if require_effigy_binary()!=binary:raise ValueError('binary_changed')
        result=bounded_run([binary,'--repo',str(checkout),'--json',*args],env=env,timeout=120)
        if result['outcome']!='complete' or result['exit']:raise ValueError('native_precondition_refused')
        value=strict_json(result['stdout'].decode())
        if not isinstance(value,dict) or value.get('schema')!='effigy.command.v1' or value.get('ok') is not True or not isinstance(value.get('result'),dict):raise ValueError('native_precondition_schema')
        return value['result']
    failure=None
    try:
        checkouts=reference.make_reference_instances(reference.reference_source(),root/'reference')
        for index,checkout in enumerate(checkouts):
            reference.point_bundle_at_task_branch(checkout)
            if index:opt.enable_profiles(checkout,Path(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE']).resolve(strict=True))
            value=call(checkout,'config','--inspect','--path','containers')
            containers=value.get('selected_value',{}).get('value')
            if value.get('schema')!='effigy.config.v1' or not isinstance(containers,dict):raise ValueError('typed_composition_unavailable')
            if index:
                if not {'hybrid_services','disposable_test'}<=set(containers):raise ValueError('optin_composition_unavailable')
            elif {'hybrid_services','disposable_test'}&set(containers):raise ValueError('default_composition_changed')
            receipt['assemblies'].append({'checkout':str(checkout),'profile':'default' if not index else 'explicit_optin','container_names':sorted(set(containers)&{'default','stack','hybrid_services','disposable_test'}),'unknown_container_count':len(set(containers)-{'default','stack','hybrid_services','disposable_test'}),'exported_silo_client_asset':(Path(__file__).parent/'dev/silo_client.py').is_file(),'exported_port_inventory_asset':(Path(__file__).parent/'dev/port_inventory.py').is_file()})
        if not all(a['exported_port_inventory_asset'] for a in receipt['assemblies']):raise ValueError('port_inventory_asset_missing')
        from dev import profile_launcher as launcher
        from silo_fixture import IMAGE, CLIENT_IMAGE
        for checkout in checkouts:
            launcher._prepare_silo_override(checkout)
            value=call(checkout,'config','--inspect','--path','containers')
            containers=value['selected_value']['value']
            if 'hybrid_services' in containers:
                task_result=call(checkout,'config','--inspect','--path','tasks')
                if task_result.get('schema')!='effigy.config.v1':raise ValueError('launcher_task_schema_refused')
                tasks=task_result.get('selected_value',{}).get('value')
                if not isinstance(tasks,dict):raise ValueError('launcher_task_schema_refused')
                rendered_launcher_controls(checkout,env,tasks,launcher,
                    lambda projection:receipt.setdefault('rendered_launcher_controls',[]).append({'checkout':str(checkout),**projection}))

            for name,container in containers.items():
                if not isinstance(container,dict):continue
                services=container.get('services',{})
                if not services:continue
                if 'minio' in services:raise ValueError('obsolete_storage_service')
                if services.get('silo',{}).get('catalog')!='silo' or services.get('silo_client',{}).get('catalog')!='silo-mc':raise ValueError('storage_identity_refused')
            for catalog,image in (('silo',IMAGE),('silo-mc',CLIENT_IMAGE)):
                target=checkout/'infra/dev/catalog'/catalog
                source=Path(__file__).parent/'dev/catalog'/catalog
                for filename in ('service.toml','compose.fragment.yml'):
                    if (target/filename).read_bytes()!=(source/filename).read_bytes():raise ValueError('storage_catalog_mismatch')
                if image not in (target/'service.toml').read_text():raise ValueError('storage_image_mismatch')
            for name,container in containers.items():
                if not isinstance(container,dict) or not container.get('services'):continue
                hosts=call(checkout,'container',name,'hosts')
                routes=hosts.get('routes')
                if not isinstance(routes,list) or any(not isinstance(r,dict) or r.get('service')=='minio' for r in routes):raise ValueError('storage_hosts_refused')
                generated_storage_contract(checkout,IMAGE,CLIENT_IMAGE,lambda projection:receipt.setdefault('generated_compose',[]).append({'checkout':str(checkout),'container':name,**projection}))
                raw=(checkout/'.effigy/runtime/compose/.effigy-compose.generated.yml').read_bytes()
                challenges={
                    'wrong_server_pin':raw.replace(IMAGE.encode(),b'foreign/server',1),
                    'wrong_client_pin':raw.replace(CLIENT_IMAGE.encode(),b'foreign/client',1),
                    'wrong_ready_command':raw.replace(b'- ready',b'- unqualified',1),
                    'wrong_service_name':raw.replace(b'  silo:\n',b'  minio:\n',1),
                    'foreign_data_adoption':raw.replace(b'-silo-data:/data',b'-minio-data:/data',1),
                    'empty_client_proxy':raw.replace(b'  silo_client:\n',b'  silo_client:\n    environment:\n      HTTP_PROXY: ""\n',1),
                    'foreign_config_mount':raw.replace(b'  silo_client:\n',b'  silo_client:\n    volumes:\n      - /foreign:/root/.mc\n',1),
                }
                for challenge,data in challenges.items():
                    if data==raw:raise ValueError('compose_control_unexercised')
                    try:generated_storage_projection(data,IMAGE,CLIENT_IMAGE,lambda projection:None)
                    except ValueError:receipt.setdefault('refusal_controls',[]).append({'container':name,'challenge':challenge,'refused':True})
                    else:raise ValueError('compose_control_false_pass')

            receipt.setdefault('storage',[]).append({'checkout':str(checkout),'named_silo':True,'named_client':True,'catalogs_match':True,'digest_pins_match':True,'existing_data_adopted':False})
    except Exception as error:
        receipt['failure_frames']=[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__) if Path(f.filename).name in ('qualify-profile-preconditions.py','silo_client.py','qualify-reference-optin.py')]
        failure=str(error) if isinstance(error,ValueError) and str(error) in {'obsolete_storage_service','storage_identity_refused','storage_catalog_mismatch','storage_image_mismatch','storage_hosts_refused','compose_boundary_refused','compose_bound_refused','compose_service_refused','compose_contract_refused','compose_control_unexercised','compose_control_false_pass','launcher_task_schema_refused','launcher_control_false_pass','launcher_control_no_boundary','launcher_control_privacy_refused','launcher_journal_refused','typed_composition_unavailable','optin_composition_unavailable','default_composition_changed','native_precondition_refused','native_precondition_schema','binary_changed'} else type(error).__name__
    receipt['failure']=failure
    path=root/'preconditions.json';path.write_text(json.dumps(receipt,indent=2)+'\n');path.chmod(0o600)
    print('PRECONDITION RESULT: '+str(failure or 'passed')+'; runtime effects=false',flush=True)
    return 1 if failure else 0

if __name__=='__main__':raise SystemExit(main())
