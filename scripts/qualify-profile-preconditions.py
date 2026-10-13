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
            receipt['assemblies'].append({'checkout':str(checkout),'profile':'default' if not index else 'explicit_optin','container_names':sorted(set(containers)&{'default','stack','hybrid_services','disposable_test'}),'unknown_container_count':len(set(containers)-{'default','stack','hybrid_services','disposable_test'}),'exported_silo_client_asset':(Path(__file__).parent/'dev/silo_client.py').is_file()})
        from dev import profile_launcher as launcher
        from silo_fixture import IMAGE, CLIENT_IMAGE
        for checkout in checkouts:
            launcher._prepare_silo_override(checkout)
            value=call(checkout,'config','--inspect','--path','containers')
            containers=value['selected_value']['value']
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
            receipt.setdefault('storage',[]).append({'checkout':str(checkout),'named_silo':True,'named_client':True,'catalogs_match':True,'digest_pins_match':True,'existing_data_adopted':False})
    except Exception as error:
        receipt['failure_frames']=[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__) if Path(f.filename).name in ('qualify-profile-preconditions.py','silo_client.py','qualify-reference-optin.py')]
        failure=str(error) if isinstance(error,ValueError) and str(error) in {'obsolete_storage_service','storage_identity_refused','storage_catalog_mismatch','storage_image_mismatch','typed_composition_unavailable','optin_composition_unavailable','default_composition_changed','native_precondition_refused','native_precondition_schema','binary_changed'} else type(error).__name__
    receipt['failure']=failure
    path=root/'preconditions.json';path.write_text(json.dumps(receipt,indent=2)+'\n');path.chmod(0o600)
    print('PRECONDITION RESULT: '+str(failure or 'passed')+'; runtime effects=false',flush=True)
    return 1 if failure else 0

if __name__=='__main__':raise SystemExit(main())
