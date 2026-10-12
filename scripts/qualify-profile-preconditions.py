#!/usr/bin/env python3
"""No-backend current-source assembly and legacy image availability gate."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
import urllib.error
import urllib.request

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
            receipt['assemblies'].append({'checkout':str(checkout),'profile':'default' if not index else 'explicit_optin','container_names':sorted(containers),'exported_silo_client_asset':(Path(__file__).parent/'dev/silo_client.py').is_file()})
        # Supported extraction only writes into this newly owned checkout. It
        # does not inspect a live backend or substitute Silo for legacy MinIO.
        call(checkouts[0],'service','extract','minio','--dir','infra/dev/catalog')
        catalog=checkouts[0]/'infra/dev/catalog/minio'
        source=Path(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE'])/'crates/effigy-catalog/catalog/minio'
        for filename in ('service.toml','compose.fragment.yml'):
            if (catalog/filename).read_bytes()!=(source/filename).read_bytes():raise ValueError('legacy_catalog_source_mismatch')
        version='RELEASE.2025-09-07T16-13-09Z'
        if ('default = "'+version+'"') not in (catalog/'service.toml').read_text():raise ValueError('legacy_image_pin_unknown')
        receipt['legacy_catalog_digest']=hashlib.sha256((catalog/'compose.fragment.yml').read_bytes()).hexdigest()
        with urllib.request.urlopen('https://auth.docker.io/token?service=registry.docker.io&scope=repository:minio/minio:pull',timeout=20) as response:
            token=strict_json(response.read(65536).decode())['token']
        request=urllib.request.Request('https://registry-1.docker.io/v2/minio/minio/manifests/'+version,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.docker.distribution.manifest.v2+json'})
        try:
            with urllib.request.urlopen(request,timeout=20) as response:status=response.status
        except urllib.error.HTTPError as error:status=error.code
        receipt['legacy_image']={'repository':'minio/minio','tag':version,'manifest_http_status':status,'authenticated_operator_credentials_used':False,'replacement_image_used':False}
        if status!=200:raise ValueError('legacy_image_unavailable_before_effects')
    except Exception as error:
        receipt['failure_frames']=[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__) if Path(f.filename).name in ('qualify-profile-preconditions.py','silo_client.py','qualify-reference-optin.py')]
        failure=str(error) if isinstance(error,ValueError) and str(error) in {'legacy_image_unavailable_before_effects','legacy_catalog_source_mismatch','legacy_image_pin_unknown','typed_composition_unavailable','optin_composition_unavailable','default_composition_changed','native_precondition_refused','native_precondition_schema','binary_changed'} else type(error).__name__
    receipt['failure']=failure
    path=root/'preconditions.json';path.write_text(json.dumps(receipt,indent=2)+'\n');path.chmod(0o600)
    print('PRECONDITION RESULT: '+str(failure or 'passed')+'; runtime effects=false',flush=True)
    return 1 if failure else 0

if __name__=='__main__':raise SystemExit(main())
