"""No-effect digest-pinned image defaults and exec-input preflight."""
import hashlib
import json
import urllib.request

from silo_fixture import PINS
from routing_guard import predicates, OWNER_CLIENT_COMMAND_INPUT

CONFIG_DIGESTS={'pgsty/silo':'sha256:a9590da2668a2589dee6e1f8754c755074695794aaba389b6c7e78199688e2d5',
                'pgsty/mc':'sha256:37a94867c70839fe649c7ecfff0adad3b8d30fbdba35cdd33bf409cf27d01378'}
EXPECTED={'expected_server_configdir':'/tmp/.mc','expected_home':'/root','expected_server_home':'/tmp',
          'expected_loopback_alias':'http://minioadmin:minioadmin@127.0.0.1:9000'}


def baseline(image_env,compose_env,service,mount_targets=(),command_input=None):
    # The selected secondary service has no workspace HOME handoff. No value
    # from image/Compose/native inputs is invented from a user or shell name.
    if any(not isinstance(p,str) or not p.startswith('/') or '..' in p.split('/') for p in mount_targets):
        raise ValueError('service_mount_boundary_refused')
    protected='/tmp/.mc' if service=='silo' else '/root/.mc'
    if any(p=='/' or protected==p or protected.startswith(p.rstrip('/')+'/') for p in mount_targets):
        raise ValueError('service_mount_boundary_refused')
    effective={**image_env,**compose_env}
    inherited_home={'presence':'absent' if 'HOME' not in effective else 'empty' if effective['HOME']=='' else 'present',
                    'expected_agreement':effective.get('HOME')=='/root', 'default_home_qualified':False}
    if command_input is not None:
        if service!='silo_client' or command_input is not OWNER_CLIENT_COMMAND_INPUT:
            raise ValueError('client_command_input_refused')
        effective['HOME']='/root'
    records=[]
    for name,rule in predicates(service):
        state='absent' if name not in effective else 'empty' if effective[name]=='' else 'present'
        agreement=(state=='absent') if rule=='absent' else state=='present' and effective[name]==EXPECTED[rule]
        records.append({'predicate':name,'rule':rule,'presence':state,'agreement':agreement,
                        'resolution':'owner_command_input' if name=='HOME' and command_input is OWNER_CLIENT_COMMAND_INPUT else 'unknown_shell_default' if name=='HOME' and state=='absent' else 'declared_inputs'})
    return {'service':service,'predicates':records,'baseline_passed':all(r['agreement'] for r in records),
            'runtime_credit':False,'mount_boundary_passed':True,
            'home_input_observation':inherited_home if service=='silo_client' else None}


def image_defaults(repository):
    pin=PINS[repository]
    with urllib.request.urlopen('https://auth.docker.io/token?service=registry.docker.io&scope=repository:'+repository+':pull',timeout=20) as response:
        token=json.loads(response.read(65537))['token']
    def fetch(kind,digest):
        request=urllib.request.Request('https://registry-1.docker.io/v2/'+repository+'/'+kind+'/'+digest,
          headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json'})
        with urllib.request.urlopen(request,timeout=30) as response:raw=response.read(8388609)
        if len(raw)>8388608 or 'sha256:'+hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('service_image_digest_refused')
        return json.loads(raw)
    index=fetch('manifests',pin['digest'])
    rows=[m for m in index['manifests'] if m.get('platform',{}).get('os')=='linux' and m.get('platform',{}).get('architecture')=='arm64']
    if len(rows)!=1 or rows[0]['digest']!=pin['arm64']:raise ValueError('service_image_digest_refused')
    child=fetch('manifests',pin['arm64'])
    if child['config']['digest']!=CONFIG_DIGESTS[repository]:raise ValueError('service_image_digest_refused')
    settings=fetch('blobs',child['config']['digest'])['config']
    if settings['Entrypoint']!=pin['entrypoint']:raise ValueError('service_image_entrypoint_refused')
    env={}
    for entry in settings.get('Env',[]):
        name,separator,value=entry.partition('=')
        if not separator or name in env:raise ValueError('service_image_env_refused')
        env[name]=value
    return env  # Private memory only, caller persists baseline booleans.
