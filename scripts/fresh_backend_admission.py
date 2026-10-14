"""Original disposable startup intent. Never infer a boot from names or late inventory."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shlex
from container_identity_observer import Observer, strict_json, projection
from original_container_route import admit_sources, RouteReader, read_small
from container_identity_observer import Refusal, identity, file_sha

PROHIBITED=('DOCKER_','CONTAINERD_','NERDCTL_','LIMA_','SSH','COLIMA_','XDG_')
PROFILE='effigy'
INSTANCE='colima-effigy'
MISSING='default_container_foreign_fixture_recipe_missing'


def refuse_inherited(env):
    if any(any(key.startswith(prefix) for prefix in PROHIBITED) for key in env):
        raise Refusal('inherited_backend_override')


class FreshBackend:
    def __init__(self, fixture, inherited):
        refuse_inherited(inherited)
        self.root=Path(fixture)
        self.root_identity=identity(self.root,True)
        # This is the new mktemp root, before any backend/tool/config effect.
        if any(self.root.iterdir()):raise Refusal('fixture_preexisting')
        if any(c in str(self.root) for c in ':\n\r\x00'):raise Refusal('mount_path')
        self.env=dict(inherited);self.identities={};self.paths={}
        for key,name in (('HOME','home'),('COLIMA_HOME','colima-home'),('LIMA_HOME','lima-home')):
            path=self.root/name;path.mkdir(mode=0o700)
            self.paths[key]=path;self.identities[key]=identity(path,True)
            self.env[key]=str(path)
        self.intent={'schema':'underlay.fresh-backend-intent.v1','root':str(self.root),
            'profile':PROFILE,'instance':INSTANCE,'runtime':'containerd',
            'roots':{key:str(path) for key,path in self.paths.items()},
            'root_identities':self.identities,'mount':{'host':str(self.root),'guest':str(self.root),'writable':True},
            'startup_attempted':False,'tool_provenance':{},'scope_inputs':[],
            'declared_sources':{'colima':'00f6c297e92a82c04a4ab507db0a61435650d7e8',
                'lima_shell_sha256':'12322b4d0df08c5236f123432fe439877adefe59e44eb49d5b9e1b26d4272642',
                'source_artifact_correspondence':'unattested'}}
        self.path=self.root/'backend-intent.json'
        self._write_intent()
        self.manifest_identities={};self.original_config_digests=[];self.policies={};self.profile_binding=None;self.start_record=None;self.original_route=None

    def _write_intent(self):
        # Original creation is exclusive. Subsequent state is separate; never rebase intent.
        if self.path.exists():raise Refusal('intent_already_recorded')
        fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(self.intent,stream,sort_keys=True)
        self.intent_sha256=hashlib.sha256(self.path.read_bytes()).hexdigest()

    def guard(self):
        if identity(self.root,True)[:4]!=self.root_identity[:4]:
            raise Refusal('fixture_identity_changed')
        for key,path in self.paths.items():
            # Directory contents can be prepared under the owned root; original inode,
            # mode and owner must remain, and a profile cannot already exist pre-start.
            if identity(path,True)[:4]!=self.identities[key][:4]:raise Refusal('root_identity_changed')
        if hashlib.sha256(self.path.read_bytes()).hexdigest()!=self.intent_sha256:raise Refusal('intent_changed')
        if self.start_record is None:
            if (self.paths['COLIMA_HOME']/PROFILE).exists() or (self.paths['LIMA_HOME']/INSTANCE).exists():
                raise Refusal('profile_preexisting')
        elif file_sha(self.start_record[0],1048576)!=self.start_record[1]:raise Refusal('start_intent_changed')
        if set(self.policies)!=set(getattr(self,'policy_records',{})):raise Refusal('original_policy_incomplete')
        for name,stamp in self.manifest_identities.items():
            if identity(name)[:4]!=stamp:raise Refusal('original_manifest_inode_changed')
        for key,(path,digest,policy,manifest_sha) in getattr(self,'policy_records',{}).items():
            if file_sha(Path(key[0])/'effigy.toml',1048576)!=manifest_sha:raise Refusal('original_manifest_changed')
            if file_sha(path,1048576)!=digest or self.policies.get(key)!=policy:raise Refusal('original_policy_changed')
        if self.profile_binding:
            if hashlib.sha256(json.dumps(self.profile_binding,sort_keys=True).encode()).hexdigest()!=self.profile_binding_sha256:raise Refusal('profile_binding_changed')
            for key,value in self.profile_binding['identities'].items():
                path=self.profile_binding[key]
                if key.endswith('_dir'):
                    if self._profile_dir(path)!=tuple(value):raise Refusal('profile_root_changed')
                elif identity(path)!=tuple(value) or file_sha(path,1048576)!=self.profile_binding[key+'_sha256']:
                    raise Refusal('profile_config_changed')

    def original_scope(self, checkout, captured_config, source_sha256):
        """Consume the actual caller's pre-start captured config bytes, never inspect rows."""
        self.guard();checkout=Path(checkout).resolve(strict=True);checkout.relative_to(self.root)
        if type(captured_config) is not bytes or not captured_config or len(captured_config)>1048576:
            raise Refusal('original_config_capture')
        if not re.fullmatch('[0-9a-f]{64}',str(source_sha256)):raise Refusal('original_source_identity')
        record={'checkout':str(checkout),'original_intent_sha256':self.intent_sha256,
            'captured_config_sha256':hashlib.sha256(captured_config).hexdigest(),'source_sha256':source_sha256,
            'service_policy_verified':False}
        path=self.root/('scope-source-'+hashlib.sha256(str(checkout).encode()).hexdigest()+'.json')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(record,stream,sort_keys=True)
        self.original_config_digests.append(record)
        # This is source association evidence only. Service/project policy still needs
        # the supported original renderer/schema rather than inferred late labels.

    def bind_tools(self, colima, limactl, ssh):
        self.guard()
        provenance={}
        for name,path in (('colima',colima),('limactl',limactl),('ssh',ssh)):
            path=Path(path);stamp=identity(path,executable=True)
            provenance[name]={'path':str(path),'identity':stamp,'sha256':file_sha(path,268435456),
                              'binary_source_attested':False}
        self.intent['tool_provenance']=provenance
        self.prepared=copy.deepcopy(self.intent)
        self.prepared['scope_inputs']=copy.deepcopy(self.original_config_digests)
        self.prepared['original_intent_sha256']=self.intent_sha256
        self.prepared_path=self.root/'backend-prepared.json'
        fd=os.open(self.prepared_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(self.prepared,stream,sort_keys=True)
        self.prepared_sha256=hashlib.sha256(self.prepared_path.read_bytes()).hexdigest()

    def planned_start_command(self, env):
        self.guard()
        if any(env.get(key)!=str(path) for key,path in self.paths.items()):raise Refusal('caller_root_contradiction')
        if any(key.startswith(('DOCKER_','CONTAINERD_','NERDCTL_','SSH','XDG_')) for key in env):raise Refusal('caller_environment_override')
        if not getattr(self,'prepared',None):raise Refusal('selected_tools_missing')
        for tool in self.prepared['tool_provenance'].values():
            if identity(tool['path'],executable=True)!=tuple(tool['identity']) or file_sha(tool['path'],268435456)!=tool['sha256']:
                raise Refusal('selected_tool_changed')
        if hashlib.sha256(json.dumps(self.prepared,sort_keys=True).encode()).hexdigest()!=self.prepared_sha256 or hashlib.sha256(self.prepared_path.read_bytes()).hexdigest()!=self.prepared_sha256:raise Refusal('prepared_intent_changed')
        return [self.prepared['tool_provenance']['colima']['path'],'start','--profile',PROFILE,
                '--runtime','containerd','--activate=false','--ssh-config=false','--ssh-agent=false',
                '--template=false','--mount',str(self.root)+':w',
                '--cpu','6','--memory','8','--disk','64']

    def require_read_contract(self):
        self.route_source=admit_sources()
        return copy.deepcopy(self.route_source)

    def verify_environment(self, env):
        if any(env.get(key)!=str(path) for key,path in self.paths.items()):raise Refusal('caller_root_contradiction')
        allowed={'LIMA_HOME','COLIMA_HOME'}
        if any(key not in allowed and key.startswith(PROHIBITED) for key in env):raise Refusal('caller_environment_override')

    def verify_tools(self):
        if not getattr(self,'prepared',None):raise Refusal('selected_tools_missing')
        for tool in self.prepared['tool_provenance'].values():
            if identity(tool['path'],executable=True)!=tuple(tool['identity']) or file_sha(tool['path'],268435456)!=tool['sha256']:
                raise Refusal('selected_tool_changed')

    def original_policy(self, checkout, container, config_raw, scope_raw):
        try:return self._original_policy(checkout,container,config_raw,scope_raw)
        except Refusal:raise
        except Exception:raise Refusal('original_policy_input_unavailable') from None

    def _original_policy(self, checkout, container, config_raw, scope_raw):
        """Actual pre-start config --inspect --path and container scope JSON, not labels."""
        self.guard();checkout=Path(checkout).resolve(strict=True);checkout.relative_to(self.root)
        if container not in ('default','hybrid_services','disposable_test'):raise Refusal('original_container_policy')
        def result(raw):
            if type(raw) is not bytes or len(raw)>1048576:raise Refusal('original_policy_cap')
            envelope=strict_json(raw)
            if envelope.get('ok') is not True or type(envelope.get('result')) is not dict:raise Refusal('original_policy_envelope')
            return envelope['result']
        selected=result(config_raw);scope=result(scope_raw);path='containers' if container=='default' else 'containers.'+container
        if selected.get('schema')!='effigy.config.v1' or selected.get('selected_path')!=path or selected.get('selected_value',{}).get('path')!=path:
            raise Refusal('original_policy_schema')
        policy=selected['selected_value']['value']
        if container=='default':
            name=policy.get('default')
            if type(name) is not str or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}',name) or type(policy.get(name)) is not dict:raise Refusal('original_default_container_alias')
            policy=policy[name]
        # Exact bd259769 policy/load.rs unwrap_or Colima; lib.rs profile default effigy.
        # These are manifest policy defaults, separate from guest nerdctl defaults.
        if policy.get('driver','colima')!='colima' or policy.get('profile',PROFILE)!=PROFILE or type(policy.get('services')) is not dict or not policy['services'] or len(policy['services'])>64:
            raise Refusal('original_policy_routing')
        # Reuse owning production Git/scope decoder, including primary-none/worktree.
        import sys
        sys.path.insert(0,str(Path(__file__).parent/'dev'))
        from port_inventory import checkout_identity
        try:chosen=checkout_identity(scope,checkout,policy)
        except Exception:raise Refusal('original_scope_identity') from None
        services=sorted(policy['services']);primary=policy.get('primary_service')
        if any(not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}',name) for name in services) or type(primary) is not str or primary not in services:raise Refusal('original_service_policy')
        key=(str(checkout),container)
        if self.start_record is not None or key in self.policies:raise Refusal('original_policy_late_or_duplicate')
        self.manifest_identities[str(checkout/'effigy.toml')]=identity(checkout/'effigy.toml')[:4]
        self.policies[key]={'project':chosen['project'],'checkout':str(checkout),'services':services,'primary':primary,'oneoffs':[]}
        record={'intent_sha256':self.intent_sha256,'config_sha256':hashlib.sha256(config_raw).hexdigest(),
                'scope_sha256':hashlib.sha256(scope_raw).hexdigest(),'manifest_sha256':file_sha(checkout/'effigy.toml',1048576),'policy':self.policies[key]}
        name='policy-'+hashlib.sha256(repr(key).encode()).hexdigest()+'.json'
        path=self.root/name;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(record,stream,sort_keys=True)
        self.policies[key]=copy.deepcopy(self.policies[key])
        if not hasattr(self,'policy_records'):self.policy_records={}
        self.policy_records[key]=(path,file_sha(path,1048576),copy.deepcopy(self.policies[key]),record['manifest_sha256'])

    def start_command(self, env):
        args=self.planned_start_command(env);self.require_read_contract();self.verify_environment(env)
        if not self.policies:raise Refusal('original_semantic_policy_missing')
        if self.start_record is not None:raise Refusal('startup_already_attempted')
        path=self.root/'backend-start-intent.json'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump({'intent_sha256':self.intent_sha256,'startup_recipe_sha256':hashlib.sha256(json.dumps(args).encode()).hexdigest()},stream)
        self.start_record=(path,file_sha(path,1048576));return args

    def _profile_dir(self, path):
        path=Path(path)
        if path.resolve(strict=True)!=path or not path.is_relative_to(self.root):raise Refusal('profile_path')
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022:raise Refusal('profile_permissions')
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid)

    def bind_generated_profile(self):
        self.guard()
        if self.start_record is None or self.profile_binding is not None:raise Refusal('original_start_required')
        directory=self.paths['LIMA_HOME']/INSTANCE;colima=self.paths['COLIMA_HOME']/PROFILE
        config=directory/'lima.yaml';colima_config=colima/'colima.yaml'
        binding={'config_dir':str(directory),'colima_dir':str(colima),'config':str(config),'colima_config':str(colima_config),'identities':{}}
        for key in ('config_dir','colima_dir'):binding['identities'][key]=self._profile_dir(binding[key])
        for key in ('config','colima_config'):
            identity(binding[key]);os.chmod(binding[key],0o600) # only new intent-owned generated files
            binding['identities'][key]=identity(binding[key]);binding[key+'_sha256']=file_sha(binding[key],1048576)
        raw=read_small(config)
        # Source-qualified limaconfig.Mount fields; deliberately narrow generated YAML.
        try:text=raw.decode('utf-8')
        except Exception:raise Refusal('mount_config_encoding') from None
        if '\t' in text or len(raw)>1048576 or re.search(r'(?m)^ *[^#\n]+: *[&*!]',text):raise Refusal('mount_config_shape')
        keys=re.findall(r'(?m)^([A-Za-z][A-Za-z0-9_]*):',text)
        if len(set(keys))!=len(keys):raise Refusal('mount_config_duplicate')
        match=re.search(r'(?ms)^mounts:\n(.*?)(?=^[A-Za-z]|\Z)',text)
        if not match:raise Refusal('sole_private_mount_missing')
        lines=[line.strip() for line in match[1].splitlines() if line.strip()]
        values={}
        for line in lines:
            m=re.fullmatch(r'(?:- )?(location|mountPoint|writable): (.+)',line)
            if not m or m[1] in values:raise Refusal('sole_private_mount_shape')
            value=m[2]
            if value.startswith('"'):
                try:value=json.loads(value)
                except Exception:raise Refusal('mount_scalar') from None
            values[m[1]]=value
        if values.get('location')!=str(self.root) or values.get('mountPoint',str(self.root))!=str(self.root) or values.get('writable')!='true':raise Refusal('sole_private_mount_mismatch')
        colima_raw=read_small(colima_config)
        if colima_raw.count(b'\nruntime: containerd\n')+int(colima_raw.startswith(b'runtime: containerd\n'))!=1:raise Refusal('original_profile_runtime')
        self.profile_binding=binding
        self.profile_binding_sha256=hashlib.sha256(json.dumps(binding,sort_keys=True).encode()).hexdigest()
        self.guard()

    def route_context(self):
        if not self.profile_binding:raise Refusal('original_profile_config_missing')
        tools=self.prepared['tool_provenance']
        return {'limactl':tools['limactl']['path'],'ssh':tools['ssh']['path'],'cwd':str(self.root),
                'instance':INSTANCE,'config':self.profile_binding['config'],'config_sha256':self.profile_binding['config_sha256'],
                'colima_home':str(self.paths['COLIMA_HOME']),'lima_home':str(self.paths['LIMA_HOME'])}

    def reader_environment(self):
        tools=self.prepared['tool_provenance']
        return {'HOME':str(self.paths['HOME']),'COLIMA_HOME':str(self.paths['COLIMA_HOME']),'LIMA_HOME':str(self.paths['LIMA_HOME']),
                'SSH':shlex.join([tools['ssh']['path'],'-o','ControlMaster=no','-o','ControlPersist=no']),
                'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}

    def admit_original_route(self, env):
        try:return self._admit_original_route(env)
        except Refusal:raise
        except Exception:raise Refusal('original_route_input_unavailable') from None

    def _admit_original_route(self, env):
        self.guard();self.verify_environment(env)
        if self.profile_binding is None:self.bind_generated_profile()
        observed=RouteReader(self,env).observe()
        if self.original_route is not None and observed!=self.original_route:
            # Capture evidence can vary only in timing-free counts; original identity
            # and full help/config/binary digests must remain exact.
            for key in ('namespace','address','binary_sha256','config_state','config_sha256','help_sha256'):
                if observed[key]!=self.original_route[key]:raise Refusal('original_route_changed')
        if self.original_route is None:self.original_route=copy.deepcopy(observed)
        return copy.deepcopy(observed)

    def observer_for(self, checkout, env, container='default', foreign_scopes=(), *, foreign_fixture=None):
        try:return self._observer_for(checkout,env,container,foreign_scopes,foreign_fixture)
        except Refusal:raise
        except Exception:raise Refusal('original_observer_input_unavailable') from None

    def _observer_for(self, checkout, env, container, foreign_scopes, foreign_fixture):
        self.guard();self.verify_environment(env)
        key=(str(Path(checkout).resolve(strict=True)),container)
        if key not in self.policies:raise Refusal('original_semantic_policy_missing')
        for policy_key,(path,digest,policy,manifest_sha) in self.policy_records.items():
            if file_sha(path,1048576)!=digest or self.policies.get(policy_key)!=policy:raise Refusal('original_policy_changed')
        scopes=[copy.deepcopy(self.policies[key])];foreign_policies=[]
        for foreign_key in foreign_scopes:
            if foreign_key not in self.policies or foreign_key==key:raise Refusal('foreign_original_policy_missing')
            foreign_policies.append(copy.deepcopy(self.policies[foreign_key]))
        if not foreign_policies:
            from foreign_container_fixture import ForeignFixture
            if not isinstance(foreign_fixture,ForeignFixture) or not foreign_fixture.owns_scope(self,key):
                raise Refusal('independent_foreign_scope_required')
        projects=[p['project'] for p in scopes+foreign_policies]
        if len(set(projects))!=len(projects):raise Refusal('foreign_project_conflict')
        self.admit_original_route(env)
        tools=self.prepared['tool_provenance'];route=self.original_route
        context={**self.route_context(),'schema':'underlay.container-observer-context.v2',
                'private_home':str(self.paths['HOME']),'startup_intent_sha256':self.intent_sha256,
                'limactl_sha256':tools['limactl']['sha256'],'ssh_sha256':tools['ssh']['sha256'],
                'namespace':route['namespace'],'address':route['address'],'boot':None,'scopes':scopes,'foreign':{}}
        probe=Observer(context,env,self.root,{k:copy.deepcopy(v) for k,v in context.items() if k!='schema'})
        values=probe.snapshot()['containers'];foreign={};seen=set()
        for full_id,value in values.items():
            matches=[p for p in foreign_policies if p['project']==value['project']]
            if matches:
                policy=matches[0]
                if value['checkout'] not in (None,'',policy['checkout']) or value['service'] not in policy['services'] or value['oneoff'] not in (None,'','false','False'):raise Refusal('foreign_original_scope_mismatch')
                token=(policy['project'],value['service'])
                if token in seen:raise Refusal('foreign_duplicate_service')
                seen.add(token);foreign[full_id]=value
            elif value['project']!=scopes[0]['project']:raise Refusal('foreign_inventory_unclassified')
        if seen!={(p['project'],s) for p in foreign_policies for s in p['services']}:raise Refusal('foreign_inventory_incomplete')
        context['foreign']=foreign
        reader=Observer(context,env,self.root,{k:copy.deepcopy(v) for k,v in context.items() if k!='schema'})
        reader.original_admission=self
        return reader

    def consume_instance_projection(self, raw):
        from container_identity_observer import strict_json
        if type(raw) is not bytes or len(raw)>65536:raise Refusal('instance_projection_cap')
        value=strict_json(raw)
        fields={'name','status','arch','cpus','memory','disk','dir','network','address','runtime'}
        if type(value) is not dict or not set(value)<=fields:raise Refusal('unsupported_instance_field')
        # Availability only. Never use this projection to construct original context.
        if value.get('name')!=INSTANCE or value.get('runtime')!='containerd' or value.get('status')!='Running':
            raise Refusal('instance_availability_unknown')
        return {'available':True,'boot_identity':'unknown','signal_authority':False}

    def observation_requirements(self):
        return {'schema':'underlay.fresh-backend-required-observation.v1',
            'original_intent_sha256':self.intent_sha256,'startup_recipe_prepared':hasattr(self,'prepared'),
            'guest_boot_uuid':'unknown_not_required_for_read_association','agent_kernel_start_and_owned_root_file':'unknown_no_signal_authority',
            'actual_mount':'requires_original_sole_private_mount_config_and_nonce_correspondence',
            'remaining_product_gap':MISSING,'original_compose_policy':'semantic_decode_prepared_requires_original_capture',
            'route_recipe_source_admitted':hasattr(self,'route_source'),'actual_route_observed':self.original_route is not None,
            'foreign_scope_intents':'required_before_independent_id_witness_capture',
            'original_namespace_address':'required_from_original_startup_configuration',
            'late_inventory_authority':False,'backend_effect_authorized':False}


def selected_tools():
    # Current selected packaged CLI metadata only; no PATH discovery or install.
    return (Path('/opt/homebrew/Cellar/colima/0.10.3/bin/colima'),
            Path('/opt/homebrew/Cellar/lima/2.2.1/bin/limactl'),Path('/usr/bin/ssh'))
