"""Original disposable startup intent. Never infer a boot from names or late inventory."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from container_identity_observer import Refusal, identity, file_sha

PROHIBITED=('DOCKER_','CONTAINERD_','NERDCTL_','LIMA_','SSH','COLIMA_','XDG_')
PROFILE='effigy'
INSTANCE='colima-effigy'
MISSING='guest_boot_agent_root_and_actual_mount_observation_unqualified'


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
        self.original_config_digests=[]

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
        if (self.paths['COLIMA_HOME']/PROFILE).exists() or (self.paths['LIMA_HOME']/INSTANCE).exists():
            raise Refusal('profile_preexisting')

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

    def require_boot_read_contract(self):
        raise Refusal(MISSING)

    def start_command(self, env):
        self.planned_start_command(env)
        # The retained Colima InstanceInfo projection has no boot UUID/agent-start/
        # opened-root-file or actual mount observation. No supported additional read
        # contract has been admitted; refuse before an irreversible backend start.
        self.require_boot_read_contract()

    def observer_for(self, checkout, env):
        # Both default and disposable service callers use this exact admission path.
        # Do not construct the reader from its own late labels or owner booleans.
        self.guard()
        checkout=Path(checkout).resolve(strict=True);checkout.relative_to(self.root)
        if not any(value['checkout']==str(checkout) for value in self.original_config_digests):raise Refusal('original_checkout_config_missing')
        if any(env.get(key)!=str(path) for key,path in self.paths.items()):raise Refusal('caller_root_contradiction')
        raise Refusal(MISSING)

    def consume_instance_projection(self, raw):
        from container_identity_observer import strict_json
        if type(raw) is not bytes or len(raw)>65536:raise Refusal('instance_projection_cap')
        value=strict_json(raw)
        fields={'name','status','arch','cpus','memory','disk','dir','network','address','runtime'}
        if type(value) is not dict or not set(value)<=fields:raise Refusal('unsupported_instance_field')
        # These are the actual retained Colima InstanceInfo fields; Running/name/dir
        # never establish a boot, agent start or actual mount.
        self.require_boot_read_contract()

    def observation_requirements(self):
        return {'schema':'underlay.fresh-backend-required-observation.v1',
            'original_intent_sha256':self.intent_sha256,'startup_recipe_prepared':hasattr(self,'prepared'),
            'guest_boot_uuid':'unqualified','agent_kernel_start_and_owned_root_file':'unqualified',
            'actual_mount_and_original_compose_routing':'unqualified',
            'foreign_scope_intents':'required_before_independent_id_witness_capture',
            'original_namespace_address':'required_from_original_startup_configuration',
            'late_inventory_authority':False,'backend_effect_authorized':False}


def selected_tools():
    # Current selected packaged CLI metadata only; no PATH discovery or install.
    return (Path('/opt/homebrew/Cellar/colima/0.10.3/bin/colima'),
            Path('/opt/homebrew/Cellar/lima/2.2.1/bin/limactl'),Path('/usr/bin/ssh'))
