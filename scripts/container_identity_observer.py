"""Qualification-only Lima/nerdctl read projection. Never remote cancellation authority."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import shlex
import stat
import subprocess
import time

DEADLINE_SECONDS=30
CALL_SECONDS=8
STDOUT_CAP=65536
STDERR_CAP=16384
MAX_IDS=64
ID=re.compile(r'[0-9a-f]{64}')
SLUG=re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}')
FIELDS={'id','created','project','checkout','service','oneoff','running','status'}
TEMPLATE='{'+','.join('"'+key+'":{{json '+expression+'}}' for key,expression in (
    ('id','.ID'),('created','.Created'),
    ('project','(index .Config.Labels "com.docker.compose.project")'),
    ('checkout','(index .Config.Labels "com.docker.compose.project.working_dir")'),
    ('service','(index .Config.Labels "com.docker.compose.service")'),
    ('oneoff','(index .Config.Labels "com.docker.compose.oneoff")'),
    ('running','.State.Running'),('status','.State.Status')))+'}'

class Refusal(RuntimeError):pass


def identity(path, directory=False, executable=False):
    path=Path(path)
    if not path.is_absolute() or path.resolve(strict=True)!=path:raise Refusal('noncanonical_path')
    info=path.lstat()
    if info.st_uid not in ((0,os.geteuid()) if executable else (os.geteuid(),)) or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise Refusal('path_ownership')
    if executable and (info.st_mode&0o022 or not info.st_mode&0o111):raise Refusal('executable_permissions')
    if directory and stat.S_IMODE(info.st_mode)!=0o700:raise Refusal('private_root_permissions')
    if not directory and info.st_nlink!=1:raise Refusal('file_identity')
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_size,info.st_mtime_ns)


def file_sha(path, limit):
    before=identity(path,executable=limit>1048576)
    if before[4]>limit:raise Refusal('input_file_cap')
    digest=hashlib.sha256();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        total=0
        while True:
            data=stream.read(16384)
            if not data:break
            total+=len(data)
            if total>limit:raise Refusal('input_file_cap')
            digest.update(data)
    if identity(path,executable=limit>1048576)!=before:raise Refusal('input_file_changed')
    return digest.hexdigest()


def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise Refusal('duplicate_field')
            result[key]=value
        return result
    try:return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs)
    except Refusal:raise
    except Exception:raise Refusal('json_framing') from None


def projection(raw, expected_id):
    if not raw.endswith(b'\n') or raw.count(b'\n')!=1:raise Refusal('inspect_framing')
    value=strict_json(raw)
    if type(value) is not dict or set(value)!=FIELDS or value['id']!=expected_id:raise Refusal('inspect_schema')
    if not ID.fullmatch(str(value['id'])):raise Refusal('inspect_identity')
    if not isinstance(value['created'],str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)',value['created']):raise Refusal('creation_identity')
    for key in ('project','service'):
        if type(value[key]) is not str or (value[key] and not SLUG.fullmatch(value[key])):raise Refusal('scope_field')
    if type(value['checkout']) is not str or len(value['checkout'])>1024 or any(c in value['checkout'] for c in '\r\n\x00'):raise Refusal('checkout_field')
    if value['oneoff'] not in ('','true','false','True','False') or type(value['running']) is not bool or value['status'] not in ('created','running','paused','restarting','removing','exited','dead'):raise Refusal('state_field')
    if value['running'] != (value['status'] in ('running','paused','restarting')):raise Refusal('state_contradiction')
    return value


def inventory(raw):
    if raw==b'':return ()  # Only accepted after complete exit/EOF; baseline cannot be empty.
    if not raw.endswith(b'\n'):raise Refusal('inventory_framing')
    rows=raw[:-1].split(b'\n')
    if len(rows)>MAX_IDS:raise Refusal('inventory_cardinality')
    try:values=tuple(row.decode('ascii') for row in rows)
    except Exception:raise Refusal('inventory_encoding') from None
    if any(not ID.fullmatch(value) for value in values) or len(set(values))!=len(values):raise Refusal('inventory_identity')
    return tuple(sorted(values))


def host_capture(argv, env, cwd, deadline):
    """Bound before retained collection; discard stderr entirely. Reap only after EOF/refusal."""
    if time.monotonic()>=deadline:raise Refusal('deadline_before_dispatch')
    try:process=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except Exception:raise Refusal('capture_launch') from None
    streams=selectors.DefaultSelector();counts={'stdout':0,'stderr':0};out=bytearray();reason=None;eof={'stdout':False,'stderr':False}
    try:
        for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
            os.set_blocking(stream.fileno(),False);streams.register(stream,selectors.EVENT_READ,name)
        while streams.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise Refusal('capture_deadline')
            for event,_ in streams.select(min(remaining,.05)):
                try:data=os.read(event.fd,4096)
                except BlockingIOError:continue
                except OSError:raise Refusal('capture_read') from None
                if not data:eof[event.data]=True;streams.unregister(event.fileobj);continue
                name=event.data;counts[name]+=len(data)
                if counts[name]>(STDOUT_CAP if name=='stdout' else STDERR_CAP):raise Refusal('capture_cap')
                if name=='stdout':out.extend(data)
        remaining=deadline-time.monotonic()
        if remaining<=0:raise Refusal('capture_deadline')
        code=process.wait(timeout=remaining)
        if code!=0:raise Refusal('capture_nonzero')
        if counts['stderr']:raise Refusal('stderr_output')
        if time.monotonic()>=deadline:raise Refusal('capture_late')
        return bytes(out),{'stdout_observed':counts['stdout'],'stderr_observed':counts['stderr'],
            'stdout_eof':True,'stderr_eof':True,'leader_reaped':True,'exit_code':0,
            'stdout_sha256':hashlib.sha256(out).hexdigest(),'remote_cancellation_verified':False}
    except Refusal as error:reason=error
    except Exception:reason=Refusal('capture_unavailable')
    finally:
        # Never poll/reap while incomplete pipes remain. Popen retains the exact direct
        # child PID; only that unreaped child can be signalled. No group or post-reap kill.
        if process.returncode is None:
            try:process.kill()
            except ProcessLookupError:pass
            try:process.wait(timeout=1)
            except Exception:reason=Refusal('direct_child_settlement_unknown')
        streams.close();process.stdout.close();process.stderr.close()
    if reason is not None:
        reason.evidence={'stdout_observed':counts['stdout'],'stderr_observed':counts['stderr'],'stdout_eof':eof['stdout'],'stderr_eof':eof['stderr'],'leader_reaped':process.returncode is not None,'exit_code':process.returncode,'remote_cancellation_verified':False}
        raise reason from None


class Observer:
    def __init__(self, context, inherited_env, fixture, original):
        try:self._admit(context,inherited_env,fixture,original)
        except Refusal:raise
        except Exception:raise Refusal('context_unavailable') from None

    def _admit(self, context, inherited_env, fixture, original):
        self.context=context;self.fixture=Path(fixture);self.bound={}
        required={'schema','limactl','limactl_sha256','ssh','ssh_sha256','colima_home','lima_home','cwd','config','config_sha256','instance','namespace','address','boot','scopes','foreign'}
        if type(context) is not dict:raise Refusal('context_schema')
        if context.get('schema')=='underlay.container-observer-context.v2':
            required|={'private_home','startup_intent_sha256'}
        elif context.get('schema')!='underlay.container-observer-context.v1':raise Refusal('context_schema')
        if set(context)!=required:raise Refusal('context_schema')
        if 'startup_intent_sha256' in context and not re.fullmatch('[a-f0-9]{64}',str(context['startup_intent_sha256'])):raise Refusal('startup_intent_identity')
        if any(type(context[k]) is not str for k in required-{'scopes','foreign','boot'}):raise Refusal('context_type')
        if type(context['scopes']) is not list or not 1<=len(context['scopes'])<=3 or type(context['foreign']) is not dict or len(context['foreign'])>MAX_IDS:raise Refusal('context_cardinality')
        if any(key.startswith(('CONTAINERD_','NERDCTL_')) or (key.startswith('LIMA_') and key!='LIMA_HOME') or key in ('SSH','COLIMA_PROFILE','DOCKER_HOST','DOCKER_CONTEXT') for key in inherited_env):raise Refusal('inherited_override')
        for key,field in (('LIMA_HOME','lima_home'),('COLIMA_HOME','colima_home')):
            if key in inherited_env and inherited_env[key]!=context[field]:raise Refusal('inherited_root_contradiction')
        # Original inputs must come from the caller's admitted new-backend/config/Compose
        # bindings, not be discovered or substituted by this metadata reader.
        original_fields=required-{'schema'}
        if type(original) is not dict or set(original)!=original_fields or any(context[k]!=original[k] for k in original_fields):raise Refusal('original_input_mismatch')
        identity(self.fixture,True)
        for key in ('colima_home','lima_home','cwd')+ (('private_home',) if 'private_home' in context else ()):
            path=Path(context[key]);path.relative_to(self.fixture)
            self.bound[key]=identity(path,True)
        if context['colima_home']==context['lima_home']:raise Refusal('independent_lima_root')
        config=Path(context['config']);config.relative_to(Path(context['lima_home'])/context['instance'])
        self.bound['config']=identity(config)
        if stat.S_IMODE(config.stat().st_mode)!=0o600:raise Refusal('config_permissions')
        for key in ('limactl','ssh','config'):
            if file_sha(context[key],1048576 if key=='config' else 268435456)!=context[key+'_sha256']:raise Refusal('provenance_changed')
            self.bound[key]=identity(context[key],executable=key in ('limactl','ssh'))
        if not SLUG.fullmatch(str(context['instance'])) or not SLUG.fullmatch(str(context['namespace'])):raise Refusal('routing_identity')
        if not re.fullmatch(r'/[a-zA-Z0-9_./-]+\.sock',str(context['address'])):raise Refusal('address_identity')
        if context['boot'] is not None and not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',str(context['boot'])):raise Refusal('boot_identity')
        # Optional historical data; never required for read association or signal authority.
        if type(context['scopes']) is not list or not context['scopes']:raise Refusal('original_scopes')
        projects=set()
        for scope in context['scopes']:
            if type(scope) is not dict or set(scope)!={'project','checkout','services','primary','oneoffs'}:raise Refusal('scope_schema')
            if not SLUG.fullmatch(str(scope['project'])) or scope['project'] in projects:raise Refusal('project_identity')
            projects.add(scope['project']);checkout=Path(scope['checkout']);checkout.relative_to(self.fixture)
            if checkout.resolve(strict=True)!=checkout:raise Refusal('original_checkout')
            if type(scope['services']) is not list or not scope['services'] or len(scope['services'])>MAX_IDS or len(set(scope['services']))!=len(scope['services']) or any(not SLUG.fullmatch(str(x)) for x in scope['services']):raise Refusal('original_services')
            if scope['primary'] is not None and scope['primary'] not in scope['services']:raise Refusal('primary_identity')
            if type(scope['oneoffs']) is not list or not set(scope['oneoffs'])<=set(scope['services']):raise Refusal('oneoff_policy')
        if type(context['foreign']) is not dict:raise Refusal('foreign_witness')
        for full_id,value in context['foreign'].items():
            if not ID.fullmatch(full_id) or projection((json.dumps(value)+'\n').encode(),full_id)!=value:raise Refusal('foreign_witness')
            if value['project'] in projects:raise Refusal('foreign_scope_conflict')
        self.context=copy.deepcopy(context)
        self.env={'HOME':context.get('private_home',str(self.fixture)),'COLIMA_HOME':context['colima_home'],'LIMA_HOME':context['lima_home'],
                  'SSH':shlex.join([context['ssh'],'-o','ControlMaster=no','-o','ControlPersist=no']),'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}
        self._baseline=None;self._post_attempted=False;self.capture_evidence=[];self.cwd_evidence=[]
        self.binding=hashlib.sha256(json.dumps({'context':context,'identities':self.bound},sort_keys=True).encode()).hexdigest()

    def guard(self):
        admission=getattr(self,'original_admission',None)
        if admission is not None:
            admission.guard();admission.verify_tools()
            if self.env!=admission.reader_environment():raise Refusal('original_reader_environment_changed')
        current=hashlib.sha256(json.dumps({'context':self.context,'identities':self.bound},sort_keys=True).encode()).hexdigest()
        if current!=self.binding:raise Refusal('context_changed')
        for key,value in self.bound.items():
            directory=key in ('colima_home','lima_home','cwd','private_home')
            current=identity(self.context[key],directory,key in ('limactl','ssh'))
            if (current[:4] if directory else current)!=(value[:4] if directory else value):raise Refusal('routing_changed')
            if key in ('limactl','ssh','config') and file_sha(self.context[key],1048576 if key=='config' else 268435456)!=self.context[key+'_sha256']:raise Refusal('provenance_changed')

    def argv(self, read_args):
        c=self.context
        return [c['limactl'],'shell','--workdir',c['cwd'],c['instance'],'sudo','nerdctl',
                '--namespace',c['namespace'],'--address',c['address'],*read_args]

    def read(self, args, deadline):
        if args!=['ps','--all','--no-trunc','--quiet'] and not (len(args)==7 and args[:6]==['container','inspect','--mode','dockercompat','--format',TEMPLATE] and ID.fullmatch(args[6])):raise Refusal('read_arguments')
        self.guard()
        raw,evidence=host_capture(self.argv(args),self.env,self.context['cwd'],min(deadline,time.monotonic()+CALL_SECONDS))
        self.guard()
        evidence['read_kind']='inventory' if args[0]=='ps' else 'projection'
        if len(self.capture_evidence)>=2*(MAX_IDS+2):raise Refusal('capture_journal_cap')
        self.capture_evidence.append(evidence)
        return raw

    def verify_cwd_correspondence(self, deadline):
        try:return self._verify_cwd_correspondence(deadline)
        except Refusal:raise
        except Exception:raise Refusal('cwd_correspondence_unavailable') from None

    def _verify_cwd_correspondence(self, deadline):
        """Only a new private nonce file, read over the same explicit instance route.

        /bin/cat FILE uses the documented cat operand/stdout interface. Guest utility
        availability is checked by the real call, never assumed from host docs.
        No guest write, container exec, arbitrary path or callback is accepted.
        """
        self.guard();c=self.context;cwd=Path(c['cwd'])
        directory=identity(cwd,True)[:4]
        dirfd=os.open(cwd,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        name='.observer-cwd-'+secrets.token_hex(16)
        path=cwd/name;stamp=None;cleaned=False
        try:
            if (os.fstat(dirfd).st_dev,os.fstat(dirfd).st_ino,os.fstat(dirfd).st_mode,os.fstat(dirfd).st_uid)!=directory:
                raise Refusal('nonce_directory_changed')
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
            nonce=secrets.token_hex(32).encode('ascii')+b'\n'
            with os.fdopen(fd,'wb') as stream:
                stream.write(nonce);stream.flush()
                info=os.fstat(stream.fileno())
                stamp=(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_size,info.st_mtime_ns)
            if identity(path)!=stamp or stat.S_IMODE(stamp[2])!=0o600:raise Refusal('nonce_identity_changed')
            self.guard()
            argv=[c['limactl'],'shell','--workdir',c['cwd'],c['instance'],'/bin/cat',str(path)]
            raw,capture=host_capture(argv,self.env,cwd,min(deadline,time.monotonic()+CALL_SECONDS))
            self.guard()
            if identity(path)!=stamp:raise Refusal('nonce_identity_changed')
            if time.monotonic()>=deadline:raise Refusal('cwd_correspondence_late')
            if raw!=nonce:raise Refusal('cwd_correspondence_mismatch')
            # Keep neither bytes nor their digest. The random value remains in memory.
            evidence={key:value for key,value in capture.items() if key!='stdout_sha256'}
            evidence.update(cwd_correspondence=True,byte_count=len(raw),universal_mount_proof=False,
                            backend_boot_verified=False,vm_signal_authority=False)
        finally:
            # Never unlink a replacement or follow a symlink, even on a failed read.
            if stamp is not None:
                try:
                    current=os.stat(name,dir_fd=dirfd,follow_symlinks=False)
                    current=(current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_size,current.st_mtime_ns)
                    unchanged_directory=identity(cwd,True)[:4]==directory
                except Exception:
                    os.close(dirfd);raise Refusal('nonce_cleanup_identity_unknown') from None
                if current!=stamp or not unchanged_directory:
                    os.close(dirfd);raise Refusal('nonce_cleanup_identity_unknown')
                os.unlink(name,dir_fd=dirfd);cleaned=True
            os.close(dirfd)
        evidence['owned_nonce_removed']=cleaned
        if len(self.cwd_evidence)>=2:raise Refusal('cwd_journal_cap')
        self.cwd_evidence.append(evidence)
        return copy.deepcopy(evidence)

    def snapshot(self):
        deadline=time.monotonic()+DEADLINE_SECONDS
        self.verify_cwd_correspondence(deadline)
        ids=inventory(self.read(['ps','--all','--no-trunc','--quiet'],deadline));values={}
        for full_id in ids:
            values[full_id]=projection(self.read(['container','inspect','--mode','dockercompat','--format',TEMPLATE,full_id],deadline),full_id)
        if ids!=inventory(self.read(['ps','--all','--no-trunc','--quiet'],deadline)):raise Refusal('changing_inventory')
        if time.monotonic()>=deadline:raise Refusal('snapshot_late')
        return {'binding':self.binding,'containers':values}

    def baseline(self):
        if self._baseline is not None:raise Refusal('baseline_already_captured')
        snapshot=self.snapshot();owned={};foreign={};seen={}
        for full_id,value in snapshot['containers'].items():
            scopes=[s for s in self.context['scopes'] if s['project']==value['project']]
            if scopes:
                scope=scopes[0]
                if value['checkout']!=scope['checkout'] or value['service'] not in scope['services']:raise Refusal('owned_scope_mismatch')
                oneoff=value['oneoff'] in ('true','True')
                if value['oneoff']=='' or (oneoff and value['service'] not in scope['oneoffs']):raise Refusal('owned_oneoff_unknown')
                if not oneoff:
                    key=(value['project'],value['service'])
                    if key in seen:raise Refusal('duplicate_owned_service')
                    seen[key]=True
                owned[full_id]=value
            elif self.context['foreign'].get(full_id)==value:foreign[full_id]=value
            else:raise Refusal('unclassified_inventory')
        if not owned or foreign!=self.context['foreign']:raise Refusal('incomplete_baseline')
        if set(seen)!={(s['project'],service) for s in self.context['scopes'] for service in s['services']}:raise Refusal('missing_declared_service')
        self._baseline={'binding':self.binding,'owned':owned,'foreign':foreign}
        return copy.deepcopy(self._baseline)

    def after(self, baseline):
        if self._baseline is None or baseline!=self._baseline or baseline.get('binding')!=self.binding:raise Refusal('baseline_binding')
        if self._post_attempted:raise Refusal('post_observation_already_attempted')
        self._post_attempted=True
        snapshot=self.snapshot();values=snapshot['containers']
        if any(full_id in values for full_id in baseline['owned']):raise Refusal('owned_id_present')
        if any(value['project'] in {s['project'] for s in self.context['scopes']} for value in values.values()):raise Refusal('owned_replacement')
        if values!=baseline['foreign'] or values!=self.context['foreign']:raise Refusal('foreign_changed_or_unclassified')
        return {'container_cleanup_verified':True,'owned_absent_count':len(baseline['owned']),
                'foreign_preservation_verified':True,'foreign_count':len(values),'retirement_verified':False,
                'binding_sha256':self.binding,'read_capture':copy.deepcopy(self.capture_evidence),'cwd_correspondence':copy.deepcopy(self.cwd_evidence),'remote_memory_bounded':False,'remote_cancellation_verified':False,
                'vm_signal_authority':False,'backend_boot_verified':False}
