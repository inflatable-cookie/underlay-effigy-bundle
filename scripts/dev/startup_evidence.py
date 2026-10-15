"""Qualification-only closed startup evidence, independent of product authority.

An admitted original batch intent plus a parent-generated command nonce enables
this protocol. Raw native output and exception messages are never evidence.
"""
from contextvars import ContextVar
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from . import owned_capture, silo_client

STARTUP_FILE_CAP=524288
STARTUP_CLEANUP_RESERVE=24576
STARTUP_ORDINARY_LIMIT=STARTUP_FILE_CAP-STARTUP_CLEANUP_RESERVE
SCHEMA='underlay.profile.native-failure.v1'
MARKER='UNDERLAY_PROFILE_FAILURE '
STAGES=frozenset(('command','source_gate','original_context','private_root','gateway_setup',
 'gateway_status','gateway_start','services_up','service_status','service_context','port_inventory',
 'bootstrap','bootstrap_readguard','bootstrap_alias','bootstrap_bucket','bootstrap_native',
 'managed_hosts','managed_state','managed_report','readiness','return','start','status','down',
 'test','test_plan','test_action','cleanup','json'))
REASONS=frozenset(('unknown','owning_gate_refused','native_nonzero','native_capture_refused',
 'native_json_refused','native_envelope_refused','marker_refused','journal_refused','deadline',
 'bounded_native_refused','source_refused','port_inventory_refused','bootstrap_readguard_refused',
 'bootstrap_alias_refused','managed_state_refused','managed_report_refused','readiness_refused'))
SOURCE_REASONS=frozenset(('alias_shape_refused', 'bounded_accounting_refused', 'bounded_container_refused', 'bounded_envelope_refused', 'bounded_limits_refused', 'bounded_observation_bytes_refused', 'bounded_observation_clock_refused', 'bounded_observation_retention_refused', 'bounded_observation_spawn_refused', 'bounded_observation_stream_refused', 'bounded_observations_phase_refused', 'bounded_observations_refused', 'bounded_phase_refused', 'bounded_schema_refused', 'bounded_selection_refused', 'bounded_service_refused', 'bounded_status_refused', 'client_command_input_refused', 'duplicate_json_key', 'guard_dispatch_refused', 'guard_framing_refused', 'guard_record_refused', 'guard_service_refused', 'invalid_mc_record', 'invalid_shell_marker', 'malformed_json', 'mc_output_truncated', 'native_bounded_refusal', 'routing_guard_refused', 'shell_framing_unknown', 'shell_operation_refused'))
SOURCE_REASONS=SOURCE_REASONS|frozenset(('source_git_root','source_git_head','source_git_tree','source_git_status','source_version','source_identity_changed','source_path','source_revision','source_tree','source_api','source_dirty','binary_identity','binary_version','binary_digest'))
OWNING_CODES={}
ERROR_CLASSES={RuntimeError:'RuntimeError',OSError:'OSError',FileNotFoundError:'FileNotFoundError',PermissionError:'PermissionError',ValueError:'ValueError',TypeError:'TypeError',subprocess.TimeoutExpired:'TimeoutExpired',KeyboardInterrupt:'KeyboardInterrupt'}
REFUSALS=frozenset(('spawn_failed','deadline','stdout_overflow','stderr_overflow','stdout_read_failure',
 'stderr_read_failure','leader_settlement_unknown','deadline_identity_unknown',
 'stdout_overflow_identity_unknown','stderr_overflow_identity_unknown',
 'stdout_read_failure_identity_unknown','stderr_read_failure_identity_unknown'))
ACTIVE=ContextVar('profile_startup_session',default=None)
CURRENT=ContextVar('profile_startup_stage',default='command')
ROLE=ContextVar('profile_startup_role',default=None)
SERVICE=ContextVar('profile_startup_service',default=None)

class NativeFailure(RuntimeError):
    def __init__(self,record):
        self.record=validate(record)
        if self.record is None:raise ValueError('native_failure_record_refused')
        super().__init__(self.record['reason'])

def base(reason='unknown',stage=None):
    session=ACTIVE.get()
    return {'schema':SCHEMA,'stage':stage or CURRENT.get(),'role':ROLE.get(),'service':SERVICE.get(),'reason':reason,
        'binding':session.binding if session else None,'nonce':session.nonce if session else None,
        'call_id':session.call_id if session else None,
        'error_class':None,'source_reason':None,'exit':None,'capture':None,'callers':[],'native':None,'effect_state':'unknown',
        'publication_unavailable':False,'cleanup_unavailable':False,'deadline_exceeded':False}

JOURNAL_REASONS=frozenset(('startup_journal_capacity','startup_journal_sticky','startup_intent_changed',
 'startup_journal_identity','startup_journal_permissions','startup_journal_link','startup_journal_write',
 'startup_journal_encoding','startup_journal_content','startup_record_refused','startup_event_refused','startup_elapsed_refused',
 'startup_host_identity_refused','startup_file_refused','startup_file_changed','startup_journal_sequence',
 'startup_journal_deadline','startup_journal_external'))
SOURCE_REASONS=SOURCE_REASONS|JOURNAL_REASONS|frozenset(('startup_binding_refused','startup_symlink_refused','startup_root_refused','startup_intent_refused','startup_source_binding_refused','startup_controls_changed','startup_scope_refused'))

JOURNAL_SOURCE_MAP={
 'Silo bootstrap journal boundary refused':'bootstrap_journal_identity',
 'Silo bootstrap journal bound refused':'bootstrap_journal_capacity',
 'Silo bootstrap journal write refused':'bootstrap_journal_write',
 'profile journal name refused':'bootstrap_journal_name',
 'profile journal path refused':'bootstrap_journal_path',
 'diagnostic_capacity_refused':'main_journal_capacity',
 'diagnostic_typed_fields_limit':'main_journal_record',
 'diagnostic_journal_identity_refused':'main_journal_identity',
 'diagnostic_journal_write_refused':'main_journal_write'}
SOURCE_REASONS=SOURCE_REASONS|frozenset(JOURNAL_SOURCE_MAP.values())

def owned_journal_reason(error):
    trace=getattr(error,'__traceback__',None)
    while trace is not None and trace.tb_next is not None:trace=trace.tb_next
    args=getattr(error,'args',())
    if (ERROR_CLASSES.get(type(error)) in ('ValueError','RuntimeError','ProfileError')
        and trace is not None and trace.tb_frame.f_code in OWNING_CODES
        and len(args)==1 and type(args[0]) is str):return JOURNAL_SOURCE_MAP.get(args[0])
    return None

class JournalRefusal(ValueError):
    def __init__(self,observation):
        self.observation=observation
        super().__init__('startup_journal_refused')

def valid_journal(value):
    keys={'schema','reason','error_class','bytes_used','bytes_requested','ordinary_limit','total_cap',
          'cleanup_reserve','limit','counts_available','secondary_reasons'}
    if type(value) is not dict or set(value)!=keys or value['schema']!='underlay.startup-journal-refusal.v1':return False
    if value['reason'] not in JOURNAL_REASONS or value['error_class'] not in ('ValueError','RuntimeError','OSError','FileNotFoundError','PermissionError','TypeError','TimeoutExpired','KeyboardInterrupt','ProfileError','other'):return False
    if type(value['counts_available']) is not bool:return False
    if type(value['secondary_reasons']) is not list or len(value['secondary_reasons'])>len(JOURNAL_REASONS) or any(x not in JOURNAL_REASONS for x in value['secondary_reasons']):return False
    for key in ('bytes_used','bytes_requested','ordinary_limit','total_cap','cleanup_reserve','limit'):
        if value[key] is not None and (type(value[key]) is not int or not 0<=value[key]<=2**64-1):return False
    if value['total_cap']!=STARTUP_FILE_CAP or value['cleanup_reserve']!=STARTUP_CLEANUP_RESERVE or value['ordinary_limit']!=STARTUP_ORDINARY_LIMIT:return False
    if value['counts_available'] and any(value[k] is None for k in ('bytes_used','bytes_requested','limit')):return False
    return True

def preflight(used,requested,limit):
    if used+requested>limit:
        raise JournalRefusal({'schema':'underlay.startup-journal-refusal.v1',
            'reason':'startup_journal_capacity','error_class':'ValueError','bytes_used':used,
            'bytes_requested':requested,'ordinary_limit':STARTUP_ORDINARY_LIMIT,
            'total_cap':STARTUP_FILE_CAP,'cleanup_reserve':STARTUP_CLEANUP_RESERVE,
            'limit':limit,'counts_available':True,'secondary_reasons':[]})

def journal_failure(error,record=None):
    record=validate(record) or base('journal_refused')
    if type(error) is JournalRefusal and valid_journal(error.observation):
        observation=json.loads(json.dumps(error.observation))
    else:
        observation={'schema':'underlay.startup-journal-refusal.v1','reason':'startup_journal_external',
          'error_class':ERROR_CLASSES.get(type(error),'other'),'bytes_used':None,'bytes_requested':None,
          'ordinary_limit':STARTUP_ORDINARY_LIMIT,'total_cap':STARTUP_FILE_CAP,
          'cleanup_reserve':STARTUP_CLEANUP_RESERVE,'limit':None,'counts_available':False,'secondary_reasons':[]}
    if 'journal_failure' in record:
        original=record['journal_failure']
        if observation['reason'] not in original['secondary_reasons']:original['secondary_reasons'].append(observation['reason'])
    else:record['journal_failure']=observation
    if record['reason'] in ('unknown','journal_refused'):
        record['reason']='journal_refused';record['source_reason']=record['journal_failure']['reason']
        record['error_class']=record['journal_failure']['error_class']
    source=owned_journal_reason(error)
    if source and record['reason']=='journal_refused':
        record['source_reason']=source;record['error_class']=ERROR_CLASSES.get(type(error),'other')
    record['publication_unavailable']=True
    return NativeFailure(record)

def _validate(value):
    if type(value) is not dict or set(value) not in (set(base()),set(base())|{'journal_failure'}):return None
    if 'journal_failure' in value and not valid_journal(value['journal_failure']):return None
    if value['schema']!=SCHEMA or value['stage'] not in STAGES or value['reason'] not in REASONS:return None
    for key,size in (('binding',64),('nonce',32),('call_id',32)):
        if value[key] is not None and (type(value[key]) is not str or re.fullmatch('[0-9a-f]{'+str(size)+'}',value[key]) is None):return None
    if value['error_class'] not in (None,'RuntimeError','OSError','FileNotFoundError','PermissionError','ValueError','TypeError','TimeoutExpired','KeyboardInterrupt','ProfileError','other'):return None
    if value['source_reason'] is not None and value['source_reason'] not in SOURCE_REASONS:return None
    if value['effect_state']!='unknown' or value['role'] not in (None,'api','front','admin') or value['service'] not in (None,'silo','silo_client'):return None
    if any(type(value[k]) is not bool for k in ('publication_unavailable','cleanup_unavailable','deadline_exceeded')):return None
    if value['exit'] is not None and (type(value['exit']) is not int or not -255<=value['exit']<=255):return None
    if type(value['callers']) is not list or len(value['callers'])>16:return None
    for item in value['callers']:
        if type(item) is not dict or set(item)!={'exit','capture'}:return None
        if item['exit'] is not None and (type(item['exit']) is not int or not -255<=item['exit']<=255):return None
    for c in [value['capture'],*(x['capture'] for x in value['callers'])]:
      if c is not None:
          if type(c) is not dict or set(c)!={'refusal','identity_admitted','leader_reaped','stdout','stderr'}:return None
          if c['refusal'] is not None and c['refusal'] not in REFUSALS:return None
          if any(type(c[k]) is not bool for k in ('identity_admitted','leader_reaped')):return None
          for name in ('stdout','stderr'):
              entry=c[name]
              if type(entry) is not dict or set(entry)!={'read_bytes','retained_bytes','eof'} or type(entry['eof']) is not bool:return None
              for k in ('read_bytes','retained_bytes'):
                  if entry[k] is not None and (type(entry[k]) is not int or not 0<=entry[k]<=2**64-1):return None
              if entry['retained_bytes'] is not None and entry['retained_bytes']>262144:return None
    n=value['native']
    if n is not None:
        if type(n) is not dict or set(n)!={'schema_valid','error_code','bounded','bounded_schema_seen','decode_reason'} or type(n['schema_valid']) is not bool:return None
        if type(n['bounded_schema_seen']) is not bool or (n['decode_reason'] is not None and n['decode_reason'] not in SOURCE_REASONS):return None
        # Only these exact error codes are source-qualified here. All other
        # public/core messages and codes remain unavailable, never copied.
        if n['error_code'] not in (None,'RunnerError'):return None
        b=n['bounded']
        if b is not None:
            if type(b) is not dict or set(b)!={'failure','phase','inner_code','refusal_observations'}:return None
            if b['failure'] not in silo_client.BOUND_FAILURES:return None
            if b['phase'] not in (None,'runtime_discovery','workspace_preparation','command_execution'):return None
            if b['inner_code'] is not None and (type(b['inner_code']) is not int or not -255<=b['inner_code']<=255):return None
            try:silo_client.refusal_observations(b['refusal_observations'],b['failure'])
            except ValueError:return None
    return json.loads(json.dumps(value))

def validate(value):
    try:return _validate(value)
    except (ValueError,TypeError,KeyError,RecursionError):return None

def observe_native(stdout,code):
    observation={'schema_valid':False,'error_code':None,'bounded':None,'bounded_schema_seen':False,'decode_reason':None}
    try:value=silo_client.strict_json(stdout)
    except ValueError:return observation
    keys={'schema','schema_version','command','ok','result','error','binary'}
    if (type(value) is not dict or set(value)!=keys or value.get('schema')!='effigy.command.v1'
        or type(value.get('schema_version')) is not int or value['schema_version']!=1 or type(value.get('ok')) is not bool):return observation
    observation['schema_valid']=True
    error=value.get('error')
    if type(error) is dict:
        # Unknown error fields/messages are discarded, including details unless
        # the maintained bounded-exec validator admits the whole projection.
        if error.get('kind')=='RunnerError':observation['error_code']=error['kind']
        details=error.get('details')
        if type(details) is dict and details.get('schema')=='effigy.container.bounded-exec.v1':
            observation['bounded_schema_seen']=True
            container=details.get('container');service=details.get('service')
            if container in ('hybrid_services','disposable_test') and service in ('silo','silo_client'):
                try:
                    _,p=silo_client.bounded_payload(stdout,code,service,container)
                    if p['failure']!='complete':observation['bounded']={
                        'failure':p['failure'],'phase':p.get('phase'),'inner_code':p.get('inner_code'),
                        'refusal_observations':p.get('refusal_observations')}
                except (ValueError,TypeError,KeyError) as error:
                    args=getattr(error,'args',())
                    if type(error) is ValueError and len(args)==1 and type(args[0]) is str and args[0] in SOURCE_REASONS:observation['decode_reason']=args[0]
    return observation

def marker_record(stderr,*,binding=None,nonce=None):
    # Effigy's shell task relays stderr verbatim. No substring matching inside
    # raw errors or JSON message strings is allowed.
    lines=[line for line in stderr.splitlines() if MARKER in line]
    if not lines:return None,False
    if len(lines)!=1 or not lines[0].startswith(MARKER):return None,True
    try:value=silo_client.strict_json(lines[0][len(MARKER):])
    except ValueError:return None,True
    record=validate(value)
    if record is None or record['binding']!=binding or record['nonce']!=nonce:return None,True
    return record,False

def register_local_errors(module):
    for function in vars(module).values():
        if isinstance(function,type) and function.__module__==module.__name__:
            for method in vars(function).values():
                method=method.__func__ if isinstance(method,(staticmethod,classmethod)) else method
                code=getattr(method,'__code__',None)
                if code is not None:OWNING_CODES[code]=True
        code=getattr(function,'__code__',None)
        if code is not None:OWNING_CODES[code]=True

def failure(error,reason='unknown'):
    if type(error) is NativeFailure:return error
    if type(error) is JournalRefusal:return journal_failure(error)
    record=base(reason)
    record['error_class']=ERROR_CLASSES.get(type(error),'other')
    source=owned_journal_reason(error)
    if source:
        record['reason']='journal_refused';record['source_reason']=source
        return NativeFailure(record)
    trace=getattr(error,'__traceback__',None)
    while trace is not None and trace.tb_next is not None:trace=trace.tb_next
    args=getattr(error,'args',())
    if (type(error) is ValueError and trace is not None and trace.tb_frame.f_code in OWNING_CODES
        and len(args)==1 and type(args[0]) is str and args[0] in SOURCE_REASONS):
        record['reason']='owning_gate_refused';record['source_reason']=args[0]
    return NativeFailure(record)

def refuse(reason):raise NativeFailure(base(reason))

def stage(name):
    if name not in STAGES:raise ValueError('startup_stage_unqualified')
    def decorate(function):
        @wraps(function)
        def call(*args,**kwargs):
            session=ACTIVE.get()
            if session is None:return function(*args,**kwargs)
            token=CURRENT.set(name)
            role_token=ROLE.set(ROLE.get())
            try:
                try:session.emit(name,'entered')
                except BaseException as error:raise journal_failure(error) from None
                try:result=function(*args,**kwargs)
                except BaseException as error:
                    primary=failure(error)
                    try:session.emit(name,'refused',primary.record)
                    except BaseException as secondary:primary=journal_failure(secondary,primary.record)
                    raise primary from None
                try:session.emit(name,'completed')
                except BaseException as error:raise journal_failure(error) from None
                return result
            finally:CURRENT.reset(token);ROLE.reset(role_token)
        return call
    return decorate

class Session:
    def __init__(self,env,repo,action,profile):
        self.binding=env.get('UNDERLAY_PROFILE_BATCH_INTENT_SHA256')
        self.nonce=env.get('UNDERLAY_PROFILE_COMMAND_NONCE')
        self.call_id=secrets.token_hex(16)
        if re.fullmatch('[0-9a-f]{64}',self.binding or '') is None or re.fullmatch('[0-9a-f]{32}',self.nonce or '') is None:raise ValueError('startup_binding_refused')
        path=Path(env['UNDERLAY_PROFILE_BATCH_INTENT'])
        self.intent_path=path
        self.root=path.parent
        for parent in (self.root,*self.root.parents):
            if parent.is_symlink():raise ValueError('startup_symlink_refused')
        root=self.root.stat()
        if root.st_uid!=os.geteuid() or stat.S_IMODE(root.st_mode)!=0o700:raise ValueError('startup_root_refused')
        raw=self.read(path,65536)
        if hashlib.sha256(raw).hexdigest()!=self.binding:raise ValueError('startup_intent_changed')
        value=silo_client.strict_json(raw)
        if (type(value) is not dict or set(value)!={'schema','head','source','binary_sha256','started_at','deadline_at','stages','controls_sha256'}
            or value['schema']!='underlay.product-batch-intent.v1' or value['stages']!=['runtime','container']
            or value['source']!='bd2597693f7c4c9ad786896a9448a7e746ff13a8'
            or value['binary_sha256']!='2d72c3df0d61c05a150d5d86c39b2ea931eca9549b794b559fa39d95dc002a59'
            or value['deadline_at']-value['started_at']!=14400 or not value['started_at']<=time.time()<value['deadline_at']):raise ValueError('startup_intent_refused')
        if any(type(value[k]) is not str or re.fullmatch('[0-9a-f]{40}' if k=='head' else '[0-9a-f]{64}',value[k]) is None for k in ('head','controls_sha256')):raise ValueError('startup_source_binding_refused')
        if hashlib.sha256(self.read(self.root/'controls.json',65536)).hexdigest()!=value['controls_sha256']:raise ValueError('startup_controls_changed')
        self.deadline=value['deadline_at'];self.sticky=False;self.sequence=0
        self.bytes=0;self.content_digest=hashlib.sha256()
        if action not in ('start','status','down','test','context') or profile not in ('hybrid','disposable_test','container'):raise ValueError('startup_scope_refused')
        self.action=action;self.profile=profile
        self.path=self.root/('startup-'+self.nonce+'-'+self.call_id+'.jsonl')
        self.fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        self.identity=os.fstat(self.fd)
        self.emit('original_context','entered')
    @staticmethod
    def read(path,cap):
        if type(cap) is not int or not 0<cap<=STARTUP_FILE_CAP:raise ValueError('startup_file_refused')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>cap:raise ValueError('startup_file_refused')
            raw=os.read(fd,cap+1);after=os.fstat(fd)
            interval=lambda i:(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
            if len(raw)!=before.st_size or interval(before)!=interval(after):raise ValueError('startup_file_changed')
            return raw
        finally:os.close(fd)
    def emit(self,name,state,record=None,role=None,original_host_identity=None,elapsed_ms=None):
        self.requested=None;self.limit=STARTUP_FILE_CAP if name in ('cleanup','down') else STARTUP_ORDINARY_LIMIT
        try:
            if self.sticky:raise ValueError('startup_journal_sticky')
            return self._emit(name,state,record,role,original_host_identity,elapsed_ms)
        except BaseException as error:
            self.sticky=True
            trace=getattr(error,'__traceback__',None)
            while trace is not None and trace.tb_next is not None:trace=trace.tb_next
            args=getattr(error,'args',())
            if type(error) is JournalRefusal and valid_journal(error.observation):raise
            reason=(args[0] if type(error) is ValueError and trace is not None
                    and trace.tb_frame.f_code in OWNING_CODES and len(args)==1
                    and type(args[0]) is str and args[0] in JOURNAL_REASONS else 'startup_journal_external')
            observation={'schema':'underlay.startup-journal-refusal.v1','reason':reason,
                'error_class':ERROR_CLASSES.get(type(error),'other'),'bytes_used':self.bytes,
                'bytes_requested':self.requested,'ordinary_limit':STARTUP_ORDINARY_LIMIT,
                'total_cap':STARTUP_FILE_CAP,'cleanup_reserve':STARTUP_CLEANUP_RESERVE,
                'limit':self.limit,'counts_available':self.requested is not None,'secondary_reasons':[]}
            raise JournalRefusal(observation) from None
    def _emit(self,name,state,record=None,role=None,original_host_identity=None,elapsed_ms=None):
        try:
            if role not in (None,'api','front','admin') or name not in STAGES or state not in ('entered','completed','refused'):raise ValueError('startup_event_refused')
            if hashlib.sha256(self.read(self.intent_path,65536)).hexdigest()!=self.binding:raise ValueError('startup_intent_changed')
            info=os.fstat(self.fd);live=self.path.lstat()
            if stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.geteuid():raise ValueError('startup_journal_permissions')
            if info.st_nlink!=1 or live.st_nlink!=1:raise ValueError('startup_journal_link')
            if not stat.S_ISREG(live.st_mode) or (info.st_dev,info.st_ino)!=(self.identity.st_dev,self.identity.st_ino) or info.st_size!=self.bytes or (info.st_dev,info.st_ino)!=(live.st_dev,live.st_ino):raise ValueError('startup_journal_identity')
            if hashlib.sha256(self.read(self.path,STARTUP_FILE_CAP)).digest()!=self.content_digest.digest():raise ValueError('startup_journal_content')
            if type(self.sequence) is not int or self.sequence<0:raise ValueError('startup_journal_sequence')
            if time.time()>=self.deadline:raise ValueError('startup_journal_deadline')
            self.sequence+=1
            if elapsed_ms is not None and (type(elapsed_ms) is not int or not 0<=elapsed_ms<=7200000):raise ValueError('startup_elapsed_refused')
            if original_host_identity is not None:
                identity_keys={'pid','ppid','pgid','uid','boot_identity','start_identity'}
                if type(original_host_identity) is not dict or set(original_host_identity)!=identity_keys:raise ValueError('startup_host_identity_refused')
                if any(type(original_host_identity[k]) is not int or not 0<=original_host_identity[k]<2**32 for k in ('pid','ppid','pgid','uid')):raise ValueError('startup_host_identity_refused')
                if re.fullmatch('[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}',original_host_identity['boot_identity']) is None:raise ValueError('startup_host_identity_refused')
                start=original_host_identity['start_identity']
                if type(start) is not dict or set(start)!={'platform','start_seconds','start_microseconds'} or start['platform']!='macos' or any(type(start[k]) is not int or start[k]<0 for k in ('start_seconds','start_microseconds')):raise ValueError('startup_host_identity_refused')
            value={'schema':'underlay.profile.startup-stage.v1','binding':self.binding,'nonce':self.nonce,'call_id':self.call_id,
                'action':self.action,'profile':self.profile,'role':role,'service':SERVICE.get(),'sequence':self.sequence,'stage':name,'state':state,
                'effect_state':'unknown','observation':validate(record) if record is not None else None,
                'original_host_identity':original_host_identity,'elapsed_ms':elapsed_ms}
            if record is not None and value['observation'] is None:raise ValueError('startup_record_refused')
            try:raw=(json.dumps(value,separators=(',',':'))+'\n').encode()
            except (ValueError,TypeError,UnicodeError):raise ValueError('startup_journal_encoding') from None
            self.requested=len(raw)
            preflight(info.st_size,len(raw),self.limit)
            try:written=os.write(self.fd,raw)
            except OSError as error:
                raise JournalRefusal({'schema':'underlay.startup-journal-refusal.v1',
                    'reason':'startup_journal_write','error_class':ERROR_CLASSES.get(type(error),'OSError'),
                    'bytes_used':self.bytes,'bytes_requested':len(raw),'ordinary_limit':STARTUP_ORDINARY_LIMIT,
                    'total_cap':STARTUP_FILE_CAP,'cleanup_reserve':STARTUP_CLEANUP_RESERVE,
                    'limit':self.limit,'counts_available':True,'secondary_reasons':[]}) from None
            if written!=len(raw):raise ValueError('startup_journal_write')
            self.bytes+=len(raw);self.content_digest.update(raw)
        except BaseException:self.sticky=True;raise
    def close(self):os.close(self.fd)

def read_stages(path,*,binding,nonce,call_id):
    raw=Session.read(path,STARTUP_FILE_CAP)
    if raw and not raw.endswith(b'\n'):raise ValueError('startup_record_refused')
    rows=[]
    keys={'schema','binding','nonce','call_id','action','profile','role','service','sequence',
          'stage','state','effect_state','observation','original_host_identity','elapsed_ms'}
    for number,line in enumerate(raw.splitlines(),1):
        row=silo_client.strict_json(line)
        if (type(row) is not dict or set(row)!=keys or row['schema']!='underlay.profile.startup-stage.v1'
            or row['binding']!=binding or row['nonce']!=nonce or row['call_id']!=call_id
            or type(row['sequence']) is not int or row['sequence']!=number
            or row['stage'] not in STAGES or row['state'] not in ('entered','completed','refused')
            or row['action'] not in ('start','status','down','test','context')
            or row['profile'] not in ('hybrid','disposable_test','container')
            or row['role'] not in (None,'api','front','admin') or row['service'] not in (None,'silo','silo_client')
            or row['effect_state']!='unknown'
            or row['observation'] is not None and validate(row['observation']) is None):raise ValueError('startup_record_refused')
        elapsed=row['elapsed_ms']
        if elapsed is not None and (type(elapsed) is not int or not 0<=elapsed<=7200000):raise ValueError('startup_elapsed_refused')
        host=row['original_host_identity']
        if host is not None:
            if type(host) is not dict or set(host)!={'pid','ppid','pgid','uid','boot_identity','start_identity'}:raise ValueError('startup_host_identity_refused')
            if any(type(host[k]) is not int or not 0<=host[k]<2**32 for k in ('pid','ppid','pgid','uid')):raise ValueError('startup_host_identity_refused')
            if type(host['boot_identity']) is not str or re.fullmatch('[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}',host['boot_identity']) is None:raise ValueError('startup_host_identity_refused')
            start=host['start_identity']
            if type(start) is not dict or set(start)!={'platform','start_seconds','start_microseconds'} or start['platform']!='macos' or any(type(start[k]) is not int or start[k]<0 for k in ('start_seconds','start_microseconds')):raise ValueError('startup_host_identity_refused')
        rows.append(row)
    return rows


def configure(env,repo,action,profile):
    if not env.get('UNDERLAY_PROFILE_BATCH_INTENT'):return None
    session=Session(env,repo,action,profile)
    ACTIVE.set(session)
    return session

def capture_command(args,*,cwd=None,env,timeout,expected=0,emit=None):
    started=time.monotonic()
    session=ACTIVE.get()
    deadline=timeout if session is None else min(timeout,session.deadline-time.time())
    if deadline<=0:refuse('deadline')
    payload=[]
    captured=owned_capture.capture(args,cwd=cwd,env=env,timeout=deadline,
        payload_sink=lambda out,err:payload.extend((out,err)))
    rawout,rawerr=payload if payload else (b'',b'')
    # Strict UTF8 is required for JSON and markers; arbitrary output is never
    # copied into a record or exception. CompletedProcess compatibility stays.
    encoding_valid=True
    try:stdout=rawout.decode('utf-8');stderr=rawerr.decode('utf-8')
    except UnicodeError:stdout='';stderr='';encoding_valid=False
    record=base('native_capture_refused' if captured['refusal'] else 'native_nonzero')
    for key,envkey,size in (('binding','UNDERLAY_PROFILE_BATCH_INTENT_SHA256',64),('nonce','UNDERLAY_PROFILE_COMMAND_NONCE',32)):
        value=env.get(envkey)
        if type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value):record[key]=value
    record['exit']=captured['exit']
    record['capture']={k:captured[k] for k in ('refusal','identity_admitted','leader_reaped','stdout','stderr')}
    complete=(encoding_valid and captured['refusal'] is None and captured['stdout']['eof'] and captured['stderr']['eof'] and captured['leader_reaped'] and captured['identity_admitted'])
    record['native']=observe_native(stdout if complete else '',captured['exit'])
    inner,bad=(marker_record(stderr,binding=env.get('UNDERLAY_PROFILE_BATCH_INTENT_SHA256'),nonce=env.get('UNDERLAY_PROFILE_COMMAND_NONCE')) if complete else (None,False))
    failed=not encoding_valid or captured['refusal'] is not None or not captured['stdout']['eof'] or not captured['stderr']['eof'] or not captured['leader_reaped'] or (expected is not None and captured['exit']!=expected)
    if not encoding_valid:record['reason']='native_json_refused'
    if inner is not None:
        caller=record['capture']
        record=inner
        if len(record['callers'])>=16:
            record['reason']='marker_refused'
        else:record['callers'].append({'exit':captured['exit'],'capture':caller})
        failed=failed or expected is not None or captured['exit']==0
    elif bad:record['reason']='marker_refused';failed=True
    elif record['native']['bounded'] is not None:
        record['reason']='bounded_native_refused';failed=failed or expected is not None or captured['exit']==0
    if captured['refusal'] is None and not captured['identity_admitted']:
        record['reason']='native_capture_refused';failed=True
    if not failed and inner is None and record['native']['bounded'] is None:record['reason']='unknown'
    if emit is not None:
        try:emit('qualification_native_capture',observation=validate(record),completed=not failed,
                 original_host_identity=captured['original_child_identity'],elapsed_ms=captured['elapsed_ms'])
        except BaseException as error:
            record=journal_failure(error,record if failed else dict(record,reason='journal_refused')).record
            failed=True
    if time.monotonic()-started>=deadline:
        record['deadline_exceeded']=True
        if not failed:record['reason']='deadline'
        failed=True
    if failed:raise NativeFailure(record)
    result=subprocess.CompletedProcess(args,captured['exit'],stdout,stderr)
    result.native_observation=record
    return result

def json_result(stdout,observation=None):
    def reject(reason):
        record=validate(observation) or base()
        record['reason']=reason
        raise NativeFailure(record)
    try:value=silo_client.strict_json(stdout)
    except ValueError:reject('native_json_refused')
    observed=observe_native(stdout,0)
    if not observed['schema_valid'] or value.get('ok') is not True or type(value.get('result')) is not dict:reject('native_envelope_refused')
    return value['result']


def cli_failure(error):
    primary=failure(error)
    session=ACTIVE.get()
    if session is not None:
        try:session.emit(primary.record['stage'],'refused',primary.record)
        except BaseException as secondary:primary=journal_failure(secondary,primary.record)
    print(MARKER+json.dumps(primary.record,separators=(',',':')),file=sys.stderr,flush=True)

register_local_errors(sys.modules[__name__])
