"""Closed private storage HTTP observations. No request values leave memory."""
import contextvars
import functools
import secrets
import time
import re
import route_observation as routes

EMIT=None
PRESERVED=set()
CURRENT=contextvars.ContextVar('storage_current',default=None)
LAST=contextvars.ContextVar('storage_last',default=None)
OWNERS=frozenset(('observe_silo_storage','observe_silo_profile','observe_silo_policy','_s3_request','prove_silo','prove_silo_gateway_route','prove_reference_upload',
 'wait_loopback_service','verify_profile_runtime','verify_disposable_action','_run_interruptible_profile_start',
 '_run_profile_collision','_verify_live','_verify_stopped','verify_scope_down','verify_stopped_scope',
 'prove_interrupted_startup','prove_failed_collision_is_scoped','recover_reference_apps','main',
 'http_request','selector','cleanup_profile','gateway_service'))
OPERATIONS=frozenset(('stage','register','login','fixture_admin_role_grant','hybrid_start','hybrid_status','hybrid_down','disposable_test','invalid_credentials_get','cors_allowed','cors_foreign','browser_context','cors_policy_readback','signed_put','signed_get',
 'signed_delete','media_create','upload_initiate','upload_finalise','presigned_put','gateway_silo','gateway_dbgate','gateway_mailpit','anonymous_get','gateway_health','service_health','signed_s3_get','signed_s3_delete'))
REASONS=routes.REASONS|frozenset(('intent','dispatch','completed','publication','external','credentials_status',
 'cors_policy','cors_policy_schema','cors_context','cors_origin','cors_status','cors_method','cors_headers','put_status','get_status','object_equal','anonymous_status',
 'delete_status','foreign_origin','s3_error_schema','response_json','response_schema','media_state'))
PHASES=frozenset(('intent','dispatch','request_sent','response_headers','response_body','validation','completed','external'))
ERRORS=frozenset(('none','timeout','os','tls','value','external'))
S3_CODES=frozenset(('AccessDenied','SignatureDoesNotMatch','InvalidAccessKeyId','NoSuchKey','NoSuchBucket',
 'InvalidRequest','SlowDown','AuthorizationHeaderMalformed','RequestTimeTooSkewed','InternalError','unknown','none'))
EXTRA=frozenset(('dispatch_started','response_received','origin_matches','method_allowed','headers_allowed',
 'policy_schema_valid','policy_origin_matches','policy_methods_match','policy_headers_match','policy_foreign_ungranted','browser_context_matches','bytes_equal','foreign_origin_absent','expected_negative','predicate_matches'))
CORS_ORIGIN_STATES=frozenset(('absent','present_equal','present_unequal'))

def configure(emit):
 global EMIT
 EMIT=emit

def validate(value):
 if type(value) is not dict or set(value)!={'schema','owner','operation','phase','reason','operation_id','facts','elapsed_ms','effect_state','publication_unavailable','error_class','s3_error'}:return None
 if any(type(value[k]) is not str for k in ('schema','owner','operation','phase','reason','effect_state','error_class','s3_error')):return None
 if value['schema']!='underlay.storage-observation.v1' or value['owner'] not in OWNERS or value['operation'] not in OPERATIONS or value['phase'] not in PHASES or value['reason'] not in REASONS:return None
 if type(value['operation_id']) is not str or re.fullmatch('[0-9a-f]{32}',value['operation_id']) is None:return None
 if type(value['elapsed_ms']) is not int or not 0<=value['elapsed_ms']<=7200000 or type(value['publication_unavailable']) is not bool:return None
 if value['effect_state'] not in ('not_dispatched','unknown') or value['error_class'] not in ERRORS or value['s3_error'] not in S3_CODES:return None
 facts=value['facts']
 if type(facts) is not dict or type(facts.get('dispatch_started')) is not bool:return None
 if value['effect_state']=='not_dispatched' and (facts['dispatch_started'] or facts.get('request_sent') is True):return None
 if 'http_status' in facts and (type(facts['http_status']) is not int or not 100<=facts['http_status']<=599):return None
 for key,item in facts.items():
  if key.endswith(('_bytes','_count')) and item is not None and (type(item) is not int or item<0):return None
 if 'cors_origin_state' in facts and (type(facts['cors_origin_state']) is not str or facts['cors_origin_state'] not in CORS_ORIGIN_STATES):return None
 base={k:v for k,v in facts.items() if k not in EXTRA and k!='cors_origin_state'}
 if not routes.safe_record(dict(role=None,operation='https',reason='unknown',facts=base)):return None
 if any(k not in routes.FACT_KEYS|EXTRA|{'cors_origin_state'} or k in EXTRA and type(v) is not bool for k,v in facts.items()):return None
 return dict(value,facts=dict(facts))

class StorageRefusal(routes.RouteObservationRefusal):
 def __init__(self,record):
  admitted=validate(record)
  if admitted is None:raise ValueError('storage_observation_refused')
  RuntimeError.__init__(self,'storage_probe_refused')
  self.storage_observation=admitted

class Operation(routes.Observation):
 def __init__(self,owner,operation='stage',emit=None):
  import qualification_batch
  if owner not in OWNERS or operation not in OPERATIONS:raise ValueError('storage_context_refused')
  self.owner=owner;self.operation=operation;self.emit=emit if emit is not None else EMIT
  self.started=time.monotonic();self.deadline=self.started+qualification_batch.cap(8)
  self.operation_id=secrets.token_hex(16);self.phase='intent';self.error_class='none';self.s3_error='none'
  self.publication_unavailable=False
  self.facts=dict(status_observed=False,headers_complete=False,body_complete=False,header_bytes=0,body_bytes=0,
   publication_available=True,header_limit_bytes=16384,header_limit_count=32,dispatch_started=False,
   request_sent=None,response_received=False,transport_eof=None)
  CURRENT.set(self)
  self.publish('intent')
 def record(self,reason='unknown'):
  record=dict(schema='underlay.storage-observation.v1',owner=self.owner,operation=self.operation,phase=self.phase,
   reason=reason,operation_id=self.operation_id,facts=dict(self.facts),elapsed_ms=round((time.monotonic()-self.started)*1000),
   effect_state='unknown' if self.facts['dispatch_started'] else 'not_dispatched',
   publication_unavailable=self.publication_unavailable,error_class=self.error_class,s3_error=self.s3_error)
  if validate(record) is None:raise ValueError('storage_observation_refused')
  return record
 def publish(self,reason='unknown',primary=None):
  if self.facts.get('status_observed'):self.facts['response_received']=True
  if self.phase in ('validation','completed'):pass
  elif self.facts.get('body_complete'):self.phase='response_body'
  elif self.facts.get('status_observed'):self.phase='response_headers';self.facts['response_received']=True
  elif self.facts.get('request_sent') is True:self.phase='request_sent'
  elif self.facts.get('dispatch_started'):self.phase='dispatch'
  record=self.record(reason);LAST.set(record)
  if self.emit is not None:
   try:self.emit('storage_observation',observation=record)
   except BaseException:
    self.publication_unavailable=True;self.facts['publication_available']=False
    if primary is not None:primary.storage_observation=self.record(reason)
    else:raise StorageRefusal(self.record('publication')) from None
  return record
 def fail(self,reason,**facts):
  if reason=='deadline':self.error_class='timeout'
  if reason in ('deadline','body_eof','body_cap'):self.facts['body_bytes_lower_bound']=True
  self.facts.update(facts)
  if time.monotonic()>=self.deadline:
   self.publication_unavailable=True;self.facts['publication_available']=False
   raise StorageRefusal(self.record(reason)) from None
  error=StorageRefusal(self.record(reason));self.publish(reason,error)
  raise error from None
 def check(self,condition,reason,**facts):
  self.phase='validation';self.gate(condition,reason,predicate_matches=bool(condition),**facts)
 def finish(self):
  self.remaining();self.phase='completed';self.publish('completed');self.remaining()

def request(owner,operation,host,port,path,*,method='GET',headers=None,body=b'',context=None,emit=None,observation=None,body_cap=1048576):
 o=observation or Operation(owner,operation,emit)
 result=routes.exchange(host,port,context,path,headers,method=method,request_body=body or b'',plain=context is None,
                        observation=o,body_cap=body_cap)
 if result[0]>=400 and owner in ('_s3_request','prove_silo'):
  from storage_correlation import s3_error
  code=s3_error(result[2])['error_code']
  o.s3_error=code if code in S3_CODES else 'unknown'
  o.publish('status')
 o.remaining()
 return result,o

def boundary(owner,*,preserve=()):
 if owner not in OWNERS:raise ValueError('storage_owner_refused')
 def decorate(function):
  PRESERVED.update(preserve)
  @functools.wraps(function)
  def wrapped(*args,**kwargs):
   # A stage is not an HTTP request: no renewed eight-second stage timer.
   started=time.monotonic();operation_id=secrets.token_hex(16)
   record=dict(schema='underlay.storage-observation.v1',owner=owner,operation='stage',phase='intent',reason='intent',
    operation_id=operation_id,facts=dict(dispatch_started=False),elapsed_ms=0,effect_state='not_dispatched',
    publication_unavailable=False,error_class='none',s3_error='none')
   if owner=='selector':
    task=args[1] if len(args)>1 else kwargs.get('name')
    record['operation']={'dev:hybrid':'hybrid_start','dev:hybrid:status':'hybrid_status','dev:hybrid:down':'hybrid_down','dev:test':'disposable_test'}.get(task,'stage')
   LAST.set(record)
   if EMIT is not None:
    try:EMIT('storage_observation',observation=record)
    except BaseException:raise StorageRefusal(dict(record,reason='publication',publication_unavailable=True)) from None
   try:return function(*args,**kwargs)
   except BaseException as error:
    if isinstance(error,(SystemExit,KeyboardInterrupt)):raise
    # Preserve every exact typed primary; unknown exceptions retain their last closed operation.
    if type(error) in PRESERVED:
     last=validate(LAST.get()) or record
     error.storage_stage_observation=dict(last,reason='external',error_class='external',effect_state='unknown')
     raise
    from dev.startup_evidence import NativeFailure
    from auth_operation import AuthRefusal
    candidate=error;seen=set()
    for _ in range(16):
     if type(candidate) in (StorageRefusal,NativeFailure,AuthRefusal,routes.RouteObservationRefusal):raise candidate from None
     if id(candidate) in seen:break
     seen.add(id(candidate));candidate=getattr(candidate,'__cause__',None)
     if candidate is None:break
    from dev.startup_evidence import NativeFailure
    from auth_operation import AuthRefusal
    if type(error) in (NativeFailure,AuthRefusal,routes.RouteObservationRefusal):raise
    last=validate(LAST.get()) or record
    refused=dict(last,reason='external',error_class='external')
    # A stage has no independent no-effects proof, even if its first operation was not dispatched.
    refused['effect_state']='unknown'
    if refused['operation']=='stage':refused['phase']='external'
    raise StorageRefusal(refused) from None
  return wrapped
 return decorate

def mark(owner,operation,phase='intent'):
 if owner not in OWNERS or operation not in OPERATIONS or phase not in PHASES:raise ValueError('storage_context_refused')
 record=dict(schema='underlay.storage-observation.v1',owner=owner,operation=operation,phase=phase,reason='intent',
  operation_id=secrets.token_hex(16),facts=dict(dispatch_started=False),elapsed_ms=0,effect_state='unknown',
  publication_unavailable=False,error_class='none',s3_error='none')
 LAST.set(record)
 if EMIT is not None:
  try:EMIT('storage_observation',observation=record)
  except BaseException:raise StorageRefusal(dict(record,reason='publication',publication_unavailable=True)) from None
 return record

def decode_api(body,o):
 import json
 o.phase='validation';o.remaining()
 try:result=json.loads(body.decode('utf-8'),object_pairs_hook=routes.unique) if body else {}
 except (ValueError,UnicodeError):o.fail('response_json',json_valid=False)
 o.check(type(result) is dict,'response_schema',json_valid=True)
 o.remaining()
 return result

def stage_record(error):
 if type(error) not in PRESERVED:return None
 return validate(getattr(error,'storage_stage_observation',None))


def cors_facts(headers, origin):
 """Fixed browser preflight requirements; values remain in memory only."""
 observed=headers.get('access-control-allow-origin')
 state='absent' if observed is None else 'present_equal' if observed==origin else 'present_unequal'
 def tokens(value,lower=True):
  if not isinstance(value,str):return None
  parts=[part.strip() for part in value.split(',')]
  if not parts or any(not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",part) for part in parts):return None
  lowered=[part.lower() for part in parts] if lower else parts
  return set(lowered) if len(lowered)==len(set(lowered)) else None
 methods=tokens(headers.get('access-control-allow-methods'),lower=False)
 allowed=tokens(headers.get('access-control-allow-headers'))
 return dict(cors_origin_state=state,origin_matches=state=='present_equal',
             method_allowed=methods is not None and 'PUT' in methods,
             headers_allowed=allowed is not None and {'authorization','x-amz-content-sha256','x-amz-date'}<=allowed)
