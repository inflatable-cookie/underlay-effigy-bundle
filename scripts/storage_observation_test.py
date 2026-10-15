"""Finite real-socket controls for the actual storage caller and closed journal."""
import hashlib,hmac,importlib.util,json,os,re,signal,socket,sys,tempfile,threading,time,unittest
from pathlib import Path
import storage_observation as storage
import route_observation as routes
from qualification_refusal import project
from reference_storage_probe import StorageDiagnosticJournal,decode_journal_rows


def load_runtime():
 spec=importlib.util.spec_from_file_location('storage_actual_optin',Path(__file__).with_name('qualify-reference-optin.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

class Producer:
 def __init__(self,mutate=None):
  self.mutate=mutate;self.requests=[];self.errors=[];self.object=b'';self.done=False
  self.sock=socket.socket();self.sock.bind(('127.0.0.1',0));self.sock.listen();self.sock.settimeout(.1)
  self.port=self.sock.getsockname()[1];self.thread=threading.Thread(target=self.loop);self.thread.start()
 def loop(self):
  while not self.done:
   try:peer,_=self.sock.accept()
   except socket.timeout:continue
   except OSError:break
   try:
    with peer:
     peer.settimeout(1);raw=b''
     while b'\r\n\r\n' not in raw:
      block=peer.recv(4096)
      if not block:break
      raw+=block
      if len(raw)>16384:raise AssertionError('control_request_cap')
     head,body=raw.split(b'\r\n\r\n',1);first,*lines=head.split(b'\r\n');method,path,_=first.decode().split(' ')
     headers={k.decode().lower():v.decode().strip() for k,v in (line.split(b':',1) for line in lines)}
     size=int(headers.get('content-length','0'))
     while len(body)<size:body+=peer.recv(size-len(body))
     self.requests.append((method,path,headers,body));index=len(self.requests)
     if 'authorization' in headers:
      date=headers['x-amz-date'];scope=date[:8]+'/us-east-1/s3/aws4_request'
      digest=hashlib.sha256(body).hexdigest();assert digest==headers['x-amz-content-sha256']
      canonical='\n'.join((method,path,'',f"host:{headers['host']}\nx-amz-content-sha256:{digest}\nx-amz-date:{date}\n",'host;x-amz-content-sha256;x-amz-date',digest))
      sign=lambda key,text:hmac.new(key,text.encode(),hashlib.sha256).digest()
      key=sign(b'AWS4invalid-fixture-key' if index==1 else b'AWS4minioadmin',date[:8])
      for part in ('us-east-1','s3','aws4_request'):key=sign(key,part)
      expected=hmac.new(key,('AWS4-HMAC-SHA256\n'+date+'\n'+scope+'\n'+hashlib.sha256(canonical.encode()).hexdigest()).encode(),hashlib.sha256).hexdigest()
      assert headers['authorization']=='AWS4-HMAC-SHA256 Credential=minioadmin/'+scope+', SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature='+expected
     status=403 if index==1 else 204 if method=='DELETE' else 200
     response=b'<Error><Code>SignatureDoesNotMatch</Code><Message>PRIVATE_SECRET</Message></Error>' if index==1 else b''
     extra={}
     if method=='PUT':self.object=body
     if method=='GET' and index!=1:response=self.object
     if method=='OPTIONS' and index==2:extra={'Access-Control-Allow-Origin':'https://browser.test','Access-Control-Allow-Methods':'PUT','Access-Control-Allow-Headers':'authorization,x-amz-content-sha256,x-amz-date'}
     if self.mutate:
      value=self.mutate(index,status,extra,response)
      if value is None:continue # Lost response after an actual fully received request.
      if type(value) is tuple and len(value)==2 and value[0]=='trickle':
       peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n')
       for _ in range(1000):peer.sendall(b'x');time.sleep(.012)
       continue
      if type(value) is bytes:peer.sendall(value);continue
      status,extra,response=value
     wire=(f'HTTP/1.1 {status} Control\r\nContent-Length: {len(response)}\r\n'+''.join(k+': '+v+'\r\n' for k,v in extra.items())+'\r\n').encode()+response
     peer.sendall(wire)
   except (OSError,ValueError):pass
   except BaseException:self.errors.append('control_producer_refused')
 def close(self):
  self.done=True;self.sock.close();self.thread.join(2)
  if self.thread.is_alive() or self.errors:raise AssertionError('control_server_settlement_refused')

class StorageControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.caller=load_runtime()
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='ur.storage-control.');self.root=Path(self.temp.name);self.root.chmod(0o700)
  fixture=self.root/'fixture';fixture.mkdir(mode=0o700);packet=self.root/'packet';packet.mkdir(mode=0o700)
  self.journal=StorageDiagnosticJournal(packet/'storage-diagnostics.jsonl',fixture);self.packet=packet
  storage.configure(self.journal.append)
 def tearDown(self):storage.configure(None);self.journal.close();self.temp.cleanup()
 def call(self,mutate=None):
  server=Producer(mutate)
  try:return self.caller.observe_silo_storage(self.root,{},server.port,'https://browser.test',self.journal),server
  finally:server.close()
 def test_actual_caller_full_signed_sequence_journal_and_privacy(self):
  result,server=self.call();self.assertTrue(result['bytes_equal']);self.assertEqual(len(server.requests),7)
  rows=decode_journal_rows((self.packet/'storage-diagnostics.jsonl').read_text())
  self.assertTrue(any(r.get('observation',{}).get('operation')=='invalid_credentials_get' for r in rows))
  text=json.dumps(rows);self.assertNotIn('PRIVATE_SECRET',text);self.assertNotIn('minioadmin',text);self.assertNotIn('browser.test',text)
 def test_every_security_and_content_gate_actual_caller(self):
  cases=[(1,'credentials_status',lambda code,h,b:(401,h,b)),
   (2,'cors_origin',lambda c,h,b:(c,dict(h,**{'Access-Control-Allow-Origin':'PRIVATE_SECRET'}),b)),
   (2,'cors_method',lambda c,h,b:(c,dict(h,**{'Access-Control-Allow-Methods':'GET'}),b)),
   (2,'cors_headers',lambda c,h,b:(c,dict(h,**{'Access-Control-Allow-Headers':''}),b)),
   (3,'put_status',lambda c,h,b:(500,h,b)),(4,'get_status',lambda c,h,b:(404,h,b)),
   (4,'object_equal',lambda c,h,b:(c,h,b'PRIVATE_SECRET')),(5,'anonymous_status',lambda c,h,b:(403,h,b)),
   (6,'delete_status',lambda c,h,b:(500,h,b)),(7,'foreign_origin',lambda c,h,b:(c,{'Access-Control-Allow-Origin':'PRIVATE_SECRET'},b))]
  for number,reason,mutator in cases:
   with self.subTest(reason=reason):
    with self.assertRaises(storage.StorageRefusal) as caught:self.call(lambda n,c,h,b:mutator(c,h,b) if n==number else (c,h,b))
    record=caught.exception.storage_observation;self.assertEqual(record['reason'],reason);self.assertTrue(record['facts']['status_observed'])
    wrapped=RuntimeError('PRIVATE_SECRET');wrapped.__cause__=caught.exception
    projected=project(wrapped,'runtime_profile');retained=routes.outer_refusals(json.dumps(projected))
    self.assertTrue(retained['typed_failure_available']);self.assertNotIn('PRIVATE_SECRET',json.dumps(retained))
 def test_real_framing_caps_EOF_and_no_mutating_retry(self):
  for wire,reason in [(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx','framing'),
    (b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx','framing'),
    (b'HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n','body_cap'),
    (b'HTTP/1.1 200 OK\r\nX: '+b'x'*16400+b'\r\n\r\n','header_cap'),
    (b'HTTP/1.1 200 OK\r\n'+b'X: a\r\n'*33+b'\r\n','header_cap'),
    (b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\na','body_eof')]:
   with self.subTest(reason=reason):
    with self.assertRaises(storage.StorageRefusal) as caught:self.call(lambda *args:wire)
    self.assertEqual(caught.exception.storage_observation['reason'],reason)
  server=Producer(lambda n,c,h,b:None if n==3 else (c,h,b))
  try:
   with self.assertRaises(storage.StorageRefusal) as caught:self.caller.observe_silo_storage(self.root,{},server.port,'https://browser.test',self.journal)
   self.assertEqual(len(server.requests),3);self.assertEqual(caught.exception.storage_observation['effect_state'],'unknown')
   self.assertTrue(caught.exception.storage_observation['facts']['request_sent'])
  finally:server.close()
 def test_absolute_deadline_and_remaining_stage_external_projection(self):
  # Real finite blocking publication exceeds the original eight-second operation;
  # no transport or mutating request follows it.
  started=time.monotonic()
  o=storage.Operation('prove_silo','cors_allowed',lambda *a,**kw:None)
  o.emit=lambda *a,**kw:time.sleep(8.03)
  with self.assertRaises(storage.StorageRefusal) as caught:o.check(True,'cors_origin',origin_matches=True)
  self.assertEqual(caught.exception.storage_observation['reason'],'deadline')
  self.assertLess(time.monotonic()-started,9)
  @storage.boundary('verify_disposable_action')
  def stage():raise RuntimeError('PRIVATE_SECRET')
  with self.assertRaises(storage.StorageRefusal) as caught:stage()
  record=caught.exception.storage_observation
  self.assertEqual(record['owner'],'verify_disposable_action');self.assertEqual(record['effect_state'],'unknown')
  self.assertNotIn('PRIVATE_SECRET',json.dumps(project(caught.exception,'runtime_profile')))
  for key,value in [('operation','PRIVATE_SECRET'),('operation',[]),('phase',{}),('error_class',[]),('phase','PRIVATE_SECRET'),('facts',{'secret':'PRIVATE_SECRET'}),('facts',{'dispatch_started':False,'header_bytes':True})]:
   self.assertIsNone(storage.validate(dict(record,**{key:value})))
  spoof=RuntimeError('storage_probe_refused');spoof.storage_observation=record
  self.assertEqual(project(spoof,'runtime_profile')['reason_id'],'unknown')

 def test_real_socket_absolute_response_deadline(self):
  def slow(n,c,h,b):time.sleep(8.03);return c,h,b
  started=time.monotonic()
  with self.assertRaises(storage.StorageRefusal) as caught:self.call(slow)
  record=caught.exception.storage_observation
  self.assertEqual(record['reason'],'deadline');self.assertTrue(record['facts']['request_sent'])
  self.assertFalse(record['facts']['status_observed']);self.assertEqual(record['effect_state'],'unknown')
  self.assertLess(time.monotonic()-started,9)

 def test_real_body_trickle_counts_and_strict_media_JSON(self):
  with self.assertRaises(storage.StorageRefusal) as caught:self.call(lambda *args:('trickle',None))
  record=caught.exception.storage_observation
  self.assertEqual(record['reason'],'deadline');self.assertTrue(record['facts']['status_observed'])
  self.assertGreater(record['facts']['body_bytes'],0);self.assertTrue(record['facts']['body_bytes_lower_bound'])
  for data,reason in [(b'{"x":1,"x":2}','response_json'),(b'\xff','response_json'),(b'[]','response_schema')]:
   o=storage.Operation('http_request','media_create',self.journal.append)
   with self.assertRaises(storage.StorageRefusal) as caught:storage.decode_api(data,o)
   self.assertEqual(caught.exception.storage_observation['reason'],reason)

 def test_uncertain_owner_exception_type_and_hold_semantics_survive(self):
  kind=self.caller.UncertainProfileOwnership
  @storage.boundary('_run_profile_collision',preserve=(kind,))
  def uncertain():raise kind('PRIVATE_SECRET')
  with self.assertRaises(kind) as caught:uncertain()
  value=project(caught.exception,'runtime_profile')
  self.assertEqual(value['reason_id'],'storage_external')
  self.assertEqual(value['storage_observation']['effect_state'],'unknown')
  self.assertNotIn('PRIVATE_SECRET',json.dumps(value))

 def test_unknown_error_enum_and_late_publication_primary(self):
  server=Producer(lambda n,c,h,b:(403,h,b'<Error><Code>PRIVATE_SECRET</Code></Error>'))
  try:
   self.caller.RUNTIME._s3_request(server.port,'GET','/bucket/',invalid_credentials=True,diagnostics=self.journal)
   self.assertEqual(storage.CURRENT.get().s3_error,'unknown')
  finally:server.close()
  o=storage.Operation('prove_silo','cors_allowed',lambda *a,**kw:None)
  o.emit=lambda *a,**kw:(_ for _ in ()).throw(OSError('PRIVATE_SECRET'))
  with self.assertRaises(storage.StorageRefusal) as caught:o.check(False,'cors_origin',origin_matches=False)
  self.assertEqual(caught.exception.storage_observation['reason'],'cors_origin');self.assertTrue(caught.exception.storage_observation['publication_unavailable'])
  self.assertNotIn('PRIVATE_SECRET',json.dumps(project(caught.exception,'runtime_profile')))

if __name__=='__main__':
 signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(60);unittest.main()
