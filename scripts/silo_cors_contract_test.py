"""Finite source controls, real production bootstrap XML and loopback OPTIONS."""
import importlib.util,json,signal,tempfile,unittest,shlex,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent/"dev"))
from unittest.mock import patch
import silo_cors_contract as cors
from container_identity_observer import Refusal
from storage_observation_test import Producer
from reference_storage_probe import StorageDiagnosticJournal,decode_journal_rows
import storage_observation as storage
from qualification_refusal import project
from route_observation import outer_refusals

XML='<CORSConfiguration><CORSRule><AllowedOrigin>https://front.example.test:54321</AllowedOrigin><AllowedOrigin>https://admin.example.test:54321</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedHeader>*</AllowedHeader></CORSRule></CORSConfiguration>'
ORIGINS=['https://front.example.test:54321','https://admin.example.test:54321']

class Controls(unittest.TestCase):
 def test_policy_source_shapes_and_closed_predicates(self):
  for xml in (XML,XML.replace('<CORSConfiguration>','<CORSConfiguration xmlns="'+cors.NS+'">'),'<?xml version="1.0" encoding="UTF-8"?>'+XML):
   facts=cors.policy_facts(xml,ORIGINS);self.assertTrue(facts['request_matches']);self.assertFalse(facts['foreign_matches'])
   self.assertTrue(facts['rules'][0]['intended_origin_set_equal'])
   self.assertNotIn('example.test',json.dumps(facts))
  for old,new,field in [('front.example.test','wrong.example.test','front_matches'),('PUT','POST','put_allowed'),('<AllowedHeader>*</AllowedHeader>','<AllowedHeader>x-amz*</AllowedHeader>','request_matches')]:
   facts=cors.policy_facts(XML.replace(old,new),ORIGINS);self.assertFalse(facts['rules'][0][field]);self.assertFalse(facts['request_matches'])
 def test_unknown_ambiguous_unsafe_xml_refuses_without_values(self):
  for xml in ('<!DOCTYPE x [<!ENTITY y "PRIVATE_SECRET">]>'+XML,XML+'PRIVATE_SECRET',XML.replace('CORSRule','Unknown'),XML.replace('<AllowedHeader>','<AllowedHeader x="PRIVATE_SECRET">'),XML.replace('</CORSRule>','<ID>a</ID><ID>b</ID></CORSRule>'),XML.replace('PUT','INPUT'),'x'*65537):
   with self.assertRaises(Refusal) as caught:cors.policy_facts(xml,ORIGINS)
   self.assertEqual(caught.exception.args,('cors_policy_schema',))
 def test_actual_production_bootstrap_xml_to_policy_to_real_http_and_journal(self):
  spec=importlib.util.spec_from_file_location('cors_bootstrap_control',Path(__file__).parent/'dev/silo_bootstrap_test.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  captured=[];original=m.shared.finite_shell
  def observe(call,journal,label,command,*args,**kw):
   if label=='cors':
    tokens=shlex.split(command);captured.append(tokens[tokens.index('%s')+1])
   return original(call,journal,label,command,*args,**kw)
  with tempfile.TemporaryDirectory(prefix='ur.cors-control.') as directory:
   root=Path(directory).resolve();root.chmod(0o700);fixture=root/'fixture';fixture.mkdir(mode=0o700)
   with patch.object(m.shared,'finite_shell',side_effect=observe):m.BootstrapTests().exercise(fixture,port=54321)
   self.assertEqual(len(captured),1);policy=cors.policy_facts(captured[0],ORIGINS);self.assertTrue(policy['request_matches'])
   journal=StorageDiagnosticJournal(root/'storage-diagnostics.jsonl',fixture)
   def selected_client(label,unused,args,timeout):
    import subprocess
    self.assertEqual(label,'cors_get');self.assertEqual(timeout,10)
    command=args[args.index('--command')+1]
    self.assertIn('cors get local/owned-bucket',command)
    prefix='mc() { test "$HOME" = /root && test "$1" = --config-dir && test "$2" = /root/.mc || return 91; shift 2; test "$1" = cors && test "$2" = get && test "$3" = local/owned-bucket && test "$#" = 3 || return 92; printf %s '+shlex.quote(captured[0])+'; }; '
    result=__import__('subprocess').run(['/bin/sh','-c',prefix+command],capture_output=True,text=True,timeout=3,env={'PATH':'/usr/bin:/bin','HOME':str(fixture)})
    self.assertEqual(result.returncode,0)
    v=dict(schema='effigy.container.bounded-exec.v1',schema_version=1,ok=True,container='hybrid_services',service='silo_client',failure='complete',code=0,limits=m.shared.BOUNDS,retained={'stdout_bytes':len(result.stdout.encode()),'stderr_bytes':len(result.stderr.encode())},preparation={'captures':0,'retained':{'stdout_bytes':0,'stderr_bytes':0}},attempts=1,workspace_user_fallback=False,remote_cancellation='unverified',stdout=result.stdout,stderr=result.stderr,stdout_bytes=len(result.stdout.encode()),stderr_bytes=len(result.stderr.encode()))
    return json.dumps(dict(schema='effigy.command.v1',schema_version=1,ok=True,result=v,error=None)),0
   policy=cors.read_policy(m.shared,selected_client,journal,'owned-bucket',ORIGINS)
   self.assertTrue(policy['request_matches'])
   server=None
   def response(n,c,h,b):
    method,path,headers,body=server.requests[-1]
    self.assertEqual(method,'OPTIONS');self.assertEqual(body,b'')
    matched=headers.get('origin')==ORIGINS[0] and headers.get('access-control-request-method')=='PUT' and set(headers.get('access-control-request-headers','').split(','))==set(cors.SIGNED_HEADERS) and policy['request_matches']
    return (200,{'Access-Control-Allow-Origin':ORIGINS[0],'Access-Control-Allow-Methods':'GET, HEAD, PUT','Access-Control-Allow-Headers':','.join(cors.SIGNED_HEADERS)},b'') if matched else (403,{},b'')
   server=Producer(response)
   try:result=cors.preflight(server.port,'owned-bucket',ORIGINS[0],journal);self.assertTrue(result['positive']);self.assertEqual(len(server.requests),1)
   finally:server.close();journal.close()
   rows=decode_journal_rows((root/'storage-diagnostics.jsonl').read_text());text=json.dumps(rows)
   self.assertIn('present_equal',text);self.assertNotIn('example.test',text)
 def test_complete403_once_then_distinct_foreign_read_only_and_privacy(self):
  with tempfile.TemporaryDirectory(prefix='ur.cors-negative.') as d:
   root=Path(d).resolve();root.chmod(0o700);fixture=root/'fixture';fixture.mkdir(mode=0o700);journal=StorageDiagnosticJournal(root/'storage-diagnostics.jsonl',fixture)
   server=Producer(lambda *a:(403,{},b''))
   try:
    result=cors.preflight(server.port,'owned-bucket',ORIGINS[0],journal)
    self.assertFalse(result['positive']);self.assertEqual(result['facts']['cors_origin_state'],'absent');self.assertEqual(len(server.requests),2)
    self.assertNotEqual(server.requests[0][2]['origin'],server.requests[1][2]['origin'])
   finally:server.close();journal.close()
 def test_actual_caller_framing_refusal_survives_outer(self):
  with tempfile.TemporaryDirectory(prefix='ur.cors-framing.') as d:
   root=Path(d).resolve();root.chmod(0o700);fixture=root/'fixture';fixture.mkdir(mode=0o700);journal=StorageDiagnosticJournal(root/'storage-diagnostics.jsonl',fixture)
   server=Producer(lambda *a:b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nPRIVATE_SECRET')
   try:
    with self.assertRaises(storage.StorageRefusal) as caught:cors.preflight(server.port,'owned-bucket',ORIGINS[0],journal)
    out=outer_refusals(json.dumps(project(caught.exception,'runtime_profile')));self.assertTrue(out['typed_failure_available']);self.assertNotIn('PRIVATE_SECRET',json.dumps(out));self.assertEqual(len(server.requests),1)
   finally:server.close();journal.close()

if __name__=='__main__':
 signal.alarm(60);unittest.main()
