"""Finite private protocol controls; no application/backend/crypto execution."""
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import auth_operation as auth

SEED = 'private-seeded-credential-do-not-emit'
PHASES = ['prepare','connect','tls','send','headers','body','decode','complete']


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix='ur.005-auth-controls.')
        cls.root = Path(cls.fixture.name).resolve(); os.chmod(cls.root,0o700)
        cls.key = cls.root/'key.pem'; cls.cert = cls.root/'cert.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-keyout',str(cls.key),'-out',str(cls.cert),'-subj','/CN=auth.fixture.test',
                        '-addext','subjectAltName=DNS:auth.fixture.test'],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=15)
        os.chmod(cls.key,0o600)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def invoke(self, call, budget=.35):
        events=[]
        try:
            result=auth.isolated(call,budget,lambda event,**fields:events.append({'event':event,**fields}))
        finally:
            self.assertNotIn(SEED,json.dumps(events))
            self.assertLess(len(json.dumps(events)),8000)
        return result,events

    def peer(self, raw, *, delay=0, trickle=False, handshake_stall=False):
        listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1); listener.settimeout(1)
        port=listener.getsockname()[1]
        def serve():
            try:
                conn,_=listener.accept(); conn.settimeout(.6)
                with conn:
                    if handshake_stall: time.sleep(.5); return
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(self.cert,self.key)
                    with context.wrap_socket(conn,server_side=True) as channel:
                        request=bytearray()
                        while b'\r\n\r\n' not in request and len(request)<4096:
                            request.extend(channel.recv(1024))
                        time.sleep(delay)
                        if trickle:
                            for byte in raw:
                                channel.send(bytes([byte])); time.sleep(.015)
                        else: channel.sendall(raw)
            except (OSError,ssl.SSLError): pass
            finally: listener.close()
        thread=threading.Thread(target=serve,daemon=True); thread.start()
        return port,thread

    def wire(self, body=None, headers=None, status=200):
        if body is None: body=json.dumps({'data':{'access_token':SEED,'session_id':'11111111-1111-1111-1111-111111111111','user':{'user_id':'22222222-2222-2222-2222-222222222222','email':'test@example.invalid','display_name':'Test','roles':['admin']}}}).encode()
        if headers is None: headers=f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n'.encode()
        return f'HTTP/1.1 {status} test\r\n'.encode()+headers+b'\r\n'+body

    def transport(self, raw, *, domain='auth.fixture.test', ca=None, budget=.35, **peer):
        port,thread=self.peer(raw,**peer)
        try:
            return self.invoke(lambda end,phase:auth.transport(domain,port,ca or self.cert,'login',
                              {'email':'test@example.invalid','password':SEED},'https://admin.fixture.test',end,phase),budget)
        finally:
            thread.join(1)
            self.assertFalse(thread.is_alive())

    def test_real_tls_response_and_private_session(self):
        raw=self.wire(); raw=raw.replace(b'Content-Type:',b'Set-Cookie: refresh=x\r\nSet-Cookie: logged_in=true\r\nContent-Type:',1)
        result,events=self.transport(raw)
        self.assertEqual(result['data']['access_token'],SEED)
        self.assertEqual([x['phase'] for x in events if x['event']=='client_phase'],PHASES)
        self.assertTrue(events[-1]['leader_reaped'])
        self.assertEqual(events[0]['budget_ms'],350)
        self.assertEqual(auth.AUTH_SECONDS,20)

    def test_absolute_tls_headers_body_trickle_and_late_valid(self):
        cases=[(self.wire(),{'handshake_stall':True}),
               (self.wire(),{'trickle':True}),
               (self.wire(body=b'{',headers=b'Content-Type: application/json\r\nContent-Length: 30\r\n'),{}),
               (self.wire(),{'delay':.45})]
        for raw,peer in cases:
            with self.subTest(peer=peer), self.assertRaises(auth.AuthRefusal):
                self.transport(raw,**peer)

    def test_strict_tls_name_and_ca(self):
        for options in ({'domain':'foreign.fixture.test'},{'ca':self.key}):
            with self.subTest(options=options), self.assertRaises(auth.AuthRefusal):
                self.transport(self.wire(),**options)

    def test_http_headers_body_schema_refusals(self):
        bodies=[b'',b'{}',b'{"data":{"access_token":"a","access_token":"b"}}',b'not-json',b'{"data":{"access_token":null}}']
        wires=[self.wire(body=x) for x in bodies]+[self.wire(status=401),self.wire(status=201),
          self.wire(headers=b'Set-Cookie: refresh=x\r\nSet-Cookie: refresh=y\r\nContent-Length: 1\r\nContent-Type: application/json\r\n'),
          self.wire(headers=b'Content-Length: 1\r\nContent-Length: 1\r\nContent-Type: application/json\r\n'),
          self.wire(headers=b'Content-Length: 65537\r\nContent-Type: application/json\r\n'),
          self.wire(headers=b'X-Large: '+b'x'*16384+b'\r\n'),
          self.wire(headers=b'Content-Length: 1\r\nContent-Type: application/json\r\n'+b''.join(f'X-{i}: x\r\n'.encode() for i in range(33)))]
        for raw in wires:
            with self.subTest(size=len(raw)), self.assertRaises(auth.AuthRefusal): self.transport(raw)

    def test_phase_duplicates_unknown_capture_and_decode_deadline(self):
        def duplicate(end,phase): phase('prepare'); phase('prepare'); return {}
        def unknown(end,phase): phase('secret_unknown_'+SEED); return {}
        def overflow(end,phase): os.write(1,b'x'*(auth.STDOUT_CAP+1)); return {}
        def stderr(end,phase): os.write(2,SEED.encode()+b'x'*auth.STDERR_CAP); return {}
        def decode(end,phase):
            for name in PHASES[:-1]: phase(name)
            time.sleep(.5); phase('complete'); return {'data':{'access_token':SEED}}
        for call in (duplicate,unknown,overflow,stderr,decode):
            with self.subTest(call=call.__name__), self.assertRaises(auth.AuthRefusal):self.invoke(call)

    def test_deadline_at_each_stage_and_preparation_before_gate(self):
        for held in PHASES[:-1]:
            def stalled(end,phase):
                for name in PHASES:
                    phase(name)
                    if name==held: time.sleep(.15)
                return {'data':{'access_token':SEED}}
            with self.subTest(stage=held), self.assertRaises(auth.AuthRefusal):
                self.invoke(stalled,.08)
        events=[]
        def slow_intent(event,**fields):
            events.append(event)
            if event=='client_intent':time.sleep(.12)
        with self.assertRaises(auth.AuthRefusal):
            auth.isolated(lambda end,phase: (_ for _ in ()).throw(AssertionError('gate must stay closed')),.05,slow_intent)
        self.assertNotIn('client_phase',events)

    def test_fixture_patch_phase_inventory_and_export_direction(self):
        source=Path(__file__).parent
        fixture=(source/'fixtures/reference-auth-diagnostic.patch').read_text()
        import re
        phases=set(re.findall(r'(?:phase = |fixture_auth_trace\()"([a-z_]+)"',fixture))
        self.assertTrue(phases <= auth.SERVER_PHASES)
        module=(source/'auth_operation.py').read_text()
        self.assertNotIn('os.environ',module)
        production='\n'.join(p.read_text() for p in (source/'dev').rglob('*.py'))
        self.assertNotIn('import auth_operation',production)
        caller=(source/'reference_storage_probe.py').read_text()
        self.assertIn('operation in ("register", "login")',caller)
        self.assertNotIn('time.sleep(15)',caller)
        self.assertIn('"scripts/auth_operation.py"',(source/'qualify-reference-optin.py').read_text())

    def test_real_short_post_window_and_schema_identity(self):
        path=self.root/'window.log'; path.write_text('unrelated '+SEED+'\n')
        events=[]; started=time.monotonic()
        with patch.object(auth,'POST_SECONDS',.12):
            auth.capture(path,self.root,lambda event,**fields:events.append(fields),post=True)
        self.assertLess(time.monotonic()-started,.12)
        self.assertFalse(events[0]['observations']); self.assertNotIn(SEED,json.dumps(events))
        value=json.loads(self.wire().split(b'\r\n\r\n',1)[1])
        auth.session_schema(value,'login',{'email':'test@example.invalid'})
        for altered in ({}, {'data':{**value['data'],'unknown':SEED}},
                        {'data':{**value['data'],'session_id':'bad'}},
                        {'data':{**value['data'],'user':{**value['data']['user'],'roles':['user']}}}):
            with self.assertRaises(auth.AuthRefusal): auth.session_schema(altered,'login',{'email':'test@example.invalid'})
        path.unlink()

    def test_genuine_retained_formatter_and_shared_decoder(self):
        path=Path('/Users/tom/ur.3AVM3Z/home/reference/main/.effigy/runtime/host-processes/hybrid_services/effigy/api.log')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        import stat,hashlib
        info=os.fstat(fd);self.assertTrue(stat.S_ISREG(info.st_mode));self.assertEqual(info.st_nlink,1)
        os.lseek(fd,max(0,info.st_size-65536),os.SEEK_SET);raw=os.read(fd,65536);os.close(fd)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'e59161a9401cef053e69c7efa9ea0b4b8379287e379c17c88eb92e9a1c531437')
        from reference_storage_probe import sanitize_service_log_line
        lines=[line for line in raw.splitlines() if auth.TARGET.encode() in line]
        self.assertEqual(len(lines),26)
        observed=[auth.decode_trace(line) for line in lines]
        self.assertTrue({('auth_verify_worker','valid'),('auth_verify_join','ok'),('api_login_response','success')} <= {(x['phase'],x['outcome']) for x in observed})
        for line in lines:self.assertTrue(sanitize_service_log_line(line.decode()).startswith('AUTH_DIAGNOSTIC'))
        for line in (lines[0]+b' '+SEED.encode(),lines[0]+b'\xff',lines[0]+b'\x1b]payload\x07',
                     lines[0].replace(b'fixture-auth-login',b'fixture-\x1b[0mauth-login'),lines[0]+b'\x1b[99m'):
            with self.assertRaises(auth.AuthRefusal):auth.decode_trace(line)

    def test_current_operation_boundary_all_markers_and_typed_refusal(self):
        from qualification_refusal import project
        from reference_storage_probe import sanitize_service_log_line
        path=self.root/'current.log'
        def line(phase,outcome):return f'underlay_profile_auth_diagnostic: correlation: "fixture-auth-login", phase: "{phase}", elapsed_ms: 1, outcome: "{outcome}"\n'
        required=''.join(line(p,o) for p,o in [('auth_verify_worker','valid'),('auth_verify_join','ok'),('api_login_response','success')])
        path.write_text(required)
        before,_=auth.capture(path,self.root,lambda *a,**k:None)
        events=[]
        with patch.object(auth,'POST_SECONDS',.08):
            _,complete=auth.capture(path,self.root,lambda e,**k:events.append(k),post=True,baseline=before['baseline'])
        self.assertFalse(complete);self.assertFalse(events[-1]['observations'])
        extras=[p for p in sorted(auth.SERVER_PHASES) if p not in ('auth_verify_worker','auth_verify_join','api_login_response')]
        with path.open('a') as f:f.write(required+''.join(line(p,'started') for p in extras))
        latest,complete=auth.capture(path,self.root,lambda *a,**k:None,post=True,baseline=before['baseline'])
        self.assertTrue(complete);self.assertGreater(latest['total_observations'],16)
        self.assertEqual(len(latest['observations']),16)
        self.assertEqual(latest['observations_omitted'],latest['total_observations']-16)
        with path.open('a') as f:f.write(required)
        events=[]
        with self.assertRaises(auth.AuthRefusal) as caught:
            auth.capture(path,self.root,lambda e,**k:events.append((e,k)),post=True,baseline=before['baseline'])
        record=project(caught.exception,'runtime_profile')
        self.assertEqual(record['reason_id'],'auth_operation_protocol')
        self.assertEqual(record['protocol_shape']['class'],'duplicate')
        self.assertEqual(record['auth_evidence']['window'],'post')
        self.assertEqual(events[0][0],'protocol_refusal');self.assertNotIn(SEED,json.dumps(record))
        with self.assertRaises(auth.AuthRefusal) as caught:
            auth.capture(path,self.root,lambda *a,**k:(_ for _ in ()).throw(RuntimeError(SEED)),post=True,baseline=before['baseline'])
        self.assertTrue(caught.exception.publication_unavailable)
        old=path.with_suffix('.old');path.rename(old);path.write_text(required)
        with self.assertRaises(auth.AuthRefusal):auth.tail(path,self.root,before['baseline'])
        path.unlink();old.unlink()
        seed=line('auth_verify_worker','valid').rstrip().encode()
        for bad in (seed+b'\x1b[2J',seed+b'\x08',seed.replace(b'elapsed_ms: 1',b'elapsed_ms: 4294967296'),seed+b', secret: "hidden"',seed.replace(b'fixture-auth-login',b'foreign'),seed+b'\r'):
            with self.assertRaises(auth.AuthRefusal):auth.decode_trace(bad)
            self.assertFalse(sanitize_service_log_line(bad.decode()).startswith('AUTH_DIAGNOSTIC'))
        class Derived(auth.AuthRefusal):pass
        self.assertEqual(project(Derived('protocol'),'runtime_profile')['reason_id'],'unknown')
        self.assertEqual(auth.AUTH_SECONDS,20);self.assertEqual(auth.POST_SECONDS,3)

    def test_actual_auth_caller_current_markers_primary_and_privacy(self):
        from reference_storage_probe import observed_auth_request, StorageDiagnosticJournal
        from qualification_refusal import publish
        checkout=self.root/'caller';path=checkout/'.effigy/runtime/host-processes/hybrid_services/effigy/api.log'
        path.parent.mkdir(parents=True,exist_ok=True)
        def line(p,o):return f'underlay_profile_auth_diagnostic correlation="fixture-auth-login" phase="{p}" elapsed_ms=1 outcome="{o}"\n'
        markers=''.join(line(p,o) for p,o in [('auth_verify_worker','valid'),('auth_verify_join','ok'),('api_login_response','success')])
        path.write_text(markers)
        events=[]
        def request(*a,**k):
            with path.open('a') as f:f.write(markers)
            return {'data':{'access_token':SEED}}
        with patch.object(auth,'request',side_effect=request):
            value=observed_auth_request(checkout,'api.fixture.test',1,self.cert,'login',{'password':SEED},'https://admin.fixture.test',lambda e,**k:events.append((e,k)))
        self.assertEqual(value['data']['access_token'],SEED)
        self.assertTrue(events[-1][1]['trace_complete']);self.assertNotIn(SEED,json.dumps(events))
        with patch.object(auth,'request',return_value={}),patch.object(auth,'POST_SECONDS',.06):
            with self.assertRaises(auth.AuthRefusal):observed_auth_request(checkout,'api.fixture.test',1,self.cert,'login',{},'https://admin.fixture.test',lambda *a,**k:None)
        primary=auth.AuthRefusal('transport')
        with patch.object(auth,'request',side_effect=primary),patch.object(auth,'POST_SECONDS',.06):
            with self.assertRaises(auth.AuthRefusal) as caught:observed_auth_request(checkout,'api.fixture.test',1,self.cert,'login',{},'https://admin.fixture.test',lambda *a,**k:None)
        self.assertIs(caught.exception,primary)
        before,_=auth.capture(path,checkout,lambda *a,**k:None)
        with path.open('a') as f:f.write(markers[:30])
        latest,complete=auth.capture(path,checkout,lambda *a,**k:None,post=True,baseline=before['baseline'])
        self.assertTrue(latest['incomplete_line']);self.assertFalse(complete)
        diagnostic=Path(tempfile.mkdtemp(prefix='ur.005-auth-journal.')).resolve();diagnostic.chmod(0o700)
        journal=StorageDiagnosticJournal(diagnostic/'storage-diagnostics.jsonl',checkout)
        bad=auth.protocol_refusal('style',33)
        record=publish(bad,'runtime_profile',journal.append);journal.close()
        self.assertEqual(record['reason_id'],'auth_operation_protocol')
        frames=(diagnostic/'storage-diagnostics.jsonl').read_text();self.assertNotIn(SEED,frames)
        self.assertEqual(json.loads(frames)['projection']['protocol_shape']['sgr_count'],32)
        # Non-SGR controls and style codes inside an enum are not normalization.
        base=line('auth_verify_worker','valid').rstrip().encode()
        for raw in (base.replace(b'valid',b'va\x1b[0mlid'),base+b'\x1b[0m'*33,base+b'\x1b[;m',base+b'\x1b[31m'):
            with self.assertRaises(auth.AuthRefusal):auth.decode_trace(raw)

    def test_register_no_marker_wait_and_post_writer_deadline(self):
        path=self.root/'register.log';path.write_text('unrelated '+SEED+'\n')
        events=[];started=time.monotonic()
        latest,complete=auth.capture(path,self.root,lambda e,**kw:events.append(kw),post=True,operation='register')
        self.assertLess(time.monotonic()-started,.1)
        self.assertFalse(complete);self.assertEqual(events[0]['reads'],1)
        self.assertEqual(events[0]['trace_applicability'],'not_applicable')
        with patch.object(auth,'POST_SECONDS',.05):
            with self.assertRaises(auth.AuthRefusal):
                auth.capture(path,self.root,lambda *a,**kw:time.sleep(.08),post=True,operation='register')
        path.unlink()

    def test_final_client_writer_overrun_has_no_return_or_retry(self):
        def call(end,phase):
            for name in PHASES:phase(name)
            return {'data':{'access_token':SEED}}
        events=[]
        def emit(event,**kw):
            events.append((event,kw))
            if event=='client_result':time.sleep(.15)
        with self.assertRaises(auth.AuthRefusal):auth.isolated(call,.1,emit)
        self.assertEqual(len([x for x in events if x[0]=='client_result']),1)
        self.assertEqual(events[-1][1]['acceptance'],'pending')
        self.assertNotIn(SEED,json.dumps(events))

    def test_remaining_uses_absolute_origin_and_unknown_group_no_signal(self):
        with patch.object(auth.time,'monotonic',side_effect=[10,10.9,11.1]):
            self.assertEqual(auth.remaining(11),1)
            self.assertAlmostEqual(auth.remaining(11),.1)
            with self.assertRaises(auth.AuthRefusal):auth.remaining(11)
        with patch.object(auth.os,'getpgid',return_value=987), patch.object(auth.os,'killpg') as kill:
            with self.assertRaises(auth.AuthRefusal): auth.terminate_owned(123)
            kill.assert_not_called()

    def test_file_phase_privacy_limits_duplicate_unknown_and_post_window(self):
        path=self.root/'api.log'
        def trace(phase='auth_verify_worker',outcome='valid'):
            return f'underlay_profile_auth_diagnostic correlation="fixture-auth-login" phase="{phase}" elapsed_ms=8053 outcome="{outcome}"\n'
        path.write_text(trace()); os.chmod(path,0o600)
        value=auth.tail(path,self.root)
        self.assertNotIn(SEED,json.dumps(value)); self.assertEqual(value['observations'][0]['elapsed_ms'],8053)
        for data in (trace()+trace(),trace(phase='unknown'),trace(outcome='unknown')):
            path.write_text(data)
            with self.assertRaises(auth.AuthRefusal):auth.tail(path,self.root)
        path.write_text('x'*70000+'\n'+trace())
        self.assertTrue(auth.tail(path,self.root)['tail_truncated'])
        events=[]
        # Read/decode or accepted journal emission crossing the single origin
        # must refuse, rather than publish a successful prefix/return.
        clock=[0.0]
        original=auth.tail
        def slow_read(*args):
            value=original(*args);clock[0]=3.001;return value
        with patch.object(auth.time,'monotonic',side_effect=lambda:clock[0]), patch.object(auth,'tail',side_effect=slow_read):
            with self.assertRaises(auth.AuthRefusal):auth.capture(path,self.root,lambda *a,**kw:None,post=True)
        clock[0]=0
        def slow_emit(*args,**fields): clock[0]=3.001
        with patch.object(auth.time,'monotonic',side_effect=lambda:clock[0]):
            with self.assertRaises(auth.AuthRefusal):auth.capture(path,self.root,slow_emit,post=True,operation='register')
        self.assertEqual(auth.POST_SECONDS,3)
        path.unlink(); path.symlink_to(self.cert)
        with self.assertRaises(OSError):auth.tail(path,self.root)
        path.unlink()


if __name__=='__main__':
    signal.alarm(60)
    unittest.main()
