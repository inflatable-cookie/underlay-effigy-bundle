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
        wires=[self.wire(body=x) for x in bodies]+[self.wire(status=401),
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
        self.assertLess(time.monotonic()-started,.3)
        self.assertFalse(events[0]['observations']); self.assertNotIn(SEED,json.dumps(events))
        value=json.loads(self.wire().split(b'\r\n\r\n',1)[1])
        auth.session_schema(value,'login',{'email':'test@example.invalid'})
        for altered in ({}, {'data':{**value['data'],'unknown':SEED}},
                        {'data':{**value['data'],'session_id':'bad'}},
                        {'data':{**value['data'],'user':{**value['data']['user'],'roles':['user']}}}):
            with self.assertRaises(auth.AuthRefusal): auth.session_schema(altered,'login',{'email':'test@example.invalid'})
        path.unlink()

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
            return f'underlay_profile_auth_diagnostic correlation="fixture-auth-login" phase="{phase}" elapsed_ms=8053 outcome="{outcome}" {SEED}\n'
        path.write_text(trace()); os.chmod(path,0o600)
        value=auth.tail(path,self.root)
        self.assertNotIn(SEED,json.dumps(value)); self.assertEqual(value['observations'][0]['elapsed_ms'],8053)
        for data in (trace()+trace(),trace(phase='unknown'),trace(outcome='unknown')):
            path.write_text(data)
            with self.assertRaises(auth.AuthRefusal):auth.tail(path,self.root)
        path.write_text('x'*70000+'\n'+trace())
        self.assertTrue(auth.tail(path,self.root)['tail_truncated'])
        events=[]
        # Virtual time demonstrates a single shared 3s post window, no resetting on reread.
        with patch.object(auth.time,'monotonic',side_effect=[0,1,1,1,3.1,3.1,3.1]), patch.object(auth.time,'sleep'):
            auth.capture(path,self.root,lambda event,**fields:events.append(fields),post=True)
        self.assertEqual(len(events),1); self.assertEqual(events[0]['elapsed_ms'],3100)
        self.assertEqual(auth.POST_SECONDS,3)
        path.unlink(); path.symlink_to(self.cert)
        with self.assertRaises(OSError):auth.tail(path,self.root)
        path.unlink()


if __name__=='__main__':
    signal.alarm(60)
    unittest.main()
