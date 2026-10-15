import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import route_observation as routes


class Server:
    def __init__(self,context,producer):
        self.context=context;self.producer=producer;self.done=threading.Event()
        self.socket=socket.socket();self.socket.bind(('127.0.0.1',0));self.socket.listen();self.socket.settimeout(.1)
        self.port=self.socket.getsockname()[1];self.errors=[]
        self.thread=threading.Thread(target=self.loop);self.thread.start()
    def loop(self):
        while not self.done.is_set():
            try:raw,_=self.socket.accept()
            except socket.timeout:continue
            except OSError:break
            try:
                with self.context.wrap_socket(raw,server_side=True) as peer:
                    peer.settimeout(1);request=b''
                    while b'\r\n\r\n' not in request and len(request)<16384:
                        block=peer.recv(4096)
                        if not block:break
                        request+=block
                    self.producer(peer,request)
            except (OSError,ssl.SSLError):raw.close()
            except BaseException as error:self.errors.append(type(error).__name__);raw.close()
    def close(self):
        self.done.set();self.socket.close();self.thread.join(2)
        if self.thread.is_alive() or self.errors:raise AssertionError('synthetic_server_settlement_failed')


class RouteControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pending_start_identity import kernel_identity
        identity=kernel_identity(os.getpid())
        if identity['uid']!=os.geteuid() or identity['pgid']!=os.getpgrp():raise AssertionError('control_group_identity_refused')
        cls.temp=tempfile.TemporaryDirectory(prefix='ur.route-control.');cls.root=Path(cls.temp.name);cls.root.chmod(0o700)
        cls.cert=cls.root/'cert.pem';cls.key=cls.root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(cls.key),'-out',str(cls.cert),
                        '-days','1','-subj','/CN=route.test','-addext','subjectAltName=DNS:route.test'],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
        cls.cert.chmod(0o600);cls.key.chmod(0o600)
        cls.server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);cls.server_context.load_cert_chain(cls.cert,cls.key)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.events=[];routes.configure(lambda event,**fields:self.events.append((event,fields)))
        self.addCleanup(routes.configure,None)
        self.context=routes.ca_context(self.cert)
    def server(self,producer):
        server=Server(self.server_context,producer);self.addCleanup(server.close);return server
    def request(self,wire,**kwargs):
        server=self.server(lambda peer,request:peer.sendall(wire))
        return routes.exchange('route.test',server.port,self.context,'/',role='front',**kwargs)
    def refused(self,reason,wire,**kwargs):
        with self.assertRaises(routes.RouteObservationRefusal) as caught:self.request(wire,**kwargs)
        self.assertEqual(caught.exception.reason,reason)
        self.assertEqual(self.events[-1][1]['observation']['reason'],reason)
        return caught.exception
    def test_real_tls_http_pipeline_and_chunked(self):
        self.assertEqual(self.request(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')[2],b'ok')
        self.assertEqual(self.request(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n')[2],b'ok')
    def test_framing_partial_caps_and_slow_absolute_deadline(self):
        cases=[('framing',b'Content-Length: 2\r\nContent-Length: 2\r\n\r\nok'),
               ('framing',b'Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nok'),
               ('body_eof',b'Content-Length: 10\r\n\r\nabc'),
               ('body_cap',b'Content-Length: 1048577\r\n\r\n'),
               ('header_cap',b'X: '+b'x'*16400+b'\r\n\r\n')]
        for reason,wire in cases:
            with self.subTest(reason=reason):self.refused(reason,b'HTTP/1.1 200 OK\r\n'+wire)
        self.refused('header_cap',b'HTTP/1.1 200 OK\r\n'+b'X: a\r\n'*33+b'\r\n')
        server=self.server(lambda peer,request:(peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\na'),time.sleep(.3)))
        with patch('qualification_batch.cap',return_value=.1):
            with self.assertRaises(routes.RouteObservationRefusal) as caught:routes.exchange('route.test',server.port,self.context,'/')
        self.assertEqual(caught.exception.reason,'deadline')
    def test_private_ca_and_sni_fail_closed(self):
        server=self.server(lambda peer,request:peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'))
        for host,context in [('wrong.test',self.context),('route.test',ssl.create_default_context())]:
            with self.assertRaises(routes.RouteObservationRefusal) as caught:routes.exchange(host,server.port,context,'/')
            self.assertEqual(caught.exception.reason,'tls_verify')
            self.assertIsInstance(caught.exception.route_observation['facts']['tls_verify_code'],int)
        bad=self.root/'bad.pem';bad.write_text('PRIVATE')
        with self.assertRaises(routes.RouteObservationRefusal) as caught:routes.ca_context(bad)
        self.assertEqual(caught.exception.reason,'ca_context')
    def state(self):return {role:{'route_domain':'route.test','address':'127.0.0.1:1','generation':'owned'} for role in ('api','front','admin')}
    def status(self):return {'routes':[{'domain':'route.test','target':'127.0.0.1:1','cert_ready':True,'tls':True}]}
    def producer(self,peer,request):
        path=request.split(b' ')[1].decode()
        if path.startswith('/?token='):
            key=next(x.split(b': ',1)[1] for x in request.split(b'\r\n') if x.lower().startswith(b'sec-websocket-key:'))
            accept=base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            peer.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: '+accept+b'\r\n\r\n');return
        if path.startswith('/__qualification'):
            host=next(x.split(b': ',1)[1].decode() for x in request.split(b'\r\n') if x.startswith(b'Host:'))
            origin='https://'+host
            body=json.dumps({'urlOrigin':origin,'requestUrl':origin+path,'requestUrlOrigin':origin,
              'requestPath':'/__qualification/origin','requestSearch':'?probe=public-origin','method':'GET',
              'host':host,'origin':origin,'forwardedProto':'https','forwardedHost':host}).encode()
        elif path=='/@vite/client':
            host=next(x.split(b': ',1)[1].decode() for x in request.split(b'\r\n') if x.startswith(b'Host:'))
            body=('const wsToken = "PRIVATE_TOKEN"; const endpoint = "wss://'+host+'";').encode()
        else:body=b'ok'
        peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nContent-Type: application/json\r\n\r\n'+body)
    def test_actual_whole_observer_with_real_ssl_origin_and_websocket(self):
        server=self.server(self.producer);routes.observe(self.status(),self.state(),server.port,self.context)
        self.assertNotIn('PRIVATE_TOKEN',json.dumps(self.events));self.assertNotIn('route.test',json.dumps(self.events))
        self.assertTrue(any(x[1]['observation']['reason']=='websocket_accept' for x in self.events))
    def test_route_predicates_before_http_and_native_json(self):
        for reason,change in [('route_absent',None),('route_target',{'target':'foreign'}),('route_certificate',{'cert_ready':False})]:
            status=self.status()
            if change is None:status['routes']=[]
            else:status['routes'][0].update(change)
            with patch.object(routes,'exchange',side_effect=AssertionError('HTTP forbidden')):
                with self.assertRaises(routes.RouteObservationRefusal) as caught:routes.observe(status,self.state(),1,self.context)
            self.assertEqual(caught.exception.reason,reason)
        # Actual maintained native capture of a source-shaped private producer.
        value={key:None for key in routes.STATUS_KEYS}
        value.update(schema='effigy.gateway.status.v1',schema_version=1,ok=True,running=True,**self.status())
        value['routes']=[dict(dict(domain='',target=None,dns_ip=None,tcp_port=None,tcp_target=None,source='task',project='control',tls=True,cert_ready=True,registered='2026-10-15T00:00:00Z'),**row) for row in value['routes']]
        value['route_count']=len(value['routes'])
        envelope={key:None for key in routes.ENVELOPE_KEYS}
        envelope.update(schema='effigy.command.v1',schema_version=1,ok=True,result=value)
        native=routes.native_status([sys.executable,'-c','import json; print('+repr(json.dumps(envelope))+')'],self.root,dict(os.environ))
        self.assertEqual(native['routes'],value['routes'])
        for text,reason in [('PRIVATE','envelope_json'),('{"ok":true,"ok":true}','envelope_json'),('{}','envelope_shape')]:
            with self.assertRaises(routes.RouteObservationRefusal) as caught:
                routes.native_status([sys.executable,'-c','print('+repr(text)+')'],self.root,dict(os.environ))
            self.assertEqual(caught.exception.reason,reason)
        self.assertNotIn('PRIVATE',json.dumps(self.events))
    def test_source_derived_mixed_dashboard_full_native_caller_and_refusal_pipeline(self):
        import copy
        import re
        from types import SimpleNamespace
        from qualification_refusal import project
        source=Path(os.environ['UNDERLAY_PROFILE_EFFIGY_SOURCE'])
        native=(source/'src/runner/gateway_command/mod.rs').read_text()
        self.assertEqual(hashlib.sha256(native.encode()).hexdigest(),'17b75a95370ca468622178d536031de5e62aa1ad514e24021cd46b625839ac25')
        contract=native.split('fn render_routes_json(',1)[1].split('fn gateway_route_dashboard(',1)[0]
        self.assertEqual(set(re.findall(r'"([a-z_]+)": route\.',contract)),set(routes.ROUTE_KEYS))
        for field in ('target','dns_ip','tcp_port','tcp_target'):
            declaration=native.split('struct GatewayRouteDashboardEntry {',1)[1].split('}',1)[0]
            self.assertRegex(declaration,field+r': Option<')
        enum=(source/'crates/effigy-gateway/src/routes.rs').read_text().split('pub enum RouteSource {',1)[1].split('}',1)[0]
        self.assertEqual(set(re.findall(r'^    (Container|Task|Manual),',enum,re.M)),{'Container','Task','Manual'})
        # Exact source-derived ten-field renderer fixture. No persistent Route-only fields.
        base=dict(domain='route.test',target='127.0.0.1:1',dns_ip=None,tcp_port=None,tcp_target=None,
                  source='task',project='control',tls=True,cert_ready=True,registered='2026-10-15T00:00:00.123456789Z')
        mixed=[base,dict(base,domain='dns.test',target=None,dns_ip='127.0.0.1',source='container',tls=False,cert_ready=False),
               dict(base,domain='tcp.test',target=None,dns_ip='127.0.0.1',tcp_port=5432,tcp_target='127.0.0.1:5432',source='manual',tls=False,cert_ready=False)]
        self.assertFalse(all(type(row['target']) is str for row in mixed)) # old production predicate counterexample
        value={key:None for key in routes.STATUS_KEYS}
        value.update(schema='effigy.gateway.status.v1',schema_version=1,ok=True,running=True,routes=mixed,route_count=len(mixed))
        envelope={key:None for key in routes.ENVELOPE_KEYS};envelope.update(schema='effigy.command.v1',schema_version=1,ok=True,result=value)
        def decode(candidate):
            return routes.native_status([sys.executable,'-c','print('+repr(json.dumps(candidate))+')'],self.root,dict(os.environ))
        self.assertEqual(decode(envelope)['routes'],mixed)
        for nullable in ('target','dns_ip','tcp_port','tcp_target'):
            candidate=copy.deepcopy(envelope);candidate['result']['routes'][2][nullable]=None
            self.assertEqual(decode(candidate)['routes'],candidate['result']['routes'])
        for port in (0,65535):
            candidate=copy.deepcopy(envelope);candidate['result']['routes'][2]['tcp_port']=port
            self.assertEqual(decode(candidate)['routes'][2]['tcp_port'],port)
        stopped=copy.deepcopy(envelope);stopped['result']['running']=False
        with self.assertRaises(routes.RouteObservationRefusal) as caught:decode(stopped)
        self.assertEqual(caught.exception.reason,'envelope_shape')

        for field in routes.ROUTE_KEYS:
            changed=copy.deepcopy(envelope);changed['result']['routes'][1][field]=[]
            with self.subTest(field=field):
                with self.assertRaises(routes.RouteObservationRefusal) as caught:decode(changed)
                evidence=caught.exception.route_observation['facts']
                self.assertEqual(evidence['route_index'],1);self.assertEqual(evidence['field_id'],field)
                self.assertEqual(evidence['observed_type'],'list');self.assertFalse(evidence['expected_class_match'])
                projected=project(caught.exception,'runtime_profile')
                retained=routes.outer_refusals(json.dumps(projected))
                self.assertTrue(retained['typed_failure_available'])
                self.assertEqual(retained['records'][0]['route_observation']['facts']['field_id'],field)
        mutations=[lambda v:v['routes'][1].update(source='unknown'),lambda v:v['routes'][1].update(tcp_port=True),
                   lambda v:v['routes'][1].update(tcp_port=65536),lambda v:v['routes'][1].update(dns_ip='::1'),
                   lambda v:v['routes'][1].update(registered='PRIVATE'),lambda v:v['routes'][1].update(PRIVATE='PRIVATE'),
                   lambda v:v['routes'][1].pop('target'),lambda v:v['routes'].append(v['routes'][0]),
                   lambda v:v.update(route_count=True),lambda v:v.update(route_count=4),
                   lambda v:v.update(routes=[base]*257,route_count=257),lambda v:v['routes'].__setitem__(1,None)]
        for mutation in mutations:
            changed=copy.deepcopy(envelope);mutation(changed['result'])
            with self.assertRaises(routes.RouteObservationRefusal) as caught:decode(changed)
            self.assertEqual(caught.exception.reason,'routes_schema')
            self.assertNotIn('PRIVATE',json.dumps(project(caught.exception,'runtime_profile')))
        # Null is structural for aliases, never positive HTTP target evidence.
        for change,reason in [({'target':None},'route_target'),({'target':'stale'},'route_target'),
                              ({'cert_ready':False},'route_certificate'),({'tls':False},'route_certificate')]:
            candidate=copy.deepcopy(mixed);candidate[0].update(change)
            with patch.object(routes,'exchange',side_effect=AssertionError('HTTP forbidden')):
                with self.assertRaises(routes.RouteObservationRefusal) as caught:routes.observe({'routes':candidate},self.state(),1,self.context)
            self.assertEqual(caught.exception.reason,reason)
        self.assertNotIn('route.test',json.dumps(self.events))
        self.assertNotIn('tcp.test',json.dumps(self.events))

    def test_row_failure_journal_and_late_publication_preserve_closed_primary(self):
        from reference_storage_probe import StorageDiagnosticJournal,decode_journal_rows
        from qualification_refusal import publish
        fixture=self.root/'journal-fixture';fixture.mkdir()
        directory=self.root/'journal-evidence';directory.mkdir(mode=0o700)
        journal=StorageDiagnosticJournal(directory/'storage-diagnostics.jsonl',fixture)
        routes.configure(journal.append)
        try:
            with self.assertRaises(routes.RouteObservationRefusal) as caught:
                routes.validate_routes([{'PRIVATE':'PRIVATE'}],1,routes.Observation(operation='gateway_status'))
            projection=publish(caught.exception,'runtime_profile',journal.append)
        finally:journal.close()
        rows=decode_journal_rows((directory/'storage-diagnostics.jsonl').read_text())
        self.assertTrue(any(row.get('event')=='route_observation' and row['observation']['facts'].get('extra_key_count')==1 for row in rows))
        self.assertTrue(routes.outer_refusals(json.dumps(projection))['typed_failure_available'])
        self.assertNotIn('PRIVATE',json.dumps(rows))
        routes.configure(lambda *a,**kw:(_ for _ in ()).throw(OSError('PRIVATE')))
        with self.assertRaises(routes.RouteObservationRefusal) as caught:
            routes.validate_routes([None],1,routes.Observation(operation='gateway_status'))
        # The earlier successful collection publication itself can refuse first;
        # exercise row refusal after admitting those two collection receipts.
        count=[0]
        def late(*a,**kw):
            count[0]+=1
            if count[0]>2:raise OSError('PRIVATE')
        routes.configure(late)
        with self.assertRaises(routes.RouteObservationRefusal) as caught:
            routes.validate_routes([None],1,routes.Observation(operation='gateway_status'))
        self.assertEqual(caught.exception.reason,'routes_schema')
        self.assertFalse(caught.exception.route_observation['facts']['row_is_dict'])
        self.assertTrue(caught.exception.publication_unavailable)
        self.assertEqual(routes.safe_record(dict(role=None,operation='gateway_status',reason='routes_schema',facts={},PRIVATE='PRIVATE')),{})
        for field,value in [('route_index',True),('observed_type','PRIVATE'),('field_id','PRIVATE'),('keys_known',1)]:
            self.assertEqual(routes.safe_record(dict(role=None,operation='gateway_status',reason='routes_schema',facts={field:value})),{})

    def test_origin_status_before_decode_and_schema_path_query(self):
        for reason,code,body in [('status',503,b'PRIVATE'),('origin_json',200,b'PRIVATE'),('origin_schema',200,b'{}')]:
            def request(*args,**kwargs):return code,{},body
            # Health responses need to pass before the origin stage.
            def producer(*args,**kwargs):return (200,{},b'ok') if kwargs['operation']=='health' else request()
            with self.assertRaises(routes.RouteObservationRefusal) as caught:
                routes.observe(self.status(),self.state(),1,self.context,producer)
            self.assertEqual(caught.exception.reason,reason)
        base={k:None for k in routes.ORIGIN_KEYS};base.update(urlOrigin='https://route.test:1',requestUrlOrigin='https://route.test:1',requestPath='/__qualification/origin',requestSearch='?probe=public-origin')
        for field,value,reason in [('urlOrigin','foreign','origin_equality'),('requestPath','/other','origin_path'),('requestSearch','?other','origin_query')]:
            body=json.dumps(dict(base,**{field:value})).encode()
            def producer(*args,**kwargs):return (200,{},b'ok') if kwargs['operation']=='health' else (200,{},body)
            with self.assertRaises(routes.RouteObservationRefusal) as caught:routes.observe(self.status(),self.state(),1,self.context,producer)
            self.assertEqual(caught.exception.reason,reason)
    def test_websocket_bad_accept_and_wrong_status(self):
        self.refused('websocket_accept',b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: PRIVATE\r\n\r\n',websocket=True,operation='websocket',token='PRIVATE_TOKEN')
        self.refused('websocket_status',b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',websocket=True,operation='websocket',token='PRIVATE_TOKEN')
    def test_late_publication_preserves_primary_and_outer_projection(self):
        from qualification_refusal import project
        routes.configure(lambda *a,**kw:(_ for _ in ()).throw(OSError('PRIVATE')))
        with self.assertRaises(routes.RouteObservationRefusal) as caught:
            routes.Observation('api','health').gate(False,'status',http_status=503,status_observed=True)
        projected=project(caught.exception,'runtime_profile')
        self.assertEqual(projected['reason_id'],'route_observation_status')
        self.assertTrue(projected['route_observation']['publication_unavailable'])
        self.assertNotIn('PRIVATE',json.dumps(projected))

    def test_vite_failures_context_races_and_outer_real_child(self):
        origin={k:None for k in routes.ORIGIN_KEYS};origin.update(urlOrigin='https://route.test:1',requestUrlOrigin='https://route.test:1',requestPath='/__qualification/origin',requestSearch='?probe=public-origin')
        cases=[({},b'\xff','utf8'),({'content-encoding':'gzip'},b'PRIVATE','vite_encoding'),
               ({},b'const wsToken="PRIVATE";','vite_endpoint'),({},b'wss 1','vite_token')]
        for headers,body,reason in cases:
            def producer(*args,**kwargs):
                if kwargs['operation']=='health':return 200,{},b'ok'
                if kwargs['operation']=='origin':return 200,{},json.dumps(origin).encode()
                return 200,headers,body
            with self.assertRaises(routes.RouteObservationRefusal) as caught:routes.observe(self.status(),self.state(),1,self.context,producer)
            self.assertEqual(caught.exception.reason,reason)
        root=self.root
        status={'private':True,'gateway_dir':str(root),'client_ca_file':str(root/'ca/rootCA.pem'),'https_addr':'127.0.0.1:1'}
        state=self.state();current=self.state();current['api']['generation']='changed'
        with self.assertRaises(routes.RouteObservationRefusal) as caught:routes.context_gate(status,root,1,state,current)
        self.assertEqual(caught.exception.reason,'context_changed')
        code="from route_observation import Observation; from qualification_refusal import project; import json,sys\ntry: Observation('api','health').gate(False,'status',http_status=503)\nexcept Exception as error: print(json.dumps(project(error,'runtime_profile')),file=sys.stderr);sys.exit(1)"
        result=subprocess.run([sys.executable,'-c',code],cwd=Path(__file__).parent,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),capture_output=True,timeout=5)
        retained=routes.outer_refusals(result.stderr.decode())
        self.assertTrue(retained['typed_failure_available'])
        self.assertEqual(retained['records'][0]['reason_id'],'route_observation_status')
        self.assertEqual(retained['records'][0]['route_observation']['facts']['http_status'],503)
        self.assertNotIn('PRIVATE',json.dumps(retained))

    def test_actual_runtime_observer_native_caller_and_projection_privacy(self):
        server=self.server(self.producer)
        ca=self.root/'ca';ca.mkdir(exist_ok=True)
        (ca/'rootCA.pem').write_bytes(self.cert.read_bytes());(ca/'rootCA.pem').chmod(0o600)
        value={key:None for key in routes.STATUS_KEYS}
        value.update(schema='effigy.gateway.status.v1',schema_version=1,ok=True,running=True,private=True,
                     gateway_dir=str(self.root),client_ca_file=str(ca/'rootCA.pem'),https_addr='127.0.0.1:'+str(server.port),**self.status())
        value['routes']=[dict(dict(domain='',target=None,dns_ip=None,tcp_port=None,tcp_target=None,source='task',project='control',tls=True,cert_ready=True,registered='2026-10-15T00:00:00Z'),**row) for row in value['routes']]
        value['routes'].append(dict(value['routes'][0],domain='alias.test',target=None,dns_ip='127.0.0.1',tcp_port=5432,tcp_target='127.0.0.1:5432',tls=False,cert_ready=False,source='manual'))
        value['route_count']=len(value['routes'])
        envelope={key:None for key in routes.ENVELOPE_KEYS};envelope.update(schema='effigy.command.v1',schema_version=1,ok=True,result=value)
        producer=self.root/'gateway-fixture'
        producer.write_text('#!'+sys.executable+'\nprint('+repr(json.dumps(envelope))+')\n');producer.chmod(0o700)
        spec=importlib.util.spec_from_file_location('route_runtime_caller',Path(__file__).with_name('qualify-reference-runtime.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.EFFIGY=str(producer)
        with patch.object(module.REFERENCE,'managed_listener_state',side_effect=lambda checkout,role,**kwargs:(None,self.state()[role])):
            module.observe_routes(self.root,self.root,dict(os.environ),self.state(),server.port)
        # The exact family cannot publish arbitrary fields or values through the outer filter.
        from qualification_refusal import project
        record={'role':'api','operation':'health','reason':'status','facts':{'http_status':500,'url':'PRIVATE','content_type_class':'PRIVATE'}}
        error=routes.RouteObservationRefusal('status',record)
        self.assertNotIn('facts',project(error,'runtime_profile').get('route_observation',{}))


if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(60)
    unittest.main()
