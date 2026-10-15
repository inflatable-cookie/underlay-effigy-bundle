"""Private route qualification. Payload stays in memory; evidence is closed."""
import base64
import hashlib
import json
import re
import socket
import ssl
import time
from contextlib import contextmanager

REASONS = frozenset(('native_exit','envelope_json','envelope_shape','routes_schema','state_schema',
 'route_absent','route_target','route_certificate','ca_context','connect','tls_verify','tls','send',
 'header_cap','header_eof','header_shape','framing','body_cap','body_eof','deadline','status','utf8',
 'origin_json','origin_schema','origin_equality','origin_path','origin_query','vite_encoding',
 'vite_endpoint','vite_token','websocket_accept','websocket_status','context_changed','unknown'))
OPERATIONS = frozenset(('gateway_status','ca','route','health','origin','vite','websocket','https'))
EMIT = None
FACT_KEYS=frozenset(('status_observed','headers_complete','body_complete','header_bytes','body_bytes','publication_available',
 'native_exit','stdout_bytes','stderr_bytes','stdout_eof','stderr_eof','envelope_valid','status_schema_valid','route_count',
 'domains_unique','ca_available','verification_required','name_verification','tls_verified','tls_verify_code',
 'connection_established','request_sent','status_line_valid','http_status','header_count','content_type_class',
 'accept_matches','duplicate_framing','ambiguous_length','transfer_supported','body_over_limit','declared_body_bytes',
 'trailers_present','extra_bytes_present','wire_over_limit','transport_error','external_error','state_available',
 'route_present','target_matches','certificate_ready','json_valid','origin_schema_valid','event_origin_matches',
 'request_origin_matches','path_matches','query_matches','encoding_supported','utf8_valid','token_match_count',
 'body_limit_bytes','header_limit_bytes','header_limit_count','token_present','gateway_port_advertised','wss_advertised','context_matches','generation_matches'))
ENVELOPE_KEYS=frozenset(('schema','schema_version','ok','binary','command','result','error'))
STATUS_KEYS=frozenset(('schema','schema_version','ok','running','pid','binary_version','current_binary_version','dns_addr',
 'proxy_addr','https_addr','client_ca_file','private','gateway_dir','tls','route_table_trust','route_table_trust_reason',
 'route_count','tcp_bind_conflict_count','tcp_bind_conflicts','routes'))
ROUTE_KEYS=frozenset(('domain','target','dns_ip','tcp_port','tcp_target','source','project','tls','cert_ready','registered'))


def safe_record(record):
    if type(record) is not dict:return {}
    role=record.get('role');operation=record.get('operation');reason=record.get('reason')
    if role not in (None,'api','front','admin') or type(operation) is not str or operation not in OPERATIONS or type(reason) is not str or reason not in REASONS:return {}
    facts={}
    source=record.get('facts',{})
    if type(source) is not dict:source={}
    for key,value in source.items():
        if key in FACT_KEYS and (type(value) is bool or value is None or type(value) is int and -128<=value<=2**64-1):facts[key]=value
        if key=='content_type_class' and value in ('json','javascript','html','other'):facts[key]=value
    return {'schema':'underlay.route-observation.v1','role':role,'role_known':role is not None,'operation':operation,
            'reason':reason,'facts':facts,'elapsed_ms':record.get('elapsed_ms') if type(record.get('elapsed_ms')) is int else None,
            'signal_authority':False,'remote_cancellation_verified':False}

HEADER_CAP=16384
BODY_CAP=1048576
ORIGIN_CAP=65536
ORIGIN_KEYS=frozenset(('urlOrigin','requestUrl','requestUrlOrigin','requestPath','requestSearch','method',
                       'host','origin','forwardedProto','forwardedHost'))


def configure(emit):
    global EMIT
    EMIT=emit


class RouteObservationRefusal(RuntimeError):
    def __init__(self, reason, record):
        if reason not in REASONS:raise ValueError('unqualified_route_reason')
        super().__init__('route_observation_'+reason)
        self.reason=reason
        self.route_observation=safe_record(record)
        self.publication_unavailable=False


class Observation:
    def __init__(self, role=None, operation='https'):
        if role not in (None,'api','front','admin') or operation not in OPERATIONS:
            raise ValueError('unqualified_route_context')
        import qualification_batch
        self.role=role;self.operation=operation
        self.started=time.monotonic();self.deadline=self.started+qualification_batch.cap(8)
        self.facts={'status_observed':False,'headers_complete':False,'body_complete':False,
                    'header_bytes':0,'body_bytes':0,'publication_available':True,'header_limit_bytes':HEADER_CAP,'header_limit_count':32}

    def remaining(self):
        value=self.deadline-time.monotonic()
        if value<=0:self.fail('deadline')
        return value

    def record(self,reason='unknown'):
        return {'schema':'underlay.route-observation.v1','role':self.role,'role_known':self.role is not None,
                'operation':self.operation,'reason':reason,'elapsed_ms':round((time.monotonic()-self.started)*1000),
                'facts':safe_record({'role':self.role,'operation':self.operation,'reason':reason,'facts':self.facts})['facts'],'signal_authority':False,'remote_cancellation_verified':False}

    def publish(self,reason='unknown',primary=None):
        record=self.record(reason)
        if EMIT is not None:
            try:EMIT('route_observation',observation=record)
            except BaseException:
                self.facts['publication_available']=False
                if primary is not None:primary.publication_unavailable=True;primary.route_observation=self.record(reason)
                else:raise RouteObservationRefusal('unknown',self.record('unknown')) from None
        return record

    def fail(self,reason,**facts):
        self.facts.update(facts)
        error=RouteObservationRefusal(reason,self.record(reason))
        self.publish(reason,error)
        raise error from None

    def gate(self,condition,reason,**facts):
        self.facts.update(facts)
        if not condition:self.fail(reason)
        self.remaining()
        self.publish(reason)
        self.remaining()


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate')
        result[key]=value
    return result


def decode_json(raw,observation,reason):
    try:return json.loads(raw.decode('utf-8') if isinstance(raw,bytes) else raw,object_pairs_hook=unique)
    except (ValueError,UnicodeError,TypeError):observation.fail(reason,json_valid=False)


def gateway_status(completed, o=None):
    o=o or Observation(operation='gateway_status')
    o.gate(completed.returncode==0,'native_exit',native_exit=completed.returncode,
           stdout_bytes=len(completed.stdout.encode()),stderr_bytes=len(completed.stderr.encode()))
    envelope=decode_json(completed.stdout,o,'envelope_json')
    o.gate(type(envelope) is dict and set(envelope)==ENVELOPE_KEYS and envelope.get('schema')=='effigy.command.v1' and type(envelope.get('schema_version')) is int and envelope.get('schema_version')==1 and envelope.get('ok') is True and type(envelope.get('result')) is dict,
           'envelope_shape',envelope_valid=type(envelope) is dict)
    status=envelope['result']
    o.gate(set(status)==STATUS_KEYS and status.get('schema')=='effigy.gateway.status.v1' and type(status.get('schema_version')) is int and status.get('schema_version')==1
           and status.get('ok') is True and status.get('running') is True and type(status.get('routes')) is list,
           'envelope_shape',status_schema_valid=status.get('schema')=='effigy.gateway.status.v1')
    routes=status['routes']
    valid=len(routes)<=256 and all(type(r) is dict and set(r)==ROUTE_KEYS and type(r.get('domain')) is str
        and type(r.get('target')) is str and type(r.get('cert_ready')) is bool for r in routes)
    o.gate(valid,'routes_schema',route_count=len(routes))
    o.gate(len({r['domain'] for r in routes})==len(routes),'routes_schema',domains_unique=len({r['domain'] for r in routes})==len(routes))
    return status


def ca_context(path):
    o=Observation(operation='ca')
    try:context=ssl.create_default_context(cafile=str(path))
    except (OSError,ssl.SSLError):o.fail('ca_context',ca_available=False)
    o.gate(context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname,'ca_context',
           ca_available=True,verification_required=context.verify_mode==ssl.CERT_REQUIRED,
           name_verification=context.check_hostname)
    return context


class Wire:
    def __init__(self,sock,o):self.sock=sock;self.o=o;self.buffer=bytearray();self.wire_bytes=0
    def recv(self):
        self.sock.settimeout(self.o.remaining())
        try:b=self.sock.recv(8192)
        except (TimeoutError,socket.timeout):self.o.fail('deadline')
        except (OSError,ssl.SSLError):self.o.fail('body_eof' if self.o.facts['headers_complete'] else 'header_eof',transport_error=True)
        self.wire_bytes+=len(b)
        if self.wire_bytes>BODY_CAP*2+HEADER_CAP:self.o.fail('body_cap',wire_over_limit=True)
        self.buffer.extend(b);return bool(b)
    def line(self,cap,reason):
        while b'\r\n' not in self.buffer:
            if len(self.buffer)>cap:self.o.fail(reason)
            if not self.recv():self.o.fail('header_eof' if reason=='header_cap' else 'body_eof',header_bytes=self.o.facts['header_bytes']+len(self.buffer))
        at=self.buffer.index(b'\r\n')
        if at>cap:self.o.fail(reason)
        line=bytes(self.buffer[:at]);del self.buffer[:at+2]
        if not self.o.facts['headers_complete']:self.o.facts['header_bytes']+=at+2
        return line
    def exact(self,n,body=False):
        while len(self.buffer)<n:
            if not self.recv():self.o.fail('body_eof',body_complete=False,body_bytes=self.o.facts['body_bytes']+(min(len(self.buffer),n) if body else 0))
        data=bytes(self.buffer[:n]);del self.buffer[:n]
        if body:self.o.facts['body_bytes']+=n
        return data


def exchange(host,port,context,path,headers=None,*,role=None,operation='https',body_cap=BODY_CAP,websocket=False,token='',observation=None):
    o=observation or Observation(role,operation)
    o.gate(context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname,'ca_context',verification_required=context.verify_mode==ssl.CERT_REQUIRED,name_verification=context.check_hostname)
    o.gate(type(body_cap) is int and 0<body_cap<=BODY_CAP,'body_cap')
    o.facts['body_limit_bytes']=body_cap
    raw=None;sock=None
    try:
        try:raw=socket.create_connection(('127.0.0.1',port),timeout=o.remaining())
        except (TimeoutError,socket.timeout):o.fail('deadline')
        except OSError:o.fail('connect',connection_established=False)
        try:
            raw.settimeout(o.remaining());sock=context.wrap_socket(raw,server_hostname=host)
        except ssl.SSLCertVerificationError as error:o.fail('tls_verify',tls_verified=False,tls_verify_code=error.verify_code)
        except (TimeoutError,socket.timeout):o.fail('deadline')
        except (OSError,ssl.SSLError):o.fail('tls',tls_verified=False)
        o.facts['tls_verified']=True
        request_headers=dict(headers or {})
        request_headers.setdefault('Host',f'{host}:{port}')
        key=''
        if websocket:
            import os
            key=base64.b64encode(os.urandom(16)).decode('ascii')
            path='/?token='+token
            request_headers.update({'Connection':'Upgrade','Upgrade':'websocket','Sec-WebSocket-Key':key,
                'Sec-WebSocket-Version':'13','Sec-WebSocket-Protocol':'vite-hmr'})
        else:request_headers.setdefault('Connection','close')
        if any('\r' in str(x) or '\n' in str(x) for x in [path,*request_headers,*request_headers.values()]):o.fail('header_shape')
        request=('GET '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in request_headers.items())+'\r\n').encode('ascii')
        try:sock.settimeout(o.remaining());sock.sendall(request)
        except (TimeoutError,socket.timeout):o.fail('deadline')
        except OSError:o.fail('send',request_sent=False)
        wire=Wire(sock,o);first=wire.line(HEADER_CAP,'header_cap');used=len(first)+2
        match=re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?',first)
        o.gate(match is not None,'header_shape',status_line_valid=match is not None)
        code=int(match.group(1));o.facts.update(status_observed=True,http_status=code)
        response={};count=0
        while True:
            line=wire.line(HEADER_CAP,'header_cap');used+=len(line)+2
            if used>HEADER_CAP:o.fail('header_cap',header_bytes=used)
            if not line:break
            count+=1
            if count>32:o.fail('header_cap',header_count=count)
            m=re.fullmatch(rb'([!#$%&\x27*+.^_`|~0-9A-Za-z-]+):[ \t]*([^\r\n]*)',line)
            if not m:o.fail('header_shape',header_count=count)
            name=m.group(1).decode('ascii').lower();value=m.group(2).decode('latin1').strip()
            if name in response and name in ('content-length','transfer-encoding','content-type','sec-websocket-accept','upgrade'):
                o.fail('framing',duplicate_framing=True)
            response[name]=value
        o.facts.update(headers_complete=True,header_bytes=used,header_count=count)
        ct=response.get('content-type','').split(';')[0].strip().lower()
        o.facts['content_type_class']='json' if ct=='application/json' else 'javascript' if ct in ('text/javascript','application/javascript') else 'html' if ct=='text/html' else 'other'
        if websocket:
            o.gate(code==101,'websocket_status',http_status=code)
            expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            o.gate(response.get('sec-websocket-accept')==expected and response.get('upgrade','').lower()=='websocket',
                   'websocket_accept',accept_matches=response.get('sec-websocket-accept')==expected)
            o.facts.update(body_complete=True,body_bytes=0);o.publish('websocket_status');o.remaining()
            return code,response,b''
        length=response.get('content-length');transfer=response.get('transfer-encoding')
        if length is not None and transfer is not None:o.fail('framing',ambiguous_length=True)
        body=bytearray()
        if transfer is not None:
            if transfer.lower()!='chunked':o.fail('framing',transfer_supported=False)
            while True:
                line=wire.line(128,'framing')
                if not re.fullmatch(rb'[0-9A-Fa-f]{1,8}',line):o.fail('framing')
                size=int(line,16)
                if len(body)+size>body_cap:o.fail('body_cap',body_bytes=len(body),body_over_limit=True)
                if size==0:
                    if wire.line(128,'framing')!=b'':o.fail('framing',trailers_present=True)
                    break
                body.extend(wire.exact(size,body=True))
                if wire.exact(2)!=b'\r\n':o.fail('framing')
        elif length is not None:
            if not re.fullmatch(r'[0-9]{1,10}',length):o.fail('framing')
            size=int(length)
            if size>body_cap:o.fail('body_cap',declared_body_bytes=size,body_over_limit=True)
            body.extend(wire.exact(size,body=True))
        else:
            while True:
                body.extend(wire.buffer);wire.buffer.clear();o.facts['body_bytes']=len(body)
                if len(body)>body_cap:o.fail('body_cap',body_bytes=len(body),body_over_limit=True)
                if not wire.recv():break
        if wire.buffer:o.fail('framing',extra_bytes_present=True)
        o.facts.update(body_complete=True,body_bytes=len(body))
        o.publish('status');o.remaining()
        return code,response,bytes(body)
    except RouteObservationRefusal:raise
    except Exception:
        o.fail('unknown',external_error=True)
    finally:
        for connection in (sock,raw):
            if connection is not None:
                try:connection.close()
                except OSError:pass


def require_status(code,o):o.gate(code==200,'status',status_observed=True,http_status=code)


def observe(status,states,port,context,request=exchange):
    routes={r['domain']:r for r in status['routes']}
    for role in ('api','front','admin'):
        o=Observation(role,'route');state=states.get(role)
        o.gate(type(state) is dict and all(type(state.get(k)) is str and state[k] for k in ('route_domain','address','generation')),
               'state_schema',state_available=type(state) is dict)
        route=routes.get(state['route_domain'])
        o.gate(route is not None,'route_absent',route_present=route is not None)
        o.gate(route['target']==state['address'],'route_target',target_matches=route['target']==state['address'])
        o.gate(route['cert_ready'] is True,'route_certificate',certificate_ready=route['cert_ready'] is True)
        o=Observation(role,'health')
        code,_,_=request(state['route_domain'],port,context,'/v1/health' if role=='api' else '/',role=role,operation='health',observation=o)
        require_status(code,o)
    for role in ('front','admin'):
        state=states[role];domain=state['route_domain'];origin=f'https://{domain}:{port}'
        observe_origin(state,port,context,role,request)
        o=Observation(role,'vite')
        code,headers,body=request(domain,port,context,'/@vite/client',role=role,operation='vite',observation=o)
        require_status(code,o)
        o.gate(headers.get('content-encoding','identity').lower()=='identity','vite_encoding',encoding_supported=headers.get('content-encoding','identity').lower()=='identity')
        try:client=body.decode('utf-8')
        except UnicodeError:o.fail('utf8',utf8_valid=False)
        tokens=re.findall(r'(?:wsToken|token)\s*[:=]\s*[\x27\"]([^\x27\"]*)[\x27\"]',client)
        o.gate(len(tokens)==1 and re.fullmatch(r'[A-Za-z0-9_-]{1,256}',tokens[0]) is not None,'vite_token',token_match_count=len(tokens),token_present=bool(tokens))
        o.gate(str(port) in client and 'wss' in client,'vite_endpoint',gateway_port_advertised=str(port) in client,wss_advertised='wss' in client)
        request(domain,port,context,'/',role=role,operation='websocket',websocket=True,token=tokens[0])
        o.remaining()


def native_status(args,cwd,env):
    from reference_compile_capture import capture
    from types import SimpleNamespace
    o=Observation(operation='gateway_status');payload=[]
    result=capture(args,cwd=cwd,env=env,timeout=o.remaining(),
        limits={'stdout':65536,'stderr':16384},payload_sink=lambda out,err:payload.append((out,err)))
    if EMIT is not None:
        try:EMIT('route_native_capture',operation='gateway_status',capture=result)
        except BaseException:
            if result['exit']!=0 or result['refusal'] is not None:
                o.facts['publication_available']=False
                o.fail('native_exit',native_exit=result['exit'])
            raise RouteObservationRefusal('unknown',o.record()) from None
    o.gate(result['exit']==0 and result['refusal'] is None and result['identity_admitted'] and result['leader_reaped']
        and all(result[k]['eof'] for k in ('stdout','stderr')),'native_exit',native_exit=result['exit'],
        stdout_bytes=result['stdout']['read_bytes'],stderr_bytes=result['stderr']['read_bytes'],
        stdout_eof=result['stdout']['eof'],stderr_eof=result['stderr']['eof'])
    try:out,err=(x.decode('utf-8') for x in payload[0])
    except UnicodeError:o.fail('utf8',utf8_valid=False)
    return gateway_status(SimpleNamespace(returncode=result['exit'],stdout=out,stderr=err),o)


def context_gate(status,gateway_root,port,states,current=None):
    o=Observation(operation='gateway_status')
    o.gate(status.get('private') is True and status.get('gateway_dir')==str(gateway_root)
        and status.get('client_ca_file')==str(gateway_root/'ca/rootCA.pem')
        and status.get('https_addr')=='127.0.0.1:'+str(port),'context_changed',
        context_matches=status.get('private') is True and status.get('gateway_dir')==str(gateway_root)
        and status.get('client_ca_file')==str(gateway_root/'ca/rootCA.pem') and status.get('https_addr')=='127.0.0.1:'+str(port))
    if current is not None:
        for role in ('api','front','admin'):
            o=Observation(role,'route')
            o.gate(all(current[role].get(k)==states[role].get(k) for k in
                   ('generation','runtime_generation','address','route_domain','route_owner')),
                   'context_changed',generation_matches=current[role].get('generation')==states[role].get('generation'))


def outer_refusals(stderr):
    """Consume the real qualifier's closed stderr projection, never raw lines."""
    records=[];omitted=0
    for line in stderr.splitlines():
        try:value=json.loads(line,object_pairs_hook=unique)
        except (ValueError,TypeError):omitted+=1;continue
        if type(value) is not dict or value.get('schema')!='underlay.qualification.refusal.v1':
            omitted+=1;continue
        from dev.startup_evidence import validate as native_record
        native=native_record(value.get('native_failure'))
        if native and value.get('reason_id')=='native_'+native['reason']:
            records.append({'schema':'underlay.qualification.refusal.v1','reason_id':value['reason_id'],
                            'native_failure':native})
            continue
        route=safe_record(value.get('route_observation'))
        if not route or value.get('reason_id')!='route_observation_'+route['reason']:
            omitted+=1;continue
        records.append({'schema':'underlay.qualification.refusal.v1','reason_id':value['reason_id'],
                        'route_observation':route,'capture_available':value.get('capture_available') is True,
                        'publication_unavailable':value.get('route_observation',{}).get('publication_unavailable') is True})
    return {'records':records[-8:],'records_omitted':max(0,len(records)-8),'unclassified_lines':omitted,
            'typed_failure_available':bool(records)}


def observe_origin(state,port,context,role,request=exchange):
    domain=state['route_domain'];origin=f'https://{domain}:{port}'
    o=Observation(role,'origin')
    code,headers,body=request(domain,port,context,'/__qualification/origin?probe=public-origin',
         {'Host':f'{domain}:{port}','Origin':origin},role=role,operation='origin',body_cap=ORIGIN_CAP,observation=o)
    require_status(code,o)  # The observed HTTP failure must precede JSON parsing.
    value=decode_json(body,o,'origin_json')
    o.gate(type(value) is dict and set(value)==ORIGIN_KEYS and all(type(value[k]) is str or value[k] is None for k in value),
           'origin_schema',origin_schema_valid=type(value) is dict and set(value)==ORIGIN_KEYS)
    o.gate(value['urlOrigin']==origin and value['requestUrlOrigin']==origin,'origin_equality',
           event_origin_matches=value['urlOrigin']==origin,request_origin_matches=value['requestUrlOrigin']==origin)
    o.gate(value['requestPath']=='/__qualification/origin','origin_path',path_matches=value['requestPath']=='/__qualification/origin')
    o.gate(value['requestSearch']=='?probe=public-origin','origin_query',query_matches=value['requestSearch']=='?probe=public-origin')
    o.remaining()
