"""Qualification-only auth client. Secrets cross inherited memory/private pipes only."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import ssl
import stat
import time

AUTH_SECONDS = 20.0
HEADER_CAP = 16384
BODY_CAP = 65536
STDOUT_CAP = 98304
STDERR_CAP = 16384
POST_SECONDS = 3.0
PHASES = {'prepare', 'connect', 'tls', 'send', 'headers', 'body', 'decode', 'complete'}
REASONS = {'deadline', 'transport', 'headers', 'body', 'schema', 'http_status',
           'capture_limit', 'capture_read', 'child', 'group_unknown', 'protocol'}


class AuthRefusal(RuntimeError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else 'protocol'
        super().__init__('auth_operation_' + self.reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuthRefusal('schema')
        result[key] = value
    return result


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise AuthRefusal('deadline')
    return value


def transport(domain, port, ca, operation, payload, origin, deadline, phase):
    """Every socket operation uses the remaining whole-operation allowance."""
    phase('prepare')
    if operation not in ('register', 'login') or not re.fullmatch(r'[a-z0-9.-]{1,253}', domain):
        raise AuthRefusal('protocol')
    body = json.dumps(payload, allow_nan=False).encode()
    if len(body) > BODY_CAP or '\r' in origin or '\n' in origin:
        raise AuthRefusal('protocol')
    context = ssl.create_default_context(cafile=str(ca))
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise AuthRefusal('protocol')
    remaining(deadline)
    phase('connect')
    raw = socket.create_connection(('127.0.0.1', port), remaining(deadline))
    try:
        phase('tls')
        raw.settimeout(remaining(deadline))
        connection = context.wrap_socket(raw, server_hostname=domain)
        with connection:
            phase('send')
            request = (f'POST /v1/auth/{operation} HTTP/1.1\r\nHost: {domain}:{port}\r\n'
                       f'Origin: {origin}\r\nContent-Type: application/json\r\n'
                       f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body
            connection.settimeout(remaining(deadline)); connection.sendall(request)
            phase('headers')
            header = bytearray()
            # Bytewise header collection prevents body bytes consuming header credit.
            while not header.endswith(b'\r\n\r\n'):
                connection.settimeout(remaining(deadline))
                chunk = connection.recv(1)
                if not chunk or len(header) >= HEADER_CAP:
                    raise AuthRefusal('headers')
                header.extend(chunk)
            try:
                lines = bytes(header[:-4]).decode('ascii').split('\r\n')
                if not re.fullmatch(r'HTTP/1\.[01] [1-5][0-9]{2} [\x20-\x7e]*', lines[0]):
                    raise AuthRefusal('headers')
                status = int(lines[0].split(' ')[1])
                if len(lines) - 1 > 32:
                    raise AuthRefusal('headers')
                fields = {}; cookies = set()
                for line in lines[1:]:
                    key, value = line.split(':', 1)
                    key = key.lower()
                    if not re.fullmatch(r'[a-z0-9-]+', key) or (key in fields and key != 'set-cookie') or any(ord(c) < 32 for c in value):
                        raise AuthRefusal('headers')
                    if key == 'set-cookie':
                        # Reviewed set_auth_cookies appends two distinct cookie identities.
                        # Repeatable field, never duplicate cookie/framing authority.
                        cookie = value.strip().split('=',1)[0]
                        if not re.fullmatch(r'[a-zA-Z0-9_-]+',cookie) or cookie in cookies or len(cookies)>=2:
                            raise AuthRefusal('headers')
                        cookies.add(cookie)
                    fields[key] = value.strip()
                if 'transfer-encoding' in fields or not re.fullmatch(r'0|[1-9][0-9]{0,5}', fields.get('content-length', '')):
                    raise AuthRefusal('headers')
                length = int(fields['content-length'])
                if not 0 < length <= BODY_CAP or fields.get('content-type', '').split(';')[0] != 'application/json':
                    raise AuthRefusal('body')
            except (ValueError, UnicodeError):
                raise AuthRefusal('headers') from None
            if not 200 <= status < 300:
                raise AuthRefusal('http_status')
            phase('body')
            received = bytearray()
            while len(received) < length:
                connection.settimeout(remaining(deadline))
                chunk = connection.recv(min(4096, length - len(received)))
                if not chunk:
                    raise AuthRefusal('body')
                received.extend(chunk)
            phase('decode')
            try:
                result = json.loads(received, object_pairs_hook=unique,
                                    parse_constant=lambda _: (_ for _ in ()).throw(AuthRefusal('schema')))
            except (ValueError, UnicodeError, RecursionError):
                raise AuthRefusal('schema') from None
            session_schema(result, operation, payload)
            remaining(deadline)
            phase('complete')
            return result
    finally:
        raw.close()


def session_schema(result, operation, payload):
    uuid = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    if not isinstance(result,dict) or set(result) != {'data'} or not isinstance(result['data'],dict):
        raise AuthRefusal('schema')
    data=result['data']
    if not {'user','session_id','access_token'} <= set(data) <= {'user','session_id','access_token','refresh_token'}:
        raise AuthRefusal('schema')
    if (not isinstance(data['access_token'],str) or not data['access_token']
            or not isinstance(data['session_id'],str) or not re.fullmatch(uuid,data['session_id'])
            or ('refresh_token' in data and (not isinstance(data['refresh_token'],str) or not data['refresh_token']))):
        raise AuthRefusal('schema')
    user=data['user']
    if (not isinstance(user,dict) or set(user) != {'user_id','email','display_name','roles'}
            or not isinstance(user['user_id'],str) or not re.fullmatch(uuid,user['user_id'])
            or user['email'] != payload.get('email') or not isinstance(user['display_name'],str)
            or not user['display_name'] or not isinstance(user['roles'],list)
            or not user['roles'] or any(not isinstance(role,str) for role in user['roles'])
            or len(set(user['roles'])) != len(user['roles'])
            or ('admin' if operation=='login' else 'user') not in user['roles']):
        raise AuthRefusal('schema')


def terminate_owned(pid):
    # pid is an unreaped direct fork child; never infer identity from a stale file.
    try:
        if os.getpgid(pid) != pid or os.getsid(pid) != pid:
            raise AuthRefusal('group_unknown')
    except ProcessLookupError:
        return 'leader_unobservable'
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return 'group_unobservable'
    time.sleep(.05)
    try:
        if os.getpgid(pid) != pid or os.getsid(pid) != pid:
            raise AuthRefusal('group_unknown')
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return 'leader_unobservable_after_term'
    return 'owned_signals'


def isolated(call, budget, emit):
    """Private IPC is bounded before reads; no private output is journaled."""
    started = time.monotonic(); deadline = started + budget
    gate_r, gate_w = os.pipe(); out_r, out_w = os.pipe(); err_r, err_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(gate_w); os.close(out_r); os.close(err_r)
            os.setsid()
            os.dup2(out_w, 1); os.dup2(err_w, 2)
            os.write(out_w, b'{"kind":"gate"}\n')
            if os.read(gate_r, 1) != b'G':
                os._exit(1)
            def phase(value):
                os.write(out_w, (json.dumps({'kind':'phase', 'phase':value})+'\n').encode())
            try:
                result = call(deadline, phase)
                remaining(deadline)
                message = {'kind':'result', 'data':result}
                code = 0
            except TimeoutError:
                message = {'kind':'refusal', 'reason':'deadline'}; code = 1
            except AuthRefusal as error:
                message = {'kind':'refusal', 'reason':error.reason}; code = 1
            except BaseException:
                message = {'kind':'refusal', 'reason':'transport'}; code = 1
            os.write(out_w, (json.dumps(message, allow_nan=False)+'\n').encode())
            os._exit(code)
        except BaseException:
            os._exit(1)
    os.close(gate_r); os.close(out_w); os.close(err_w)
    streams = selectors.DefaultSelector()
    counts = {'stdout':0, 'stderr':0}; buffers = {'stdout':bytearray(), 'stderr':bytearray()}
    for fd, name in ((out_r,'stdout'), (err_r,'stderr')):
        os.set_blocking(fd, False); streams.register(fd, selectors.EVENT_READ, name)
    reason = None; result = None; seen = []; gate = False; terminal = False; reaped = False
    try:
        while streams.get_map():
            remaining(deadline)
            for key, _ in streams.select(min(.05, remaining(deadline))):
                try: chunk = os.read(key.fd, 4096)
                except OSError: raise AuthRefusal('capture_read') from None
                if not chunk:
                    streams.unregister(key.fd); continue
                name = key.data; counts[name] += len(chunk)
                if counts[name] > (STDOUT_CAP if name == 'stdout' else STDERR_CAP):
                    raise AuthRefusal('capture_limit')
                buffers[name].extend(chunk)
                if name == 'stderr':
                    continue
                while b'\n' in buffers[name]:
                    line, _, rest = buffers[name].partition(b'\n'); buffers[name] = bytearray(rest)
                    try: value = json.loads(line, object_pairs_hook=unique)
                    except (ValueError, UnicodeError, RecursionError): raise AuthRefusal('protocol') from None
                    if value == {'kind':'gate'} and not gate:
                        if os.getpgid(pid) != pid or os.getsid(pid) != pid:
                            raise AuthRefusal('group_unknown')
                        emit('client_intent', pid=pid, group=pid, session=pid,
                             new_unreaped_child=True, budget_ms=int(budget*1000))
                        remaining(deadline)
                        os.write(gate_w, b'G'); os.close(gate_w); gate_w = None; gate = True
                    elif (gate and not terminal and set(value) == {'kind','phase'} and value['kind'] == 'phase'
                          and value['phase'] in PHASES and value['phase'] not in seen):
                        seen.append(value['phase']); emit('client_phase', phase=value['phase'], elapsed_ms=int((time.monotonic()-started)*1000))
                    elif gate and not terminal and set(value) == {'kind','data'} and value['kind'] == 'result':
                        terminal = True; result = value['data']
                    elif gate and not terminal and set(value) == {'kind','reason'} and value['kind'] == 'refusal' and value['reason'] in REASONS:
                        terminal = True; reason = value['reason']
                    else:
                        raise AuthRefusal('protocol')
        # WNOHANG is used only after EOF; once reaped, no signal may follow.
        while True:
            remaining(deadline)
            child, status = os.waitpid(pid, os.WNOHANG)
            if child:
                reaped = True; break
            time.sleep(min(.005, remaining(deadline)))
        if buffers['stdout'] or counts['stderr'] or not terminal or status != 0 or reason:
            raise AuthRefusal(reason or 'child')
        if seen != ['prepare','connect','tls','send','headers','body','decode','complete']:
            raise AuthRefusal('protocol')
        remaining(deadline)
        emit('client_result', outcome='success', elapsed_ms=int((time.monotonic()-started)*1000),
             stdout_bytes=counts['stdout'], stderr_bytes=counts['stderr'], leader_reaped=True,
             group_absence='not_independently_observed')
        return result
    except BaseException as caught:
        error = caught if isinstance(caught, AuthRefusal) else AuthRefusal('protocol')
        settlement = 'already_reaped'
        if not reaped:
            settlement = terminate_owned(pid)
            # Bounded WNOHANG reap; no reader joins or post-reap signals.
            end = time.monotonic() + 1.0
            while time.monotonic() < end:
                child, _ = os.waitpid(pid, os.WNOHANG)
                if child: reaped = True; break
                time.sleep(.005)
        emit('client_result', outcome=error.reason, elapsed_ms=int((time.monotonic()-started)*1000),
             stdout_bytes=counts['stdout'], stderr_bytes=counts['stderr'], leader_reaped=reaped,
             settlement=settlement, group_absence='not_independently_observed', remote_mutation='uncertain')
        raise error from None
    finally:
        streams.close()
        for fd in (out_r, err_r, gate_w):
            if fd is not None: os.close(fd)


def request(domain, port, ca, operation, payload, origin, emit):
    return isolated(lambda end, phase: transport(domain, port, ca, operation, payload, origin, end, phase), AUTH_SECONDS, emit)


TRACE = re.compile(r'correlation="?fixture-auth-login"?\s+phase="?([a-z_]+)"?\s+elapsed_ms=(\d+)\s+outcome="?([a-z_]+)"?')
SERVER_PHASES = {'api_login_handler','api_login_response','api_login_auth_call','api_login_role_lookup',
                 'auth_verify_spawn','auth_verify_worker','auth_verify_join','auth_rate_limit','auth_user_lookup',
                 'auth_lockout_check','auth_locked_attempt_record','auth_credential_lookup','auth_failed_attempt_write',
                 'auth_failed_attempt_reset','auth_credential_last_used','auth_totp_lookup','auth_session_create'}
OUTCOMES = {'started','ok','error','completed','success','validation_error','auth_error','valid','invalid',
            'join_error','found','not_found','locked','clear','recorded','recorded_and_locked','configured','not_configured'}


def tail(path, root):
    path = Path(path); root = Path(root)
    if root.resolve() != root or path.parent.resolve() != path.parent or not path.is_relative_to(root):
        raise AuthRefusal('protocol')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1:
            raise AuthRefusal('protocol')
        start = max(0, before.st_size - 65536); os.lseek(fd, start, os.SEEK_SET)
        raw = os.read(fd, min(before.st_size,65536))
        if start: raw = raw.partition(b'\n')[2]
        observations = []; keys = set()
        incomplete = bool(raw and not raw.endswith(b'\n'))
        lines = raw.splitlines()
        if incomplete: lines = lines[:-1]
        for line in lines:
            if b'underlay_profile_auth_diagnostic' not in line: continue
            found = TRACE.search(line.decode('utf-8', errors='replace'))
            if not found: raise AuthRefusal('protocol')
            phase, elapsed, outcome = found.groups()
            if phase not in SERVER_PHASES or outcome not in OUTCOMES or len(elapsed)>10:
                raise AuthRefusal('protocol')
            key = (phase,outcome)
            if key in keys: raise AuthRefusal('protocol')
            keys.add(key)
            observations.append({'phase':phase,'outcome':outcome,'elapsed_ms':int(elapsed)})
        return {'available':True,'bytes':len(raw),'digest':hashlib.sha256(raw).hexdigest(),
                'tail_truncated':bool(start), 'incomplete_line':incomplete, 'observations':observations[-16:], 'observation_limit':len(observations)>16}
    finally:
        os.close(fd)


def capture(path, root, emit, *, post=False):
    started = time.monotonic(); end = started + (POST_SECONDS if post else 0)
    latest = None
    while True:
        try: latest = tail(path, root)
        except OSError: latest = {'available':False,'observations':[], 'reason':'file_unavailable'}
        except AuthRefusal:
            emit('server_phase_window', window='post' if post else 'pre', available=False, reason='phase_protocol', observations=[])
            raise
        if not post or any(x['phase']=='api_login_response' for x in latest['observations']) or time.monotonic() >= end:
            break
        time.sleep(min(.05,max(0,end-time.monotonic())))
    emit('server_phase_window', window='post' if post else 'pre', elapsed_ms=int((time.monotonic()-started)*1000),
         **latest, authority='observation_only', clock='server_elapsed_not_client_clock')
