"""Bounded owner-scoped transition observations; never lifecycle authority."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

_sink = None
_root = None
_owners = {}
EVENTS = {'successor_launched', 'child_exited', 'shutdown', 'dependency_unavailable',
          'dependency_tuple_changed', 'inspection_error', 'retention_limit'}
PREDICATES = {'state_file_missing', 'state_file_unreadable', 'state_file_unsafe',
              'state_schema_invalid', 'state_identity_mismatch', 'state_not_ready',
              'route_owner_missing', 'owner_unverified', 'route_not_matching', 'route_table_unreadable'}
KEYS = {'schema', 'sequence', 'event', 'owner', 'runtime_generation', 'supervisor', 'phase',
        'generation', 'predecessor_generation', 'child', 'child_group', 'listener', 'exit',
        'observed_dependencies', 'assignments', 'inspection_error'}
NAMES = {'api', 'front', 'admin', 'interrupted_probe', 'collision_probe'}
MAX_BYTES = 256 * 1024


def configure(sink, root):
    global _sink, _root
    _sink, _root = sink, Path(root).resolve(strict=True)
    _owners.clear()


def _require(ok):
    if not ok:
        raise ValueError('invalid_transition')


def _integer(x):
    return type(x) is int and 0 <= x < 2**63


def _gen(x):
    return isinstance(x, str) and re.fullmatch('[0-9a-f]{32}', x) is not None


def _process(x):
    _require(isinstance(x, dict) and set(x) == {'pid', 'boot_identity', 'start_identity'})
    _require(_integer(x['pid']) and x['pid'] > 0)
    _require(isinstance(x['boot_identity'], str) and re.fullmatch('[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', x['boot_identity']))
    s = x['start_identity']
    _require(isinstance(s, dict))
    if s.get('platform') == 'macos':
        _require(set(s) == {'platform', 'start_seconds', 'start_microseconds'}
                 and _integer(s['start_seconds']) and _integer(s['start_microseconds'])
                 and s['start_microseconds'] < 1000000)
    else:
        _require(set(s) == {'platform', 'start_ticks'} and s.get('platform') == 'linux' and _integer(s['start_ticks']))


def _url(value, public=False):
    _require(isinstance(value, str) and len(value) < 256)
    u = urlsplit(value)
    _require(not u.username and not u.password and not u.query and not u.fragment and u.path in ('', '/'))
    _require(u.scheme == ('https' if public else 'http') and 0 < (u.port or (443 if public else 80)) < 65536)
    _require(bool(re.fullmatch(r'(?:api\.|admin\.)?acme(?:-w[0-9a-f]{8})?\.test', u.hostname or '')) if public else u.hostname == '127.0.0.1')


def _record(r, owner, checkout):
    _require(isinstance(r, dict) and not set(r) - KEYS)
    _require(r.get('schema') in {'effigy.managed.host-transition-evidence.v1', 'effigy.managed.host-transition-evidence.v2'})
    _require(isinstance(owner, str) and r.get('owner') == owner and _gen(r.get('runtime_generation')))
    _require(_integer(r.get('sequence')) and r['sequence'] > 0 and r.get('event') in EVENTS)
    _process(r.get('supervisor'))
    for k in ('generation', 'predecessor_generation'):
        if r.get(k) is not None:
            _require(_gen(r[k]))
    for k in ('child', 'listener'):
        if r.get(k) is not None:
            _process(r[k])
    if r.get('child_group') is not None:
        _require(_integer(r['child_group']) and r['child_group'] == (r.get('child') or {}).get('pid'))
    if r.get('phase') is not None:
        _require(r['phase'] in {'pre_publication', 'published'})
    if r.get('exit') is not None:
        _require(isinstance(r['exit'], dict) and set(r['exit']) == {'code', 'signal'})
        _require(all(v is None or type(v) is int and -2**31 <= v < 2**31 for v in r['exit'].values()))
    if r.get('inspection_error') is not None:
        _require(r['inspection_error'] in {'child_completion', 'dependency_state'})
    if r['event'] != 'retention_limit':
        _require(_gen(r.get('generation')))
        if r['event'] != 'successor_launched':
            _require(r.get('phase') in {'pre_publication', 'published'})
        _require(r.get('child') is not None and r.get('child_group') == r['child']['pid'])
    if r['event'] == 'child_exited':
        _require(r.get('exit') is not None)
    if r['event'] == 'inspection_error':
        _require(r.get('inspection_error') is not None)
    deps = r.get('observed_dependencies', [])
    _require(isinstance(deps, list) and len(deps) <= 3)
    names = set()
    for d in deps:
        _require(isinstance(d, dict) and not set(d) - {'name', 'status', 'tuple_status', 'predicate', 'runtime_generation', 'generation', 'address'})
        _require(d.get('name') in {'api', 'front', 'admin'} and d['name'] not in names)
        names.add(d['name'])
        _require(d.get('status') in {'observed', 'unavailable'})
        if d.get('predicate') is not None:
            _require(d['predicate'] in PREDICATES)
        if r['schema'].endswith('.v2'):
            _require(d.get('tuple_status') in {'observed', 'absent', 'unreadable', 'unavailable'})
            observed = d['tuple_status'] == 'observed'
            _require(observed == (d['status'] == 'observed'))
        else:
            _require('tuple_status' not in d)
            observed = d['status'] == 'observed'
        if observed:
            _require(d.get('predicate') is None)
            _require(_gen(d.get('runtime_generation')) and _gen(d.get('generation'))
                     and isinstance(d.get('address'), str) and re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', d['address'])
                     and 0 < int(d['address'].split(':')[1]) < 65536)
        else:
            if r['schema'].endswith('.v2'):
                marker = d.get('tuple_status')
                required = {'absent': {'state_file_missing'},
                            'unreadable': {'state_file_unreadable', 'state_file_unsafe', 'state_schema_invalid', 'state_identity_mismatch', 'route_table_unreadable'},
                            'unavailable': {'state_not_ready', 'route_owner_missing', 'owner_unverified', 'route_not_matching'}}
                _require(d.get('predicate') in required.get(marker, set()))
            _require(all(d.get(k) is None for k in ('runtime_generation', 'generation', 'address')))
    if r['schema'].endswith('.v2'):
        event = r['event']
        exit_value, inspection = r.get('exit'), r.get('inspection_error')
        if event == 'child_exited':
            _require(not deps and inspection is None and ((exit_value['code'] is None) != (exit_value['signal'] is None)))
        elif event == 'dependency_unavailable':
            _require(exit_value is None and inspection is None and len(deps) == 1 and deps[0]['status'] == 'unavailable')
        elif event == 'dependency_tuple_changed':
            _require(exit_value is None and inspection is None and bool(deps) and all(d['status'] == 'observed' for d in deps))
        elif event == 'inspection_error':
            _require(exit_value is None)
            if inspection == 'child_completion':
                _require(not deps)
            else:
                _require(len(deps) == 1 and deps[0]['status'] == 'unavailable' and deps[0]['tuple_status'] in {'unreadable', 'absent'})
        else:
            _require(not deps and exit_value is None and inspection is None)
    assignments = r.get('assignments', {})
    _require(isinstance(assignments, dict) and len(assignments) <= 12)
    for k, v in assignments.items():
        m = re.fullmatch(r'EFFIGY_MANAGED_HOST_(API|FRONT|ADMIN)_(INTERNAL_URL|PUBLIC_URL|STATE_FILE|GENERATION)', k)
        _require(m is not None)
        suffix = m[2]
        if suffix == 'GENERATION':
            _require(_gen(v))
        elif suffix == 'STATE_FILE':
            _require(v == str(checkout / '.effigy/runtime/host-processes/hybrid_services/effigy' / (m[1].lower() + '.listener.json')))
        else:
            _url(v, suffix == 'PUBLIC_URL')
    # Every retained string above has a finite grammar or exact owned-path match.
    return {**{k: v for k, v in r.items() if k != "owner"},
            "owner_sha256": hashlib.sha256(owner.encode()).hexdigest()}


def _object(pairs):
    result = {}
    for k, v in pairs:
        _require(k not in result)
        result[k] = v
    return result


def collect_known(checkout, reason):
    for (path, name), owner in list(_owners.items()):
        if path == str(checkout):
            collect(checkout, name, owner, reason)


def collect(checkout, name, owner, reason):
    """Snapshot exact receipt bytes before cleanup/rejection; gaps remain UNKNOWN."""
    if _sink is None:
        return None
    result = {'role': name if name in NAMES else 'unknown', 'reason': reason if reason in {'listener_observation', 'live_identity_mismatch', 'before_cleanup', 'post_cleanup_forensic'} else 'unknown',
              'knowledge': 'unknown', 'issues': [], 'records': [], 'authority': 'observation_only'}
    fds = []
    try:
        checkout = Path(checkout)
        _require(checkout.is_absolute() and '..' not in checkout.parts and name in NAMES)
        relative = checkout.relative_to(_root)
        if isinstance(owner, str):
            _owners[(str(checkout), name)] = owner
        fd = os.open(_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(fd)
        for component in (*relative.parts, '.effigy', 'runtime', 'host-processes', 'hybrid_services', 'effigy'):
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            fds.append(fd)
            _require(os.fstat(fd).st_uid == os.getuid())
        receipt = os.open(name + '.transitions.jsonl', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        fds.append(receipt)
        info = os.fstat(receipt)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= MAX_BYTES)
        chunks = []
        total = 0
        while total <= MAX_BYTES:
            chunk = os.read(receipt, min(65536, MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk); total += len(chunk)
        raw = b''.join(chunks)
        _require(len(raw) <= MAX_BYTES)
        result.update(checkout=str(checkout), sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                      inode=info.st_ino, device=info.st_dev)
        after = os.fstat(receipt)
        if (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            result['issues'].append('changed_during_read')
        if raw and not raw.endswith(b'\n'):
            result['issues'].append('incomplete_tail')
            raw = raw.rsplit(b'\n', 1)[0] if b'\n' in raw else b''
        expected = 1
        lines = raw.splitlines()
        if len(lines) > 512:
            result['issues'].append('record_limit')
        for line in lines[:512]:
            if not line.strip():
                continue
            try:
                r = _record(json.loads(line, object_pairs_hook=_object), owner, checkout)
                if r['sequence'] < expected:
                    result['issues'].append('sequence_regression'); continue
                if r['sequence'] != expected:
                    result['issues'].append('sequence_gap')
                expected = r['sequence'] + 1
                result['records'].append(r)
                if r['event'] == 'retention_limit':
                    result['issues'].append('retention_limit')
            except (ValueError, TypeError, KeyError, UnicodeError):
                result['issues'].append('malformed_or_unassociated')
        if not result['records']:
            result['issues'].append('missing_records')
        if not result['issues']:
            result['knowledge'] = 'bounded_complete_observation'
    except FileNotFoundError:
        result['issues'].append('missing')
    except PermissionError:
        result['issues'].append('permission_denied')
    except (OSError, ValueError, TypeError):
        result['issues'].append('unsafe_or_unassociated')
    finally:
        for fd in reversed(fds):
            os.close(fd)
    result['issues'] = sorted(set(result['issues']))
    _sink('managed_transition_snapshot', snapshot=result)
    return result
