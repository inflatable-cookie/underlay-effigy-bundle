"""Bounded host compile diagnostics: payload stays in memory, receipts are closed."""
import os
import re
import selectors
import subprocess
import time
from pathlib import PurePosixPath

from pending_start_identity import IdentityUnknown, kernel_identity

LIMIT = 262144
SAFE_LOCATIONS = frozenset((
    "crates/api/src/main.rs", "crates/api/src/routes/shared/auth/basic.rs",
    "crates/auth/src/local/login.rs", "crates/auth/src/local/mod.rs",
))


def diagnostic_summary(stdout, stderr):
    text = (stdout + b'\n' + stderr).decode('utf-8', errors='replace')
    # Do not copy error messages, URLs, source lines, argv or environment values.
    categories = {
        'ssh_authentication': ('Permission denied (publickey)', 'failed to authenticate when downloading repository'),
        'git_dependency_fetch': ('failed to get', 'Unable to update', 'failed to fetch'),
        'tool_unavailable': ('cargo: command not found', 'cargo: not found'),
        'rustup_toolchain_unavailable': ('no default is configured', 'toolchain is not installed'),
        'rust_compile_error': ('error[E',),
        'linker_failure': ('linking with', 'linker command failed', 'Undefined symbols for architecture'),
        'build_completed': ('Finished `dev` profile',),
        'dependency_offline_unavailable': ('attempting to make an HTTP request, but --offline was specified', 'no matching package named'),
        'network_resolution': ('Could not resolve host', 'failed to resolve address'),
    }
    found = sorted(name for name, needles in categories.items() if any(s in text for s in needles))
    locations = []
    for path, line, column in re.findall(r'(?m)^\s*--> (crates/[A-Za-z0-9_./-]+\.rs):(\d{1,7}):(\d{1,7})\s*$', text):
        if path in SAFE_LOCATIONS and '..' not in PurePosixPath(path).parts:
            locations.append({'path': path, 'line': int(line), 'column': int(column)})
    return {'categories': found or ['unclassified'],
            'rust_codes': sorted(set(re.findall(r'\berror\[(E[0-9]{4})\]', text))),
            'locations': locations[:64], 'locations_truncated': len(locations) > 64}


def capture(args, *, cwd, env, timeout=600):
    if not 0 < timeout <= 900 or env is None:
        raise ValueError('compile_capture_inputs_refused')
    started = time.monotonic()
    process = subprocess.Popen(args, cwd=cwd, env=dict(env), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        original = kernel_identity(process.pid)
    except IdentityUnknown:
        original = None
    identity_admitted = (original is not None and original['ppid'] == os.getpid()
                         and original['uid'] == os.geteuid() and original['pgid'] == process.pid)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    counts = dict.fromkeys(buffers, 0)
    eof = dict.fromkeys(buffers, False)
    streams = selectors.DefaultSelector()
    for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
        os.set_blocking(stream.fileno(), False)
        streams.register(stream, selectors.EVENT_READ, name)
    refusal = None
    try:
        while streams.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                refusal = 'deadline'
                break
            for key, _ in streams.select(min(.1, remaining)):
                try:
                    data = os.read(key.fileobj.fileno(), 8192)
                except OSError:
                    refusal = key.data + "_read_failure"
                    break
                name = key.data
                if not data:
                    eof[name] = True
                    streams.unregister(key.fileobj)
                    continue
                counts[name] += len(data)
                buffers[name].extend(data[:max(0, LIMIT - len(buffers[name]))])
                if counts[name] > LIMIT:
                    refusal = name + '_overflow'
                    break
            if refusal:
                break
        if refusal:
            # The unreaped Popen child and precise kernel identity must both match.
            try:
                current = kernel_identity(process.pid) if identity_admitted else None
            except IdentityUnknown:
                current = None
            if identity_admitted and current == original:
                process.kill()
            else:
                refusal += '_identity_unknown'
        try:
            process.wait(timeout=max(.01, min(5, timeout - (time.monotonic() - started))))
        except subprocess.TimeoutExpired:
            refusal = refusal or 'leader_settlement_unknown'
        result = {'schema': 'underlay.reference.compile-capture.v1',
                  'exit': process.returncode, 'refusal': refusal,
                  'identity_admitted': identity_admitted, 'original_child_identity': original,
                  'leader_reaped': process.returncode is not None,
                  'group_absence': 'unverified', 'remote_cancellation': 'not_applicable',
                  'elapsed_ms': round((time.monotonic() - started) * 1000),
                  'stdout': {'read_bytes': counts['stdout'], 'retained_bytes': len(buffers['stdout']), 'eof': eof['stdout']},
                  'stderr': {'read_bytes': counts['stderr'], 'retained_bytes': len(buffers['stderr']), 'eof': eof['stderr']},
                  'diagnostics': diagnostic_summary(bytes(buffers['stdout']), bytes(buffers['stderr']))}
        return result
    finally:
        streams.close()
        process.stdout.close()
        process.stderr.close()
