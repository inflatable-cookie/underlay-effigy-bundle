"""Finite fair host capture; raw payload lives only in the caller's memory.

Only the original unreaped, kernel-matched direct child may be signalled.
Reaping it never proves descendant or remote cancellation.
"""
import os
import selectors
import subprocess
import time
from .host_identity import IdentityUnknown, kernel_identity
LIMIT=262144

def capture(args, *, cwd=None, env, timeout=600, payload_sink=None, limits=None, identity_reader=None):
    if not 0 < timeout <= 7200 or env is None:
        raise ValueError('host_capture_inputs_refused')
    limits = limits or {"stdout": LIMIT, "stderr": LIMIT}
    if set(limits) != {"stdout", "stderr"} or any(type(x) is not int or not 0 < x <= LIMIT for x in limits.values()):
        raise ValueError("compile_capture_limits_refused")
    identity_reader=identity_reader or kernel_identity
    started = time.monotonic()
    try:
        process = subprocess.Popen(args, cwd=cwd, env=dict(env), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
    except OSError:
        return {'schema':'underlay.profile.host-capture.v1','exit':None,'refusal':'spawn_failed',
                'identity_admitted':False,'original_child_identity':None,'leader_reaped':False,
                'group_absence':'unverified','remote_cancellation':'unverified','elapsed_ms':round((time.monotonic()-started)*1000),
                'stdout':{'read_bytes':None,'retained_bytes':None,'eof':False},
                'stderr':{'read_bytes':None,'retained_bytes':None,'eof':False},'diagnostics':{}}
    try:
        original = identity_reader(process.pid)
    except (IdentityUnknown,OSError,subprocess.SubprocessError):
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
                buffers[name].extend(data[:max(0, limits[name] - len(buffers[name]))])
                if counts[name] > limits[name]:
                    refusal = name + '_overflow'
                    break
            if refusal:
                break
        if not refusal and not streams.get_map():
            try:
                process.wait(timeout=max(.001, timeout-(time.monotonic()-started)))
            except subprocess.TimeoutExpired:
                refusal='deadline'
        if refusal:
            # The unreaped Popen child and precise kernel identity must both match.
            try:
                current = identity_reader(process.pid) if identity_admitted else None
            except (IdentityUnknown,OSError,subprocess.SubprocessError):
                current = None
            if identity_admitted and current == original:
                process.kill()
            else:
                refusal += '_identity_unknown'
        try:
            process.wait(timeout=max(.01, min(5, timeout - (time.monotonic() - started))))
        except subprocess.TimeoutExpired:
            refusal = refusal or 'leader_settlement_unknown'
        result = {'schema': 'underlay.profile.host-capture.v1',
                  'exit': process.returncode, 'refusal': refusal,
                  'identity_admitted': identity_admitted, 'original_child_identity': original,
                  'leader_reaped': process.returncode is not None,
                  'group_absence': 'unverified', 'remote_cancellation': 'unverified',
                  'elapsed_ms': round((time.monotonic() - started) * 1000),
                  'stdout': {'read_bytes': counts['stdout'], 'retained_bytes': len(buffers['stdout']), 'eof': eof['stdout']},
                  'stderr': {'read_bytes': counts['stderr'], 'retained_bytes': len(buffers['stderr']), 'eof': eof['stderr']},
                  'diagnostics': {}}
        if payload_sink is not None:
            payload_sink(bytes(buffers["stdout"]), bytes(buffers["stderr"]))
        return result
    finally:
        streams.close()
        process.stdout.close()
        process.stderr.close()
