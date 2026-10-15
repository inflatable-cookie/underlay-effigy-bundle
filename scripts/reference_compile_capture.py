"""Bounded host compile diagnostics: payload stays in memory, receipts are closed."""
import os
import re
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


def capture(args, *, cwd, env, timeout=600, payload_sink=None, limits=None):
    # Compile retains its original 900s bound; the shared reader also serves
    # already-configured longer profile selectors without changing their timer.
    if not 0 < timeout <= 900 or env is None:
        raise ValueError('compile_capture_inputs_refused')
    from dev.owned_capture import capture as host_capture
    payload=[]
    result=host_capture(args,cwd=cwd,env=env,timeout=timeout,limits=limits,
        identity_reader=kernel_identity,payload_sink=lambda out,err:payload.extend((out,err)))
    out,err=payload if payload else (b'',b'')
    result['schema']='underlay.reference.compile-capture.v1'
    result['remote_cancellation']='not_applicable'
    result['diagnostics']=diagnostic_summary(out,err)
    if payload_sink is not None:payload_sink(out,err)
    return result
