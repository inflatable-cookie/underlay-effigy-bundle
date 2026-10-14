#!/usr/bin/env python3
"""One isolated, finite public-API CPU observation; never starts services."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

SOURCE = '72d6fd91a3096ffd85b2ab25e9f5cff8bb6e6d03'
RETAINED = Path('/Users/tom/ur.OYmGFy/home')
CAP = 16384


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(root, name, value):
    path = root / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')


def packages(path):
    result = {}
    for block in path.read_text().split('[[package]]')[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        version = re.search(r'^version = "([^"]+)"', block, re.M)
        checksum = re.search(r'^checksum = "([^"]+)"', block, re.M)
        source = re.search(r'^source = "([^"]+)"', block, re.M)
        key = (name[1], version[1])
        if key in result:
            raise ValueError('duplicate_package')
        result[key] = (source[1] if source else None, checksum[1] if checksum else None)
    return result


def bounded(root, kind, command, env, deadline):
    # Child waits for parent to durably record its newly created session/group.
    gate = 'import os,sys; b=sys.stdin.buffer.read(1); os.execv(sys.argv[1],sys.argv[1:]) if b==b"G" else sys.exit(1)'
    process = subprocess.Popen([sys.executable, '-c', gate, *command], cwd=root / 'probe',
                               env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    group = os.getpgid(process.pid)
    assert group == process.pid
    save(root, kind + '-group.json', {'pid':process.pid,'group':group,'session':os.getsid(process.pid),
                                    'new_unreaped_child':True,'recorded_before_exec':True})
    process.stdin.write(b'G'); process.stdin.close()
    streams = selectors.DefaultSelector()
    buffers = {'stdout':bytearray(), 'stderr':bytearray()}
    counts = dict.fromkeys(buffers, 0)
    reason = 'complete'
    for name, stream in [('stdout',process.stdout),('stderr',process.stderr)]:
        os.set_blocking(stream.fileno(), False); streams.register(stream,selectors.EVENT_READ,name)
    try:
        while streams.get_map():
            if time.monotonic() >= deadline:
                reason = 'deadline'; break
            for entry, _ in streams.select(min(.1, max(0,deadline-time.monotonic()))):
                data = os.read(entry.fileobj.fileno(),4096)
                if not data:
                    streams.unregister(entry.fileobj); continue
                name = entry.data; counts[name] += len(data)
                buffers[name].extend(data[:max(0,CAP-len(buffers[name]))])
                if counts[name] > CAP:
                    reason = name + '_overflow'; break
            if reason != 'complete': break
        if reason != 'complete':
            # Leader has never been reaped, so its PID cannot have been reused.
            if os.getpgid(process.pid) != group:
                raise ValueError('owned_group_changed')
            os.killpg(group, signal.SIGTERM)
            time.sleep(.1)
            # Do not poll/reap the leader between group verification and signals.
            if os.getpgid(process.pid) != group:
                raise ValueError('owned_group_changed')
            os.killpg(group, signal.SIGKILL)
        try:
            code = process.wait(timeout=max(.1,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            reason = 'deadline'
            if os.getpgid(process.pid) != group:
                raise ValueError('owned_group_changed')
            os.killpg(group, signal.SIGTERM)
            time.sleep(.1)
            if os.getpgid(process.pid) != group:
                raise ValueError('owned_group_changed')
            os.killpg(group, signal.SIGKILL)
            code = process.wait(timeout=5)
    finally:
        streams.close(); process.stdout.close(); process.stderr.close()
    receipt = {'exit':code,'reason':reason,'bytes':counts,
               'retained_sha256':{k:hashlib.sha256(v).hexdigest() for k,v in buffers.items()},
               'stream_cap':CAP,'reaped':True}
    save(root,kind + '-capture.json',receipt)
    return receipt, buffers


def main():
    started = time.monotonic()
    root = Path(tempfile.mkdtemp(prefix='ur.005-auth-cpu.'))
    root.chmod(0o700)
    print('PRIVATE CPU PACKET: ' + str(root),flush=True)
    source = RETAINED / '.cargo/git/checkouts/underlay-d2d5ac68e32e8122/72d6fd9'
    head = subprocess.run(['git','-C',str(source),'rev-parse','HEAD'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    if head != SOURCE: raise ValueError('source_identity')
    rust = Path(__file__).parent / 'fixtures/auth-cpu.rs'
    lock = RETAINED / 'reference/main/apps/acme-api/Cargo.lock'
    save(root,'intent.json',{'run':'da782a4a-3c37-4398-b1c6-49408efd930e','brief':39,
        'initial_head':'3d81a78ab0b6da2a8bd92f0a284b63445589bdeb',
        'brief_sha256':'44453c03869507a68823bb8dbf3a3c36d4f1bdf0f2c7ddf402bea8068cbb4905',
        'task':'b3ae8bae-190d-42f4-8132-430253bb02fe','source':SOURCE,'once':True,
        'cost':{'algorithm':'argon2id','version':19,'memory_kib':131072,'iterations':4,'parallelism':4},
        'build_seconds':600,'execution_seconds':60,'build_jobs':2,'stream_cap':CAP,
        'source_fixture_sha256':digest(rust),'harness_sha256':digest(Path(__file__)),
        'retained_lock_sha256':digest(lock),'no_services':True})
    home = root / 'home'; home.mkdir(mode=0o700)
    cargo_home = home / '.cargo'
    shutil.copytree(RETAINED / '.cargo',cargo_home,ignore=shutil.ignore_patterns('credentials*','.global-cache','.package-cache*'))
    copied_source = cargo_home / 'git/checkouts/underlay-d2d5ac68e32e8122/72d6fd9'
    for relative in ('rust/crates/underlay-auth/src/hashing.rs','rust/crates/underlay-auth/Cargo.toml','Cargo.toml'):
        if digest(source / relative) != digest(copied_source / relative):
            raise ValueError('copied_source_changed')
    probe = root / 'probe'; (probe / 'src').mkdir(parents=True)
    shutil.copyfile(rust,probe / 'src/main.rs'); shutil.copyfile(lock,probe / 'Cargo.lock')
    (probe / 'Cargo.toml').write_text('[package]\nname="underlay-auth-cpu-probe"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nunderlay-auth={git="ssh://git@github.com/inflatable-cookie/underlay.git",rev="'+SOURCE+'",features=["hashing"]}\ntokio={version="=1.53.1",features=["rt"]}\n[profile.dev]\nopt-level=0\n')
    cargo = shutil.which('cargo')
    if not cargo: raise ValueError('cargo_unavailable')
    env = {k:os.environ[k] for k in ('PATH','RUSTUP_HOME','DEVELOPER_DIR','SDKROOT') if k in os.environ}
    env['RUSTUP_HOME'] = os.environ.get('RUSTUP_HOME',str(Path.home()/'.rustup'))
    env.update(HOME=str(home),CARGO_HOME=str(cargo_home),CARGO_TARGET_DIR=str(root/'target'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='2')
    build, _ = bounded(root,'build',[cargo,'build','--offline','--jobs','2'],env,started+600)
    if build['exit'] != 0 or build['reason'] != 'complete':
        raise ValueError('build_refusal')
    admitted = packages(lock); resolved = packages(probe/'Cargo.lock')
    for key, value in resolved.items():
        if key[0] == 'underlay-auth-cpu-probe': continue
        # Tag versus exact rev is the same immutable Git object.
        if key not in admitted or value[1] != admitted[key][1]: raise ValueError('dependency_lock_changed')
        if value[0] != admitted[key][0] and not (value[0] and admitted[key][0] and value[0].endswith('#'+SOURCE) and admitted[key][0].endswith('#'+SOURCE)):
            raise ValueError('dependency_source_changed')
    binary = root/'target/debug/underlay-auth-cpu-probe'
    fingerprints = []
    for file in (root/'target/debug/.fingerprint').glob('argon2-*/lib-argon2.json'):
        value = json.loads(file.read_text())
        fingerprints.append({key:value[key] for key in ('rustc','features','target','profile')})
    prior = [json.loads(file.read_text()) for file in (RETAINED/'.cargo-target/debug/.fingerprint').glob('argon2-*/lib-argon2.json')]
    if not fingerprints or any(not any(all(value[key]==item[key] for key in ('rustc','features','target','profile')) for item in prior) for value in fingerprints):
        raise ValueError('build_profile_changed')
    save(root,'build-identity.json',{'binary_sha256':digest(binary),'lock_sha256':digest(probe/'Cargo.lock'),
        'dependencies_admitted':len(resolved)-1,'profile':'debug','opt_level':0,
        'argon2_fingerprints':fingerprints,
        'hashing_source_sha256':digest(copied_source/'rust/crates/underlay-auth/src/hashing.rs')})
    execution_started = time.monotonic()
    result, output = bounded(root,'probe',[str(binary)],env,execution_started+60)
    rows = []
    phases = {'hash','runtime','preparation','schedule','worker_entry','verification','join','total'}
    outcomes = {'completed','started','valid','invalid','error','panic','cancelled','random_error'}
    for line in output['stdout'].splitlines():
        row = json.loads(line)
        if set(row) != {'phase','elapsed_us','outcome'} or row['phase'] not in phases or row['outcome'] not in outcomes or type(row['elapsed_us']) is not int or row['elapsed_us'] < 0:
            raise ValueError('probe_schema')
        rows.append(row)
    expected = [('hash','completed'),('schedule','started'),('worker_entry','started'),('verification','valid'),('join','completed'),('total','valid')]
    passed = result['exit']==0 and result['reason']=='complete' and result['bytes']['stderr']==0 and [(r['phase'],r['outcome']) for r in rows]==expected
    save(root,'result.json',{'passed':passed,'phases':rows,'capture':result,'execution_wall_ms':(time.monotonic()-execution_started)*1000,
        'stored_historical_phc_known':False,'historical_cause_proven':False,'service_runtime_acceptance':False})
    print(json.dumps({'passed':passed,'phases':rows,'effect':'synthetic_cpu_only'}),flush=True)
    if not passed: raise ValueError('probe_refusal')


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        # Closed exception class only: no cargo/error/secret payload echo.
        print(json.dumps({'passed':False,'failure_class':type(error).__name__}),flush=True)
        sys.exit(1)
