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
sys.dont_write_bytecode = True
import tempfile
import time
from auth_cpu_inputs import admit_cache, source_agrees, read_file, Refusal

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
    for block in read_file(path, 2*1024*1024).decode().split('[[package]]')[1:]:
        for field in ('name','version','source','checksum'):
            if len(re.findall(r'^'+field+r' = ',block,re.M)) > 1:
                raise ValueError('ambiguous_lock_field')
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        version = re.search(r'^version = "([^"]+)"', block, re.M)
        checksum = re.search(r'^checksum = "([^"]+)"', block, re.M)
        source = re.search(r'^source = "([^"]+)"', block, re.M)
        key = (name[1], version[1])
        if key in result:
            raise ValueError('duplicate_package')
        result[key] = (source[1] if source else None, checksum[1] if checksum else None)
    return result


def profile_admitted(fingerprints, prior):
    keys=('rustc','features','target','profile')
    if not fingerprints or any(not any(all(value.get(key)==item.get(key) and key in value and key in item for key in keys) for item in prior) for value in fingerprints):
        raise ValueError('build_profile_changed')


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
                try: data = os.read(entry.fileobj.fileno(),4096)
                except OSError:
                    reason='read_failure'; break
                if not data:
                    streams.unregister(entry.fileobj); continue
                name = entry.data; counts[name] += len(data)
                buffers[name].extend(data[:max(0,CAP-len(buffers[name]))])
                if counts[name] > CAP:
                    reason = name + '_overflow'; break
            if reason != 'complete': break
        def terminate_owned():
            # Never reap between a successful identity check and its signal.
            # macOS may stop exposing getpgid after TERM, even before wait.
            try: current=os.getpgid(process.pid)
            except ProcessLookupError: return 'leader_unobservable'
            if current!=group: raise Refusal('owned_group_changed')
            try: os.killpg(group,signal.SIGTERM)
            except ProcessLookupError: return 'group_unobservable'
            time.sleep(.1)
            try: current=os.getpgid(process.pid)
            except ProcessLookupError: return 'leader_unobservable_after_term'
            if current!=group: raise Refusal('owned_group_changed')
            try: os.killpg(group,signal.SIGKILL)
            except ProcessLookupError: return 'group_unobservable_after_term'
            return 'owned_kill_sent'
        termination='not_needed'
        if reason!='complete': termination=terminate_owned()
        try:
            code=process.wait(timeout=max(.1,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            reason='deadline'; termination=terminate_owned()
            code=process.wait(timeout=5)
    finally:
        streams.close(); process.stdout.close(); process.stderr.close()
    receipt = {'exit':code,'reason':reason,'bytes':counts,
               'retained_sha256':{k:hashlib.sha256(v).hexdigest() for k,v in buffers.items()},
               'stream_cap':CAP,'reaped':True,'termination':termination,'group_absence':'not_independently_observed'}
    save(root,kind + '-capture.json',receipt)
    return receipt, buffers


def main():
    started = time.monotonic()
    root = Path(tempfile.mkdtemp(prefix='ur.005-auth-cpu.')).resolve(strict=True)
    root.chmod(0o700)
    print('PRIVATE CPU PACKET: ' + str(root),flush=True)
    save(root,'intent.json',{'run':'4c39a9ba-037c-403b-ac40-62d135f1b668','brief':41,
        'brief_sha256':'4cdcd019279e3d09933456cbccdccd23c63b297f153e423baa8bb5e39f6368d8',
        'initial_head':'224a84bda22de0c21d7d4506b58247461a88fb81',
        'task':'b3ae8bae-190d-42f4-8132-430253bb02fe','source':SOURCE,'once':True,
        'archive_protocol':'verified-cache-archives-fresh-cargo-unpack.v1',
        'build_seconds':600,'build_jobs':2,'execution_seconds':60,'stream_cap':CAP,
        'harness_sha256':digest(Path(__file__)),
        'input_module_sha256':digest(Path(__file__).with_name('auth_cpu_inputs.py')),
        'fixture_sha256':digest(Path(__file__).parent/'fixtures/auth-cpu.rs'),
        'cost':{'algorithm':'argon2id','version':19,'memory_kib':131072,'iterations':4,'parallelism':4},
        'admission':'not_yet_observed','no_services':True})
    source = RETAINED / '.cargo/git/checkouts/underlay-d2d5ac68e32e8122/72d6fd9'
    head = subprocess.run(['git','-C',str(source),'rev-parse','HEAD'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    if head != SOURCE: raise ValueError('source_identity')
    clean = subprocess.run(['git','-C',str(source),'diff','--quiet',SOURCE,'--','Cargo.toml','rust'],check=False,timeout=10)
    if clean.returncode != 0: raise Refusal('git_source_changed')
    rust = Path(__file__).parent / 'fixtures/auth-cpu.rs'
    lock = RETAINED / 'reference/main/apps/acme-api/Cargo.lock'
    # Keep the actual consumer declaration's source ID, so the copied lock pins
    # the Git object without turning a tag source into a new resolver source.
    reference_manifest = RETAINED / 'reference/main/apps/acme-api/Cargo.toml'
    declaration = re.search(r'^underlay-auth = (.+)$',reference_manifest.read_text(),re.M)
    expected_declaration = '{ git = "ssh://git@github.com/inflatable-cookie/underlay.git", tag = "v0.10.3" }'
    if declaration is None or declaration[1] != expected_declaration:
        raise ValueError('consumer_manifest_changed')
    for relative in ('Cargo.toml','rust/crates/underlay-auth/Cargo.toml','rust/crates/underlay-auth/src/lib.rs','rust/crates/underlay-auth/src/hashing.rs','rust/crates/underlay-core/Cargo.toml'):
        if not (source / relative).is_file(): raise ValueError('source_layout')
    admitted = packages(lock)
    auth = admitted.get(('underlay-auth','0.10.3'))
    if auth is None or not auth[0].endswith('#'+SOURCE): raise ValueError('lock_source_identity')
    home = root / 'home'; home.mkdir(mode=0o700)
    cargo_home = home / '.cargo'; cargo_home.mkdir(mode=0o700)
    # Only authenticated archives and resolver metadata enter the private home.
    # No registry src tree is copied: Cargo materializes authenticated archives.
    archive_inputs = admit_cache(RETAINED/'.cargo/registry/cache',admitted,cargo_home/'registry/cache')
    for key in ('argon2-0.5.3','password-hash-0.5.0','tokio-1.53.1'):
        if key not in archive_inputs: raise Refusal('critical_archive_missing')
    shutil.copytree(RETAINED/'.cargo/registry/index',cargo_home/'registry/index')
    shutil.copytree(RETAINED/'.cargo/git/db',cargo_home/'git/db')
    save(root,'archive-admission.json',{'packages':len(archive_inputs),
        'archives':{key:value[1] for key,value in archive_inputs.items()},
        'lock_sha256':digest(lock),'reference_manifest_sha256':digest(reference_manifest)})
    probe = root / 'probe'; (probe / 'src').mkdir(parents=True)
    shutil.copyfile(rust,probe / 'src/main.rs'); shutil.copyfile(lock,probe / 'Cargo.lock')
    (probe / 'Cargo.toml').write_text('[package]\nname="underlay-auth-cpu-probe"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nunderlay-auth={git="ssh://git@github.com/inflatable-cookie/underlay.git",tag="v0.10.3",features=["hashing"]}\ntokio={version="=1.53.1",features=["rt"]}\n[profile.dev]\nopt-level=0\n')
    cargo = shutil.which('cargo')
    if not cargo: raise ValueError('cargo_unavailable')
    env = {k:os.environ[k] for k in ('PATH','RUSTUP_HOME','DEVELOPER_DIR','SDKROOT') if k in os.environ}
    env['RUSTUP_HOME'] = os.environ.get('RUSTUP_HOME',str(Path.home()/'.rustup'))
    env.update(HOME=str(home),CARGO_HOME=str(cargo_home),CARGO_TARGET_DIR=str(root/'target'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='2')
    # Finite version metadata must match the compiler retained for Reference.
    rustc = shutil.which('rustc')
    if not rustc: raise ValueError('rustc_unavailable')
    metadata, output = bounded(root,'toolchain',[rustc,'--version','--verbose'],env,min(started+600,time.monotonic()+10))
    previous=json.loads((RETAINED/'.cargo-target/.rustc_info.json').read_text())
    candidates=[value.get('stdout','').encode() for value in previous['outputs'].values() if 'rustc ' in value.get('stdout','')]
    if metadata['exit']!=0 or metadata['reason']!='complete' or bytes(output['stdout']) not in candidates:
        raise ValueError('toolchain_changed')
    build, build_output = bounded(root,'build',[cargo,'build','--offline','--jobs','2'],env,started+600)
    if build['exit'] != 0 or build['reason'] != 'complete':
        raise ValueError('build_refusal')
    admitted = packages(lock); resolved = packages(probe/'Cargo.lock')
    for key, value in resolved.items():
        if key[0] == 'underlay-auth-cpu-probe': continue
        # Tag versus exact rev is the same immutable Git object.
        if key not in admitted or value[1] != admitted[key][1]: raise ValueError('dependency_lock_changed')
        if value[0] != admitted[key][0] and not (value[0] and admitted[key][0] and value[0].endswith('#'+SOURCE) and admitted[key][0].endswith('#'+SOURCE)):
            raise ValueError('dependency_source_changed')
    for directory in (cargo_home/'registry/src').glob('*/*'):
        if directory.name not in archive_inputs: raise Refusal('selected_archive_unadmitted')
        source_agrees(directory,archive_inputs[directory.name][0])
    checkouts=list((cargo_home/'git/checkouts').glob('underlay-*/*'))
    if len(checkouts)!=1: raise Refusal('git_checkout_count')
    copied_source=checkouts[0]
    git_head=subprocess.run(['git','-C',str(copied_source),'rev-parse','HEAD'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    if git_head!=SOURCE: raise Refusal('copied_git_object')
    for relative in ('Cargo.toml','rust/crates/underlay-auth/Cargo.toml','rust/crates/underlay-auth/src/hashing.rs','rust/crates/underlay-core/Cargo.toml'):
        if digest(source/relative)!=digest(copied_source/relative): raise Refusal('copied_git_source')
    binary = root/'target/debug/underlay-auth-cpu-probe'
    fingerprints = []
    for file in (root/'target/debug/.fingerprint').glob('argon2-*/lib-argon2.json'):
        value = json.loads(file.read_text())
        fingerprints.append({key:value[key] for key in ('rustc','features','target','profile')})
    prior = [json.loads(file.read_text()) for file in (RETAINED/'.cargo-target/debug/.fingerprint').glob('argon2-*/lib-argon2.json')]
    profile_admitted(fingerprints,prior)
    save(root,'build-identity.json',{'binary_sha256':digest(binary),'lock_sha256':digest(probe/'Cargo.lock'),
        'dependencies_admitted':len(resolved)-1,'profile':'debug','opt_level':0,
        'argon2_fingerprints':fingerprints,
        'hashing_source_sha256':digest(copied_source/'rust/crates/underlay-auth/src/hashing.rs')})
    execution_started = time.monotonic()
    result, output = bounded(root,'probe',[str(binary)],env,execution_started+60)
    rows = phase_rows(output['stdout'])
    expected = [('hash','completed'),('schedule','started'),('worker_entry','started'),('verification','valid'),('join','completed'),('total','valid')]
    passed = result['exit']==0 and result['reason']=='complete' and result['bytes']['stderr']==0 and [(r['phase'],r['outcome']) for r in rows]==expected
    save(root,'result.json',{'passed':passed,'phases':rows,'capture':result,'execution_wall_ms':(time.monotonic()-execution_started)*1000,
        'stored_historical_phc_known':False,'historical_cause_proven':False,'service_runtime_acceptance':False})
    print(json.dumps({'passed':passed,'phases':rows,'effect':'synthetic_cpu_only'}),flush=True)
    if not passed: raise ValueError('probe_refusal')


def phase_rows(data):
    rows = []
    phases = {'hash','runtime','preparation','schedule','worker_entry','verification','join','total'}
    outcomes = {'completed','started','valid','invalid','error','panic','cancelled','random_error'}
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value: raise ValueError('duplicate_phase_field')
            value[key]=item
        return value
    for line in data.splitlines():
        row = json.loads(line,object_pairs_hook=unique)
        if set(row) != {'phase','elapsed_us','outcome'} or row['phase'] not in phases or row['outcome'] not in outcomes or type(row['elapsed_us']) is not int or row['elapsed_us'] < 0:
            raise ValueError('probe_schema')
        rows.append(row)
    return rows


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        # Closed exception class only: no cargo/error/secret payload echo.
        print(json.dumps({'passed':False,'failure_class':type(error).__name__}),flush=True)
        sys.exit(1)
