"""Configured default-feature linking before any private backend effects."""
import hashlib
import os
from pathlib import Path
import platform
import stat
import subprocess
import re

from reference_compile_capture import capture
import qualification_batch

PATCH_FILES = ('apps/acme-api/crates/api/src/routes/shared/auth/basic.rs',
               'apps/acme-api/crates/auth/src/local/login.rs',
               'apps/acme-api/crates/auth/src/local/mod.rs')


def file_identity(path, *, limit=67108864):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_size > limit:
            raise RuntimeError('api_preparation_file_identity_refused')
        digest = hashlib.sha256()
        prefix = b''
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            if len(prefix) < 32:
                prefix += block[:32-len(prefix)]
            digest.update(block)
        after = os.fstat(fd)
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_uid, s.st_nlink)
        if stamp(before) != stamp(after) or stamp(path.lstat()) != stamp(before):
            raise RuntimeError('api_preparation_file_changed')
        return {'sha256': digest.hexdigest(), 'device': before.st_dev, 'inode': before.st_ino,
                'bytes': before.st_size}, prefix
    finally:
        os.close(fd)


def inputs(checkout, env, patch_receipt):
    checkout = Path(checkout).resolve(strict=True)
    fixture = Path(env['UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT']).resolve(strict=True)
    target_path = Path(env['CARGO_TARGET_DIR'])
    target = target_path.resolve(strict=True)
    if target_path.is_symlink() or not target.is_relative_to(fixture) or not checkout.is_relative_to(fixture):
        raise RuntimeError('api_preparation_private_target_refused')
    if env.get('CARGO_NET_OFFLINE') != 'true' or env.get('CARGO_BUILD_JOBS') != '2':
        raise RuntimeError('api_preparation_environment_refused')
    if any(key in env for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_PROFILE_DEV_OPT_LEVEL')):
        raise RuntimeError('api_preparation_build_override_refused')
    config_path = checkout / 'apps/acme-api/effigy.toml'
    config = config_path.read_text()
    tasks = re.findall(r'(?m)^(build|api) = \"([^\"]*)\"$', config)
    if sorted(tasks) != [('api', 'cd {repo} && cargo run -p acme-api {args}'), ('build', 'cd {repo} && cargo build {args}')]:
        raise RuntimeError('api_preparation_configured_caller_refused')
    lock, _ = file_identity(checkout / 'apps/acme-api/Cargo.lock', limit=1048576)
    if lock['sha256'] != patch_receipt['cargo_lock_sha256']:
        raise RuntimeError('api_preparation_lock_changed')
    files = {name: file_identity(checkout / name)[0]['sha256'] for name in PATCH_FILES}
    expected = {item['path']: item['sha256_after'] for item in patch_receipt['files']}
    if files != expected:
        raise RuntimeError('api_preparation_patch_changed')
    # Closed compiler identity; payload is never published, and no compilation occurs.
    version = subprocess.run(['rustc', '-vV'], cwd=checkout/'apps/acme-api', env=env,
                             capture_output=True, timeout=min(8, qualification_batch.cap(8)))
    if version.returncode or version.stderr or len(version.stdout) > 4096:
        raise RuntimeError('api_preparation_toolchain_unavailable')
    if b'host: aarch64-apple-darwin\n' not in version.stdout:
        raise RuntimeError('api_preparation_toolchain_platform_refused')
    return {'schema': 'underlay.reference.api-inputs.v1', 'checkout': str(checkout),
            'target': str(target), 'package': 'acme-api', 'features': 'default', 'profile': 'debug',
            'locked': True, 'offline': True, 'jobs': 2,
            'cargo_home': str(Path(env['CARGO_HOME']).resolve(strict=True)),
            'rustup_home': str(Path(env['RUSTUP_HOME']).resolve(strict=True)),
            'source': patch_receipt['reference_source_commit'], 'patch_sha256': patch_receipt['patch_sha256'],
            'lock_sha256': lock['sha256'], 'instrumented_files': files,
            'manifest_sha256': file_identity(config_path)[0]['sha256'],
            'cargo_manifest_sha256': file_identity(checkout/'apps/acme-api/Cargo.toml')[0]['sha256'],
            'toolchain_sha256': hashlib.sha256(version.stdout).hexdigest()}


def artifact(identity):
    if (platform.system(), platform.machine().lower()) != ('Darwin', 'arm64'):
        raise RuntimeError('api_preparation_platform_refused')
    binary = Path(identity['target']) / 'debug/acme-api'
    if binary.resolve(strict=True) != binary or not os.access(binary, os.X_OK):
        raise RuntimeError('api_preparation_artifact_path_refused')
    receipt, prefix = file_identity(binary, limit=1073741824)
    # MH_MAGIC_64, CPU_TYPE_ARM64, MH_EXECUTE. A check-only or wrong target cannot qualify.
    if prefix[:8] != b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01' or prefix[12:16] != b'\x02\x00\x00\x00':
        raise RuntimeError('api_preparation_linked_platform_refused')
    return dict(receipt, path=str(binary), platform='darwin-arm64', package='acme-api', profile='debug')


def prepare(effigy, checkout, env, patch_receipt, emit):
    before = inputs(checkout, env, patch_receipt)
    result = capture([effigy, '--repo', str(Path(checkout)/'apps/acme-api'), 'build',
                      '--', '-p', 'acme-api', '--locked', '--offline'],
                     cwd=Path(checkout)/'apps/acme-api', env=env,
                     timeout=qualification_batch.cap(900))
    failed = (result['exit'] != 0 or result['refusal'] is not None or not result['identity_admitted']
              or not result['leader_reaped'] or not all(result[name]['eof'] for name in ('stdout','stderr')))
    try:
        emit('reference_api_link_capture', selector='acme-api/build', inputs=before, capture=result)
    except Exception:
        if failed:
            raise RuntimeError('api_preparation_configured_build_refused_publication_unavailable') from None
        raise
    if failed:
        raise RuntimeError('api_preparation_configured_build_refused')
    after = inputs(checkout, env, patch_receipt)
    if before != after:
        raise RuntimeError('api_preparation_inputs_changed')
    linked = artifact(after)
    emit('reference_api_linked', inputs=after, artifact=linked, completed=True)
    return {'inputs': after, 'artifact': linked, 'capture': result}


def admit_launch(prepared, checkout, env, patch_receipt, emit):
    current = inputs(checkout, env, patch_receipt)
    expected = dict(prepared['inputs'], checkout=current['checkout'])
    if current != expected or artifact(current) != prepared['artifact']:
        raise RuntimeError('api_preparation_launch_inputs_changed')
    emit('reference_api_launch_admitted', inputs=current, preparation_completed=True,
         listener_timeout_seconds=480, outer_readiness_seconds=540)
