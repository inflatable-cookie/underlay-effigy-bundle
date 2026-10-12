"""Finite private nerdctl metadata observation; metadata is not attestation."""
import hashlib
from pathlib import Path
import re
import shutil
import urllib.request

from storage_correlation import bounded_run

VERSION_TEMPLATE = '{{.Client.Version}}|{{.Client.GitCommit}}|{{.Client.Os}}|{{.Client.Arch}}'
REFERENCE_COMMIT = '59253e9931873e79b92fe3400f14e69d6be34025'
FORMAT_PORTS = '''func FormatPorts(ports []cni.PortMapping) string {
 if len(ports) == 0 { return "" }
 strs := make([]string, len(ports))
 for i, p := range ports {
  strs[i] = fmt.Sprintf("%s:%d->%d/%s", p.HostIP, p.HostPort, p.ContainerPort, p.Protocol)
 }
 return strings.Join(strs, ", ")
}'''


def host_identity(executable):
    path = Path(executable)
    if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_file():
        raise ValueError('formatter_host_identity_refused')
    stat = path.stat()
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'device': stat.st_dev, 'inode': stat.st_ino, 'size': stat.st_size}


def bind_host(env):
    selected = shutil.which('colima', path=env.get('PATH'))
    if not selected:
        raise ValueError('formatter_host_identity_refused')
    identity = host_identity(Path(selected).resolve(strict=True))
    env['UNDERLAY_CORRELATION_COLIMA_BIN'] = identity['path']
    env['UNDERLAY_CORRELATION_COLIMA_SHA256'] = identity['sha256']
    return identity


def bound_colima(env):
    identity = host_identity(env['UNDERLAY_CORRELATION_COLIMA_BIN'])
    selected = shutil.which('colima', path=env.get('PATH'))
    if (identity['sha256'] != env['UNDERLAY_CORRELATION_COLIMA_SHA256'] or not selected
            or str(Path(selected).resolve(strict=True)) != identity['path']):
        raise ValueError('formatter_host_identity_refused')
    return identity['path']


def version_arguments(env, fixture):
    supplied = Path(fixture)
    root = supplied.resolve(strict=True)
    if supplied != root or supplied.is_symlink() or root.stat().st_uid != __import__('os').getuid() or root.stat().st_mode & 0o077:
        raise ValueError('formatter_private_scope_refused')
    home = Path(env['COLIMA_HOME'])
    if (home.is_symlink() or home.resolve(strict=True) != root / 'colima'
            or Path(env['HOME']).resolve(strict=True) != root / 'home'
            or root.name != 'fixture' or not root.parent.name.startswith('ur.005-storage.')
            or home.stat().st_mode & 0o077
            or any(key in env for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'COLIMA_PROFILE'))):
        raise ValueError('formatter_private_scope_refused')
    return [bound_colima(env), 'nerdctl', '--profile', 'effigy', '--',
            'version', '--format', VERSION_TEMPLATE]


def version_projection(raw):
    if len(raw) > 512:
        raise ValueError('formatter_version_unknown')
    match = re.fullmatch(rb'(v?[0-9]+\.[0-9]+\.[0-9]+)\|([0-9a-f]{40})\|linux\|(arm64|amd64)\n', raw)
    if not match:
        raise ValueError('formatter_version_unknown')
    version, commit, arch = (item.decode('ascii') for item in match.groups())
    return {'version': version, 'git_commit': commit, 'os': 'linux', 'arch': arch,
            'evidence': 'reported_metadata_not_cryptographic_attestation'}


def formatter_projection(source):
    if len(source) > 262144:
        raise ValueError('formatter_source_unknown')
    try:
        text = source.decode('utf-8')
        start = text.index('func FormatPorts(ports []cni.PortMapping) string {')
        position = start + text[start:].index('{')
        depth = 1
        end = position + 1
        while depth and end < len(text):
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        actual = text[start:end]
        if depth or re.sub(r'\s+', '', actual) != re.sub(r'\s+', '', FORMAT_PORTS):
            raise ValueError('formatter_source_unknown')
    except (UnicodeDecodeError, ValueError):
        raise ValueError('formatter_source_unknown') from None
    return {'formatter_sha256': hashlib.sha256(source).hexdigest(),
            'relationship': 'reported_commit_source_matches_reviewed_CNI_mapping_formatter',
            'binary_source_attestation': False}


def observe(env, fixture, journal):
    args = version_arguments(env, fixture)
    before = host_identity(args[0])
    captured = bounded_run(args, env=env, timeout=15, cap=16384)
    journal.append('formatter_version_input', outcome=captured['outcome'], exit=captured['exit'],
                   stdout_bytes=captured['stdout_bytes'], stderr_bytes=captured['stderr_bytes'],
                   stdout_sha256=hashlib.sha256(captured['stdout']).hexdigest(),
                   stderr_sha256=hashlib.sha256(captured['stderr']).hexdigest(),
                   host=before, evidence='current_input_before_validation')
    if (captured['outcome'] != 'complete' or captured['exit'] or captured['stderr_bytes']
            or host_identity(args[0]) != before):
        raise ValueError('formatter_capture_refused')
    metadata = version_projection(captured['stdout'])
    journal.append('formatter_metadata', **metadata)
    # Read only immutable public source at the reported full commit. No guest
    # upgrade, RPC fallback, or source equivalence inferred from a version label.
    url = 'https://raw.githubusercontent.com/containerd/nerdctl/' + metadata['git_commit'] + '/pkg/formatter/formatter.go'
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            source = response.read(262145)
    except Exception:
        raise ValueError('formatter_source_unavailable') from None
    projection = formatter_projection(source)
    journal.append('formatter_source', git_commit=metadata['git_commit'], **projection)
    return {**metadata, **projection}
