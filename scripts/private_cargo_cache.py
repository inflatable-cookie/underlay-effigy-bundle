"""Qualification-only exact-lock offline public Cargo input admission."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
INDEX = 'index.crates.io-1949cf8c6b5b557f'
GIT = {
    'git+ssh://git@github.com/inflatable-cookie/underlay.git?tag=v0.10.3#72d6fd91a3096ffd85b2ab25e9f5cff8bb6e6d03': ('underlay-d2d5ac68e32e8122', '72d6fd91a3096ffd85b2ab25e9f5cff8bb6e6d03', 'v0.10.3'),
    'git+https://github.com/inflatable-cookie/nightfire.git?tag=v0.4.1#ccce719c27387d0eae2456ae07d2c169b3244c3f': ('nightfire-e9eed1c9fe662d4f', 'ccce719c27387d0eae2456ae07d2c169b3244c3f', 'v0.4.1'),
}


class CacheRefused(RuntimeError):
    def __init__(self, reason, package=None):
        self.reason = reason
        self.package = package
        super().__init__(reason)


def read_public(path, root, cap):
    path = Path(path); root = Path(root)
    if not path.is_relative_to(root) or '..' in path.relative_to(root).parts: raise CacheRefused('source_path_escape')
    for component in (root, *path.relative_to(root).parents):
        candidate = component if component == root else root / component
        if candidate.is_symlink(): raise CacheRefused('source_symlink')
    try: fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError: raise CacheRefused('source_file_unavailable') from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
            raise CacheRefused('source_file_bound')
        with os.fdopen(os.dup(fd), 'rb') as source: data = source.read(cap + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
            raise CacheRefused('source_copy_mutation')
        return data
    finally: os.close(fd)


def lock_packages(raw):
    # Closed Cargo-generated v4 grammar; no general TOML parser or dependency install.
    try: text = raw.decode('utf-8')
    except UnicodeError: raise CacheRefused('lock_encoding') from None
    sections = text.split('[[package]]')
    if not re.fullmatch(r'(?:#[^\n]*\n|\s)*version = 4\s*', sections[0]):
        raise CacheRefused('lock_version')
    packages = []; seen = set()
    for block in sections[1:]:
        fields = {}; in_dependencies = False
        for line in block.splitlines():
            if not line.strip() or line.startswith('#'): continue
            if line == 'dependencies = [':
                if in_dependencies: raise CacheRefused('lock_grammar')
                in_dependencies = True; continue
            if in_dependencies:
                if line == ']': in_dependencies = False; continue
                if not re.fullmatch(r' "[A-Za-z0-9_.+:/?=#@() -]+",', line): raise CacheRefused('lock_dependency_grammar')
                continue
            match = re.fullmatch(r'(name|version|source|checksum) = "([^"\\]+)"', line)
            if not match or match[1] in fields: raise CacheRefused('lock_field')
            fields[match[1]] = match[2]
        if in_dependencies or not {'name', 'version'} <= set(fields): raise CacheRefused('lock_incomplete')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', fields['name']) or not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]*', fields['version']): raise CacheRefused('lock_package_identity')
        identity = tuple(fields.get(x) for x in ('name', 'version', 'source'))
        if identity in seen: raise CacheRefused('lock_duplicate')
        seen.add(identity)
        source = fields.get('source')
        if source == REGISTRY:
            if not re.fullmatch(r'[0-9a-f]{64}', fields.get('checksum', '')): raise CacheRefused('lock_checksum')
        elif source is not None and source not in GIT: raise CacheRefused('lock_source')
        packages.append(fields)
    if not packages: raise CacheRefused('lock_empty')
    return packages


def index_path(name):
    if len(name) == 1: return '1/' + name
    if len(name) == 2: return '2/' + name
    if len(name) == 3: return '3/' + name[0] + '/' + name
    return name[:2] + '/' + name[2:4] + '/' + name


def admit_index(raw, package):
    if not raw.startswith(b'\x03\x02\x00\x00\x00'): raise CacheRefused('index_version', package['name'])
    parts = raw[5:].split(b'\x00')
    if not parts[-1] == b'' or len(parts) % 2: raise CacheRefused('index_framing', package['name'])
    matched = []
    for version, entry in zip(parts[1:-1:2], parts[2:-1:2]):
        def unique(pairs):
            value = {}
            for k, v in pairs:
                if k in value: raise CacheRefused('index_duplicate')
                value[k] = v
            return value
        try: item = json.loads(entry, object_pairs_hook=unique)
        except (ValueError, UnicodeError): raise CacheRefused('index_json', package['name']) from None
        if type(item) is not dict: raise CacheRefused('index_type', package['name'])
        if item.get('name') != package['name'] or item.get('vers', '').encode() != version: raise CacheRefused('index_identity', package['name'])
        if item['vers'] == package['version']: matched.append(item)
    if len(matched) != 1 or matched[0].get('cksum') != package['checksum']: raise CacheRefused('index_lock_checksum', package['name'])


def write_new(path, raw):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output: output.write(raw)


def git(args, env, *, input=None):
    # Object reads are separately finite and never invoke Cargo or network.
    result = subprocess.run(['git', *args], env=env, input=input, capture_output=True, timeout=30)
    if result.returncode or len(result.stdout) > 1048576 or len(result.stderr) > 16384: raise CacheRefused('git_object_read')
    return result.stdout


def initialize(checkout, cargo_home, target, env, *, host_cache=Path('/Users/tom/.cargo')):
    checkout = Path(checkout); cargo_home = Path(cargo_home); target = Path(target); host_cache = Path(host_cache)
    if not cargo_home.is_absolute() or cargo_home.is_symlink() or target.is_symlink() or cargo_home == host_cache or cargo_home.is_relative_to(host_cache): raise CacheRefused('private_cache_boundary')
    if cargo_home.exists() and list(cargo_home.iterdir()): raise CacheRefused('private_cache_not_empty')
    fixture = Path(env.get('UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT', ''))
    if not fixture.is_absolute() or fixture.is_symlink() or not all(p.resolve().is_relative_to(fixture.resolve(strict=True)) for p in (checkout, cargo_home, target)):
        raise CacheRefused('private_cache_path_escape')
    for path in (cargo_home, target):
        if any(part.is_symlink() for part in (path, *path.parents) if part.is_relative_to(fixture)):
            raise CacheRefused('private_cache_symlink')
    original = dict(env)
    if any(k.startswith(('SSH', 'CARGO_')) for k in env if k not in ('CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS')): raise CacheRefused('private_cache_environment')
    lock = read_public(checkout/'apps/acme-api/Cargo.lock', checkout, 1048576)
    packages = lock_packages(lock)
    cargo_home.mkdir(mode=0o700, parents=True, exist_ok=True); target.mkdir(mode=0o700, parents=True, exist_ok=True)
    child = dict(env); child.update(CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(target), CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='2', GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
    records = []
    for p in packages:
        if p.get('source') != REGISTRY: continue
        filename = p['name']+'-'+p['version']+'.crate'
        candidates = [host_cache/'registry/cache'/index/filename for index in (INDEX, 'index.crates.io-6f17d22bba15001f')]
        path = next((x for x in candidates if x.exists()), None)
        if path is None: raise CacheRefused('registry_archive_missing', p['name']+'@'+p['version'])
        try: archive = read_public(path, host_cache, 67108864)
        except CacheRefused as error: raise CacheRefused(error.reason, p['name']+'@'+p['version']) from None
        if hashlib.sha256(archive).hexdigest() != p['checksum']: raise CacheRefused('registry_archive_checksum', p['name']+'@'+p['version'])
        metadata_path = host_cache/'registry/index'/INDEX/'.cache'/index_path(p['name'])
        if not metadata_path.exists(): raise CacheRefused('registry_index_missing', p['name']+'@'+p['version'])
        try: metadata = read_public(metadata_path, host_cache, 8388608)
        except CacheRefused as error: raise CacheRefused(error.reason, p['name']+'@'+p['version']) from None
        admit_index(metadata, p)
        write_new(cargo_home/'registry/cache'/INDEX/filename, archive)
        private_index = cargo_home/'registry/index'/INDEX/'.cache'/index_path(p['name'])
        if not private_index.exists(): write_new(private_index, metadata)
        elif private_index.read_bytes() != metadata: raise CacheRefused('private_index_mutation')
        records.append({'package':p['name'],'version':p['version'],'checksum':p['checksum'],'index_sha256':hashlib.sha256(metadata).hexdigest()})
    write_new(cargo_home/'registry/index'/INDEX/'config.json', b'{"dl":"https://static.crates.io/crates","api":"https://crates.io"}\n')
    git_records = []
    for source in sorted({p['source'] for p in packages if p.get('source') in GIT}):
        name, commit, tag = GIT[source]; origin = host_cache/'git/db'/name
        if origin.is_symlink(): raise CacheRefused('git_source_symlink')
        actual = git(['--git-dir='+str(origin),'rev-parse',commit+'^{commit}'],child).decode().strip()
        tree = git(['--git-dir='+str(origin),'rev-parse',commit+'^{tree}'],child).decode().strip()
        if actual != commit or not re.fullmatch(r'[0-9a-f]{40}',tree): raise CacheRefused('git_locked_commit')
        if name.startswith('underlay-'):
            tagged = git(['-C','/Users/tom/Dev/projects/underlay','rev-parse',tag+'^{commit}'],child).decode().strip()
            if tagged != commit: raise CacheRefused('git_tag_commit')
        private = cargo_home/'git/db'/name
        git(['init','--bare','--template=',str(private)],child)
        # Local file transport only; no host configuration, hooks or alternates copied.
        git(['--git-dir='+str(private),'-c','protocol.file.allow=always','fetch','--no-tags',str(origin),commit],child)
        git(['--git-dir='+str(private),'update-ref','refs/tags/'+tag,commit],child)
        for path in ('hooks','objects/info/alternates','config.worktree'):
            if (private/path).exists(): raise CacheRefused('private_git_forbidden_metadata')
        if git(['--git-dir='+str(private),'rev-parse',commit+'^{tree}'],child).decode().strip() != tree: raise CacheRefused('private_git_tree')
        # Replace init's local core-only config with the same closed core recipe.
        (private/'config').write_text('[core]\n\trepositoryformatversion = 0\n\tbare = true\n\tfilemode = true\n')
        git_records.append({'commit':commit,'tree':tree,'tag':tag})
    if read_public(checkout/'apps/acme-api/Cargo.lock',checkout,1048576) != lock or dict(env) != original: raise CacheRefused('cache_input_mutated')
    receipt = {'schema':'underlay.private-cargo-inputs.v1','lock_sha256':hashlib.sha256(lock).hexdigest(),'registry':records,'git':git_records,'offline':True,'build_jobs':2,'credentials_copied':False,'target_artifacts_copied':False,'ambient_mutated':False,'private_cargo_home':str(cargo_home),'private_target':str(target)}
    receipt['private_inputs'] = {str(p.relative_to(cargo_home)):hashlib.sha256(read_public(p,cargo_home,134217728)).hexdigest() for p in cargo_home.rglob('*') if p.is_file()}
    write_new(cargo_home/'admission.json', json.dumps(receipt,sort_keys=True).encode())
    return child, receipt


def verify(env, receipt):
    root = Path(env.get('CARGO_HOME', ''))
    if not root.is_absolute() or root.is_symlink() or env.get('CARGO_NET_OFFLINE') != 'true' or env.get('CARGO_BUILD_JOBS') != '2':
        raise CacheRefused('private_cache_context_changed')
    if str(root) != receipt['private_cargo_home'] or env.get('CARGO_TARGET_DIR') != receipt['private_target']:
        raise CacheRefused('private_cache_context_changed')
    for name in ('config', 'config.toml', 'credentials', 'credentials.toml'):
        if (root/name).exists(): raise CacheRefused('private_cache_config_or_credentials')
    for private in (root/'git/db').glob('*'):
        for name in ('hooks', 'objects/info/alternates', 'config.worktree'):
            if (private/name).exists(): raise CacheRefused('private_git_forbidden_metadata')
    for name, digest in receipt['private_inputs'].items():
        path = root/name
        if hashlib.sha256(read_public(path, root, 134217728)).hexdigest() != digest:
            raise CacheRefused('private_cache_input_changed')
    return True


def verify_environment(env):
    root = Path(env.get('CARGO_HOME', ''))
    if not root.is_absolute(): raise CacheRefused('private_cache_context_missing')
    raw = read_public(root/'admission.json',root,1048576)
    def unique(pairs):
        out = {}
        for key,value in pairs:
            if key in out: raise CacheRefused('private_admission_duplicate')
            out[key]=value
        return out
    try: receipt = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError): raise CacheRefused('private_admission_json') from None
    if type(receipt) is not dict or receipt.get('schema') != 'underlay.private-cargo-inputs.v1': raise CacheRefused('private_admission_schema')
    verify(env,receipt)
    return receipt


def summary(receipt):
    # The full public-input manifest stays in its own bounded private file.
    # Do not spend the fixed runtime journal budget on hundreds of package rows.
    return {'schema':receipt['schema'],'lock_sha256':receipt['lock_sha256'],
            'registry_package_count':len(receipt['registry']),
            'private_input_count':len(receipt['private_inputs']),
            'git':receipt['git'],'offline':receipt['offline'],
            'build_jobs':receipt['build_jobs'],
            'admission_sha256':hashlib.sha256(json.dumps(receipt,sort_keys=True).encode()).hexdigest()}
