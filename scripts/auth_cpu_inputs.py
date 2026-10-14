"""Bounded archive identity and fresh Cargo source provenance."""
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

# Retained cache: largest archive 9,679,450 bytes; aggregate 53,304,128.
COMPRESSED = 16 * 1024 * 1024
EXPANDED = 128 * 1024 * 1024
MEMBERS = 8192
FILE = 32 * 1024 * 1024


class Refusal(ValueError):
    pass


def read_file(path, cap):
    path = Path(path)
    for parent in (path, *path.parents):
        if parent.is_symlink(): raise Refusal('symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > cap:
            raise Refusal('file_shape_or_limit')
        data = bytearray()
        while len(data) <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
        after = os.fstat(fd)
        current = path.lstat()
        fields = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
        if len(data)>cap or fields(before)!=fields(after) or fields(after)!=fields(current):
            raise Refusal('changed_or_limit')
        return bytes(data)
    finally:
        os.close(fd)


def archive(path, name, version, checksum):
    raw = read_file(path, COMPRESSED)
    if hashlib.sha256(raw).hexdigest() != checksum: raise Refusal('archive_checksum')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            expanded = stream.read(EXPANDED + 1)
        if len(expanded)>EXPANDED: raise Refusal('expanded_limit')
        prefix = name+'-'+version
        files = {}; seen = set(); count = 0
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as stream:
            for member in stream:
                count += 1
                if count>MEMBERS: raise Refusal('member_limit')
                parts = PurePosixPath(member.name).parts
                canonical = '/'.join(parts)
                if (not parts or parts[0]!=prefix or any(p in ('.','..') for p in parts)
                        or member.name.rstrip('/')!=canonical or canonical in seen):
                    raise Refusal('member_path_or_duplicate')
                seen.add(canonical)
                if member.isdir(): continue
                if not member.isfile() or member.size>FILE or len(parts)<2:
                    raise Refusal('member_type_or_limit')
                data = stream.extractfile(member).read(FILE+1)
                if len(data)!=member.size: raise Refusal('member_size')
                files['/'.join(parts[1:])] = (hashlib.sha256(data).hexdigest(),bool(member.mode & 0o111))
        if 'Cargo.toml' not in files: raise Refusal('package_manifest')
        return raw, files, {'compressed_bytes':len(raw),'expanded_bytes':len(expanded),'members':count,'files':len(files),'sha256':checksum}
    except (tarfile.TarError, EOFError, OSError):
        raise Refusal('archive_format') from None


def unique_archive(cache, name, version):
    matches = list(Path(cache).glob('*/'+name+'-'+version+'.crate'))
    if len(matches)!=1: raise Refusal('archive_missing_or_duplicate')
    return matches[0]


def source_agrees(directory, expected):
    observed = {}
    for path in Path(directory).rglob('*'):
        if path.is_symlink(): raise Refusal('source_symlink')
        if path.is_dir(): continue
        relative = path.relative_to(directory).as_posix()
        data = read_file(path, FILE)
        if relative=='.cargo-ok':
            # Cargo's unpack-complete marker is not source or checksum authority.
            if len(data)>256: raise Refusal('generated_marker_limit')
            continue
        observed[relative] = (hashlib.sha256(data).hexdigest(),bool(path.stat().st_mode & 0o111))
    if observed!=expected: raise Refusal('source_members_changed')


def admit_cache(cache, lock, destination):
    admitted = {}; total = 0
    for (name,version),(source,checksum) in lock.items():
        if not source or not source.startswith('registry+'): continue
        matches = list(Path(cache).glob('*/'+name+'-'+version+'.crate'))
        if not matches: continue  # Optional, unselected package: no credit.
        path = unique_archive(cache,name,version)
        raw, files, evidence = archive(path,name,version,checksum)
        total += len(raw)
        if total>128*1024*1024: raise Refusal('aggregate_archive_limit')
        target = Path(destination)/path.parent.name/path.name
        target.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream: stream.write(raw)
        admitted[name+'-'+version]=(files,evidence)
    return admitted
