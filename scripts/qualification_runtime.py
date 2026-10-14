"""Pin the private Effigy binary used by the isolated profile proofs."""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import subprocess
from pathlib import Path


SUPPORTED_EFFIGY_SOURCE = "bd2597693f7c4c9ad786896a9448a7e746ff13a8"
SUPPORTED_EFFIGY_SHA256 = "2d72c3df0d61c05a150d5d86c39b2ea931eca9549b794b559fa39d95dc002a59"


def require_effigy_binary() -> str:
    binary_value = os.environ.get("UNDERLAY_PROFILE_EFFIGY_BIN")
    source_value = os.environ.get("UNDERLAY_PROFILE_EFFIGY_SOURCE")
    if not binary_value or not source_value:
        raise RuntimeError(
            "set UNDERLAY_PROFILE_EFFIGY_BIN and UNDERLAY_PROFILE_EFFIGY_SOURCE "
            "to the privately built final-handover binary and source checkout"
        )

    binary = Path(binary_value).expanduser().resolve(strict=True)
    source = Path(source_value).expanduser().resolve(strict=True)
    if (platform.system(), platform.machine().lower()) != ("Darwin", "arm64"):
        raise RuntimeError("profile qualification binary is qualified only for macOS arm64")
    source_root = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    revision = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if source_root != str(source):
        raise RuntimeError("Effigy source path must name the qualified checkout root")
    if revision != SUPPORTED_EFFIGY_SOURCE:
        raise RuntimeError(
            f"Effigy source must be {SUPPORTED_EFFIGY_SOURCE}, got {revision}"
        )

    from dev.profile_launcher import SUPPORTED_TREE, SUPPORTED_API
    tree = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD^{tree}"],
                          check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    if tree != SUPPORTED_TREE or any(hashlib.sha256((source/name).read_bytes()).hexdigest() != digest
                                     for name,digest in SUPPORTED_API.items()):
        raise RuntimeError("qualified Effigy source tree/public API differs")
    cleanliness = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if cleanliness:
        raise RuntimeError("qualified Effigy source checkout has changes")
    before = binary.stat()
    if not stat.S_ISREG(before.st_mode) or not os.access(binary, os.X_OK):
        raise RuntimeError("qualified Effigy binary must be an executable regular file")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != SUPPORTED_EFFIGY_SHA256:
        raise RuntimeError(
            f"private Effigy binary hash differs from the supported build: {digest}"
        )
    version = subprocess.run(
        [str(binary), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if version != "effigy v0.14.1":
        raise RuntimeError(f"unexpected private Effigy binary version: {version}")
    after = binary.stat()
    final_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) or digest != final_digest:
        raise RuntimeError("private Effigy binary changed while its identity was being validated")

    print(f"EFFIGY SOURCE: {revision}", flush=True)
    print(f"EFFIGY BINARY: {binary}", flush=True)
    print(f"EFFIGY VERSION: {version}", flush=True)
    print(f"EFFIGY SHA256: {digest}", flush=True)
    return str(binary)
