"""Pin the private Effigy binary used by the isolated profile proofs."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


SUPPORTED_EFFIGY_SOURCE = "2f7b1819fd0e72afff18a6053be424719ecf71fc"
SUPPORTED_EFFIGY_SHA256 = "2f4f888c76f424d41cc981881bc544a14fb82f024c0c50a2e3b5022bd4fb16fc"


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
    revision = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if revision != SUPPORTED_EFFIGY_SOURCE:
        raise RuntimeError(
            f"Effigy source must be {SUPPORTED_EFFIGY_SOURCE}, got {revision}"
        )

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

    print(f"EFFIGY SOURCE: {revision}", flush=True)
    print(f"EFFIGY BINARY: {binary}", flush=True)
    print(f"EFFIGY VERSION: {version}", flush=True)
    print(f"EFFIGY SHA256: {digest}", flush=True)
    return str(binary)
