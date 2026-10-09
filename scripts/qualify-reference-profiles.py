#!/usr/bin/env python3
"""Qualify safe Underlay Reference configuration and adapter plans."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DEFAULT_REFERENCE = Path.home() / "Dev" / "projects" / "underlay-reference"
EFFIGY = shutil.which("effigy")
EXPECTED_ADAPTERS = {
    "acme-api/api": ["cargo", "run", "-p", "acme-api"],
    "acme-admin/dev": ["vite", "dev", "--host", "0.0.0.0", "--force"],
    "acme-front/dev": ["vite", "dev", "--host", "0.0.0.0", "--force"],
}


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 60,
    expected: int = 0,
    show_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    print(f"COMMAND: {' '.join(args)}", flush=True)
    result = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    print(f"EXIT: {result.returncode}", flush=True)
    if show_output:
        if result.stdout:
            print(result.stdout.rstrip(), flush=True)
        if result.stderr:
            print(result.stderr.rstrip(), flush=True)
    else:
        print(
            f"OUTPUT: captured stdout={len(result.stdout)} bytes stderr={len(result.stderr)} bytes",
            flush=True,
        )
    if result.returncode != expected:
        raise RuntimeError(
            f"expected exit {expected}, got {result.returncode}: {' '.join(args)}"
        )
    return result


def effigy_json(checkout: Path, *args: str) -> dict:
    result = run(
        [EFFIGY, "--repo", str(checkout), *args],
        timeout=30,
        show_output=False,
    )
    return json.loads(result.stdout)


def manifest_section(manifest: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^\[{re.escape(name)}\]\s*\n(.*?)(?=^\[|\Z)", manifest
    )
    if not match:
        raise RuntimeError(f"missing manifest section [{name}]")
    return match.group(1)


def reference_source() -> Path:
    configured = os.environ.get("UNDERLAY_REFERENCE_SOURCE")
    source = Path(configured).expanduser() if configured else DEFAULT_REFERENCE
    source = source.resolve()
    if not source.is_dir():
        raise RuntimeError(
            "set UNDERLAY_REFERENCE_SOURCE to an existing clean underlay-reference checkout"
        )
    top = run(["git", "-C", str(source), "rev-parse", "--show-toplevel"], show_output=False)
    if Path(top.stdout.strip()).resolve() != source:
        raise RuntimeError(f"Reference source is not a repository root: {source}")
    dirty = run(["git", "-C", str(source), "status", "--porcelain"], show_output=False)
    if dirty.stdout.strip():
        raise RuntimeError(
            "Reference source has local changes; refusing to copy an ambiguous pilot state"
        )
    commit = run(["git", "-C", str(source), "rev-parse", "HEAD"], show_output=False)
    branch = run(["git", "-C", str(source), "branch", "--show-current"], show_output=False)
    print(
        f"REFERENCE SOURCE: {source} branch={branch.stdout.strip() or '(detached)'} "
        f"commit={commit.stdout.strip()}",
        flush=True,
    )
    return source


def make_reference_instances(source: Path, root: Path) -> list[Path]:
    main = root / "main"
    source_commit = run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], show_output=False
    ).stdout.strip()
    run(["git", "clone", "--no-hardlinks", "--local", str(source), str(main)], timeout=120)
    run(["git", "-C", str(main), "checkout", "--detach", source_commit], cwd=root)

    worktree_root = root / "worktrees"
    worktree_root.mkdir()
    worktrees = []
    for name in ("first", "second"):
        target = worktree_root / name
        run(
            ["git", "-C", str(main), "worktree", "add", "--detach", str(target), "HEAD"],
            cwd=root,
        )
        worktrees.append(target)
    return [main, *worktrees]


def point_bundle_at_task_branch(checkout: Path) -> None:
    manifest_path = checkout / "effigy.toml"
    manifest = manifest_path.read_text(encoding="utf-8")
    bundle_section = manifest_section(manifest, "bundle")
    current_source = re.search(r"(?m)^base\s*=\s*\{[^\n]*\}$", bundle_section)
    if not current_source or 'type = "git"' not in current_source.group(0):
        raise RuntimeError("Reference bundle source is not the expected released Git source")
    pattern = re.compile(r"(?m)^base\s*=\s*\{[^\n]*type\s*=\s*\"git\"[^\n]*\}$")
    replacement = f'base = {{ type = "path", dir = {json.dumps(REPO.as_posix())} }}'
    updated, count = pattern.subn(replacement, manifest, count=1)
    if count != 1:
        raise RuntimeError("could not replace exactly one Reference bundle source line")
    manifest_path.write_text(updated, encoding="utf-8")


def prove_reference_configuration(checkouts: list[Path]) -> None:
    for checkout in checkouts:
        point_bundle_at_task_branch(checkout)

    main = checkouts[0]
    bundle = effigy_json(main, "bundle", "inspect", "--json")["result"]
    assert bundle["source"]["source_type"] == "path"
    assert Path(bundle["source"]["source_path"]).resolve() == REPO.resolve()

    effective = run(
        [EFFIGY, "--repo", str(main), "config", "--inspect"],
        show_output=False,
    ).stdout
    effective_manifest = effective.split("Effective Manifest\n------------------\n", 1)[1]
    assert '[bundle.sources]\nsiblings = false' in effective_manifest
    assert 'catalog = "workspace-rust-bun"' in effective_manifest
    for port in (41001, 41002, 41003):
        assert f'"{port}:{port}"' in effective_manifest

    consumer_manifest = (main / "effigy.toml").read_text(encoding="utf-8")
    assert 'siblings = false' in manifest_section(consumer_manifest, "bundle.sources")
    assert 'project_name = "underlay-reference-dev"' in manifest_section(
        consumer_manifest, "bundle"
    )
    print(
        "PASS Reference assembly: branch bundle path, sources.siblings=false, "
        "workspace-rust-bun, and unchanged published ports 41001/41002/41003",
        flush=True,
    )

    app_config = (main / "config" / "effigy.toml").read_text(encoding="utf-8")
    api_runtime = manifest_section(app_config, "acme_api.runtime")
    api_database = manifest_section(app_config, "acme_api.database")
    assert 'host = "0.0.0.0"' in api_runtime
    assert "port = 41001" in api_runtime
    assert 'public_host = "api.acme.test"' in api_runtime
    assert 'url = "postgres://' in api_database
    assert "postgres.acme.test" in api_database

    front_config = (main / "apps" / "acme-front" / "vite.config.ts").read_text(
        encoding="utf-8"
    )
    admin_config = (main / "apps" / "acme-admin" / "vite.config.ts").read_text(
        encoding="utf-8"
    )
    assert re.search(r"port:\s*41003\b", front_config)
    assert re.search(r"port:\s*41002\b", admin_config)
    assert re.search(r"strictPort:\s*true", admin_config)
    assert re.search(r'"acme\.test"', front_config)
    assert re.search(r'"admin\.acme\.test"', admin_config)
    print(
        "PASS actual Reference adapter configuration: Rust API binds 0.0.0.0:41001; "
        "front Vite uses 41003; admin Vite strictly binds 41002; DB URL is "
        "postgres.acme.test and browser hosts are acme.test/admin.acme.test",
        flush=True,
    )


def prove_worktree_plans(checkouts: list[Path]) -> None:
    scopes = []
    domains = []
    for checkout in checkouts:
        scope = effigy_json(checkout, "container", "scope", "--json")["result"]["scope"]
        hosts = effigy_json(checkout, "container", "hosts", "--json")["result"]
        scopes.append(scope.get("token") or "primary")
        domains.append(hosts["base_domain"]["effective"])
        assert all(
            route["origin"] is None or route["origin"].startswith("https://")
            for route in hosts["routes"]
        )
        run([EFFIGY, "--repo", str(checkout), "dev", "--plan"], timeout=30)

    assert len(set(scopes)) == 3, scopes
    assert len(set(domains)) == 3, domains
    print(f"PASS Reference main/worktree scopes: {scopes}", flush=True)
    print(f"PASS Reference main/worktree HTTPS host maps: {domains}", flush=True)


def prove_real_adapter_task_plans(checkout: Path) -> None:
    tasks = run(
        [EFFIGY, "--repo", str(checkout), "tasks", "--json"],
        timeout=30,
        show_output=False,
    ).stdout
    for selector in EXPECTED_ADAPTERS:
        assert selector in tasks, f"missing Reference selector {selector}"

    plans = {}
    for selector, expected_tokens in EXPECTED_ADAPTERS.items():
        plan = run(
            [EFFIGY, "--repo", str(checkout), selector, "--plan"],
            timeout=30,
        ).stdout
        for token in expected_tokens:
            assert token in plan, f"{selector} plan missing {token!r}"
        plans[selector] = "resolved"
    print(f"PASS Reference Rust/Vite/SvelteKit Effigy adapter plans: {plans}", flush=True)


def main() -> int:
    if EFFIGY is None:
        raise RuntimeError("effigy must be installed to run this proof")
    source = reference_source()
    root = Path(tempfile.mkdtemp(prefix="underlay-reference-profile-"))
    print(f"PRIVATE FIXTURE ROOT: {root}", flush=True)
    try:
        checkouts = make_reference_instances(source, root)
        version = run([EFFIGY, "--version"], timeout=30).stdout.strip()
        print(f"EFFIGY: {version}", flush=True)
        prove_reference_configuration(checkouts)
        prove_worktree_plans(checkouts)
        prove_real_adapter_task_plans(checkouts[0])
        print(
            "NOT RUN: no container up/build, gateway/TLS helper, service startup, or "
            "host app launch; the required TLS isolation/authorization path is not established.",
            flush=True,
        )
        print(
            "BLOCKED: Reference host listeners have fixed ports and no bundle-owned "
            "host-child route ownership path; configuration/plans do not prove service "
            "reachability, HTTPS/HMR, restart, readiness publication, or isolated teardown.",
            flush=True,
        )
        return 0
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"REFERENCE QUALIFICATION FAILED: {error}", flush=True)
        raise SystemExit(1)
