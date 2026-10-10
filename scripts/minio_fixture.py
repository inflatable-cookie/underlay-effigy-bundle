"""Pinned, task-private MinIO image builder for Reference qualification."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath


PACKET_ROOT = Path.home() / ".local/share/northstar/release-audits/underlay-effigy-bundle/reference-prerequisites-2026-10-10"
MINIO_VERSION = "RELEASE.2025-09-07T16-13-09Z"
MINIO_COMMIT = "07c3a429bfed433e49018cb0f78a52145d4bedeb"
MINIO_TAG_OBJECT = "01ce918d8279a20e4706b96a64396146894adee4"
MINIO_ARCHIVE_SHA256 = "8819e3e7817e46b7b3798f8f200ead208562e571563c2e040352378031abe9f2"
MC_VERSION = "RELEASE.2025-08-13T08-35-41Z"
MC_COMMIT = "7394ce0dd2a80935aded936b09fa12cbb3cb8096"
MC_ARCHIVE_SHA256 = "95cd293c7119f16921a6dc515a1fb74a2227f19fd994b9c8b770a154e802ac44"
GO_BASE = "golang:1.24.6@sha256:8d9e57c5a6f2bede16fe674c16149eee20db6907129e02c4ad91ce5a697a4012"
ALPINE_BASE = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
IMAGE = "underlay-reference/minio:release-2025-09-07-fixture"


def command(args: list[str], *, env: dict[str, str], cwd: Path | None = None, timeout: int = 3600) -> str:
    print(f"COMMAND: {' '.join(args)}", flush=True)
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    print(f"EXIT: {result.returncode}", flush=True)
    if result.stdout.strip():
        print(result.stdout.rstrip(), flush=True)
    if result.stderr.strip():
        print(result.stderr.rstrip(), flush=True)
    if result.returncode:
        # Preserve enough bounded build context for a private fixture failure
        # receipt to identify the failing stage without dumping an unbounded
        # compiler log or any task environment values.
        stderr = result.stderr.rstrip()[-3600:]
        stdout = result.stdout.rstrip()[-1200:]
        excerpt = "\n".join(part for part in (stderr, stdout) if part)
        raise RuntimeError(
            f"command exited {result.returncode}: {' '.join(args)}"
            + (f"\nbounded command output tail:\n{excerpt}" if excerpt else "")
        )
    return result.stdout


def _source_records() -> dict[str, dict]:
    packet = json.loads((PACKET_ROOT / "sources.json").read_text(encoding="utf-8"))
    if not isinstance(packet, list):
        raise RuntimeError("prepared sources.json must be a list")
    result = {record.get("name"): record for record in packet if isinstance(record, dict)}
    expected = {
        "minio": (MINIO_COMMIT, MINIO_ARCHIVE_SHA256),
        "mc": (MC_COMMIT, MC_ARCHIVE_SHA256),
    }
    for name, (commit, digest) in expected.items():
        record = result.get(name)
        if not record or record.get("commit") != commit or record.get("sha256") != digest:
            raise RuntimeError(f"prepared source record for {name} differs from the approved pin")
        if record.get("url") != f"https://codeload.github.com/minio/{name}/tar.gz/{commit}":
            raise RuntimeError(f"prepared source URL for {name} is not the pinned codeload archive")
    return result


def _safe_extract(archive: Path, destination: Path, expected_sha: str, expected_root: str) -> Path:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != expected_sha:
        raise RuntimeError(f"pinned archive hash mismatch for {archive.name}: {digest}")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != expected_root:
                raise RuntimeError(f"unsafe or unexpected archive path in {archive.name}")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise RuntimeError(f"unexpected link or special file in {archive.name}: {member.name}")
            if not (member.isdir() or member.isfile()):
                raise RuntimeError(f"unexpected non-file archive member in {archive.name}: {member.name}")
        # Avoid tarfile's platform-dependent extraction filters while keeping
        # the same safety contract on the bundled Python version: no links,
        # special files, traversal paths, or writes outside destination.
        root = destination.resolve(strict=True)
        for member in members:
            name = PurePosixPath(member.name)
            target = destination.joinpath(*name.parts)
            if root not in target.parents and target != root:
                raise RuntimeError(f"archive target escaped its private root: {member.name}")
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise RuntimeError(f"could not read regular archive member {member.name}")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    source = destination / expected_root
    if not (source / "go.mod").is_file() or not (source / "go.sum").is_file():
        raise RuntimeError(f"pinned source archive is missing go.mod/go.sum: {archive.name}")
    return source


def _write_dockerfile(build_root: Path) -> None:
    dockerfile = f"""FROM {GO_BASE} AS source-build
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org,direct
WORKDIR /src/minio
COPY minio/ ./
RUN mkdir -p /out && test -s go.mod && test -s go.sum && go mod download && go mod verify && \\
    GOOS=linux GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w -X github.com/minio/minio/cmd.Version={MINIO_VERSION} -X github.com/minio/minio/cmd.CopyrightYear=2025 -X github.com/minio/minio/cmd.ReleaseTag={MINIO_VERSION} -X github.com/minio/minio/cmd.CommitID={MINIO_COMMIT} -X github.com/minio/minio/cmd.ShortCommitID={MINIO_COMMIT[:12]}' -o /out/minio .

WORKDIR /src/mc
COPY mc/ ./
RUN mkdir -p /out && test -s go.mod && test -s go.sum && go mod download && go mod verify && \\
    GOOS=linux GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w -X github.com/minio/mc/cmd.Version={MC_VERSION} -X github.com/minio/mc/cmd.CopyrightYear=2025 -X github.com/minio/mc/cmd.ReleaseTag={MC_VERSION} -X github.com/minio/mc/cmd.CommitID={MC_COMMIT} -X github.com/minio/mc/cmd.ShortCommitID={MC_COMMIT[:12]}' -o /out/mc .

FROM {ALPINE_BASE} AS runtime
COPY --from=source-build /out/minio /usr/bin/minio
COPY --from=source-build /out/mc /usr/bin/mc
COPY --from=source-build /src/minio/dockerscripts/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh
COPY --from=source-build /src/minio/LICENSE /licenses/minio/LICENSE
COPY --from=source-build /src/mc/LICENSE /licenses/mc/LICENSE
COPY --from=source-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN chmod 0755 /usr/bin/minio /usr/bin/mc /usr/bin/docker-entrypoint.sh && mkdir -p /data /licenses/minio /licenses/mc
VOLUME ["/data"]
ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
CMD ["minio"]
"""
    (build_root / "Containerfile").write_text(dockerfile, encoding="utf-8")


def prepare_source_image(runtime_root: Path, environment: dict[str, str]) -> dict[str, str]:
    """Verify pinned inputs and build a local image in task-private Colima."""
    records = _source_records()
    # Colima mounts the private HOME into its guest. Keep the build context
    # inside that mount instead of the fixture root's sibling path; otherwise
    # nerdctl resolves a relative Containerfile under HOME and cannot see the
    # host context.
    build_root = Path(environment["HOME"]).resolve(strict=True) / "minio-source-build"
    build_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources_root = build_root / "source"
    sources_root.mkdir(mode=0o700)
    minio_record = records["minio"]
    mc_record = records["mc"]
    minio_archive = Path(minio_record["path"]).expanduser().resolve(strict=True)
    mc_archive = Path(mc_record["path"]).expanduser().resolve(strict=True)
    minio_source = _safe_extract(
        minio_archive,
        sources_root / "minio-extract",
        MINIO_ARCHIVE_SHA256,
        f"minio-{MINIO_COMMIT}",
    )
    mc_source = _safe_extract(
        mc_archive,
        sources_root / "mc-extract",
        MC_ARCHIVE_SHA256,
        f"mc-{MC_COMMIT}",
    )
    # Docker receives only the two pinned source trees and this owned Dockerfile.
    shutil.copytree(minio_source, build_root / "minio", symlinks=False)
    shutil.copytree(mc_source, build_root / "mc", symlinks=False)
    _write_dockerfile(build_root)

    runtime_env = environment.copy()
    colima_home = Path(runtime_env["COLIMA_HOME"]).resolve(strict=True)
    if colima_home == Path.home().resolve() or runtime_root.resolve() not in colima_home.parents:
        raise RuntimeError("Colima profile home is not isolated beneath this task's private root")
    arch_output = command(
        ["colima", "ssh", "--profile", "effigy", "--", "uname", "-m"],
        env=runtime_env,
        timeout=60,
    ).strip()
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(arch_output)
    if not arch:
        raise RuntimeError(f"unsupported private Colima guest architecture: {arch_output}")
    command(
        [
            "colima", "nerdctl", "--profile", "effigy", "--", "build",
            "--platform", f"linux/{arch}", "--tag", IMAGE,
            "--file", str(build_root / "Containerfile"), str(build_root),
        ],
        env=runtime_env,
        timeout=5400,
    )
    minio_version = command(
        ["colima", "nerdctl", "--profile", "effigy", "--", "run", "--rm", "--entrypoint", "/usr/bin/minio", IMAGE, "--version"],
        env=runtime_env,
        timeout=60,
    )
    mc_version = command(
        ["colima", "nerdctl", "--profile", "effigy", "--", "run", "--rm", "--entrypoint", "/usr/bin/mc", IMAGE, "--version"],
        env=runtime_env,
        timeout=60,
    )
    if MINIO_VERSION not in minio_version or MINIO_COMMIT[:12] not in minio_version:
        raise RuntimeError("built MinIO binary did not report the pinned release and commit")
    if MC_VERSION not in mc_version or MC_COMMIT[:12] not in mc_version:
        raise RuntimeError("built mc binary did not report the pinned release and commit")
    binary_hashes = command(
        [
            "colima", "nerdctl", "--profile", "effigy", "--", "run", "--rm",
            "--entrypoint", "/bin/sh", IMAGE, "-c", "sha256sum /usr/bin/minio /usr/bin/mc",
        ],
        env=runtime_env,
        timeout=60,
    )
    hashes = {}
    for line in binary_hashes.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] in {"/usr/bin/minio", "/usr/bin/mc"}:
            hashes[fields[1].rsplit("/", 1)[1]] = fields[0]
    if set(hashes) != {"minio", "mc"}:
        raise RuntimeError("could not record hashes of both source-built MinIO executables")
    image_id = command(
        ["colima", "nerdctl", "--profile", "effigy", "--", "image", "inspect", "--format", "{{.Id}}", IMAGE],
        env=runtime_env,
        timeout=60,
    ).strip()
    result = {
        "image": IMAGE,
        "image_id": image_id,
        "platform": f"linux/{arch}",
        "minio_version": MINIO_VERSION,
        "minio_commit": MINIO_COMMIT,
        "minio_tag_object": MINIO_TAG_OBJECT,
        "minio_archive_sha256": MINIO_ARCHIVE_SHA256,
        "mc_version": MC_VERSION,
        "mc_commit": MC_COMMIT,
        "mc_archive_sha256": MC_ARCHIVE_SHA256,
        "minio_binary_sha256": hashes["minio"],
        "mc_binary_sha256": hashes["mc"],
        "go_base": GO_BASE,
        "alpine_base": ALPINE_BASE,
    }
    metadata = runtime_root / "minio-source-image.json"
    metadata.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"PASS pinned local MinIO source image: {json.dumps(result, sort_keys=True)}", flush=True)
    print("LIMIT: this local image does not qualify the unavailable published minio/minio catalog pull", flush=True)
    return result


def install_minio_catalog_override(effigy: str, checkout: Path, env: dict[str, str],
                                  cors_origin: str) -> str:
    """Use Effigy's documented project-local catalog override in a fixture."""
    command(
        [effigy, "--repo", str(checkout), "service", "extract", "minio", "--dir", "infra/dev/catalog", "--json"],
        env=env,
        timeout=60,
    )
    fragment = checkout / "infra/dev/catalog/minio/compose.fragment.yml"
    raw = fragment.read_text(encoding="utf-8")
    baseline = raw
    original = "image: minio/minio:{{ version }}"
    if original not in raw:
        raise RuntimeError("extracted MinIO catalog fragment differs from the pinned source baseline")
    raw = raw.replace(original, f"image: {IMAGE}")
    for before, after in (
        ('"{{ api_port }}:9000"', '"0:9000"'),
        ('"{{ console_port }}:9001"', '"0:9001"'),
    ):
        if before not in raw:
            raise RuntimeError(f"MinIO fixture catalog fragment lacks expected port mapping {before}")
        raw = raw.replace(before, after)
    marker = 'MINIO_ROOT_PASSWORD: "{{ root_password }}"'
    if marker not in raw:
        raise RuntimeError("MinIO fixture catalog fragment lacks the baseline root-password mapping")
    raw = raw.replace(
        marker,
        marker
        + "\n      MINIO_API_CORS_ALLOW_ORIGIN: " + json.dumps(cors_origin)
        + '\n      MC_HOST_local: "http://{{ root_user }}:{{ root_password }}@127.0.0.1:9000"',
    )
    fragment.write_text(raw, encoding="utf-8")
    print(
        f"FIXTURE ONLY: {checkout}/infra/dev/catalog/minio uses the exact-source image {IMAGE} and server CORS origin {cors_origin}; published default remains untouched",
        flush=True,
    )
    return baseline
