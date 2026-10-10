# Underlay Effigy Bundle

Git-hosted bundle for the Underlay-style Rust + Bun workspace stack.

## Usage

In your repo's `effigy.toml`:

```toml
[bundle]
base = { type = "git", url = "git@github.com:inflatable-cookie/underlay-effigy-bundle.git" }
host = "acme.test"
workspace_subdir = "acme"
databases = ["acme", "acme_test"]
```

When `project_name` is omitted, the bundle derives one from
`<workspace_subdir>-underlay`, for example `acme-underlay`.

## Inputs

See `bundle.toml` for the full input schema.

Key required inputs:
- `host` — Primary local hostname
- `workspace_subdir` — Repo path under `/workspace-root`
- `databases` — Postgres databases to create

Optional inputs:
- `browser_runtime` — Workspace image browser layer (`"none"` by default,
  `"chromium"` for the opt-in Chromium system libraries). Requires
  Effigy `>= 0.13.1`; older releases reject this bundle revision on the
  `minimum_effigy_version` floor instead of silently ignoring the setting.
- `sources.siblings` — `true` by default, preserving the sibling Underlay and
  Poodle checkout workflow. Set it to `false` when using released packages;
  the bundle then omits sibling catalogs, bootstrap children and dependency
  sync, Underlay validation, and sibling hydration in the UI setup helper.

For consumers that use released Underlay and Poodle packages, opt out of
sibling checkouts in the bundle inputs:

```toml
[bundle.sources]
siblings = false
```

## Development profile qualification

The bundle owns opt-in Rust/Vite managed-listener adapters and a SvelteKit
development public-origin hook in `scripts/dev/`. They use Effigy's owned
loopback binding, generation report, readiness and dependency interfaces. The
hook validates a configured HTTPS origin and keeps SvelteKit's event/request
URLs coherent behind the private HTTPS gateway. Consumer default selectors
remain container-based; this change supplies qualification machinery and
explicit disposable consumer overrides.

Use the approved private Effigy source and binary:

```sh
export UNDERLAY_PROFILE_EFFIGY_SOURCE=/path/to/private/effigy
export UNDERLAY_PROFILE_EFFIGY_BIN=/path/to/private/effigy/target/release/effigy
export UNDERLAY_REFERENCE_SOURCE=~/Dev/projects/underlay-reference
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:public-origin
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-runtime
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-container
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:silo-contract-tests
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:silo-artifacts
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-storage
```

The scripts verify Effigy source
`2f7b1819fd0e72afff18a6053be424719ecf71fc` and private `effigy v0.14.1`
binary SHA-256
`2f4f888c76f424d41cc981881bc544a14fb82f024c0c50a2e3b5022bd4fb16fc`.
The runtime selectors pull approved digest-pinned PGSTY Silo and MC images,
create fresh private Reference main/worktree instances and retain redacted
receipts outside the repository. They use a private gateway/CA and isolated
Colima runtime without installing system trust or changing the operator
checkout. See [development profile ownership](docs/knowledge/contracts/dev-profiles.md)
for interfaces, prerequisites and selector coverage.

The retained Reference pilot proves three concurrent actual API/front/admin
stacks, owned readiness before routes, public HTTPS origins/HMR,
Postgres/SMTP connectivity, restart/dependent propagation, collision,
interruption recovery and isolated teardown. Its former source-built upstream
MinIO receipts are historical evidence. Current storage qualification uses
published PGSTY Silo and MC through fixture-only overrides; Silo is a downstream
fork, not unchanged upstream MinIO. Real Reference presigned HTTPS upload,
API finalisation, signed download/delete, credentials/CORS controls and owned
cleanup passed. Container-only build/start also passed with that override. The original published default MinIO image pull remains
unqualified (`insufficient_scope`); Silo does not repair that registry access.
No hybrid/dev:test consumer migration or default switch is delivered.

## Browser runtime (`browser_runtime`)

The bundle forwards `browser_runtime` to the `workspace-rust-bun` catalog
service as its `BROWSER_RUNTIME` image build arg:

```toml
[bundle]
# ... required inputs ...
browser_runtime = "chromium"
```

- `none` (default) leaves the ordinary Rust/Bun image unchanged.
- `chromium` installs Debian Bookworm Chromium runtime libraries and a
  basic font set as root at image build. Unknown values fail the image
  build.
- Changing the value requires rebuilding the workspace image (for example
  `effigy container reset --keep-data` followed by `effigy container up`)
  before the new layer takes effect. Always pass `--keep-data`: a plain
  `reset` deletes persistent named volumes, including local database data.
- The image ships no browser binary, Playwright, or Node. The consuming
  repo owns its matching browser installation into the `dev` user cache
  (for example `bunx playwright install --only-shell chromium` or the
  Playwright revision its lockfile pins), after the rebuilt image is up.

## Bundle-owned secrets

The bundle declares the shared Underlay runtime secret contract, including:

- `auth_jwt_private_key`
- `auth_jwt_public_key`
- `auth_oauth_secret_key`
- `encryption_key`
- `aws_access_key_id`
- `aws_secret_access_key`
- `smtp_password`
- `auth_google_client_secret`

App-specific secrets should stay in the consuming repo.
