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

The bundle owns optional Rust and Vite managed-listener adapters in
`scripts/dev/`. They consume Effigy's loopback bind and generation report
variables. The Vite adapter also consumes the managed API public URL, writes
the Reference-style generated client URLs at process start, sets SvelteKit's
`ORIGIN`, and points the HMR WebSocket at the gateway's actual HTTPS port.
These adapters are not wired into the default `dev` selector; container
behavior and its published ports remain unchanged.

Run both qualification selectors with the privately built Effigy source and
binary from the approved owner handover:

```sh
export UNDERLAY_PROFILE_EFFIGY_SOURCE=/path/to/private/effigy
export UNDERLAY_PROFILE_EFFIGY_BIN=/path/to/private/effigy/target/release/effigy
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles

export UNDERLAY_REFERENCE_SOURCE=~/Dev/projects/underlay-reference
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference
```

The scripts reject other source revisions and binary hashes. Set
`UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT` to inventory a prepared private
Reference main checkout plus two worktrees and their runtime receipts. That
mode reads the fixture only and never starts, stops or edits it. It can verify
the private gateway using `EFFIGY_GATEWAY_PRIVATE_STATE_ROOT`; TLS clients
trust only the fixture CA.

The 2026-10-09 Reference run used clean source commit
`16b35df4bebe920b14eca9d43abc626de44cb617`, private sibling-disabled bundle
assembly, and isolated Colima services. Postgres connectivity and the Rust
API's direct loopback health request succeeded. Effigy's exact-source managed
listener verifier then timed out before publishing that API route, so the
Reference hybrid profile, browser origin/HMR path, restart propagation and
teardown are not qualified. The pinned MinIO image was denied by both
configured registries; the disposable run used a stub solely to reach the
remaining checks. This does not qualify the default service stack. See
[development profile ownership](docs/knowledge/contracts/dev-profiles.md) for
the complete receipts and limits.

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
