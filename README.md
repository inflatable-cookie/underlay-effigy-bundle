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

Run `effigy proof:dev-profiles` to assemble the bundle in a private consumer
fixture and exercise the supported host-listener boundary. The proof uses a
private checkout and two private worktrees, leaves the container runtime,
gateway daemon and system resolver untouched, and uses only OS-assigned host
ports. Default container startup is deliberately not part of this selector:
the bundle's TLS routes require Effigy's `mkcert -install` path, which can
change the host trust store. The disposable fixture goes under `~/Dev/projects`
when that directory exists; set `UNDERLAY_PROFILE_FIXTURE_PARENT` to another
existing directory when needed.

The designated Underlay Reference pilot uses `effigy proof:dev-profiles:reference`.
It reads a clean checkout at `~/Dev/projects/underlay-reference` by default;
set `UNDERLAY_REFERENCE_SOURCE` to another clean Reference checkout when needed.
The selector clones it into a fresh temporary directory, makes two private
worktrees, points their bundle source at this checkout, and checks Reference
configuration and task plans. It does not start apps or containers or invoke
TLS, gateway, or resolver operations.

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
