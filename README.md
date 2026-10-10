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
The Reference pilot showed that setting `ORIGIN` does not make SvelteKit's
development `event.url.origin` reflect the public HTTPS scheme when its Vite
listener is plain HTTP behind the gateway. The hybrid profile remains
unqualified for that consumer path. These adapters are not wired into the
default `dev` selector; container behavior and its published ports remain
unchanged.

Run both qualification selectors with the privately built Effigy source and
binary from the approved owner handover:

```sh
export UNDERLAY_PROFILE_EFFIGY_SOURCE=/path/to/private/effigy
export UNDERLAY_PROFILE_EFFIGY_BIN=/path/to/private/effigy/target/release/effigy
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles

export UNDERLAY_REFERENCE_SOURCE=~/Dev/projects/underlay-reference
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference
```

The scripts reject other source revisions and binary hashes. The approved
handover is Effigy source
`2f7b1819fd0e72afff18a6053be424719ecf71fc`; the current selector pin is its
privately built `effigy v0.14.1` binary (SHA-256
`2f4f888c76f424d41cc981881bc544a14fb82f024c0c50a2e3b5022bd4fb16fc`). The
retained Reference runtime receipts below used another private build of that
same source (SHA-256
`b7ba80a301b5d543cab745d9ddd91a55dd3e058619abfcd90752bed2e970d1ae`); the
updated selectors are rerun against the current pin. Set
`UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT` to inventory a prepared private
Reference main checkout plus two worktrees and their runtime receipts. The
selector may add a temporary origin probe route inside that disposable clone;
it does not modify the source checkout. It verifies the private gateway using
`EFFIGY_GATEWAY_PRIVATE_STATE_ROOT`; TLS clients trust only the fixture CA.

The 2026-10-10 Reference run used clean source commit
`16b35df4bebe920b14eca9d43abc626de44cb617`, a private main clone, two private
worktrees, sibling-disabled assembly, and a private Colima profile. On the
main clone, the actual Reference API, front Vite app, and admin Vite app each
reported a distinct loopback listener; Effigy verified ownership/readiness
before registering their private HTTPS routes. The API connected to real
Postgres and applied migrations. Mailpit accepted SMTP EHLO. The API and both
Vite routes returned HTTPS responses with the fixture CA and correct SNI, and
the frontend HMR WebSocket upgraded through the actual private HTTPS port.
SvelteKit's `event.url.origin` still reported the internal HTTP scheme while
the browser request was HTTPS. The two worktree apps, MinIO, restart and
dependent-route propagation, interruption recovery, and isolated teardown
preserving foreign resources remain unqualified. A later read found the three
main-clone host-process states unavailable; Effigy's down removed the private
routes, but the recorded API listener needed exact-PID cleanup after its
supervisor was absent. The default stack did not start: the pinned MinIO image
pull was denied. No substitute image was treated as MinIO evidence. See
[development profile ownership](docs/knowledge/contracts/dev-profiles.md) for
the receipts and limits.

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
