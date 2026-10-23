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

The bundle requires Effigy `>= 0.15.0` (`minimum_effigy_version`). Older
releases refuse it.

## Inputs

See `bundle.toml` for the full input schema.

Key required inputs:
- `host` — Primary local hostname
- `workspace_subdir` — Repo path under `/workspace-root`
- `databases` — Postgres databases to create

Optional inputs:
- `browser_runtime` — Workspace image browser layer (`"none"` by default,
  `"chromium"` for the opt-in Chromium system libraries).
- `sources.siblings` — `true` by default, preserving the sibling Underlay and
  Poodle checkout workflow as pinned `[sources.*]` checkouts. Set it to
  `false` when using released packages; the bundle then emits no sibling
  source, sibling catalog, sibling validation, or `deps:prepare` setup step.
- `sources.underlay_rev` and `sources.poodle_rev` — the commits those
  checkouts are pinned to (see below).

For consumers that use released Underlay and Poodle packages, opt out of
sibling checkouts in the bundle inputs:

```toml
[bundle.sources]
siblings = false
```

## Bootstrap and pinned sources

`effigy bootstrap` clones the repo, materialises its pinned sources, runs its
`setup` selectors in order, then runs `start`. The bundle sets:

```toml
[bootstrap]
setup = ["secrets init", "container up --detach", "minio:reconcile", "deps:prepare"]
start = "dev"
```

- `deps:prepare` replaces the retired `bootstrap deps sync`. It hydrates the
  sibling checkouts, client, ui, front and admin with the same fingerprinted
  helper the dev tabs use. It exists only when `sources.siblings = true` and
  `workspace.js_root` is false. With `workspace.js_root = true`, setup runs
  `workspace:js:prepare` (one frozen root install) instead.
- A consumer `[bootstrap].setup` replaces the bundle list whole. Effigy never
  concatenates the two. Write the full order you want, for example
  `setup = ["secrets init", "bootstrap:state"]`.
- `start` is inherited as `"dev"`. A consumer that sets no `start` keeps it.
  `effigy bootstrap --no-start` runs setup and skips start.
- With `sources.siblings = true`, `[sources.underlay]` and `[sources.poodle]`
  clone at `sources.underlay_rev` and `sources.poodle_rev`. The defaults are
  Underlay `v0.10.5` (`54975f3d87684c84ad1e9b99ec9577db4df7c675`) and Poodle
  `v0.4.11` (`3fff871e6b21a0abdd08f766cd02a440d8871f91`). Pins never float:
  `main` does not move the sibling checkouts.
- Bootstrap never resets, fetches or cleans an existing checkout. A checkout
  elsewhere, at another commit, or with local changes is reported as drift and
  left alone. `effigy bootstrap --plan` lists each source and its state.
- Use full 40-character commit SHAs. An empty pin refuses the config. Effigy
  does not check SHA shape at render, so a malformed pin fails at checkout.

Consumer override: another Underlay commit and a replacement setup list:

```toml
[bundle.sources]
underlay_rev = "<40-character commit>"

[bootstrap]
setup = ["secrets init", "bootstrap:state"]
```

## Host development profiles (opt-in)

Run the API, front and admin on the host while services stay in containers:

```toml
[bundle.profiles]
enabled = true
dev = "hybrid"                # optional: make `effigy dev` start the hybrid profile
test_task = "acme-api/test"   # what dev:test runs
test_timeout_secs = 900
```

With `dev = "hybrid"`, `effigy dev` opens the hybrid TUI: a `services` tab
plus live `front`, `admin`, `api` and `jobs` log tabs. Quitting it stops the
stack. `effigy dev:hybrid` starts the same stack detached, and
`effigy dev:down` stops it. The whole-stack container session remains
available as `dev:container`.

`effigy dev:hybrid:release` and `effigy dev:container:release` are the same
modes with front and admin served from production builds instead of the Vite
dev server: no HMR, and a save rebuilds the bundle (refresh to see it). The
Rust API and jobs are unchanged, and the data is shared with the dev modes.

- `effigy dev:hybrid` starts the `hybrid` services, the API, front and admin
  listeners and the background `jobs` worker; the listeners are served behind
  the gateway on the usual app hostnames. `dev:hybrid:status`,
  `dev:hybrid:logs` and `dev:hybrid:down` operate it. Use it instead of `dev`,
  not alongside it.
- `effigy dev:test` starts a fresh `test.<host>` environment, runs
  `test_task` once, and tears it down, even on failure or timeout.
- Linked worktrees get their own scoped hostnames, ports and data
  automatically.

Needs Effigy `main` at or after `e91cd4c` (2026-10-15), installed with
`effigy bootstrap:local`; restart a running shared gateway after installing. The app reads its public host,
CORS origins, cookie domain, database and SMTP settings from the environment
the bundle supplies; object-store settings still come from the app's own
config. See [development profiles](docs/knowledge/contracts/dev-profiles.md#opt-in-profiles)
for the full contract and adoption limits.

## Development profile tooling

`scripts/dev/` holds the bundle's profile adapters: the managed Rust and Vite
listeners, the release server for the release modes, and the SvelteKit
public-origin hook. They use Effigy's owned loopback binding, generation
report, readiness and dependency interfaces. Their checks:

```sh
effigy test:profiles                      # profile_env and release-server unit tests
effigy proof:dev-profiles:public-origin   # public-origin hook security and chaining
effigy proof:bootstrap-sources            # bootstrap render/plan regression (fixtures only)
effigy proof:dns-base-domain              # DNS base-domain render regression
```

The earlier private-Effigy qualification harness is retired; its evidence is
summarised in [development profile ownership](docs/knowledge/contracts/dev-profiles.md).

## Object storage

The default object store is PGSTY Silo, a maintained MinIO fork, from the
Effigy catalog's `silo` service. Upstream `minio/minio` images are no longer
pullable (`insufficient_scope`). The Compose service keeps the name `minio`, so
in-container endpoints such as `http://minio:9000`, the `s3` loopback alias,
the `s3.<host>` and `minio.<host>` routes, and the existing data volume are
unchanged.

The `silo` service needs Effigy catalog pack 1.2.0 or later. Until that pack
is published, install it from a catalog-pack checkout:

```sh
effigy service pack install --path ../effigy-catalog-pack/pack
```

Without it, `effigy container up` fails with an unknown `silo` catalog
service. `effigy service pack rollback` returns to the previous catalog.

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
