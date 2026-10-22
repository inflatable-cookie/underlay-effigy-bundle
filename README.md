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

## Development profile qualification

The bundle owns opt-in Rust/Vite managed-listener adapters and a SvelteKit
development public-origin hook in `scripts/dev/`. They use Effigy's owned
loopback binding, generation report, readiness and dependency interfaces. The
hook validates a configured HTTPS origin and keeps SvelteKit's event/request
URLs coherent behind the private HTTPS gateway. Consumer default selectors
remain container-based; this change supplies qualification machinery and
explicit disposable consumer overrides.

The selectors below are the retained task-004 qualification tooling. They
still pin the older private Effigy build they qualified and are not needed to
use the profiles above.

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
fork, not unchanged upstream MinIO. Silo signed object operations,
credentials/CORS controls and container-only build/start passed with that
override. The covering Reference storage proof also passed registration,
media creation, presigned upload, finalisation and signed retrieval/deletion,
with verified owned cleanup. An earlier registration-response timeout remains
historical evidence with an unestablished cause; the later pass does not explain
that timeout or establish a runtime fix. See the owning development-profile
contract above for the qualification boundary.
No hybrid/dev:test consumer migration or default switch is delivered.

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
