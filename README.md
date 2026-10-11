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

## Development profiles

The bundle keeps its existing container-backed `dev` path as the default and
also exposes `dev:container` as its stable name. Host-process profiles are
emitted only when `profiles.enabled = true`. They require the exact qualified
Effigy source and binary paths; semver alone is not sufficient because a
local-version build can report the old release version while missing the
managed-listener and private-gateway contracts.

```toml
[bundle.profiles]
enabled = true
effigy_source = "/path/to/effigy-at-8ecd64b3"
effigy_binary = "/path/to/qualified/effigy-8ecd64b3-macos-arm64"
test_task = "app-api/test" # one bounded Effigy selector for dev:test
test_timeout_secs = 900
# silo_bucket = "acme-media" # defaults to <first database>-media
```

The opt-in selectors are `dev:hybrid`, `dev:hybrid:status`,
`dev:hybrid:down`, `dev:test`, `dev:test:status`, and `dev:test:down`. Effigy
starts each profile's isolated services and its declared host listeners in one
owned container lifecycle so status and cleanup cover both together.
`dev:hybrid` runs Rust and Vite on the host with isolated Postgres, DbGate,
Mailpit, and the pinned published PGSTY Silo service. Host listeners use
Effigy's owned bind, generation, readiness, route and dependent-URL contracts.
`dev:test` runs only the configured selector, enforces its timeout, then
withdraws its private routes and stops its disposable profile containers. Its
isolated named database volumes remain owned by that profile for normal worktree
cleanup. It never invokes full QA. Use `dev:test:down` to reconcile a run
interrupted before its normal cleanup.

The profile launcher checks the clean Effigy source revision
`8ecd64b37963cd6832a2b6ffa528034c56828504`, binary version `effigy v0.14.1`,
and qualified macOS arm64 SHA-256
`03d10d8e58601896949ff042eb1b179f8cebddcb176d95c48d5573494b4ab324` before
starting services, the gateway, or cleanup. The current opt-in runtime is
qualified on macOS arm64; unsupported platforms and changed/unknown binaries
are refused with the container profile still available. Child Effigy calls
use the verified absolute binary, never a `PATH` fallback.

The project-local Silo server and MC client catalogs are installed only after
opt-in and only when neither `infra/dev/catalog/silo` nor
`infra/dev/catalog/silo-mc` conflicts with the bundle-owned versions. They use
the approved published images, provision `profiles.silo_bucket` (default
`<first database>-media`), and keep the shared MinIO catalog and container
default unchanged. Stop the profile through its selector before removing the
generated local overrides.
Opt-in assembly raises the effective Effigy minimum to `0.14.1`; omitted or
disabled profile inputs keep the existing `0.13.1` floor. The exact source and
binary gate still rejects same-version local builds without the qualified
managed-listener and private-gateway capabilities.

The bundle also owns Rust/Vite managed-listener adapters and a SvelteKit
development public-origin hook in `scripts/dev/`. The hook validates a
configured HTTPS origin and keeps SvelteKit event/request URLs coherent behind
the private HTTPS gateway. Its direct readiness exception accepts only the
configured service hostname on the exact safe prepublication probe; browser
requests still require the public authority. Consumer `dev` default changes
and permanent Reference source adoption remain separate work.

## Development profile qualification

Use the approved private Effigy source and binary:

```sh
export UNDERLAY_PROFILE_EFFIGY_SOURCE=/path/to/private/effigy
export UNDERLAY_PROFILE_EFFIGY_BIN=/path/to/private/effigy/target/release/effigy
export UNDERLAY_REFERENCE_SOURCE=~/Dev/projects/underlay-reference
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:public-origin
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:profile-contract-tests
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-runtime
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-container
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:silo-contract-tests
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:silo-artifacts
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-storage
```

The scripts verify Effigy source
`8ecd64b37963cd6832a2b6ffa528034c56828504` and private `effigy v0.14.1`
binary SHA-256
`03d10d8e58601896949ff042eb1b179f8cebddcb176d95c48d5573494b4ab324`.
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
The original published default MinIO image pull remains
unqualified (`insufficient_scope`); Silo does not repair that registry access.
No consumer default switch or Reference source migration is delivered.

The opt-in admission pin is Effigy source `8ecd64b3`; listener state already
contains the effective scoped hostname. Current-source production-selector
receipts establish actual Reference registration/login and signed Silo media
upload/finalisation/download/delete, plus three-instance HTTPS origins/HMR.
These exact-input receipts are retained without repeating successful storage
operations during remaining-lifecycle verification. Historical auth response
timeouts have no established cause. The separate container-only proof passed
and verified cleanup. The remaining-lifecycle attempt passed the guarded API restart and admin
handoff, but front failed before listener publication when its qualified
profile-context lookup exited 1. Interruption/collision and actual `dev:test`
execution were not reached; complete profile readiness remains unproven.
The restart harness requires the canonical configured API catalog cwd, exact
private executable command/path/digest, its unique executable mapping, recorded
start/ancestry/generation and sole kernel socket ownership before signaling.
Unrelated `lsof txt` mappings do not substitute for any identity gate.

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
