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
  Effigy `>= 0.14.1`; older releases reject this bundle revision on the
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
effigy_source = "/path/to/effigy-at-0412cc7b"
effigy_binary = "/path/to/qualified/effigy-0412cc7b-macos-arm64"
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
`0412cc7b17f4aab3905e6853a08985270d1454d0`, binary version `effigy v0.14.1`,
and qualified macOS arm64 SHA-256
`be6ef9733e308b1c410c79d0d70bb8ee1f0141f7b4cc67bd6fe67744629d93eb` before
starting services, the gateway, or cleanup. The current exact-source admission supports
macOS arm64; unsupported platforms and changed/unknown binaries
are refused before storage or profile startup. Child Effigy calls
use the verified absolute binary, never a `PATH` fallback.

Default/container storage now uses explicitly named `silo` and `silo_client`
services instead of MinIO. The bundle installs its pinned PGSTY server/client
fragments under `infra/dev/catalog/silo` and `infra/dev/catalog/silo-mc`, refusing
conflicting files. Silo uses a distinct per-project `silo-data` volume; existing
MinIO volumes and objects are neither adopted nor migrated. Shared Effigy
catalog publication is separate. All non-storage container services remain.

`dev` and `dev:container` prepare those fragments, admit the exact qualified
binary, start the container stack, run the bounded Silo bootstrap, then enter
the container development session. Default bootstrap uses `<first database>-media`;
opt-in profiles can set `profiles.silo_bucket`. Both set anonymous download and
CORS for exactly the effective front/admin HTTPS origins. Default runtime needs
`UNDERLAY_PROFILE_EFFIGY_SOURCE`, `UNDERLAY_PROFILE_EFFIGY_BIN` and an owned
`EFFIGY_GATEWAY_PRIVATE_STATE_ROOT`; missing inputs refuse before service startup.
The manifest floor is `0.14.1` for all assemblies because storage bootstrap uses
native bounded execution. Semver alone never certifies the exact capability.

The bundle also owns Rust/Vite managed-listener adapters and a SvelteKit
development public-origin hook in `scripts/dev/`. The hook validates a
configured HTTPS origin and keeps SvelteKit event/request URLs coherent behind
the private HTTPS gateway. Its direct readiness exception accepts only the
configured service hostname on the exact safe prepublication probe; browser
requests still require the public authority. Consumer `dev` default changes
and permanent Reference source adoption remain separate work.

## Development profile qualification

Admission accepts only the clean qualified Effigy source
`0412cc7b17f4aab3905e6853a08985270d1454d0` and private Darwin arm64 binary
SHA256 `be6ef9733e308b1c410c79d0d70bb8ee1f0141f7b4cc67bd6fe67744629d93eb`.
Version/semver is not attestation. Every child uses the retained absolute binary;
old, unknown, changed and unsupported identities refuse before effects.

Set `UNDERLAY_PROFILE_EFFIGY_BIN`, `UNDERLAY_PROFILE_EFFIGY_SOURCE` and
`UNDERLAY_REFERENCE_SOURCE` to the admitted artifact, owned source checkout and
read-only Reference source. Run covering selectors through that artifact:

```sh
"$UNDERLAY_PROFILE_EFFIGY_BIN" proof:dev-profiles:profile-contract-tests
UNDERLAY_BOOTSTRAP_MC_SOURCE_ROOT=/path/to/immutable-mc-source \
"$UNDERLAY_PROFILE_EFFIGY_BIN" proof:dev-profiles:silo-bootstrap-tests
"$UNDERLAY_PROFILE_EFFIGY_BIN" proof:dev-profiles:lifecycle-contract-tests
"$UNDERLAY_PROFILE_EFFIGY_BIN" proof:dev-profiles:profile-compile
"$UNDERLAY_PROFILE_EFFIGY_BIN" proof:dev-profiles:profile-preconditions
```

The preconditions selector assembles default Reference main and explicit opt-in
worktrees without a backend, verifies named Silo/client mappings, and checks
copied fragments, digest pins and native generated Compose health, alias,
config-mount and volume boundaries. Mutations of those genuine generated inputs
must refuse. MinIO image availability is not a precondition.
Current owner/generation, production bootstrap/CORS and whole-profile acceptance
require fresh runtime proof; historical storage receipts cannot supply those gates.

The opt-in launcher task currently does not explicitly bind
`EFFIGY_PROFILE_SILO_BUCKET` or the declared route inputs used by its bootstrap
context. Host-process environment declarations do not bind the launcher task.
The bootstrap rejects a missing or invalid bucket before its MC stages; the
rendered task-to-launcher input contract must be qualified before profile use.

The exported production `scripts/dev/silo_client.py` owns the default and opt-in MC recipe:
client command-local HOME `/root` before MC initialization, global config-dir
`/root/.mc`, alias-set API `S3v4` / path `auto`. Client MC/proxy environment
overrides must remain absent even empty. Server HOME `/tmp`, config-dir
`/tmp/.mc` and independent loopback alias remain strict. Idempotent bucket,
anonymous download and two exact browser-origin CORS policies are preserved.
Each finite stage uses native8000ms /65536stdout /16384stderr bounds, separate
prep/command accounting and unique inner/outer success. Readonly guards precede
mutations; no unbounded fallback, infinite shell loop or uncertain mutation retry.
CORS uses a noclobber nonce file and exact-path trap cleanup.

Qualification shares the exported recipe/guard/decoder; production imports no
qualification code. Source, real-shell/native-envelope and genuine pinned
network-none image controls are distinct evidence. Safe mode0600 field/stage/
phase/count receipts exclude credentials, commands, raw environment/config and
output. Native negative command bytes remain unavailable. Historical causes
stay unknown, guest-reported metadata is not binary attestation, numeric DNS/
container-ID inventory is unobserved, and Linux host runtime is unqualified.
Host client settlement does not prove remote cancellation/rollback. New VM/
images/volumes stay held; scoped down or empty inventory is not retirement.

See [development profile ownership](docs/knowledge/contracts/dev-profiles.md)
for the supported interfaces and evidence boundaries. Independent review and
consumer adoption remain separate; no default migration or release is implied.

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
