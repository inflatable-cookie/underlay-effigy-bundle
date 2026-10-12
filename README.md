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
`6da2f94bcc1400f9165b954a5343bd0cb14267ac`, binary version `effigy v0.14.1`,
and qualified macOS arm64 SHA-256
`5febcae9e40625898beab1f7f5dd93c8fbb67df083b1d16466dabcca89dae8c8` before
starting services, the gateway, or cleanup. The current exact-source admission supports
macOS arm64; unsupported platforms and changed/unknown binaries
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
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:profile-compile
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-runtime
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-container
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:silo-contract-tests
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:silo-artifacts
"$UNDERLAY_PROFILE_EFFIGY_BIN" --repo "$PWD" proof:dev-profiles:reference-storage
```

The scripts verify Effigy source
`6da2f94bcc1400f9165b954a5343bd0cb14267ac` and private `effigy v0.14.1`
binary SHA-256
`5febcae9e40625898beab1f7f5dd93c8fbb67df083b1d16466dabcca89dae8c8`.
The runtime selectors pull approved digest-pinned PGSTY Silo and MC images,
create fresh private Reference main/worktree instances and retain redacted
receipts outside the repository. They use a private gateway/CA and isolated
Colima runtime without installing system trust or changing the operator
checkout. See [development profile ownership](docs/knowledge/contracts/dev-profiles.md)
for interfaces, prerequisites and selector coverage.

The historical Reference pilot proves three concurrent actual API/front/admin
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

The current opt-in admission pin is Effigy source `6da2f94b`; listener state already
contains the effective scoped hostname. Current-source production-selector
receipts establish actual Reference registration/login and signed Silo media
upload/finalisation/download/delete, plus three-instance HTTPS origins/HMR.
These exact-input receipts are retained without repeating successful storage
operations during remaining-lifecycle verification. Historical auth response
timeouts have no established cause. The separate container-only proof passed
and verified cleanup. The earlier remaining-lifecycle attempt passed API/admin handoff but front
failed its context lookup before publication. With phase diagnostics, API/front
handoff passed, while admin context failed at `host-inventory / default.hosts`
with exit 1 and class `ProfileError`. The underlying rejection reason remains
unestablished. Interruption/collision and actual `dev:test` execution were not
reached; complete profile readiness remains unproven.
The subsequent nested-envelope diagnostic attempt failed closed at front's
post-restart ownership/readiness check without capturing a context-error record.
Its probe-time listener snapshot was not retained; the cause remains unknown.
Typed snapshots now preserve both helpers' exact observations before validation
and on rejection. A later attempt passed restart/handoff, then exposed an
interruption-fixture precondition conflict: after owned profile down, its route
lookup still required ready listeners and rejected the correctly stopped front.
This is a bundle qualification-helper counterexample; historical rejection
causes remain unknown. Probe setup now validates and captures the effective domain
before down and reuses it for cleanup, preserving all live ownership gates.
A subsequent attempt reused the input-matched restart/origin proof and passed
that setup boundary, then refused before interruption launch: the fixture
manifest inspector recognized only `interrupted_probe`, rather than the three
production hosts plus the probe. Configuration inspection exited zero; whether
composition or the inspection parser caused that historical mismatch was then
unestablished. A subsequent assembly-only typed `effigy.config.v1` comparison
resolved the boundary: the default list contained `api/front/admin`, while
adding the fixture's local probe array replaced it with `interrupted_probe`.
The regex agreed with both semantic lists. No parser correction or service
launch followed that diagnostic counterexample. The fixture helper now uses
`[manifest].extend` for the host-process array, preserving production entries
field for field and restoring original manifest bytes. Typed assembly and
hermetic refusal/restoration controls cover both probe injection paths.
The corrected runtime attempt reached the owned HTTP503 interruption probe and
SIGINT, then stopped at its teardown assertion: supported down left the probe
record `failed`, while the helper required `stopped`. The main profile is down;
both private siblings remain active and held because the runner refused further
cleanup. Recovery, remaining lifecycle and `dev:test` acceptance are unproven.
The revised fixture waits in actual pending startup before bind/report and
records kernel boot/start identities with microseconds and the detached child
group. Launcher SIGINT and scoped child cleanup are separate proof steps;
a historic cleared `failed` record alone supplies neither proof.
The next bounded attempt reached nine fresh ready listeners and matched the
retained restart/build inputs. It stopped in the main checkout's initial
live-identity precondition, before probe injection, down or SIGINT: admin had
changed child generation, PID and address while its supervisor and runtime
generation stayed unchanged. The generic error wording says “foreign/after
down”, but the captured timeline establishes this earlier boundary. Cause is
unknown; no interruption, collision, recovery or cleanup credit follows.
The three new cleanup down selectors returned zero, but their VM/residue remain
held because the complete proof failed. Earlier held resources were untouched.
The restart harness requires the canonical configured API catalog cwd, exact
private executable command/path/digest, its unique executable mapping, recorded
start/ancestry/generation and sole kernel socket ownership before signaling.
Unrelated `lsof txt` mappings do not substitute for any identity gate.
Context failures now retain fixed phase, container-operation, exit status and
allowlisted error class/message, without captured stdout or arbitrary stderr.
Nested negative envelopes also retain a fixed source reason and their actual
process exit separately; unknown reasons remain explicitly unclassified.
The qualification harness copies these records outside the fixture before
teardown. Diagnostic-only changes must preserve the accepted successful recipes
before auth/storage receipts can be reused.

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

Current opt-in admission uses qualified source `6da2f94b` and its private macOS
arm64 artifact. Historical runtime receipts above keep their original source
identity; they do not qualify the new binary. The harness collects bounded v2
transition observations before validation failures and cleanup, preserving
selected causes and reserved launch assignments. Missing, partial or lost
records remain unknown and never authorize cleanup or baseline replacement.

New-source proof currently stops at first-worktree host-signed S3 GET HTTP 404
after MC upload; main Reference auth/storage passed. The response framing/body
and cause remain unknown. Remaining lifecycle and `dev:test` are unqualified.
Legal phase-less launch records and default-port public URLs are now retained
by the collector; corrected post-cleanup observations do not grant earlier
probe-time or cleanup credit.

`proof:dev-profiles:storage-correlation` is a bounded service-only diagnostic,
not whole-profile acceptance. It derives only the Silo server/client declarations
from the actual Reference export, retains their catalog pins, and omits app
listeners and explicit DNS routes in the disposable fixture. The catalog TCP
alias still requires the reviewed private gateway. It records selected MC
alias/config scope, native selected-service observations, scoped Compose identity,
separate producer/consumer exits and stat, signed response phases/framing and allowlisted S3 error codes.
Bodies and credentials stay in memory. Its hermetic controls are selected by
`proof:dev-profiles:storage-correlation-tests` with the same exact-source binary
and source environment used by runtime qualification.

The first service-only setup stopped before Silo startup because the helper
supplied `--repo` to a gateway command. Pinned Effigy rejects that argument before
execution; gateway ownership instead uses `--private-state-root`. All four actual setup/up/status/down gateway argument lists pass the pinned
side-effect-free parser control. The minimal fixture now uses the native runtime
root schema; `sources.siblings=false` stays in the production bundle assembly
context. Both actual main/worktree policies pass native configuration and host
inventory gates before runtime, preserving only Silo/client services.

The helper queries native checkout scope once before effects and binds it to
the caller-owned canonical Git fixture/source. Primary `none/null` requires the
exact declared project and no scope labels; a worktree requires its exact full
token and documented effective project. Shared overrides and foreign/conflicting
identity refuse. Native generated Compose is checked before startup and again
against actual status afterward; these observations grant no cleanup authority.

The preceding service-only attempt passed those scope checks, private gateway and
main services, alias bootstrap and client override checks. It stopped on the
Silo server `hostname` probe (inner exit 127, Effigy outer exit 1), before MC
object operations or S3 requests. The stderr message was not retained, so no
underlying cause or historical 404 explanation is established. A supported
container identity probe with demonstrated executable preconditions is the next
bounded prerequisite. Recorded new service/gateway down calls exited zero;
VM/images/volumes remain held and retirement is unproven. Old held resources
remain untouched; whole-profile acceptance remains incomplete.

Storage correlation evidence follows the [owning evidence boundary](docs/knowledge/contracts/dev-profiles.md#storage-endpoint-evidence-boundary): native selected services and live published ports plus exact challenge-byte correspondence. DNS/IP addresses and network inventory remain unobserved. This diagnostic cannot certify whole-profile acceptance or retirement.

The preceding `6da2f94b` command-mode shell collected output internally before
emitting it. An external pipe cap cannot prove the required inner capture bound,
so that diagnostic stopped after both native checkout preflights and before
VM/gateway/service startup. At that boundary image-interface and endpoint correspondence execution remained
unqualified; the historical storage failure cause remains unknown.

The current private Darwin arm64 gate accepts exact source `0412cc7b` and its
reviewed artifact checksum, using native bounded JSON shell capture with one
deadline and cumulative independent stream limits. Full command/accounting
validation precedes byte credit. Host-client reap is not remote cancellation or
rollback; uncertain effects and old residue remain held. No Linux consumer or
default rollout is qualified by this diagnostic.

On the new qualified source, both native checkout gates and genuine pinned
network-none image utility/local-stat controls passed. Main service startup
returned success, but live-port reconciliation refused an unrecognized backend
representation before alias/bootstrap or object operations. The rejected port
text was not retained, so its precise shape and the historical 404 cause remain
unknown. No second attempt was made. Available post-down inventory was empty;
new VM/images/volumes remain held without retirement credit. Storage and pending
whole-profile acceptance remain incomplete.

The port reader now distinguishes exposed-only tokens from published mappings.
Exposure grants no host-binding credit: complete, unique loopback mappings must
match configured service targets exactly. Safe field/token projections precede
refusal in both checkout paths. File-only native-parser controls cover the
correction; they do not identify the missing historical token or deployed guest
formatter version. No new runtime or cleanup was performed. Storage and full
profile acceptance remain pending.
