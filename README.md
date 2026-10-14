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
effigy_source = "/path/to/effigy-at-bd259769"
effigy_binary = "/path/to/qualified/effigy-bd259769-macos-arm64"
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
`bd2597693f7c4c9ad786896a9448a7e746ff13a8`, binary version `effigy v0.14.1`,
and qualified macOS arm64 SHA-256
`2d72c3df0d61c05a150d5d86c39b2ea931eca9549b794b559fa39d95dc002a59` before
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
`bd2597693f7c4c9ad786896a9448a7e746ff13a8` and private Darwin arm64 binary
SHA256 `2d72c3df0d61c05a150d5d86c39b2ea931eca9549b794b559fa39d95dc002a59`.
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
Shell/interpreter source forensics and external artifact-acquisition helper
controls are optional diagnostics, outside the exported product and its hard
acceptance gates. Their failures remain unadmitted. Exact image provenance,
real command interfaces, native bounds, privacy and independent cleanup remain
mandatory; this does not change the native login-shell command.

Post-down inventory and gateway observations alone do not prove cleanup.
The disposable-test qualification wrapper now captures exact owned listener
identities before its single configured action returns, then independently checks
child/group/socket/route absence and unchanged sibling identities. This is source
and hermetic-control preparation; fresh runtime proof remains required.
A qualification-only direct-Lima reader now implements bounded full-ID/creation
and Compose-label observation with independent post-down foreign preservation.
Both qualifiers prepare fresh private HOME/Colima/Lima startup intent and refuse
inherited overrides and preexisting profiles. The original-route read recipe is
now source-qualified: bounded rootful metadata, version and matching nerdctl help
reads establish the selected config and namespace/address before Compose. Source
defaults alone never supply a live route receipt. Semantic pre-start config/scope
policy, original file identities and private cwd nonce correspondence bind the
reader; boot/VM/agent identity stays unknown with no signal/retirement authority.

This is source and hermetic-control preparation. The default fixture still needs
an independent foreign-service witness recipe, and dev:test needs its service
baseline captured inside the ready action wrapper and handed back before
teardown. These paths hold safely rather than grant cleanup credit. Qualified
Effigy159 handover, fresh runtime acceptance and the five independent review
subjects remain required. Partial host absence cannot pass whole-product cleanup.



Earlier `0412cc7b` disposable Reference evidence covers production bootstrap, three
instances with HTTPS origins/HMR and browser CORS, and registration/login/media
upload, finalisation, read and delete. Complete lifecycle acceptance remains
unqualified: the API acquired a new address/generation and route target after
restart, but front/admin successor generations were not established. Main scoped
down refused front/admin records whose state was `unavailable`; the files still
existed. Those resources remain
held; interruption, dev:test and default-container acceptance are not established.
The historical `77d22adc` gate requires fresh runtime evidence. Snapshot projections
preserve `unavailable` as an observed state without granting ready/stopped or
cleanup credit; a missing report remains distinct from an existing state file.

Fresh `77d22adc` evidence also covers three-instance initial HTTPS/origins/HMR,
production Silo bootstrap/CORS and real Reference media operations. Restart
remains incomplete: the API changed address/generation and route target; front
changed generation, while admin's launched successor reached `failed` with an
absent report and `child_unavailable` ownership observation. All three scoped
downs returned zero, but independent cleanup absence was not established.
VM/images/volumes remain held; later lifecycle, dev:test and default-container
acceptance remain unqualified. No child-exit refusal was found in the captured
bounded log tails; that does not establish absence of other errors.

Retained evidence localizes the admin successor failure to the bundle's SMTP
service-port context check, before Vite creation or listener-report writing.
The current API assignment was received correctly. The diagnostic is
`loopback_binding_unavailable`; the exact status mappings and Compose bytes
used in that check were not retained. No port-parser repair, timeout increase,
Compose race or native child-exit defect is established by that evidence.

Production context admits the complete six-target hybrid/test service inventory
through an exported shared decoder. Canonical nerdctl grouped/range mappings,
including Silo 9000–9001, pass only with complete live/Compose/declaration tuple
equality and checkout/project association. Exposure, unknown/foreign/duplicate
bindings, unsupported entries and missing/changed source refuse across the
whole inventory. No explicit-live bypass or declaration-only fallback remains.
All ports resolve before later host renders. The private mode0600 journal retains
fixed reasons/counts/full-payload digests, never raw ports, token hashes,
configuration, environment or arguments. Stable reads do not prove atomic
status association. Source controls do not explain historical missing tokens or
certify fresh runtime/cleanup acceptance.

Fresh main-profile execution with this decoder passed complete service-inventory
agreement, API/front/admin CA-verified HTTPS readiness, HTTPS request/event
origins, HMR upgrades and exact-origin Silo bucket CORS. Reference registration
returned 200; login timed out before response headers at the existing eight-second
request deadline. Its bounded auth trace reached the password-verification worker
after successful user/credential lookups, without a captured verification result
or join. This does not establish the verification failure mechanism or eventual
outcome. Other-instance runtime, media, restart and remaining acceptance stages
were not reached. Main scoped down returned zero; independent cleanup remains
unverified and the new VM/images/volumes remain held.

Read-only examination of the later retained API file found verification `valid`
at 8,053 ms of worker time, after the request timeout and pre-cleanup tail capture.
No join or HTTP response is recorded. Both this run and the earlier 4,234 ms
successful verification used matching auth source, lockfile, instrumentation and
configured Argon2id costs (128 MiB, four iterations, four lanes). The eight-second
socket wait is a probe default, not an auth latency contract. Different timing
origins, build artifacts and unobserved CPU/load prevent a causal performance
comparison. No cost reduction or timeout adjustment follows from this evidence.

The standalone `proof:dev-profiles:auth-cpu` diagnostic authenticates cached
crate archives against the retained lock, lets fresh private Cargo unpack them,
and checks complete selected source membership/digests and debug fingerprint
classes. One offline build and synthetic in-memory verification completed at
unchanged 128 MiB/t4/p4 costs: hash preparation 5,126 ms, worker scheduling 86 µs,
verification `valid` 3,970 ms, join 3,971 ms. The nine-second total includes hash
preparation, which login does not repeat. This one observation is neither an SLA
nor an explanation of the retained 8,053 ms verification. Services were not run.
Register and login qualification each use a fixed 20-second absolute client
operation budget, including preparation, TLS, request, bounded headers/body and
session decoding. This is a finite functional proof policy, not a production
latency promise. Other request limits and auth costs stay unchanged. The private
client refuses incomplete/late responses and records closed phases;
a timed-out mutation stays uncertain and is never resent. The shared decoder now covers genuine application traces; final writer and
post-window deadline checks refuse observable overrun. Remaining application
and lifecycle acceptance is separate from these source controls. See the
[auth operation contract](docs/knowledge/contracts/dev-profiles.md#absolute-auth-operation-policy).

Both opt-in launcher tasks explicitly bind the bucket and all seven declared
route names. Before service startup, the launcher validates their shapes and
compares them with the current composed API declaration through a bounded,
read-only Effigy config inspection. Missing, malformed, mismatched or unknown
source inputs refuse with finite field presence/type/agreement diagnostics;
raw values, environments and config envelopes are not journalled. The same
bounded bootstrap journal records invalid bucket or context fields before MC
operations. Source-only rendered caller controls do not certify runtime readiness.

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

The current private source gate also verifies the qualified tree and four public
API file hashes. Bounded native failures can include versioned host refusal
observations: unknown counts stay unknown and overflow read counts can exceed
retained output. These observations grant no guest execution, cancellation,
signal or cleanup authority.

Disposable qualification captures service IDs inside the ready action before
the configured test and transfers them through an immutable private handoff.
Default-container qualification predeclares a separate genuine Silo witness
project without host ports. Cleanup requires original full IDs and creation
records to be absent, with foreign records unchanged. The new source requires
fresh runtime acceptance; the prepared controls do not provide that acceptance.

Qualification constructs a separate private child environment before fresh-root
admission. It excludes inherited backend-routing and SSH context classes, retains
only declared host tool/platform and invocation inputs, then assigns new owned
roots. The ambient operator environment is unchanged. Explicit overrides added
after construction still refuse, and the ready wrapper checks the original root
context instead of rebuilding or stripping it.

Reference acceptance also requires its instrumented API compile to pass before
backend startup. Bounded compile capture records stream counts, framing, safe diagnostic categories
and Rust error codes without raw compiler payloads. The pinned Reference dependencies
use SSH; a fresh Cargo cache can require authentication that the isolated child
environment does not inherit. A failed compile stops the attempt; assembly and private vault
checks alone provide no runtime or cleanup acceptance.

The disposable Reference qualifiers can prepare an exact-lock private offline
Cargo cache from admitted public host-cache inputs. Registry checksums and locked
Git commits/trees are verified before the configured build; credentials, host
configuration and compiled targets are excluded. The same frozen private Cargo
context reaches the ready-action wrapper. Cache admission is preparation evidence;
the configured build and full runtime/cleanup proofs must still pass.
