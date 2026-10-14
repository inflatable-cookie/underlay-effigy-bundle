# Development profiles and ownership

## Direction

The bundle exposes opt-in hybrid and disposable-test profiles. Hybrid uses
isolated service containers for Postgres, DbGate, Mailpit and published PGSTY
Silo, with Rust and Bun processes on the host. `dev:container` names the
existing Linux whole-stack path. `dev:test` runs one configured Effigy selector
within a bounded timeout, then withdraws its private routes and stops its
disposable profile containers. Named database volumes remain owned by that
profile for normal checkout cleanup. It never runs full QA.

Profile declarations are rendered only when `profiles.enabled = true`; its
default is false. The `dev` task and omitted-input composition remain container-based;
default storage explicitly changes from MinIO to Silo. Switching a consumer's `dev` default and permanent Reference
source adoption require separate explicit work. Storage and profile startup both require exact-source admission.

The bundle inputs `profiles.effigy_source` and `profiles.effigy_binary` must
name the clean qualified source checkout and absolute executable. Before any
profile state, service, gateway or cleanup operation, the launcher checks
source commit `77d22adcbdbca20752720d6671310f13894d219f`, version `effigy
v0.14.1`, and macOS arm64 binary SHA-256
`95b16dbf56f507f0593ca205694fc5e667d311eee7e67b4e1d3afc81ba724938`. Current
exact-source admission is macOS arm64 only; new-source runtime acceptance is
still incomplete. Unknown, changed, wrong-platform or
unavailable identities fail before runtime effects, with actionable input
guidance. Each nested Effigy operation uses that verified absolute path, never
`PATH`. The effective Effigy floor is `0.14.1` in all assemblies because the
Silo bootstrap requires bounded native execution. The
floor is supplemental; it cannot prove this exact capability because old
`+local` builds can satisfy the opt-in floor.

`profiles.test_task` accepts one selector, with no shell text or extra
arguments. `profiles.test_timeout_secs` defaults to 900 and is bounded to
1–7200 seconds. A failed or interrupted action still attempts the test
profile's exact down and route-withdrawal operations; uncertainty retains the
owned scope for explicit recovery through `dev:test:down`.

Before default/container or opt-in startup, the launcher installs the bundle-owned local Silo
server and MC client catalogs under `infra/dev/catalog/silo` and
`infra/dev/catalog/silo-mc` only when those exact paths are absent. Conflicting
local catalogs are preserved and cause refusal before startup. Both images use
approved digest-pinned PGSTY releases; default storage now names Silo and its
client explicitly. The shared catalog is not published or changed. The local overrides remain until the operator stops
the profile. They are not a shared catalog publication or an existing-data migration. `profiles.silo_bucket` selects the application's actual
development bucket; its safe default is the first configured database name
followed by `-media`.

## Ownership

The bundle owns Rust and Vite adapters, service declarations, profile-specific
connection URLs, browser origins, HMR configuration and selector wiring.
Effigy owns language-agnostic execution, environment delivery, readiness and
gateway ownership primitives. Oxide separately owns Rust build and cache
management. The bundle must not introduce another supervisor, allocator or
cache manager to cover a missing Effigy primitive.

Host processes connect to services through reachable loopback endpoints.
Browser-facing HTTPS URLs are distinct from internal bind addresses. Qualified
profiles must prove SvelteKit origins and Vite HMR WebSocket connectivity
through the gateway. Host and Linux dependencies and build artifacts are not
interchangeable.

## Runtime identity and ports

An instance identity covers its checkout, runtime generation and profile.
Frontend, admin, API and additional Rust listeners have distinct owned
addresses. Prefer OS port zero with discovery of the actual listener where the
adapter supports it. Otherwise require exclusive allocation claims, strict
binding and bounded collision retry. A free-port probe is not a reservation.

Publish a route only after proving readiness of its owned listener. Keep the
actual address current across restart and reject foreign hostname takeover.
Cleanup affects only recorded instance resources. Neither age nor a missing
PID establishes that an allocation can be released; uncertain ownership must
remain explicit.

## Qualification boundary

Underlay Reference is the designated pilot for profile qualification and later
opt-in implementation and adoption proof. Use disposable owned checkouts,
worktrees and instances of `underlay-reference`; preserve its operator checkout
and live stack. Acowtancy is excluded from testing, mutation and rollout until
the solution is qualified and explicit later adoption is arranged.

Use those private disposable consumer fixtures and isolated owned resources. Cover
two worktrees and a main-checkout identity starting simultaneously, occupied
ports, child restart, partial launch failure, interrupted cleanup and uncertain
ownership. Isolated teardown must preserve foreign processes and routes.
Assemble the branch from a private consumer and prove unchanged default inputs
and `sources.siblings = false`, following [release.md](release.md).

Existing live infrastructure is read-only. Profile qualification does not
authorize changes to Acow deployment, volumes, data or config; live gateway,
resolver or settings; the global executable; Queue/Nucleus scheduling; frozen
010; providers, workflows, releases or tags. Existing allocation-pruning and
consumer host-wiring findings remain separate evidence, not claimed repairs.

If supported interfaces cannot establish these properties, report the
smallest generic Effigy capability gap with an executable reproduction. A
blocked capability must not become an invented CLI or private protocol.

## Supported mechanism

Qualification uses Effigy source
`77d22adcbdbca20752720d6671310f13894d219f` and its private `effigy v0.14.1`
binary, SHA-256
`95b16dbf56f507f0593ca205694fc5e667d311eee7e67b4e1d3afc81ba724938`.
The scripts require explicit source and binary paths and verify both identities.
The owning interfaces are Effigy's contract 005 managed host listener routes
and guide 063 managed host listeners/private gateway at that source. The
earlier `2f7b1819` build remains historical evidence and is not admitted by the
current opt-in gate.

Effigy supports `containers.<name>.host_processes` with `listener.bind`, HTTP
readiness, a TLS route, and `depends_on`. An adapter strictly binds
`EFFIGY_MANAGED_HOST_LISTENER_BIND`, then writes
`effigy.managed.host-listener-report.v1` to
`EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE`, echoing
`EFFIGY_MANAGED_HOST_LISTENER_GENERATION`. Effigy verifies kernel ownership
and readiness before publication. Dependents receive current internal/public
URLs, state file and generation through `EFFIGY_MANAGED_HOST_<NAME>_*` and
restart on dependency endpoint/readiness changes. Failed-generation
diagnostics describe report, ownership, HTTP readiness and publication phases;
they are not ownership authority.

The bundle's Rust adapter passes the bind preference into the actual Rust
selector, discovers its descendant's loopback listener, and reports the
actual address. The Vite adapter loads the application's installed
configuration, strictly binds its managed loopback address, resolves the
current scoped API route and gateway HTTPS port, then sets browser and HMR
URLs. Effigy owns their lifecycle; these adapters introduce no allocator or
cache manager. They are not connected to the bundle's default `dev` selector.

`scripts/dev/sveltekit-public-origin.mjs` supplies an explicit development hook
wrapper for an HTTP Vite listener behind an HTTPS gateway. A consumer opts in
through SvelteKit's supported `kit.files.hooks.server` setting. The disposable
Reference wrapper imports/chains its original `handle` and re-exports the
original hooks, including `handleError`. It is disabled outside development
or without the explicit profile flag. The configured HTTPS origin is fixed;
Host, forwarded context and unsafe request Origin are validated against it.
The wrapper presents coherent `event.url` and `event.request.url`, retaining
path/query, method, headers, cookies and the unread body stream. Its narrowly
scoped readiness path permits the configured service hostname when Effigy's
direct prepublication HTTP probe sends that hostname without a port or
forwarded headers. This applies only to a safe GET/HEAD on the exact readiness
path with no Origin; browser requests still require the configured public
authority. It does not widen CSRF/CORS or change the upstream transport.

Private gateway mode requires a canonical caller-owned mode-0700 root via
`EFFIGY_GATEWAY_PRIVATE_STATE_ROOT` and explicit `--private-state-root`.
Certificates/CA remain in that root without trust installation, resolver,
alias or global gateway changes. Proof clients verify the fixture CA, actual
registered certificate/SAN, explicit SNI/name resolution and reported HTTPS
port.

## Reference pilot assurance and limits

### Opt-in admission before a released capability

The operator authorized bounded implementation within this agreed profile
direction: "You have blanket approval,you don't need to keep asking". This
covers the opt-in bundle implementation, its independent review and closeout.
It does not authorize release/tag changes, global binary replacement, shared
catalog publication or adoption, consumer default migration, or live settings
changes. Reference remains the disposable pilot and Acowtancy remains excluded.

The qualified opt-in Effigy source is
`77d22adcbdbca20752720d6671310f13894d219f`. Its trusted private macOS arm64
binary has SHA256
`95b16dbf56f507f0593ca205694fc5e667d311eee7e67b4e1d3afc81ba724938`.
This source includes the independently qualified managed-listener checkout
hostname mapping and passed exact-source milestone assurance.
Published `v0.14.1` does not contain the private gateway and managed-listener
primitives used by these profiles. A version string is not capability proof:
Effigy's minimum-version check accepts any `+local.*` build, including older
local builds.

Until a qualified release is available, an explicit opt-in must verify trusted
source provenance and the selected platform binary's checksum before its first
runtime effect. Unknown, older or unsupported binaries must refuse with
actionable guidance. Child execution must retain that verified binary identity;
falling back to the executable on `PATH` is not allowed. The qualified macOS
binary does not establish a Linux consumer-host binary checksum or assurance.

Managed listener `route_domain` in runtime state is already the effective
checkout hostname. Qualification must use it directly, without applying the
host map again. The declared name is exposed as `declared_route_domain` by
`container up`; `container hosts` inventories declared and effective listener
names. The canonical scoped form is `api.acme-w<hostkey>.test` for
`api.acme.test`. Effective names govern readiness Host, TLS certificates,
route publication, public URLs and dependent public URLs across restart.
Primary and explicitly shared runtime identity preserve declared names.

New managed-listener/private-gateway fragments must stay outside default
composition. Consumers omitting the opt-in retain their existing container
configuration and effective version requirements. A released minimum can be
added only after its actual immutable release is qualified, and remains
supplemental to the local-build admission guard.

Opt-in qualification may select the pinned published Silo images through a
documented local service override. An additive shared Silo catalog entry,
catalog artifact publication, generated Effigy baseline adoption and consumer
migration are separately owned changes. They must not rename Silo as MinIO or
replace existing MinIO defaults, volumes or data implicitly.

Underlay Reference is the designated disposable pilot. Its operator checkout
and live stack remain untouched. Acowtancy testing or adoption is excluded
until qualification and a later explicit adoption ruling. No consumer default
switch is delivered here.

The executable runtime proof uses a clean Reference source checkout (qualified
commit `fa6a5e89ad83db460a5506b7fa3f915fa767d72a`), a private main clone and two
private worktrees. It assembles this bundle branch with
`sources.siblings = false`. Fixture-only app/config overrides exercise actual
Reference Rust API and front/admin Vite/SvelteKit applications. The hybrid
fixture excludes the workspace image and keeps host/Linux artifacts separate.

The retained pre-Silo runtime proof establishes nine simultaneous distinct ready application listeners
and routes across those three identities. All three reach real isolated
Postgres, Mailpit and MinIO over loopback. Verified private HTTPS route probes
return the configured public origin in both SvelteKit URL surfaces, preserving
path/query; front and admin HMR WebSockets upgrade with 101. An owned ready API
restart changes endpoint/generation and route target, and restarts both
dependents with the current API URL. Occupied-port launch fails strictly before
publication while another instance's listener/route survives. A controlled
startup interruption records owned readiness 503, reconciles through exact
scope down, and recovers without signaling uncertain process identities.
Teardown of one worktree withdraws its sockets/routes while both other
instances continue serving.

Those lifecycle receipts use the earlier upstream source-image override. The
focused published-Silo proof covers changed storage inputs; the earlier
receipts are not presented as Silo artifact or upload assurance.

A published-Silo three-instance execution also observed an unrelated worktree
admin child recycle under the same supervisor during another checkout's
interruption/reconciliation window. Its API and front remained unchanged.
That execution stopped before collision and isolated teardown; cleanup settled.
The child exit/dependency-change cause is unestablished, so earlier passing
receipts do not establish repeatable lifecycle isolation for this case.
The harness rejects stale survivor identities before mutation and any changed
owner, generation, address or process identity afterward. It retains timed
before/after identity evidence and the interruption/reconciliation receipt even
when that check fails. A recycled child is never accepted merely because its
supervisor or replacement route survives. Consumer profile readiness remains
unclaimed pending independent lifecycle qualification.

### Published Silo qualification ruling

The operator selected PGSTY Silo as the first published-image candidate for
the disposable Reference pilot on 2026-10-10 (owning ruling on main `92e687a`). Qualification uses release and
digest pins for the server and its maintained client, rather than requiring
local MinIO image builds. Silo is a downstream MinIO fork; it must be reported
as Silo, not as an unchanged upstream MinIO artifact.

Prove image provenance and architecture, service readiness, bucket bootstrap,
CORS, signed uploads and downloads, deletion, and owned cleanup with fresh
fixture data. Check the bundled client and health command explicitly; matching
S3 APIs do not establish identical executable or administration behavior.
Published-image qualification does not certify the unavailable upstream image.

Keep the existing bundle and catalog defaults until qualification supports a
separately explicit migration. Existing data and volumes are outside the pilot.
Any later change to the shared Effigy catalog belongs to its owner; a private
fixture override must not silently become a fleet default.

### Published artifact and runtime evidence

Fixture-only catalog overrides use:

- Server `docker.io/pgsty/silo:RELEASE.2026-09-16T00-00-00Z@sha256:635197cb9f36d01bee221d34d1c7d7960f6a95c48b0b6c01d99cd13bdae51a46`.
- Client `docker.io/pgsty/mc:RELEASE.2026-09-16T00-00-00Z@sha256:cfc83108c3abb371f8fb84d99c1fdc88f8c237e022409b0081fb7c0a3be634dd`.

The artifact verifier checks both Linux platforms, selected child/config and
attestation content hashes, OCI entrypoints and release/source metadata.
Server source is `pgsty/silo` commit
`2a4d51406b7ed87af5fe6fe0f801f3290f96eb3c`; client source is `pgsty/mc` commit
`e952aa78f10a2b77dd525a2b7e3143bcda0cd377`. Matching published in-toto provenance
is available. This verification does not authenticate a publisher signature;
OCI SBOM availability is recorded separately per image/platform. The exact
Silo release also publishes Linux SPDX 2.3 SBOMs and Sigstore checksum/provenance
assets. The artifact proof verifies the release SBOM content digests and the
arm64 executable checksum against the pulled image; it does not verify the
Sigstore signatures or treat an archive SBOM as a complete OCI-image SBOM.
The MC release has no separate assurance assets in the inspected release.
Private arm64 pulls and executable version checks match those releases/commits. The server
provides `silo`, `mc` and `mcli`; the standalone client entrypoint is `mc`.
The extracted catalog retains its `server` command and `mc ready local`
contract. No shared catalog or published image is changed.

The focused storage selector prepares fresh owned Postgres/Mailpit/Silo and
actual Reference API/front/admin. It applies an explicit fixture-only Rust
S3Config override: host operations use the actual loopback service endpoint,
while presigning and public URLs use the registered private HTTPS route/port.
Reference's unconfigured development branch still hardcodes `s3.acme.test`;
this adapter patch is qualification code, not a delivered consumer default.
The service protocol proofs establish server HTTP readiness and `mc ready local`, owned
bucket bootstrap/removal, exact front/admin browser-origin controls, signed
object PUT/GET/DELETE (200/200/204), and rejected incorrect credentials (403).
A foreign-origin preflight returns 204 without a CORS grant. Actual front/admin
origin and HMR probes also pass with this service override.

The covering `proof:dev-profiles:reference-storage` execution passed the actual
Reference application path through the CA-verified private gateway:
registration and login (200), media creation (201), upload initiation (200),
presigned PUT to the registered HTTPS Silo authority (200), finalisation (200,
state `ready`), and signed GET/DELETE (200/204). Retrieved bytes matched the
uploaded bytes. The selector exited 0 and verified owned cleanup. Tokens,
credentials, response bodies and presigned queries are not included in protocol
receipts. This proves the disposable fixture integration, without certifying
consumer profile rollout or unchanged published defaults.

An earlier covering execution exited 1 during `POST /v1/auth/register` when its
CA-verified `GatewayHTTPSConnection` timed out reading the response with an
eight-second socket timeout. That execution did not reach the media path and
verified cleanup. Its retained receipt does not establish whether registration
committed or which API/gateway phase caused the delay. The later passing
execution used a fresh fixture account; it does not explain the earlier timeout
or establish a runtime fix or repeatability guarantee. No Silo or Effigy
capability failure is inferred from the historical timeout.

The storage probe attempts to register a fresh fixture account and grants it
admin only after successful registration in the private database. It does not
use operator or seed credentials.
Exact supported host/container down, recorded process/socket/route absence,
retirement, zero environment/route inventory and private profile purge all
settle before `cleanup_verified = true`. Failed fixture preparations remain
retained separately; their subsequent corrections are not core runtime gap
claims.

Container-only assembly/build/start passed with the published Silo override,
preserving `workspace-rust-bun`, default 41001/41002/41003 inputs and
`sources.siblings = false`. The original published `minio/minio` pull remains
unavailable in gathered evidence (`insufficient_scope`). This candidate does
not repair it or certify unchanged published defaults. A shared catalog image,
client/health/bootstrap change and any consumer migration require separate
owner work after independent qualification review. Acow remains excluded; no
live volumes or migration are exercised.

Cleanup stops/reconciles each exact host/container scope and verifies recorded
process identities, socket closure and route withdrawal while the runtime
profile exists. Worktree retire removes their scope records; the main
checkout returns an empty idempotent `scope = null` receipt, which is accepted
only after independent exact-scope reconciliation. Retirement alone is never
host cleanup evidence. After zero runtime environments/routes are confirmed,
the private gateway stops and the run-owned profile purges with `exists =
false`. Interrupted readiness diagnostics remain retained even after ownership
fields clear. Earlier uncertain records/residue are not reclaimed by these
proofs; the cause of the historical unavailable Reference generation remains
unestablished.

Local assurance is macOS host plus Linux containers. It does not establish a
local Linux Reference host proof or dedicated grace-to-SIGKILL end-to-end
coverage. Review/CI and any consumer migration remain separate gates.

### Current-source proof boundary

Current admission is0412/be6, as specified below. Historical pilot and earlier
runtime source labels/receipts remain immutable external evidence; they do not
certify current bootstrap inputs or new ownership/generation. Receipt reuse
requires explicit exact source/binary/Reference fixture/lock/build/recipe/helper
input matching. Storage bytes do not prove current app publication, origins,
CORS, restarts, interruption, teardown or Reference finalisation. No runtime
owner/group identity transfers across instances. Safe snapshots/transition
receipts are observations only; missing/truncated/unknown evidence refuses.

## Pending-start interruption and terminal records

At the qualified Effigy source, managed startup first writes a `starting`
record without a child and then writes `starting` with the spawned child's
boot and precise start identity. A macOS identity retains both seconds and
microseconds. The child starts its own process group with PGID equal to its
root PID; the supervisor is detached from the selector launcher.

A readiness failure reaps that child group and clears active child/listener
identities, addresses, URLs and route owner in a historic `failed` record.
Scoped down can skip an absent supervisor PID file without rewriting this
record. Neither `failed`, an absent PID file nor diagnostic PIDs prove cleanup.

The disposable interruption probe uses a bounded generation-bound private
barrier before binding or reporting a listener. It exits failure after 45
seconds without publication; the core's readiness deadline is unchanged.
Before cancellation, qualification requires the actual `starting` state,
matching kernel boot/start identities including microseconds, exact child
PGID, supervisor ancestry and every recorded group member's ancestry. The
read-only macOS kernel reader uses `proc_pidinfo(PROC_PIDTBSDINFO)`, matching
the pinned core and SDK layout; unknown/denied reads refuse proof.

SIGINT cancels only the owned selector launcher. Scoped production down is a
separate action for detached managed processes. A cleared `failed` or
`stopped` probe can qualify only against its captured pretermination receipt,
with independent exact-process/group absence, private route/publication
absence, main service/gateway shutdown and unchanged sibling generations.
Reused PIDs, incomplete precision or surviving group members remain held.
Existing historic failed packets cannot be upgraded to interruption or cleanup
proof. The same pretermination requirement applies to the occupied-bind probe.

A subsequent isolated production-selector attempt reached nine fresh ready
listeners and matched retained source/build acceptance inputs, then refused
before the pending probe was injected. In the main checkout, the initial admin
record and the later live record had different child generations, PIDs, precise
starts and loopback addresses; supervisor identity and runtime generation were
unchanged. This was the initial live-identity precondition, before any down or
SIGINT, despite the shared helper's generic “foreign/after scoped down” error
wording. It establishes an observed identity change, not its cause or a core
cleanup defect. The strict identity gate remains intact; no baseline replacement
or second runtime was attempted. Three new scoped cleanup selectors returned
zero, but complete lifecycle/retirement assurance remains unavailable and the
private VM/residue stay held. Prior held siblings and uncertain resources were
not inspected or changed by this attempt.

## Qualification selectors

Set `UNDERLAY_PROFILE_EFFIGY_SOURCE`, `UNDERLAY_PROFILE_EFFIGY_BIN` and
`UNDERLAY_REFERENCE_SOURCE` explicitly. The repository owns these selectors:

- `proof:dev-profiles`: supporting synthetic binding/identity proof.
- `proof:dev-profiles:reference`: disposable Reference assembly/configuration
  and actual adapter plans; it does not launch applications.
- `proof:dev-profiles:public-origin`: helper security, opt-out, hook chaining
  and request/body preservation tests with bounded runner lifetime.
- `proof:dev-profiles:profile-contract-tests`: admission/cleanup contracts and
  context phase/error redaction controls with bounded runner lifetime.
- `proof:dev-profiles:profile-compile`: Python/JavaScript syntax compilation
  without generating bytecode or build artifacts.
- `proof:dev-profiles:reference-runtime`: real three-instance applications,
  published Silo, HTTPS/HMR and lifecycle proof with owned teardown.
- `proof:dev-profiles:lifecycle-contract-tests`: hermetic survivor identity
  checks, including a recycled child under an unchanged supervisor.
- `proof:dev-profiles:reference-container`: independent container-only
  assembly/build/start preserving genuine legacy images; no Silo substitution.
- `proof:dev-profiles:silo-contract-tests`: hermetic digest/config/source and
  attestation mismatch controls.
- `proof:dev-profiles:silo-artifacts`: anonymous pinned registry metadata proof
  for both Linux platforms, without runtime effects.
- `proof:dev-profiles:reference-storage`: focused real Reference application and
  Silo storage proof covering registration, presigned upload, finalisation and
  signed retrieval/deletion with supported owned teardown. It retains unchanged
  three-instance lifecycle coverage.

Runtime selectors create fresh private roots and retain redacted receipts
outside the repository. Published artifact/config mismatches fail closed; no
manual source-image build or global Effigy replacement is required.

### Qualified transition observations

The active opt-in gate admits source
`77d22adcbdbca20752720d6671310f13894d219f` and the privately qualified macOS
arm64 binary SHA256
`95b16dbf56f507f0593ca205694fc5e667d311eee7e67b4e1d3afc81ba724938`.
The version string remains `effigy v0.14.1` and is not source attestation.
Earlier `8ecd64b3`/`03d10d8e` records remain historical evidence. Generic runtime
changes invalidate transfer of their source-sensitive runtime acceptance;
the qualification runner requires fresh exported-profile runtime proof rather
than changing historical matching guards.

The bundle collector observes the supported `<name>.transitions.jsonl` beside
listener state through bounded, owner-scoped, no-follow opens, including each
parent directory. It retains at most 512 complete records / 256 KiB, validating
v2 and historical v1 shapes, exact owner association, precise boot/start and
child-group identities, selected event/predicate, predecessor/successor and
reserved dependency launch assignments. The owner is retained as a digest;
reserved state-file assignments must equal the expected owned dependency path.
No arbitrary environment, command, error text, credential or response body is
retained. Snapshots go to the external mode-0600 diagnostic journal before
listener validation, at strict live-baseline mismatch, and before cleanup.

Missing/unreadable/unsafe receipts, initial sequence loss, gaps, duplicate or
regressed sequence, malformed/schema-invalid records, changed reads, incomplete
tails and retention limits are UNKNOWN. Historical v1 records cannot supply
missing v2 tuple predicates. Observations never authorize signalling, resource
adoption, baseline replacement, retries or cleanup. An unavailable dependency
tuple is not a generation-change observation. The strict same-run baseline and
independent current process/socket/route ownership gates remain required.

The maintained launch shape omits `phase` for `successor_launched`; public URL
assignments may omit the default HTTPS port. These legal forms must be retained
without inventing a publication phase or explicit launch port. The collector
checks v2 event-specific dependency predicates/tuple completeness and opens
receipt files nonblocking so a FIFO cannot hold validation alive.

New-source runtime evidence currently includes main Reference auth/media
finalisation and signed object operations, and ready HTTPS/origin/HMR on main
and the first private worktree. On the first worktree, MC upload completed but
the subsequent host-signed object GET returned HTTP 404. Response framing/body
were not retained, so endpoint/bucket disagreement and the underlying cause
remain unknown. Three-instance, restart, interruption/recovery, collision,
uncertainty, full teardown and disposable-test readiness on the new source
remain unqualified. Historic passing receipts do not fill those gaps.

Initial transition projections rejected the two legal launch forms above and
remain UNKNOWN in their original journal. A corrected post-cleanup forensic
read retains launch/shutdown observations and reserved assignments separately;
it cannot replace a probe-time observation or establish precleanup ownership.
The stopped attempt's VM/residue and all older held instances remain preserved.

### Service-only endpoint correlation

The supported container `up` interface starts the selected policy; it has no
service subset option. The bounded storage-correlation fixture therefore derives
the actual exported `hybrid_services` typed policy and retains only its original
Silo server/client catalog declarations, driver/profile/project/host settings.
It selects Silo as primary, removes app processes and explicit DNS routes, and
verifies the resulting typed composition before runtime. This is disposable
diagnostic configuration, not a production export or default change. The
catalog's TCP alias still requires the reviewed private gateway capability.

Pinned shell source loads policy from the supplied checkout and invokes Compose
with that policy's files and explicit `-p` project. The retained first-worktree
manifest has a scoped default network, a loopback Silo mapping at 8540, and no
client `MC_HOST_local` declaration. Production bootstrap persists alias `local`
as `http://silo:9000` in the client container. These configuration observations
do not prove the historical executed alias, DNS result or object namespace.

The pinned [PGSTY MC alias resolver](https://github.com/pgsty/mc/blob/e952aa78f10a2b77dd525a2b7e3143bcda0cd377/cmd/config.go)
checks `MC_HOST_<alias>` first, then the customized configuration map (including
`MC_CONFIG_ENV_FILE`), then the persisted alias configuration. The diagnostic
requires those client overrides absent and the expected `/root` home before
crediting its persisted alias projection. The retained Compose declaration
alone cannot establish any of those runtime environment preconditions.

The diagnostic collector retains only selected alias URL/config scope,
native selected-service observations, Compose digest/project/scope and reconciled
live loopback map, challenge digests, separate producer/consumer exits and MC stat, signed request
phase/status/framing/count, finite S3 `Error.Code` and digested request ID.
Unknown XML codes/headers remain unclassified; arbitrary messages, XML bodies,
MC configuration, credentials and signatures are never persisted. A negative
write/stat/read or identity comparison stops the path without retries or a
host-write fallback. Cross-scope reads must not find the other scope's object.
The private journal and bounded sanitized service logs precede scoped cleanup;
observations do not authorize adopting or retiring uncertain resources.

The service-only setup reached typed main/worktree composition and pinned-image
verification but stopped before service startup: its original gateway call
incorrectly included `--repo`. Exact-source CLI rejects that global argument for
Gateway before execution, independently of the valid JSON/private-root flags.
The corrected helper omits `--repo` only for explicit-private-root gateway calls;
the maintained parser control verifies exit 2 and an unchanged owned directory
for the rejected form. A focused control now audits every actual setup/up/status/
down argument list against the pinned parser before effects.

The earlier minimal-policy rejection identified an invalid root `sources` field.
The disposable minimal fixture now emits only native runtime container settings;
`sources.siblings=false` remains checked in the original production bundle
assembly context. Both actual main/worktree manifests pass exact-binary typed
configuration load, policy equality and effective-host inventory before VM
startup. Hermetic native-load controls replace the former text assertion and
reject unknown root/fixture fields, wrong types, malformed TOML, foreign checkout
identity and unexpected application/service host inventory. Catalog pins and
service declarations remain unchanged; production exports/defaults are unaffected.

An earlier service-only attempt rejected primary Compose because the helper
required a worktree scope label for every checkout. Pinned `container scope`
provides the policy-independent distinction: `none/null` for an unmarked primary
checkout; `worktree` with its full 32-hex token for a linked worktree. The helper
now queries this contract once per owned fixture before effects, validates
canonical Git top-level/source and private Git-directory confinement, then binds
the intended project/service policy. Primary requires exact declared project
and no scope label. Worktree requires exact token and the documented effective
project suffix. Missing/unknown kinds or tokens, foreign checkout/project,
shared overrides and extra/conflicting labels refuse. No fabricated token or
cleanup exemption is introduced.

Native `hosts` loads generated Compose without backend startup. When present,
that freshly owned generated file is checked against the independent scope
identity before effects; actual post-up status and Compose labels are checked
again. Typed hosts scope must agree with the native identity and scoped
shared-identity overrides refuse. Strict mapping, finite label observations and
error classifications are retained before rejection. Identity observations grant
no resource-adoption, signal or cleanup authority.

The preceding attempt passed both actual main/worktree native composition/scope/
pre-backend Compose gates, pinned image/executable verification, private TLS/
gateway and main service up/status. Runtime primary scope correlation passed.
Alias bootstrap and client environment override checks returned inner/outer zero.
The next Silo server identity probe (`hostname`) returned inner 127 while Effigy
returned outer 1. It stopped before MC alias projection/object write/stat or any
host S3 request; worktree services were not launched. The original stderr text
was not retained, so the underlying message remains unobserved. The smallest
next prerequisite is a bounded qualification-helper identity probe using the
supported selected-container contract with executable preconditions established
before services, preserving server/client/project/namespace correspondence.
No utility fallback, product/core repair or second runtime was attempted.

New main service down and private gateway down exited zero; subsequent service
status projected no services. Private VM/images/volumes remain held and
retirement remains unproven. Prior held resources and packets remain untouched.
Empty sanitized service logs are a limitation. No MC/S3 correlation PASS or
historical 404 cause is established; lifecycle/disposable-test and independent
review/hosted assurance remain incomplete.

### Storage endpoint evidence boundary

The service-only qualification method binds the native selected project, service
and available runtime identity to unique challenge bytes along the persisted
client alias name-path, selected server loopback alias, and actual published host
endpoint. Live published ports must agree uniquely with fresh generated Compose.
Container names are opaque observations. Numeric DNS/IP addresses, container IDs
and network inventory are unobserved: object correspondence does not observe a
DNS address. These observations grant no adoption, signal or cleanup authority.

Each independent producer and consumer must succeed. Reverse host writes use
different bytes, read exactly by both selected server and client. Foreign keys
in each scope's existing bucket require an S3 NoSuchKey response; generic 404
and NoSuchBucket do not prove isolation. Missing or unavailable post-down
inventory remains unknown. VM/images/volumes and all older residue stay held.

The qualified source `6da2f94bcc1400f9165b954a5343bd0cb14267ac` command-mode
container shell captures before emitting output: `execute_command_mode_shell`
requests capture, transport supplies no deadline, and `run_command_capture_until`
uses `Command.output()` on that branch. The deadline branch also reads streams
into unbounded vectors. A bounded external pipe reader cannot establish an inner
container stdout/stderr byte cap. That storage diagnostic therefore refused before
VM/gateway/service effects after native main/worktree preflights. This is a
capture-evidence capability boundary, not evidence of the historical 404 cause
or a Silo defect. No streaming alternative or in-container bounded producer is
qualified by this change; the pinned-image and storage correspondence paths
remained unavailable until that boundary was resolved.

Source anchors: [command-mode capture](https://github.com/inflatable-cookie/effigy/blob/6da2f94bcc1400f9165b954a5343bd0cb14267ac/crates/effigy-runtime/src/shell.rs),
[execution transport](https://github.com/inflatable-cookie/effigy/blob/6da2f94bcc1400f9165b954a5343bd0cb14267ac/src/runner/exec_command/transport.rs).
MC alias/stat decoders use the pinned [alias message](https://github.com/pgsty/mc/blob/e952aa78f10a2b77dd525a2b7e3143bcda0cd377/cmd/alias-main.go)
and [stat message](https://github.com/pgsty/mc/blob/e952aa78f10a2b77dd525a2b7e3143bcda0cd377/cmd/stat.go)
structures; local and S3 stat share `parseStat` and indented JSON serialization.
Source-shaped controls do not certify execution against the published images.

### Reviewed bounded storage command capture

Current private Darwin arm64 admission accepts source `77d22adcbdbca20752720d6671310f13894d219f`
and binary SHA256 `95b16dbf56f507f0593ca205694fc5e667d311eee7e67b4e1d3afc81ba724938`.
The preceding `6da2f94b`/`5febcae9` capture refusal is historical evidence.
Finite storage commands use only the reviewed shell `--bounded` surface with
all deadline/stdout/stderr limits supplied, plus JSON. The helper checks native
whole-operation accounting, separate preparation and command counts, complete
status and unique inner markers. Raw bounded envelopes and successful secret
output remain private in memory; refusal projects only finite reasons/counts.
The external cap is supplemental and cannot replace the native capture bound.

Host-client group termination/reap proves neither remote command cancellation
nor object rollback or service retirement. Failed effectful commands leave
remote effects uncertain and are never repeated. Synchronous filesystem calls
cannot be interrupted midway; natural post-reap survivors remain held. This
private Darwin pilot supplies no real Linux consumer proof or fleet/default
rollout. The owner QA passed with one identified passed LEAK; its mechanism
remains unestablished, and no leak-free or historical-cause claim is made.

The first diagnostic on this current source passed both actual disposable native
compositions/scopes/hosts and generated Compose identity gates, then started one
new private VM. Both pinned images passed network-none shell utility, local-file
producer/stat, multiline JSON and required MC command-help checks before service
startup. Main up/status succeeded; live-port reconciliation rejected an unknown
backend port representation before alias overrides/bootstrap or object writes.
Only the finite rejection class and native response byte count were retained;
the rejected port value is unobserved and cannot be reconstructed from later
stopped status. This supplies no DNS, Silo/core defect or historical-cause proof.
The bounded native command helper itself did not reach real service execution.

New scoped down and private gateway down returned success, with available empty
post-down service inventory. These observations do not prove volume retirement
or remote cancellation. New VM/images/volumes and all prior residue remain held.
Before any further storage runtime authority, the bundle owner needs a bounded
safe pre-validation live-port projection and an exact pinned-backend format
contract/control. No guessed port-format broadening or second runtime is
qualified by this outcome. Storage correspondence and all outstanding
whole-profile/independent assurance remain unproven.

### Port representation and pre-validation diagnostics

Qualified nerdctl2.3.1 commit04f63fe15f3f8d77fe41e56ab7ff1d1f3e312860
formatter SHA256fdb45765534a00d4b75a910f24bf540b8ca6adf5934ddbcec6d63d562bcb38dc
groups HostIP/protocol and compresses equal-span adjacent host/container ports.
Bounded expansion requires exact unique full independently declared loopbackTCP
inventory equality; at most16 entries and never more than declared inventory.
Exposure-only target tokens have zero host credit. Wildcard/foreign/unknown/
malformed/duplicate/conflicting/nonTCP/oversize/noncanonical mappings refuse.
Safe field shape/count/digest projections precede validation in both checkouts.
Guest version/commit is reported metadata, not cryptographic binary attestation.

### Opt-in production Silo bootstrap

The exported production-owned `scripts/dev/silo_client.py` supplies client
command-local HOME `/root` before initialization, global `--config-dir /root/.mc`
and alias API `S3v4` / path `auto`. Qualification shares this asset; production
imports no qualification script. Client MC_CONFIG_DIR/MC_CONFIG_ENV_FILE/
MC_HOST_local and proxy/routing overrides remain absent even empty. Server
HOME `/tmp`, config-dir `/tmp/.mc`, env-file/proxy absence and exact independent
Compose loopback alias remain required. No legacy catalog/service/default/image
or global environment changes follow from opt-in bootstrap.

Readonly guards precede every mutation. Alias, readiness, idempotent bucket,
anonymous-download and exact two-browser-origin CORS stages execute once through
native bounded shell: absolute8000ms, cumulative65536stdout/16384stderr budgets,
separate preparation/command accounting and unique inner/outer completion.
No unbounded shell fallback or infinite shell readiness loop. Mutating failure
leaves uncertain effects held, with no automatic retry. CORS uses a noclobber
nonce file and exact-path trap cleanup; no foreign file cleanup is inferred.
Stage records use owner0600 no-follow files and finite labels/reasons/counts;
raw credentials/environment/argv/config/output/envelopes never persist. Native
negative command bytes remain unavailable. Host client settlement is not remote
cancellation/rollback, and synchronous filesystem operations have midcall limits.

Pinned MC emits pretty typed JSON. Alias set omits src; nondeprecated alias list
requires exact `/root/.mc/config.json`, exact endpoint/API/path/credentials in
private memory. Stat name/type/size and bucket/pipe success fields are separately
validated; malformed/duplicate/extra/foreign records refuse with known-field
presence/type/agreement before rejection. Genuine pinned network-none image
output controls complement source and shell doubles before services. Diagnostic
main/worktree storage correspondence has passed: client->server-loopback->host
exact bytes, distinct hostPUT->server/client bytes, own survival and foreign
known-bucket404/NoSuchKey. Numeric DNS/IP/container IDs remain unobserved; no
historical cause is inferred and original production default HOME/autoprobe is
not qualified by explicit recipe proof.

### Silo default storage boundary

The bundle explicitly replaces the fresh default/container MinIO service with
`silo` and `silo_client`, using the same pinned PGSTY fragments as opt-in profiles.
No Silo image is installed under a MinIO name. The distinct Silo volume does not
adopt existing MinIO objects, volumes or credentials. Shared catalog publication
and existing consumer data migration are separate work. Non-storage defaults,
container execution and the `dev:container` escape remain.

Default startup prepares only exact bundle-owned catalog files, then verifies
the qualified absolute binary and requires an owned private gateway root before
service effects. Bounded bootstrap uses the same exported MC recipe as profiles,
with `<first database>-media` and exactly the effective front/admin HTTPS CORS
origins. No qualification-script import or unbounded replacement bootstrap is
allowed. The minimum Effigy version is 0.14.1; exact-source admission remains
stronger than that floor.

No-effect disposable assembly checks named services, fragments and pins. Actual
production bootstrap, default-container build/start, current nine listeners,
Reference media, lifecycle, dev:test and ownership-preserving shutdown require
current runtime evidence. Historical storage success supplies no current
owner/generation or changed bootstrap/CORS credit. Cleanup uses newly proven
scoped resources only; VM/images/volumes remain held. No retirement follows from
down0 or empty inventory, and old held resources remain protected.

Both opt-in launcher tasks explicitly bind the bucket and all seven declared
route inputs. Managed host-process and launcher-task environments remain
separate. Before service effects, the launcher records field presence/type/shape
and compares those values with the composed API declaration using the verified
absolute binary and bounded read-only config capture. Missing, malformed,
valid-but-mismatched or unavailable source data refuses before startup. Only
fixed field names, booleans, capture counts and closed reasons enter the owner
0600/no-follow/single-link/128KiB journal; raw values/config/environments stay in
memory. Invalid bootstrap bucket/context fields also record finite evidence
before MC operations.

The source-only controls consume genuine Effigy-rendered launcher environments
and challenge each binding before the service-effect boundary. They do not
qualify runtime bootstrap/CORS, publication, lifecycle or cleanup. Silo service
logs are unavailable because no qualified finite backend log surface exists;
the timeout-only native logs fallback is removed. Absence of logs is not proof
of absence of errors. The existing bounded, sanitized API file-tail observation
remains separate from backend service logs.

Earlier `0412cc7b` production evidence covers three disposable Reference identities
with nine initially ready API/front/admin listeners, verified private HTTPS,
front/admin public origins, gateway HMR WebSocket upgrades, and exact browser
CORS preflight. The shared production bootstrap reached its bounded stages.
Reference registration/login, media creation and upload initiation/finalisation
returned their expected statuses; signed upload/read/delete succeeded with exact
bytes and finalised state `ready`. This evidence does not certify the default
container or disposable-test execution paths.

Restart evidence remains partial. After the exact owned API listener was stopped,
the API published a new generation/address and its route followed that address.
Neither front nor admin successor generation was established within the bounded
dependent check. Their bounded transition observations contain
`dependency_unavailable` in the published phase without a successor record;
these observations are not ownership or cleanup authority. Both sibling scoped
downs returned zero, while main down refused front/admin listener records in
state `unavailable`. The files still existed unchanged before cleanup; the old
snapshot projection omitted that supported status and rendered it `unknown`.
Supervisor logs recorded a terminal owned-child observation error. Neither the
projection omission nor that observation proves state disappearance or the
historical supervision cause. Independent child/group/socket/route absence was not established.
Keep the uncertain resources held; do not infer stopped ownership from missing
records, force terminal states, rebase listener baselines or retry remote
mutations. The underlying dependent restart/record-loss cause is not established;
it requires owning source/evidence assessment before further execution.

Current admission is the reviewed `77d22adc` source and `95b16dbf` private
Darwin arm64 artifact. It includes standard direct container/task-environment
mapping and owned-child exit observation/settlement with dependent replacement
proof. Mixed container-sequence legacy routing is unchanged. The reported
version is not attestation; no global install or Linux runtime qualification
follows. Earlier receipts remain historical and do not certify these changed
inputs. The named passing bootstrap-help LEAK has no established cause or
connection to the earlier Reference refusal.

The observation helper preserves source-supported `unavailable`, original state
file provenance, unresolved owner/route fields and absent report provenance
separately. Readiness still requires `ready`; down still holds `unavailable`
even when owner fields are empty. Unknown/malformed states refuse. No projection
converts an unavailable generation to stopped, clears its history or grants
signal/route/group settlement authority.

Before cleanup, qualification reads at most a 64KiB tail from each known
API/front/admin host-process log without following links. It retains only the
reviewed owned-child exit diagnostic categories, PID/count/digest/status fields,
capture failure variants and elapsed time, with explicit tail/record truncation.
Unrecognized diagnostic text becomes a byte count and digest. Raw log text is
not copied; unavailable files remain unavailable. These structural observations
do not establish remote cancellation, authorize signals or prove group absence.

Fresh `77d22adc` Reference evidence proves initial nine listeners across three
identities, verified HTTPS/public origins/HMR, production Silo bootstrap/browser
CORS and real registration/login/media upload-finalisation/read/delete. The API
restart published a changed generation/address and updated its route target.
Front successor generations were observed; a further replacement followed
another published `dependency_unavailable`/`owner_unverified` observation, so
the baseline must not be silently rebased. Admin also has a successor-launched
transition, but its recorded successor state is `failed`, report `absent`,
ownership `child_unavailable`, and route `not_reached`. The bounded dependent
gate did not establish a ready admin successor. The collapsed ownership
predicate's lower-level cause remains unestablished.

Retained admin log bytes match the exact pre-cleanup bounded-tail digest. Their
closed context diagnostic agrees with the captured context-error receipt:
phase `service-port`, operation `smtp`, class `ProfileError`, message
`loopback_binding_unavailable`, exit 1. The adapter stack location is context
decoding, before public-config generation, Vite creation/listen or report write.
The native supervisor then observes `child_unavailable`; that is consistent
with this adapter exit rather than evidence of a child-exit capture defect.
The successor launch receipt assigns the new API generation and internal URL
correctly. An absent admin report does not imply a missing API assignment.

The bundle context validator requires all declared service ports, including
Mailpit SMTP target 1025, before returning Vite's route context. Its closed
diagnostic does not distinguish an unrecognized published mapping, an
unconfirmed loopback/Compose match or a missing/ambiguous target binding.
The failure-time native status service rows, allocation list, Compose path and
corresponding Compose bytes/file identity were not retained. The later
generated Compose file is not that missing input. Multiple context operations
can refresh a checkout's generated Compose snapshot, but no retained paired
input demonstrates that this caused the refusal. Mixed-sequence routing,
port-format changes and timeout exhaustion are likewise not established causes.

The smallest bundle-owned follow-up is source-only qualification of finite
per-predicate status/Compose agreement evidence and their snapshot association,
preserving strict loopback equality and refusal. A correction requires a
demonstrated counterexample; a generic capability proposal belongs to the
Effigy owner only if the supported source surface cannot provide the needed
association. This diagnosis grants no runtime retry or cleanup authority.

Production service ports are admitted by the exported sibling asset
`scripts/dev/port_inventory.py`. Rust's direct `profile_context`, Vite's bounded
context subprocess, profile environment generation and launcher start/context
receipts use that shared path. Qualification imports production; production
never imports qualification. Storage correlation uses the same grouped grammar,
scope/project comparison and captured Compose reader with its separate Silo
policy. Default/container bootstrap has a separate policy and does not acquire
the six-target profile requirement.

Hybrid and disposable-test context require exactly PostgreSQL 5432, Mailpit
1025/8025, Silo 9000/9001 and DbGate 3000, plus the known portless Silo client.
The decoder reconstructs nerdctl 2.3.1's sorted group context: an exact loopback
address opens a group and TCP closes it. Canonical paired equal-span ranges
expand only within the existing 16-mapping bound. A fully corroborated Silo
9000–9001 range is supported. Exposure-only tokens confer zero host credit;
unknown/foreign services, addresses, protocols, duplicate tokens/tuples,
dangling groups, mergeable adjacency, reversed/overlapping/unequal ranges,
noncanonical or out-of-range numbers and extra/missing bindings refuse anywhere
in the complete inventory, including outside the requested target.

The entire live service tuple inventory must equal the entire admitted Compose
inventory. `status.ports` is a second declaration view, not independent live
allocation attestation; it must be complete, parseable and equal as well.
Duplicates are checked before set comparisons. Explicit live mappings do not
bypass Compose equality, and declaration-only/empty-live fallback is removed.
The generated service and short-port-list schema refuses unsupported entries
instead of skipping them. The selected policy and native checkout scope are
compared with the local Git primary/worktree kind and project/scope labels;
primary has no scope token/label and may omit service project labels,
while its generated volume project labels and native declaration still agree;
worktree service labels carry the supported native token and project. These comparisons grant no process, listener or cleanup authority.

All six ports resolve once from the captured status/Compose pair before later
host inventory calls can render another composition. Missing or unreadable
source always refuses, independently of journal availability. The caller-owned
mode0600/no-follow/single-link/128KiB journal retains fixed reasons, complete
payload/source digests, file identity/read timing, equality booleans and safe
counts/class histograms, never raw native output, ports, token hashes,
configuration, arguments, environments or credentials. Source paths remain
inside the selected checkout, without symlink components, with one link and
caller ownership. Initial metadata and bounded descriptor/pathname reads must
agree. Cached bindings refer only to those consumed bytes.

The reviewed native serializer supplies no status-to-Compose generation token.
The shared renderer can rewrite its pathname; read stability does not establish
atomic association or exclude replacement before the first observation or
same-identity changes outside the captured interval. The bounded filesystem
reader does not claim cancellation of a synchronous filesystem operation.
`atomic_association=false` remains explicit.

Source controls check the maintained formatter goldens/digest and a source-derived
Go model, then execute the actual qualified native parser/serializer against a
private finite fake backend. Primary and two real disposable worktrees exercise
hybrid/test whole production context, Rust environment propagation and the
actual Vite bounded context-CLI subprocess/JSON decode expressions. Gateway/routes are controlled inputs, not live-service evidence. The
reviewed startup path completes Compose up/readiness and primary-service exec
readiness before starting managed host processes; context still refuses any
incomplete service inventory without polling or fallback. Core gateway and port
recovery parser behavior is separately owned and does not authorize bundle
cleanup or a generic prerequisite. Historical SMTP and Silo failure-time tokens
remain unavailable: these source corrections do not reconstruct their causes.
Changed admission inputs invalidate retained lifecycle reuse and require fresh,
separately authorized runtime acceptance; source controls do not certify it.

All three scoped downs returned zero. Independent exact child/group/socket/
route absence was not established, so cleanup remains unverified and VM/images/
volumes remain held. The bounded tails from all nine host-process logs contain
no recognized child-exit refusal diagnostic; this is limited to those tails and
that diagnostic schema, not absence-of-error evidence. Interruption/recovery,
collision/uncertainty, verified isolated teardown, dev:test and default-container
execution were not reached after the first restart refusal.

### Current repaired-inventory runtime boundary

Fresh main-profile execution of the shared whole-inventory decoder recorded
complete live/Compose/declaration agreement without a service-port refusal.
Production startup reached API/front/admin listener readiness and CA/name/SNI
verified HTTPS. Front/admin request/event origins, gateway HMR upgrades and Silo
exact-origin bucket CORS passed. These observations cover that main instance,
not simultaneous runtime across the assembled primary and two worktrees.

Reference registration returned HTTP 200 with a complete decoded response.
After the disposable administrative-role grant, login sent its request but
timed out before response headers at the existing eight-second deadline.
The bounded pre-cleanup auth trace records successful rate-limit, user, lockout
and credential lookups, followed by password-verification worker entry. It has
no verification outcome, join or handler-response observation. The diagnostic
patch wraps the existing Argon2 verification call; worker entry does not prove
completion, failure, deadlock or the eventual response. The smallest next
assessment belongs to that Reference auth path and its bounded phase evidence;
no service-port, gateway or generic supervisor defect follows from this timeout.

The first refusal stopped acceptance before media operations, other-instance
runtime, restart/dependent handoff, interruption/recovery, collision/uncertainty,
dev:test and default-container execution. Recorded main scoped down returned
zero, but exact child/group/socket/route absence and foreign preservation were
not independently established. Cleanup remains unverified; the new VM/images/
volumes and previous held resources remain held. No second attempt or timeout
increase is justified by these observations.

Read-only assessment of the later retained API file adds a worker `valid`
observation at 8,053 ms, timestamped after the request timeout and the bounded
pre-cleanup log capture. The earlier tail correctly lacked that later event;
it was a capture-window limit. No join or handler response is recorded in the
later file. Request elapsed time and worker elapsed time use different origins;
subtracting their durations does not give a completion-to-timeout interval.

The consumed Reference commit and patched auth/handler/config source, Cargo
manifest/lock and Underlay hashing source match the earlier successful fixture.
The actual dependency is Underlay `v0.10.3` at `72d6fd91`, Argon2 `0.5.3`,
password-hash `0.5.0` and Tokio `1.53.1`. Both startup logs report configured
Argon2id costs of 131,072 KiB, four iterations and four lanes. Registration hashes
through that configured hasher; verification uses the algorithm/version/costs
from the stored PHC through password-hash's verifier. No stored PHC was retained,
so exact stored parameters remain unobserved. Neither PHC nor credential data
may be reconstructed from a live database for this assessment.

Both fixtures ran debug artifacts with matching dependency feature/profile
fingerprint classes, but their binary digests differ. Source equality and those
fingerprints do not attest identical runtime CPU/load or complete compiler
flags. The previous worker `valid` at 4,234 ms and join at 4,236 ms therefore show
an earlier successful observation, not an eight-second upper bound. The probe's
`GatewayHTTPSConnection` supplies an eight-second socket timeout; the audited
auth/handler path supplies no corresponding verification latency contract.

The diagnostic wrapper preserves the verification call and error mapping and
records join errors if the awaiting task reaches that branch. Worker panic or
termination can omit its completion event, and loss of the awaiting handler can
omit a join; neither occurred by inference here. The later `valid` event rules
out an indefinitely stuck verification call for this observed request, while
its missing join/response and exact shutdown interaction remain unknown.

### Standalone auth CPU observation

`proof:dev-profiles:auth-cpu` uses the actual public Underlay hashing API at the
consumed source/lock and unchanged Argon2id 131,072 KiB/t4/p4 costs. A fresh
synthetic password and PHC remain in memory. Hash preparation is timed separately
from scheduling, worker entry, verification and join; phase outcomes and panic
classes exclude secret/error payloads. Existing Underlay correctness tests do
not define this cost's latency bound.

Archive identity is unconditional: exactly one cached archive per available
locked registry package, SHA256 equal to its source/checksum-bearing lock entry,
regular single-link no-follow stable read. Missing optional unselected packages
receive no credit; selected packages must be admitted. Compressed input is capped
at 16 MiB per archive and 128 MiB aggregate (retained maximum 9,679,450 bytes and
aggregate 53,304,128). Expanded input is capped at 128 MiB per archive, 8,192
members and 32 MiB per file. Noncanonical/traversing/absolute/wrong-prefix or
repeated member paths, links, special files and oversized input refuse. No Cargo
checksum metadata is invented. Registry source directories are not copied:
fresh private Cargo unpacks authenticated archives, and all materialized source
files must match archive membership, full-file digests and executable mode.
Only the bounded generated `.cargo-ok` marker is separately classified and
provides no source authority.

The consumer tag-based source ID and exact Git object/lock pin remain unchanged.
Fresh Git materialization is checked against that object and consumed library,
workspace and core manifests/source. Resolver metadata and Git DB are copied
privately, with no global cache or checkout changes. Complete resolved dependency
source/version/checksum and Argon2 debug fingerprint admission precede execution.
Preparation/build share 600 seconds and two jobs; execution has a separate
60-second absolute deadline and 16 KiB caps per stream before collection. A new
session leader waits for durable group identity before exec. Deadline/read/overflow
refusal signals only a currently observable matching owned group, then reaps the
leader. Loss of leader observability after TERM does not authorize guessed KILL;
group absence remains explicitly unobserved. Controlled noncrypto cases exercise
these refusals; syntax compilation alone does not qualify execution paths.

One archive-admitted operation completed: offline build exit zero, 115 resolved
dependencies admitted, compiler metadata and Argon2 debug feature/profile classes
matching the retained Reference build. Build capture was 0 stdout/3,148 stderr
bytes; CPU capture was 358 stdout/0 stderr bytes, both complete within caps.
Synthetic verification returned `valid` in 3,970.352 ms; join completed at
3,970.576 ms from scheduling, with worker entry at 86 µs. Hash preparation took
5,126.403 ms; total in-process work took 9,097.603 ms. Hash preparation is outside
the login verification path and must not be conflated with login wait time.
Recorded leaders exited and were reaped without signals; this does not certify
independent group absence, escaped compiler children or service cleanup.

This observation confirms supported hashing/verification/join under its own
inputs. It does not reconstruct stored historical PHC, machine load, handler
shutdown or a latency maximum from the earlier 4,234 ms and 8,053 ms observations.
Initial manifest-layout and cache-metadata refusals remain separate historical
preparation failures, with no compilation/CPU credit. Source controls now cover
genuine archives/source artifacts, corruption/identity/path/type/limit/source
mutations, lock/profile/phase refusal and finite local capture counterexamples.

### Absolute auth operation policy

The qualification owner selects **20.000 seconds** for each registration and
login client operation. The allowance includes preparation, process creation,
loopback connection, verified private CA and effective-name SNI, send, headers,
body and complete JSON/session validation. Observed 4–8 second verification
samples plus connection/scheduling/response margin motivate this finite functional
proof policy; they provide no maximum, SLA or production latency contract.
Other HTTP/media/storage/readiness checks keep their existing eight-second socket
limits. Underlay/Reference auth source, parameters, credentials and roles do not
change. The standalone CPU proof is not repeated by the request proof.

`auth_operation.py` is qualification-only; production assets never import it.
An inherited-memory child waits behind a private pipe gate until the parent
records its fresh unreaped session/group identity and intent. The parent starts
one monotonic deadline before preparation/fork, caps stdout IPC at 96 KiB and
stderr at 16 KiB before collection, and refuses late or incomplete output even
when a server worker later reports valid verification. Tokens and credentials
stay in memory/private pipes; neither raw output nor its secret-derived digest
is persisted. Closed phases distinguish preparation, connect, TLS, send,
headers, body, decode and completion. Only a zero-exit, fully decoded session
inside the deadline succeeds. This client owns no application listener.

Headers have a 16 KiB total and 32-field cap; bodies have a 64 KiB cap. The
consumed Axum JSON response has Content-Length and application/json framing.
Unknown framing, partial/empty/oversized bodies, duplicate framing fields, invalid
JSON/session/user/role schemas and HTTP errors refuse. The reviewed cookie helper
appends two distinct Set-Cookie identities: this repeatable HTTP field gets at
most two entries, with duplicate cookie identities refused. No cookie value is
recorded. Strict TLS name/CA verification and explicit loopback routing remain
mandatory; no insecure path or arbitrary auth-budget override exists.

On deadline/capture failure, termination is limited to the new unreaped direct
child whose current session/group still matches. A lost/changed identity supplies
no guessed signal authority. Reaping a client does not cancel or roll back its
remote registration/login mutation; failure stops the batch without resend.
Group absence is not independently inferred from leader reaping. Synchronous
filesystem calls and OS scheduling during an individual call remain explicit
limits; checks at subsequent boundaries refuse deadline overrun rather than
crediting it as success.

One pre-request tail and one post-result/refusal window (at most 3 seconds of
polling) read only the admitted new checkout's fixed API file. No backend/log
command or HTTP replay supplies this evidence. No-follow, owned regular
single-link files provide at most 64 KiB per read and the last 16 closed
phase/outcome observations. Whole-tail digest/bytes, missing file, partial line,
truncation and observation limits are explicit; unknown/duplicate phase evidence
refuses. Server elapsed clocks stay distinct from client elapsed clocks. Late
worker/join/handler observations never replace HTTP/session success. File I/O
midcall is not claimed interruptible. Registration has no login instrumentation,
so unavailable register phases remain unavailable.

`proof:dev-profiles:auth-operation-controls` exercises private TLS peers, trickled
headers, partial bodies, late completion, short absolute deadlines at every
phase, strict names/CA, malformed/framing/schema/capture refusal, seeded-secret
privacy, unknown group refusal and bounded file windows. These controls launch
no Reference application or backend and grant no service acceptance credit.

### Auth capture counterexample and corrected source boundary

Actual verified registration and login returned complete valid sessions in
6,907 ms and 8,043 ms respectively under the fixed 20-second operation policy.
Both private clients exited successfully and were reaped, with 1,046/1,048 IPC
stdout bytes and no stderr. No group-absence or remote-cancellation inference
follows from reaping. The application/auth parameters and public source remain
unchanged. These are individual functional observations, not latency maxima.

The initial phase parser accepted only equals-style fields. The actual Reference
tracing formatter emits colon-style fields: a bounded retained tail contains
26 genuine auth lines, none accepted by the new parser, while the existing
source-backed sanitizer recognizes all 26. This is a bundle capture counterexample,
not an HTTP/auth/crypto or generic Effigy failure. Login had already completed
its valid HTTP/session response when post-window capture refused. The fixture
controls used equals-style lines and did not qualify the genuine formatter.
A finite read-only reconciliation observed verification `valid` at 7,373 ms,
join `ok` at 7,374 ms and handler `success` at 7,499 ms; those server origins
must not be subtracted from the client clock or used to reconstruct historical
causes. These observations do not replace the refused pre-cleanup capture.

The initial final-success journal emission followed the parent's last deadline
check, with no post-emission check before returning. Synchronous journal I/O
can therefore overrun without subsequent refusal at that boundary. No such
client overrun is established for these successful requests; that source boundary required a post-emission deadline check and a corresponding
controlled counterexample before complete absolute-operation qualification.

The registration post window measured 3,005 ms against the configured 3,000 ms
polling allowance. Its strict whole-window bound is therefore unproven;
filesystem/scheduling cause is not established. The short-deadline and virtual
clock controls allowed boundary overrun and did not establish the selected
strict total. The source correction required genuine formatter controls, closed
enum/duplicate refusal, and whole-window deadline/overrun refusal before further
application acceptance. Original source and immutable receipts preserve this
counterexample; later source controls do not retroactively pass it or replay
the completed request.

Only the main profile reached this auth boundary. The other instances, media
finalisation/read/delete, restart/dependent handoff, interruption/recovery,
collision/uncertainty, dev:test and default Silo container acceptance remain
unproven on these inputs. Main scoped down returned zero, but independent exact
child/group/socket/route absence and foreign preservation were not established.
The new VM/images/volumes stay held; scoped down supplies no retirement credit.

The current qualification decoder is shared by file observation and sanitized
log capture. It full-matches the known diagnostic target, correlation and four
source-ordered fields in the genuine colon formatter or quoted equal formatter;
unknown/duplicate/mixed fields, invalid UTF-8, missing fields, bad integer types
or range and unknown enums refuse. Retained genuine bytes stay in memory during
controls. The CPU helper's distinct typed JSON phase protocol remains unchanged;
it is not a second server-trace parser and no CPU operation is repeated.

Registration takes one snapshot with login-trace applicability explicitly absent.
Login accepts observation completeness only when its actual verification, join
and handler success markers are present in an untruncated complete tail; HTTP
session validity remains a separate condition. Post windows share one three-second
origin across read/decode, optional bounded polling and journal emission. They
stop before forced exhaustion with partial/unavailable evidence, never a success
prefix, and refuse observable overrun after final emission. Final client HTTP
validity is published as a pending observation; a subsequent deadline check must
succeed before response return. Slow writer controls establish refusal without
re-emission/retry. Synchronous filesystem midcalls remain uninterruptible limits.

The storage diagnostic journal now enforces its 128 KiB total, owned single-link
identity and a finite 256-distinct-snapshot index. Only byte-equivalent typed
listener/transition snapshots collapse; source reads and validation still occur,
changed identities/tuples/causes/refusals remain recorded, and closed aggregate
omission counts declare that the cache grants no authority. Capacity refusal is
sticky across best-effort logging; selectors and final receipt publication check
it before further credit. Reserved bytes admit the closed refusal/aggregate
record without raising the cap. Source controls do not establish the remaining
three-instance/application/lifecycle/default-container acceptance.
