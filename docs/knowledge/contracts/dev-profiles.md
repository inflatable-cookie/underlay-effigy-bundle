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
default is false. The unchanged `dev` task and omitted-input composition remain
container-based. Switching a consumer's `dev` default and permanent Reference
source adoption require separate explicit work. Unsupported profile admission
does not change the container-only path.

The bundle inputs `profiles.effigy_source` and `profiles.effigy_binary` must
name the clean qualified source checkout and absolute executable. Before any
profile state, service, gateway or cleanup operation, the launcher checks
source commit `6da2f94bcc1400f9165b954a5343bd0cb14267ac`, version `effigy
v0.14.1`, and macOS arm64 binary SHA-256
`5febcae9e40625898beab1f7f5dd93c8fbb67df083b1d16466dabcca89dae8c8`. Current
exact-source admission is macOS arm64 only; new-source runtime acceptance is
still incomplete. Unknown, changed, wrong-platform or
unavailable identities fail before runtime effects, with actionable input
guidance. Each nested Effigy operation uses that verified absolute path, never
`PATH`. The effective Effigy floor rises to `0.14.1` only when profiles are
enabled; default-input consumers retain the existing `0.13.1` floor. The
floor is supplemental; it cannot prove this exact capability because old
`+local` builds can satisfy the opt-in floor.

`profiles.test_task` accepts one selector, with no shell text or extra
arguments. `profiles.test_timeout_secs` defaults to 900 and is bounded to
1–7200 seconds. A failed or interrupted action still attempts the test
profile's exact down and route-withdrawal operations; uncertainty retains the
owned scope for explicit recovery through `dev:test:down`.

On first opt-in start, the launcher installs the bundle-owned local Silo
server and MC client catalogs under `infra/dev/catalog/silo` and
`infra/dev/catalog/silo-mc` only when those exact paths are absent. Conflicting
local catalogs are preserved and cause refusal before startup. Both images use
approved digest-pinned PGSTY releases; the shared catalog and default MinIO
stack remain unchanged. The local overrides remain until the operator stops
the profile. They are not a shared catalog migration or an upstream MinIO
availability fix. `profiles.silo_bucket` selects the application's actual
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
`6da2f94bcc1400f9165b954a5343bd0cb14267ac` and its private `effigy v0.14.1`
binary, SHA-256
`5febcae9e40625898beab1f7f5dd93c8fbb67df083b1d16466dabcca89dae8c8`.
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
`6da2f94bcc1400f9165b954a5343bd0cb14267ac`. Its trusted private macOS arm64
binary has SHA256
`5febcae9e40625898beab1f7f5dd93c8fbb67df083b1d16466dabcca89dae8c8`.
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

Current-source production-selector receipts establish three concurrent actual
Reference API/front/admin stacks with distinct effective routes, verified
HTTPS origins/HMR and genuine pinned Silo. Reference registration/login and
media initiation, presigned upload, finalisation (`ready`), signed retrieval
and deletion passed under unchanged security and eight-second request bounds.
The earlier auth timeouts remain unexplained; a later pass does not establish
their cause or a product repair.

Remaining-lifecycle verification reuses that acceptance only after checking
the source/binary, Reference commit/auth fixture patch/lock/build identity,
production recipe files and relevant helper functions against the retained
receipt. The bundle head must descend from the retained head; changed
production inputs still refuse reuse. It performs necessary owned setup but
issues no repeated successful auth/storage requests.

Before a targeted restart signal, the harness requires the exact configured
API catalog task cwd and canonical checkout cwd for its adapter. It checks the
private API executable command/path/digest, exactly one matching canonical
executable mapping among `lsof txt` entries, recorded start identity, current
supervisor/adapter/listener ancestry, generation/report/current route and sole
kernel ownership of the exact loopback listener. Other mapped files are not
executable ownership evidence. Missing, ambiguous, foreign or changed identity
refuses before signaling; the signal decision and observations are durably
recorded outside the fixture. No basename or directory-prefix ownership test
is accepted.

The earlier uninstrumented guarded restart passed all pre-signal checks and changed the API address
and generation while preserving its current route. Admin restarted, but front
entered a failed, unpublished listener generation. Its adapter reported
`qualified profile context lookup failed (status 1)`; the managed diagnostic
retained `report = absent`, `ownership = child_unavailable`, and
`route = not_reached`. The context subprocess stderr was not retained, so the
underlying context failure is unestablished and is not attributed to generic
Effigy or Reference behavior. The assertion stopped before the pending
interruption/collision and `dev:test` proofs. No retry or readiness certification
is inferred from the partial restart.

The context diagnostic boundary records only a fixed schema, phase,
container-operation, exit status and allowlisted error class/message. Phases
cover admission, configuration, service status, Compose bindings, host inventory,
gateway status/port, effective route validation and service-port resolution.
Captured stdout, arbitrary stderr, exception text, commands, environment values,
credentials, secret paths and response bodies are never included. The Vite
adapter preserves approved records on nonzero exit, spawn/timeout and decode
failure; unknown errors retain a fixed failure class rather than raw text.
The qualification harness collects bounded validated front/admin records into
its private external journal before scoped teardown. Redaction controls inject
secret payloads into errors, stdout and stderr, and verify their exclusion.
Successful recipe equivalence is checked separately from the diagnostic code:
changed timeouts or production behavior invalidate retained acceptance reuse.

The nested command boundary preserves a negative `effigy.command.v1` envelope
before classifying nonzero exits. It records the nested process exit separately
from the context/adapter exit, including zero-exit negative envelopes. The
exact-source allowlist accepts `RunnerError` and maps verified container-policy
templates to `default_target_missing`, `container_not_defined`,
`working_directory_missing` or `project_name_conflict`. Dynamic substitutions
and error details are discarded. Unknown classes/reasons are explicit;
malformed JSON, invalid envelopes, spawn failures and timeouts remain distinct.
Hermetic controls exercise the production process/JSON code, actual Vite adapter
and durable receipt collector together; injected failures do not establish the
cause of earlier runtime failures.

Restart observers now retain typed, nonauthoritative listener snapshots before
validation in both listener helpers and immediately on rejection. The private
external journal records a monotonic sequence, checkout/profile identity,
current and previous generations, byte count/digest/file identity, report
schema/generation/address, recorded process identities, finite ownership and
readiness phase values, and the effective route/current target. Unrecorded PGID
or dependent endpoint fields stay unavailable. Rejection records reuse the
same observed bytes instead of rereading after cleanup. Missing, malformed,
permission-denied and unknown fields are explicit; arbitrary state/report
extras, environment, credentials and URL queries are excluded.

Hermetic controls cover both production collection paths, including a ready
observation followed by an unready generation, and seeded-secret exclusion.
The retained-proof comparison normalizes only these exact diagnostic read and
decorator substitutions; readiness, ownership, report and route predicates
still participate in the comparison. Diagnostics grant no readiness credit.
API log capture reads at most 64 KiB, and the supported non-following Silo log
command has a five-second capture budget independent of readiness deadlines.

The instrumented remaining-lifecycle attempt passed the guarded API restart
and front handoff, but admin failed before listener publication. Its retained
`profile_context_failed` journal entry identifies `phase = host-inventory`,
`operation = default.hosts`, `error_class = ProfileError`, `exit_status = 1`,
and the fixed message `operation_failed`. This is the context lookup's supported
unqualified `container hosts` suboperation. The nested rejection reason is not
retained by that classification; no generic core or concurrency defect is
established. The attempt stopped before interruption/collision and `dev:test`,
with scoped down followed by preserved private runtime residue. No retry or
complete dependent-handoff acceptance is inferred.

With nested-envelope diagnostics enabled, the next bounded attempt reached the
post-restart front listener check and refused because the listener was not owned
and ready. It captured no context-error record. The rejected probe-time listener
snapshot was not retained, so this does not establish a nested rejection,
concurrency defect or generic core cause. The attempt stopped; later lifecycle
and `dev:test` acceptance remain unproven. Scoped down selectors returned zero,
and private runtime residue was preserved. Silo log capture timed out, which
limits correlated service evidence.

With probe-time capture, the subsequent attempt passed the guarded API and
dependent restarts, current private HTTPS routes, origins and HMR. It then
stopped during interruption fixture preparation. The interruption helper calls
`dev:hybrid:down`, verifies stopped records and live sibling identities, then
calls `route_domains`; that route helper calls the ready-only `listener_state`
validator. The captured main front observation changed from ready with its new
owned endpoint to `stopped`, with generation/address/owner cleared, before this
rejection. The identical rejected observation was preserved before cleanup.

This demonstrates a bundle qualification precondition conflict, not a generic
core defect or a cause for the historical failures. The smallest owning follow-up
is to establish the supported effective route identity while the profile is
ready, before interruption setup's down, retaining all readiness, stopped-state
and foreign-survivor checks. No correction or second runtime was performed in
this diagnostic attempt. Interruption/recovery, collision/partial failure,
uncertain-owner and foreign-preserving teardown, and `dev:test` acceptance remain
incomplete. Three final down selectors returned zero; exact post-cleanup status
reported no services and private gateways down with empty routes. Recorded
processes and sockets were checked separately; the private VM and residue remain
held, without a retirement or purge claim. Non-following Silo log capture reached
its five-second budget and was skipped with a classified timeout.

Lifecycle probe setup now captures its canonical effective domain while the
profile is live. The existing host-map and ready listener checks remain, and
current live owners must match the caller's current checkout states before any
down action. Interruption setup and stopped cleanup reuse that exact immutable
domain. Collision setup uses the same validated capture. Missing/conflicting
mapping, foreign identity or an unready live listener still refuses before
launch; stopped records do not serve as publication evidence. No additional
ready-only route lookup is performed after down.

Remaining-lifecycle execution can consume the completed restart/origin packet
only after matching its bound source revision, journal digest, success records,
validation function source and Reference source/patch/lock/build-selector
inputs. Fresh setup readiness and current owner checks remain mandatory.
The receipt retains completed acceptance, without transferring any old runtime
owner, process, endpoint or generation, or reporting a skipped proof as a new
pass. Auth/storage reuse retains its existing exact-input admission.

The next bounded attempt matched the retained restart/origin receipt against
fresh build inputs, without repeating the API restart signal or completed
storage operations. Current setup still established nine ready listeners and
live owner identities. It passed the corrected pre-stop domain capture, then
refused during interruption-probe manifest inspection, before launching the
interrupted selector. The supported `config --inspect` command exited zero,
but `_profile_manifest_hosts` recognized only `interrupted_probe`, where the
helper required `api`, `front`, `admin` and that probe. The failure branch
restored the original fixture manifest. This is an observed bundle fixture
inspection/declaration mismatch; parser versus composition cause remains
unestablished, and no generic core defect is certified. A further owning
correction must establish additive probe configuration and supported effective
host inspection without replacing production declarations or weakening gates.

Assembly-only diagnosis subsequently compared the supported versioned
`effigy.config.v1` selected value at
`containers.hybrid_services.host_processes` with the existing text regex in a
fresh private Reference/bundle archive fixture, preserving `sources.siblings =
false`. Before probe injection, both semantic and regex names were `api`,
`front`, `admin`; afterward both were only `interrupted_probe`. The outer
`effigy.command.v1` envelope and inner selected path/schema were verified;
both configuration commands exited zero. Only names/types/count, source
ownership and manifest digest were retained; full configuration remained in
memory. Thus this reproduction establishes effective local-array replacement,
not a regex defect. No parser edit or replacement runtime attempt followed.

The exact pinned bundle composition source treats non-table incoming values
as replacements. Its separate bundle-extension path supports combining default
and local arrays when explicitly selected. The smallest owning proposal is a
fixture-only supported array-extension declaration for this path, proved to
preserve the production hosts plus the probe with strict names/order/duplicate
and refusal controls. This is a proposal, not an implemented or qualified
correction; production composition/defaults and live ownership gates remain
unchanged.

The disposable fixture helper now applies that documented `[manifest].extend`
path at the incoming Reference manifest layer. Existing literal extension
paths are retained; duplicate/conflicting or unsupported settings fail closed.
Typed inspection verifies exact `api/front/admin/probe` order and fieldwise
equality of the original three entries in memory. Neither their declarations
nor their secret fields are copied into fixture output. Only the owned probe
is declared locally. Inspection failures restore the complete original bytes;
both interruption and collision/partial-failure callers also restore them on
success and on thrown errors, including uncertain resource ownership. This
restoration does not grant cleanup authority or manufacture stopped records.

Actual private export assembly proved the original three entries unchanged
with one added probe, and the original semantic list and exact manifest bytes
restored after removal. Hermetic controls cover both injection paths, existing
extension settings, CRLF bytes, changed/missing/duplicate/unknown declarations,
wrong types/contracts, seeded-secret exclusion, symlink refusal and restoration
on inspection error/interruption/uncertain owner state. Product exports and
legacy default composition remain unchanged.

The corrected remaining-lifecycle attempt established nine fresh ready listeners
and matched the retained restart/build receipt, without another API restart
signal or storage acceptance replay. Its actual interruption probe reached
HTTP503 with an accepted report, exclusive socket ownership and no published
route. SIGINT was sent only to the recorded launcher group. The subsequent
supported `dev:hybrid:down` completed, but the probe's durable listener status
remained `failed`. `_verify_profile_stopped_records` requires `stopped` and
refused before recovery. This is a new terminal-record expectation boundary;
it does not by itself establish unsafe core cleanup or a qualified teardown.
No helper relaxation or second isolated runtime followed.

Read-only held status subsequently showed main services/routes empty, gateway
down, three production listener records stopped and the probe failed without a
route owner. Its recorded claimed socket had no listener observed. Both private
siblings remained active, with five services each, ten gateway routes each and
six ready application listeners total. Further cleanup was withheld under the
runner's uncertain-owner rule; all private scopes/VM/residue were preserved.
Original manifest bytes were restored by the caller's unconditional finalizer;
post-failure inspection found neither the local probe nor its extension setting.
Silo log capture reached its five-second budget. Interruption recovery,
collision/partial failure, uncertainty/foreign-preserving teardown and
`dev:test` acceptance remain incomplete.

The smallest owning follow-up is a bounded assessment of the supported terminal
failed-generation/absent supervisor-PID behavior against the helper's stop-record
expectation. Any correction must prove exact recorded ownership and child/socket/
route absence plus sibling-preserving cleanup; accepting `failed` alone would
not establish those invariants. The new counterexample grants no cleanup or
lifecycle acceptance credit.



Three final down selectors returned zero. Exact status reported empty services
and private gateway routes, nine stopped listener records, 21 recorded PIDs
absent and nine recorded sockets without listeners. These observations do not
prove retirement; the private VM and residue remain held. Silo log capture
reached its separate five-second budget. Remaining interruption/recovery,
collision/partial failure, uncertain-owner/foreign-preserving teardown and
`dev:test` acceptance remain incomplete; no second attempt was performed.


The separate exact-source container-only selector passed assembly, published
Silo/MC executable checks and build/start with the workspace image unchanged,
then verified exact cleanup and private-profile purge. Remaining exported
restart/dependent handoff, interruption/collision, foreign-preserving teardown
and `dev:test` acceptance require their own complete receipt. Earlier held
private runtime residue is preserved; empty routes, missing PIDs or a successful
down command alone do not prove retirement or authorize broad cleanup.

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
  assembly/build/start with the disclosed published Silo override.
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
`6da2f94bcc1400f9165b954a5343bd0cb14267ac` and the privately qualified macOS
arm64 binary SHA256
`5febcae9e40625898beab1f7f5dd93c8fbb67df083b1d16466dabcca89dae8c8`.
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
container/DNS/server identities, Compose digest/project/scope and loopback map,
known object digest, exact pipeline exit and post-write MC stat, signed request
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
container stdout/stderr byte cap. The storage diagnostic therefore refuses before
VM/gateway/service effects after native main/worktree preflights. This is a
capture-evidence capability boundary, not evidence of the historical 404 cause
or a Silo defect. No streaming alternative or in-container bounded producer is
qualified by this change; the pinned-image and storage correspondence paths
remain unavailable until that boundary is resolved.

Source anchors: [command-mode capture](https://github.com/inflatable-cookie/effigy/blob/6da2f94bcc1400f9165b954a5343bd0cb14267ac/crates/effigy-runtime/src/shell.rs),
[execution transport](https://github.com/inflatable-cookie/effigy/blob/6da2f94bcc1400f9165b954a5343bd0cb14267ac/src/runner/exec_command/transport.rs).
MC alias/stat decoders use the pinned [alias message](https://github.com/pgsty/mc/blob/e952aa78f10a2b77dd525a2b7e3143bcda0cd377/cmd/alias-main.go)
and [stat message](https://github.com/pgsty/mc/blob/e952aa78f10a2b77dd525a2b7e3143bcda0cd377/cmd/stat.go)
structures; local and S3 stat share `parseStat` and indented JSON serialization.
Source-shaped controls do not certify execution against the published images.
