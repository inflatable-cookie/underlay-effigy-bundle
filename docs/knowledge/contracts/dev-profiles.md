# Development profiles and ownership

## Direction

The intended consumer development default is hybrid: isolated service
containers for Postgres, MinIO, Mailpit and DbGate, with Rust and Bun processes
on the host. `dev:container` retains the Linux whole-stack path. `dev:test`
provides a short-lived, worktree-isolated host and service environment without
automatically running full QA.

These are intended profiles, not a claim that the current bundle implements
them. Existing defaults remain container-based. New profile additions must be
opt-in and backward-compatible; switching a consumer's `dev` default requires
an explicit migration after qualification. Container-only use remains valid.

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

## Supported Effigy boundary and Reference execution — 2026-10-10

The final Effigy owner handover is source commit
`2f7b1819fd0e72afff18a6053be424719ecf71fc`. The retained Reference runtime
receipts used its privately built `effigy v0.14.1` binary (SHA-256
`b7ba80a301b5d543cab745d9ddd91a55dd3e058619abfcd90752bed2e970d1ae`). The
current qualification selector pin is a second private `effigy v0.14.1`
build from the same source (SHA-256
`2f4f888c76f424d41cc981881bc544a14fb82f024c0c50a2e3b5022bd4fb16fc`); the
generic and configuration-only Reference selectors are rerun against this
build after the pin change. The inspected source documents were
`docs/knowledge/contracts/005-container-runtime-contract.md` and
`docs/guides/063-container-system-guide.md` in that exact checkout.

Effigy supports `containers.<name>.host_processes` declarations with
`listener.bind`, HTTP readiness, a TLS route, and `depends_on`. An adapter
strictly binds `EFFIGY_MANAGED_HOST_LISTENER_BIND`, then writes
`effigy.managed.host-listener-report.v1` to
`EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE` and echoes
`EFFIGY_MANAGED_HOST_LISTENER_GENERATION`. Effigy verifies the kernel-owned
socket and readiness before route publication. Dependents receive the current
`EFFIGY_MANAGED_HOST_<NAME>_INTERNAL_URL`, `_PUBLIC_URL`, `_STATE_FILE`, and
`_GENERATION` values and restart when the dependency endpoint or readiness
changes. Failure diagnostics include the report, claimed address, ownership,
candidate inspection, observed listener PID, HTTP probe/status, and route;
these fields diagnose a failed generation but do not establish ownership.
This supersedes the earlier missing-capability and timeout findings.

Effigy private gateway mode uses a caller-owned mode-0700 root selected with
`EFFIGY_GATEWAY_PRIVATE_STATE_ROOT` and `--private-state-root`. Private TLS
setup and startup use the fixture CA without installing it or changing the
system resolver, aliases, global gateway state, or trust store. Clients must
use the fixture CA and explicit SNI/name resolution. Qualification used the
gateway's reported HTTPS port rather than assuming port 443; the fixture CA
remained uninstalled.

### Designated Reference receipts

The pilot source was a clean Underlay Reference checkout at
`16b35df4bebe920b14eca9d43abc626de44cb617`; the source checkout stayed
untouched. The private main clone and two detached worktrees retained
`sources.siblings = false`, the `workspace-rust-bun` catalog, the default
Reference project name, and container ports 41001/41002/41003. Effigy
reported separate checkout scopes and HTTPS host maps. The actual managed-app
runtime proof ran on the private main clone only; worktree app concurrency is
not established.

The bundle's opt-in adapters are
`scripts/dev/managed-rust-listener.py` and
`scripts/dev/managed-vite-listener.mjs`. The Rust adapter starts Reference's
actual `acme-api/api` task with Effigy's loopback bind preference, discovers
the listener within that task's process tree, and writes the versioned
generation report. The Vite adapter loads the installed Reference
Vite/SvelteKit configuration, consumes Effigy's managed API public URL, writes
the generated client URL module, sets SvelteKit `ORIGIN`, and configures HMR
for the gateway's actual HTTPS port. Fixture-only overrides requested
loopback port zero and private domains; no consumer default or source
checkout changed.

On the private main clone, the actual Reference API, front Vite app, and admin
Vite app each reached `ready` with distinct loopback listener addresses. Their
generation reports matched Effigy's state, and each route owner matched the
recorded process identity. Effigy registered the three HTTPS routes only
after listener readiness. The API reached the real Postgres service over its
loopback host endpoint and applied SQLx migrations. Mailpit accepted an SMTP
EHLO on its loopback endpoint. The private gateway reported the routes as
TLS-enabled with certificates ready; CA-verified requests with explicit SNI
returned HTTP 200 for the API, front, and admin routes. The frontend Vite
client advertised the actual gateway HTTPS port and `wss`; its WebSocket
upgrade through that gateway returned 101.

The SvelteKit origin probe returned HTTPS in the browser `Origin` header but
HTTP in `event.url.origin`, despite the adapter setting `ORIGIN` and Vite's
public origin. The installed Reference SvelteKit development middleware builds
the request scheme from Vite's `server.https` setting and request host; the
managed host listener is HTTP behind the HTTPS gateway. The bundle adapter
does not currently make this event URL reflect the public HTTPS scheme. Treat
SvelteKit public-origin behavior as unqualified until the bundle has a
supported app-level solution that passes the real route probe.

A later read-only selector invocation found all three main-clone listener
state files at `unavailable`, with no current address. The API state still
contained a prior route-owner record, and its recorded listener PID still
held the old loopback socket while the recorded supervisor and wrapper PIDs
were absent. The cause was not established. No process was signaled while
that state was uncertain. After Effigy's exact `container hybrid down`
removed the routes and containers, the recorded API listener PID, start
identity, executable path and socket were rechecked; that exact PID received
SIGTERM and exited. This manual cleanup is not a successful supervisor
recovery proof. The earlier ready-state, route, HTTPS and HMR observations
remain receipts for that earlier generation only; restart and
dependent-route replacement were not qualified.

The private hybrid service fixture ran real Postgres and Mailpit and omitted
the workspace Rust/Bun image. It did not include MinIO or DbGate. A separate
private-consumer default `container up` stopped at the pinned MinIO image
pull with registry `insufficient_scope`; no substitute image counts as
MinIO evidence, and the default stack did not start. Therefore default
container startup and the full Postgres/MinIO/SMTP service set remain
unqualified.

### Current assurance

On 2026-10-10, both `proof:dev-profiles` and
`proof:dev-profiles:reference` exited 0 with the current pinned binary hash
above. The generic selector passed six synthetic concurrent listeners and an
occupied-port collision; the Reference selector used a fresh private main
clone and two worktrees for configuration, scope, and actual adapter-plan
checks only. `northstar/check-links` also exited 0. These current selector
receipts do not replace the earlier Reference runtime receipts or clear their
listed blockers.

The bundle's default container profile and fixed ports remain unchanged.
Private Reference plans, sibling-disabled assembly, an earlier ready main
generation's API/front/admin listeners, Postgres/Mailpit connectivity,
verified HTTPS routes, and Vite HMR are proven for those exact fixture
inputs. The current main listener records later became unavailable, so this
does not qualify stable lifecycle recovery. The hybrid profile and `dev:test`
are still unavailable. The worktree applications were not launched
concurrently. MinIO/default startup, SvelteKit event URL origin, listener
restart and dependent route replacement, partial failure, interrupted or
uncertain-owner recovery, and teardown preserving the other instances and a
foreign route/process remain unqualified. Do not switch a consumer's default
or claim either profile ready from these receipts.

### Private teardown receipts

Effigy's `container hybrid down` and default `container down` each exited 0.
The subsequent status calls found no services in either main-clone profile;
the private gateway route table had zero routes. Exact `container retire`
calls for the main clone and two worktree scopes exited 0 with no remaining
resources or unverified profiles, but also reported `scope = null` and
`record_removed = false`, so they did not constitute a host-process cleanup
receipt. After the recorded API listener was stopped as described above, the
private Colima profile purge exited 0 and reported `exists = false`. Private
gateway down exited 0; final status reported `running = false`, zero routes,
and `ca_installed = false`. No system trust store, resolver, aliases, or
global gateway settings were changed. The worktree apps were never launched,
so this does not prove teardown of three active instances or preservation of
a foreign route/process.

The Reference selector accepts
`UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT` for a private main clone and its two
worktrees. It may add a temporary origin-probe route only within that
disposable clone; the source checkout is read-only. The qualification scripts
require both `UNDERLAY_PROFILE_EFFIGY_SOURCE` and
`UNDERLAY_PROFILE_EFFIGY_BIN`, pinned to the exact source and private binary
hash above. They never choose a global Effigy binary implicitly.
