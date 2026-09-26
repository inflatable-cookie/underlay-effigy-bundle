# Agent Instructions For Underlay Effigy Bundle

A Git-hosted Effigy bundle for the Underlay-style Rust + Bun workspace stack.
Consumers reference it by Git URL with no pinned ref, so **every merge to
`main` reaches every consumer on their next Effigy run**. Treat each merge as
a release.

## Where things live

- How to use the bundle: `README.md`, with the input schema in `bundle.toml`
- Knowledge: `docs/knowledge/README.md`
- How a change is released: `docs/knowledge/contracts/release.md`
- What's next: `docs/plan.md`

Tasks, briefs and status live in Queue, never in this repository (lean
Northstar, `northstar-lean` skill).

## Product rules

- Keep inputs backward-compatible. A new input gets a safe default, and a
  change that needs a newer Effigy raises `minimum_effigy_version` so older
  Effigy refuses the bundle instead of silently ignoring the setting.
- App-specific secrets stay in the consuming repository; the bundle declares
  only the shared Underlay runtime secret contract.

## Validate

Assemble the bundle from a consumer checkout (for example acowtancy) before
merging; see `docs/knowledge/contracts/release.md`.
