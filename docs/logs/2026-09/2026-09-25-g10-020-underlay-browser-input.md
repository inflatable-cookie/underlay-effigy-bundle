---
kind: northstar-task-closeout
task: Effigy g10.020 — Underlay bundle Chromium input
status: complete
completed: 2026-09-25
pr: https://github.com/inflatable-cookie/underlay-effigy-bundle/pull/2
merged_commit: 1da2f0ed801c76f542db4830ab6eb2534c84a323
---

# Effigy g10.020 — Underlay bundle Chromium input

This records the Underlay bundle portion of the [canonical Effigy g10.020 task](https://github.com/inflatable-cookie/effigy/blob/792abbaaaf02be9b89921017051158721d7c2e35/docs/roadmaps/g10/020-underlay-bundle-chromium-input.md). The task is complete in this repository.

## Outcome

PR [#2](https://github.com/inflatable-cookie/underlay-effigy-bundle/pull/2) merged to `main` as `1da2f0ed801c76f542db4830ab6eb2534c84a323`. It adds the typed `browser_runtime` input with default `none`, forwards it to the `workspace-rust-bun` service, raises the bundle floor to Effigy 0.13.1, and documents image rebuild and consumer-owned browser installation.

## Acceptance and review

- The published Effigy 0.13.1 `aarch64-apple-darwin` binary rendered omitted input as `browser_runtime = "none"` and explicit opt-in as `browser_runtime = "chromium"`; both values reached the Compose `BROWSER_RUNTIME` build arg. The review records SHA-256 verification against the release record.
- Published Effigy 0.13.0 rejected the bundle because it requires Effigy >= 0.13.1.
- The v1.1.0 catalog Compose fragment maps the service parameter to `BROWSER_RUNTIME`.
- The accepted Northstar review verdict is recorded in [the exact-head review comment](https://github.com/inflatable-cookie/underlay-effigy-bundle/pull/2#issuecomment-5833117909) for head `45313ad5cbee6538d1910f55d0774d82006a9a01`. An earlier review identified that plain container reset could delete persistent volumes; the follow-up commit changed the example to `effigy container reset --keep-data`. The accepted review reported no blocking findings.
- The accepted review reports `git diff --check` passed and a clean worktree at the reviewed head. The PR had no configured checks; GitHub's formal reviews collection is empty, with acceptance carried by the Northstar-marked review comment.

## Limits and deferred work

This bundle change does not alter image bytes. It did not repeat the non-root Playwright/Chromium launch, render, and close smoke already accepted from g10.017. The consuming project still needs to rebuild its workspace image after opting in and install its matching browser revision into the `dev` user cache. Acowtancy's browser gesture and request evidence remains the approved follow-up; no failure in this bundle's acceptance evidence remains open.

## Next

Preserve the approved pointer from the canonical task: Acowtancy Chatterbox enables `browser_runtime`, rebuilds its workspace, and resumes g05.195 browser gesture and request evidence. The bundle repository has no further approved task queued; more bundle scope needs planning direction.
