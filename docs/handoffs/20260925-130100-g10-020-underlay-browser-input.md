---
kind: northstar-handoff
title: "Effigy g10.020 — Underlay bundle Chromium input"
handoff_mode: worker-pr-loop
worker_mode: implementation
dispatch_authority: orchestrator
status: ready-to-launch
base_required: pushed-main
queue_dispatch: northstar-queue
queue_approval: "Tom approved the two-repository opt-in Playwright/Chromium lane with 'Go for it' on 2026-09-25, chose Effigy 0.13.1 as the supporting release, approved its notes and cut, then said 'Continue' after publication. This submission covers only the Underlay bundle follow-up."
queue:
  capability: general
  notifyOriginOnCloseout: true
---

## What This Thread Was Doing

Implement [Effigy g10.020](https://github.com/inflatable-cookie/effigy/blob/792abbaaaf02be9b89921017051158721d7c2e35/docs/roadmaps/g10/020-underlay-bundle-chromium-input.md) in this repository. The pinned card owns scope, acceptance, and stop conditions. It is part of the operator-approved shared browser-runtime lane; this repo owns the consumer bundle input and export only.

## Why It Matters

Acowtancy g05.195 needs real Playwright browser evidence. The shared catalog image now has the libraries, but this bundle does not expose its opt-in parameter. An older Effigy must fail the bundle revision cleanly instead of ignoring the setting.

## Current State

- Bundle `main` is clean and selects `catalog = "workspace-rust-bun"` in `export.toml`. `bundle.toml` has typed inputs but no `browser_runtime` input. The manifest floor is still 0.10.0.
- Effigy [v0.13.1](https://github.com/inflatable-cookie/effigy/releases/tag/v0.13.1) is published and install-verified. The built-in service accepts `browser_runtime = "none"` by default or `"chromium"` explicitly. Catalog-pack v1.1.0 supplies its exact image bytes.
- g10.017 proved linux-arm64 Playwright 1.55.1 Chromium build 1193 launching, rendering, and closing as non-root `dev`. This task changes no image bytes and does not need to repeat that smoke.
- Queue owns the worker, independent review, and PR merge. Chatterbox owns the cross-repository g10.020 planning card and Acowtancy notification after closeout.

## Boundaries

Edit only bundle `bundle.toml`, `export.toml`, `README.md`, and directly necessary bundle-owned validation evidence. Add a typed string `browser_runtime` input defaulting to `"none"`; pass it to the workspace service. Raise `minimum_effigy_version` to `"0.13.1"` for this bundle revision. Document image rebuild and consumer-owned matching browser installation. Do not edit Effigy, catalog-pack, Acowtancy, workflows, tags, or release surfaces. Do not add Node, Playwright, a browser binary, arbitrary apt inputs, or a per-project Dockerfile.

## Important Context

The approved card is pinned above. Effigy's external bundle adoption guide is `docs/guides/065-external-bundle-adoption.md`; the catalog service reference is `docs/guides/067-catalog-services-reference.md`. Use the **published 0.13.1 binary**, not a local `+local` build, to prove bundle composition. Also use released 0.13.0 to prove the version floor rejects the new bundle. A local development build can bypass the minimum-version check and is not a valid negative oracle. Preserve unrelated work.

## Suggested Next Move

Wire the typed input and service parameter, update the README, then make a temporary path-sourced consumer manifest with the bundle's required inputs. Show default `none` and explicit `chromium` reaching the service and Compose build arg through released Effigy 0.13.1. Show 0.13.0 fails on the version floor. Run focused validation and `git diff --check`, then open one non-draft PR.

## Completion Protocol

Obtain independent exact-head review and current-base validation before Queue merges. Report rendered values, released binary identities, the 0.13.0 rejection, PR/reviewed head/merge, and material limits. Tell the origin Chatterbox when terminal so it can update g10.020 and notify Acowtancy to rebuild and resume its browser proof.
