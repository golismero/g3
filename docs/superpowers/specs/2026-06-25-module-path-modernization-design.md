# Module Path Modernization (`go.work` + real import paths) — Design

**Date:** 2026-06-25
**Status:** Implemented
**Parent:** [`docs/future/http-routing-and-rest-migration.md`](../../future/http-routing-and-rest-migration.md) — "Related cleanup — drop the vanity module paths"

This is **Precursor B** of the HTTP-routing / REST-migration program. It is a self-contained, mechanical cleanup that is *orthogonal* to the REST migration but a natural companion: once the module paths are real and a workspace exists, the later SDK work has one consistent go-gettable scheme instead of a special case.

---

## Program context (for orientation — not this spec's scope)

The parent watchlist decomposes into roughly four orthogonal pieces. Only **B** is in scope here:

| Tier | Piece | Status |
|---|---|---|
| **A** | `g3log` → `log/slog` | **Deferred** — transversal to everything (709 call sites); own spec+plan later. |
| **B** | **Vanity module paths → real GitHub paths + `go.work`** | **This spec.** |
| **C** | huma code-first OpenAPI flag-day (routes + RFC 7807 envelope + generated Go/Python clients + g3cli/g3tui/python updates) | Deferred — own spec. |
| **D** | PyPI publish + `clients/python` submodule fold-back + Knife migration | Deferred — own spec, after C. |

B detailed below; A/C/D intentionally left as outlines (revisit each before starting, per the tiered-plan convention).

---

## Goal

Replace the pre-public-repo **vanity module paths** (`golismero.com/g3lib`, …) — which only ever resolved via `replace ../` — with **real import paths under the actual remote** (`github.com/golismero/g3/src/g3lib`, …), and add a repo-root **`go.work`** workspace for cross-module local development.

Non-goals: publishing the internal modules, retiring `replace`, changing any runtime behavior, touching the `g3log` API.

---

## Decisions

### 1. Path scheme: `github.com/golismero/g3/src/<module>`

The remote is `git@github.com:golismero/g3.git`, so the canonical import path for each module under `src/` is `github.com/golismero/g3/src/<module>`. Applied to all nine modules: `g3`, `g3api`, `g3cli`, `g3config`, `g3lib`, `g3log`, `g3scanner`, `g3tui`, `g3worker`.

### 2. Keep `replace`; add `go.work` (do **not** retire `replace`)

The parent doc floats retiring `replace ../` in favor of `go.work`. We **keep `replace`** for now. Rationale:

- **`go.work` and `replace` cover different commands.** `go.work` redirects modules locally for `go build` / `go test` / gopls. `go mod tidy` and `go get` **ignore `go.work`** and resolve each module's graph independently — for an *unpublished* intra-repo dependency (`github.com/golismero/g3/src/g3lib`), only `replace` makes that resolve from local disk. Drop `replace` and the dependency-maintenance flow breaks the moment local cross-module edits are uncommitted.
- **`replace` is not a fetch hazard.** Go **ignores `replace` directives in dependency (non-main) modules**, so a downstream consumer is unaffected by them. What would block a fetch is the paired `require … v0.0.0-00010101000000-000000000000` **sentinel pseudo-version**, which only resolves because `replace` intercepts it locally. `replace` + sentinel are a matched pair that keeps these modules *honestly internal* until we choose to publish.
- **Fully retiring `replace` belongs with publishing (tier C/D).** It requires real `src/<module>/vX.Y.Z` tags, sentinel→real `require` bumps in dependency order, and a commit-before-tidy discipline. That is the SDK-publishing work, not a mechanical precursor. The one artifact that *will* be published — the `clients/go` SDK — is deliberately designed to own its types and depend on none of these `replace`-laden modules, so it publishes cleanly regardless.

`go.work` is **committed** (this is an application monorepo; everyone should resolve locally) with a `go 1.26.2` directive matching all member modules. `go.work.sum` is committed if/when the toolchain generates it (none needed currently — all dependency checksums are already covered by per-module `go.sum`).

### 3. Build-flow simplification

`go.work` makes the per-target `go mod tidy` in `src/Makefile` obsolete (it was a decade-old hack to keep `go.sum` fresh on every build, predating workspaces). Removed from the build path. Dependency collection for the Docker layer-cache (`misc/collect-go-deps.py` → `misc/deps.txt`) moves to the `update` target, off the hot build path.

### 4. Version-stamp bug fix (surfaced by the rename)

`Version` is defined in package `g3lib` (`src/g3lib/common.go:34`), but every build stamped it via `-X g3lib.Version=…`. Go's linker `-X importpath.name` requires the **full import path**; the real path was `golismero.com/g3lib`, so `g3lib.Version` matched nothing — **the version stamp was a silent no-op** (`g3 --version` always reported `dev`). The rename forces these ldflags to the correct full path, which incidentally fixes the stamp. Corrected at all four sites:

- `Dockerfile:15`
- `misc/build-dist.sh:73`
- `.github/workflows/release.yml` (×2)

→ `-X github.com/golismero/g3/src/g3lib.Version=${VERSION}`

This was surfaced and fixed rather than quietly corrected, per "surface bugs, never hide them."

---

## Change set

Done in this work (rename + Makefile + dep-collection prefix by the user; the items below verified/completed in-session):

| Area | Change |
|---|---|
| `src/*/go.mod` (×9) | `module` / `replace` / `require` lines → `github.com/golismero/g3/src/*`. `replace` retained (targets stay `../<module>`). Internal requires keep the `v0.0.0-00010101…` sentinel. |
| All `*.go` imports | `golismero.com/*` → `github.com/golismero/g3/src/*` (incl. the `log "…/g3log"` alias). |
| `go.work` (new, repo root) | `go 1.26.2`; `use` block listing all nine `./src/*` modules. **Committed.** |
| `src/Makefile` | `go mod tidy` removed from build targets; build resolves via `go.work` / `replace`. |
| `misc/collect-go-deps.py:30` | Internal-module filter prefix → `github.com/golismero/g3/src/`. |
| `Dockerfile:15`, `misc/build-dist.sh:73`, `.github/workflows/release.yml` (×2) | `-X` ldflag → full import path (version-stamp fix). |
| `.golangci.yml:26` | Lingering `golismero.com/g3lib.SyncWebSocket` → full path (rename leftover, was missed alongside lines 30–31). |

---

## Verification performed (lint + build only)

- `go work edit -json` — `go.work` valid; all nine modules registered.
- `cd src/g3api && go build ./...` — cross-module compile through the workspace: **OK**.
- `make -C src all` — full build via the `replace` path: all seven binaries built: **OK**.
- `go tool nm bin/g3 | grep Version` → symbol is `github.com/golismero/g3/src/g3lib.Version` (authoritative confirmation the new `-X` path matches; the old short path could not).
- `go version -m` confirms the `-ldflags` string is embedded in build metadata (explains why a naive `strings` grep is not a clean test of the stamp).
- `misc/deps.txt` contains no internal modules (filter working).

**Left to the user (runtime / git, by convention):**
- Confirm `g3 --version` now reflects a stamped version (build a release-flavored binary or `make docker` with `VERSION=…`).
- Regenerate `misc/deps.txt` via the `update` target if dependency versions changed (not required by the rename itself — external dep paths are unchanged).
- Commit.

---

## Risks & notes

- **Behavior-preserving.** No runtime code paths change; this is paths + build wiring. The only *intended* behavior change is the version stamp going from broken→working.
- **`replace` + `go.work` coexist cleanly** — `go.work` `use` wins for workspace builds, `replace` covers `tidy`/Docker. Redundant-looking but each serves a different command.
- **Docker build unaffected** — it resolves via `replace` (whole `src/` tree is `COPY`'d); `go.work` is a local-dev convenience and is not required inside the image.

---

## Optional follow-ups (not required for B)

- **Fold `go work sync` into `make update`** — after per-module `go get -u`, `go work sync` propagates the MVS-selected version of each shared dependency (mongo/redis/mqtt, pulled via `g3lib`) into all nine `go.mod` files, eliminating cross-module version skew. Small, beneficial; can land with B or separately.
- **Modernize the Docker dep-prefetch** — the `deps.txt` + `collect-go-deps.py` layer-cache trick predates BuildKit; a `RUN --mount=type=cache,target=/go/pkg/mod` cache mount could replace it. Orthogonal Docker optimization; own ticket.

---

## Forward link

When tier C/D publishes the modules and adds `clients/go/`: delete the `replace` directives, swap each sentinel `require` for a real `src/<module>/vX.Y.Z` tag (dependency order), and `go.work`'s `use` keeps local dev resolving unchanged. This spec is the foundation that makes that a deletion rather than a new concept under pressure.
