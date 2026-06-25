# Remove `POST /plugin/describe` — Design

**Date:** 2026-06-25
**Status:** Approved, ready for implementation plan
**Context:** Standalone removal pulled forward from the (unscheduled) REST migration watchlist
(`docs/future/http-routing-and-rest-migration.md`, "/plugin/describe removed" section).

## Goal

Delete the abandoned LLM-contract endpoint `POST /plugin/describe` and all describe-only
code across the server, the shared `g3lib` library, and the Python SDK. Leave the
human-facing `POST /plugin/list` endpoint and its shared plumbing intact.

## Background

`/plugin/describe` is the last surviving footprint of the abandoned "LLM in g3api"
experiment (added during knife integration). Plugin metadata gained an optional `llm:`
block (`G3LLMMetadata`: `summary`/`accepts`/`produces`); the endpoint filtered to plugins
declaring that block and projected each into a `PluginContract`. **No production plugin
declares an `llm:` block today**, so the endpoint already returns an empty list in practice.
LLM tooling is moving to a separate project that will consume the generated clients, so the
mechanism is dead weight.

The removal cleaves cleanly along purpose: everything LLM-contract-shaped goes; the only
entanglement is `ReqListPlugins`, an empty request struct shared with `/plugin/list`, which
stays.

## Changes by layer

### 1. Server — `src/g3api/g3api.go`
- Delete the `/plugin/describe` route registration + handler (lines ~1405-1433).
- Delete the `buildPluginContract()` helper (lines ~137-148).

### 2. Shared lib — `src/g3lib/`
- `api.go`: delete the `PluginContract` struct (~534-539).
- `plugin.go`: delete the `G3LLMMetadata` struct (~66-76) and the `G3Plugin.LLM` field (~88).
- **Keep** `ReqListPlugins` and its `Decode` — shared with `/plugin/list`.

### 3. Python SDK — `clients/python/g3client/`
- `api/plugins.py`: delete the `describe()` method (~18-21).
- `types.py`: delete the `PluginContract` dataclass (~147-162).
- Remove any now-dead `PluginContract` import / `__all__` export left behind.
- `scanner` / `manager` facades are untouched, so **Knife is unaffected** (it couples only
  to the `manager` facade; `describe()` lived in the `api` tier).

### 4. Stale references
- Remove the "Intentionally no `llm:` block … not exposed via /plugin/describe" comment
  lines in the three debug plugin definitions:
  `plugins/debug/passthrough/passthrough.g3p`, `plugins/debug/error/error.g3p`,
  `plugins/debug/force-exec/force-exec.g3p`. The `llm:` mechanism they reference no longer
  exists, so the comments are stale.
- `docs/future/http-routing-and-rest-migration.md`: mark-done-in-place — add a
  `✅ Done (2026-06-25): removed standalone ahead of the migration` note on the
  `/plugin/describe` section (line ~51) and on the endpoint-table reference (line ~191).

## Out of scope (deliberately untouched)
- `ReqListPlugins`, `POST /plugin/list`, `POST /config/env`.
- Anything not LLM-contract-shaped.

## Risk

The only cross-cutting type is `G3Plugin.LLM`. It is `omitempty` and never populated by any
plugin, so removing it cannot break plugin parsing, the `g3config` registry, or any stored
JSON. The endpoint already returns an empty list, so removing it is not a behavioral
regression for any real client.

## Verification
- Go: build `g3api` and `g3lib` (and dependents) clean; correctness-only lint.
- Python: import check of `g3client` is the user's to run.
- No new tests — pure deletion, no new behavior.
