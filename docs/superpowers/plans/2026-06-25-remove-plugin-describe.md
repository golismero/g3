# Remove `POST /plugin/describe` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the abandoned `POST /plugin/describe` LLM-contract endpoint and all describe-only code across the server, `g3lib`, and the Python SDK, leaving `/plugin/list` intact.

**Architecture:** Pure deletion. The endpoint filtered plugins declaring an optional `llm:` metadata block and projected each into a `PluginContract`; no production plugin declares that block, so the endpoint already returns an empty list. Removal cleaves along purpose — everything LLM-contract-shaped goes; the empty `ReqListPlugins` request struct stays because `/plugin/list` shares it.

**Tech Stack:** Go 1.25 (`net/http`, go-playground/validator), Python 3 (httpx-based SDK), Jsonnet (`.g3p` plugin definitions).

## Global Constraints

- **Tests are user-owned** — do NOT write or run tests, do NOT run binaries or hit servers. Verification is build + correctness-only lint.
- **Git is user-owned** — do NOT run mutating git commands. The user commits the whole change in one batch at the end.
- **No formatting enforcement** — do not run gofmt/goimports/ruff-format.
- **Keep `ReqListPlugins`** (`src/g3lib/api.go:494-500`) — shared with `/plugin/list`.
- Spec: `docs/superpowers/specs/2026-06-25-remove-plugin-describe-design.md`.

---

### Task 1: Remove the server endpoint and helper

**Files:**
- Modify: `src/g3api/g3api.go` (delete handler ~1400-1433, helper ~137-148)

**Interfaces:**
- Consumes: nothing.
- Produces: removes the `/plugin/describe` route and `buildPluginContract`; no symbol other tasks depend on.

- [ ] **Step 1: Delete the `/plugin/describe` route block.** Remove the comment + handler registration in `src/g3api/g3api.go`, from the comment line beginning `// LLM-facing tool contract:` through the closing `}))` of the `http.HandleFunc(apiPath+"/plugin/describe", ...)` registration. Exact block to delete:

```go
		///////////////////////////////////////////////////////////////////////////////////////////
		// LLM-facing tool contract: per-plugin Summary/Accepts/Produces/Operations
		// sourced from optional .g3p `llm:` metadata, with graceful fallback when
		// the block is absent. Excludes Description/URL/Image (those stay on
		// /plugin/list for humans and GUIs).
		http.HandleFunc(apiPath+"/plugin/describe", requireToken(apiToken, func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Handling: plugin/describe")
			var request g3lib.ReqListPlugins
			if err := request.Decode(r); err != nil {
				log.Error("Error decoding payload: " + err.Error())
				g3lib.SendApiError(w, http.StatusBadRequest, "Bad request.")
				return
			}

			pluginNames := make([]string, 0, len(plugins))
			for key := range plugins {
				pluginNames = append(pluginNames, key)
			}
			sort.Strings(pluginNames)

			contracts := make([]g3lib.PluginContract, 0, len(plugins))
			for _, name := range pluginNames {
				plugin := plugins[name]
				// Tools without an `llm:` block in their .g3p are not reachable
				// to LLM consumers — the absence of the block is the opt-out
				// signal. Present-but-empty (`llm: {}`) still counts as opt-in.
				if plugin.LLM == nil {
					continue
				}
				contracts = append(contracts, buildPluginContract(plugin))
			}

			g3lib.SendApiResponse(w, contracts)
		}))
```

The `/plugin/list` block immediately above and the `/config/env` block immediately below stay. Leave one blank line between them.

- [ ] **Step 2: Delete the `buildPluginContract` helper.** Remove this function (and its doc comment) from `src/g3api/g3api.go`:

```go
// buildPluginContract assembles the LLM-facing contract for one plugin. The
// caller MUST have ensured plugin.LLM != nil; plugins without the LLM block
// are not reachable to LLM consumers and are filtered out at the handler
// before reaching this function.
func buildPluginContract(plugin g3lib.G3Plugin) g3lib.PluginContract {
	return g3lib.PluginContract{
		Name:     plugin.Name,
		Summary:  plugin.LLM.Summary,
		Accepts:  plugin.LLM.Accepts,
		Produces: plugin.LLM.Produces,
	}
}
```

- [ ] **Step 3: Build to confirm `g3api` still compiles after the g3lib changes.** Deferred to Task 2's build step (this task references `g3lib.PluginContract`/`g3lib.G3Plugin.LLM`, which Task 2 removes — build after both). No standalone build here.

---

### Task 2: Remove the `g3lib` describe-only types

**Files:**
- Modify: `src/g3lib/api.go` (delete `PluginContract` + orphan comment ~528-539)
- Modify: `src/g3lib/plugin.go` (delete `G3LLMMetadata` ~66-76 and `G3Plugin.LLM` field ~88)

**Interfaces:**
- Consumes: nothing.
- Produces: removes types `g3lib.PluginContract`, `g3lib.G3LLMMetadata`, and field `G3Plugin.LLM`. After this task plus Task 1, no references to these remain.

- [ ] **Step 1: Delete `PluginContract` and its orphaned comment from `src/g3lib/api.go`.** Remove this block (note the first two comment lines are a dangling `PluginContractOperation` doc with no corresponding type — remove them too):

```go
// PluginContractOperation describes one command variant a plugin exposes
// (`/scan/task/dispatch` selects a variant by Index).
// PluginContract is the LLM-facing contract for one plugin. Served by
// /plugin/describe. Excludes Description/URL/Image (those stay on /plugin/list
// for humans and GUIs). All fields are author-populated from the plugin's
// `llm:` block — no auto-derivation, no fallbacks.
type PluginContract struct {
	Name     string   `json:"name"`
	Summary  string   `json:"summary"`
	Accepts  []string `json:"accepts"`
	Produces []string `json:"produces"`
}
```

`PluginListItem` directly above and `ReqCheckScriptSyntax` below stay.

- [ ] **Step 2: Delete `G3LLMMetadata` from `src/g3lib/plugin.go`.** Remove the struct and its doc comment:

```go
// G3LLMMetadata is the additive plugin metadata that opts a plugin in to the
// LLM-facing /plugin/describe surface. Presence of this block is the opt-in
// signal; all three fields are required and non-empty when the block is
// present (g3config validates this at plugin load time). There is no
// fallback derivation — what /plugin/describe returns is exactly what plugin
// authors declared here.
type G3LLMMetadata struct {
	Summary  string   `json:"summary"  validate:"required"`               // LLM-specific one-line explanation of the tool.
	Accepts  []string `json:"accepts"  validate:"required,min=1,dive,required"` // G3Data _type(s) this plugin consumes.
	Produces []string `json:"produces" validate:"required,min=1,dive,required"` // G3Data _type(s) this plugin emits (an importer routinely emits multiple types).
}
```

- [ ] **Step 3: Delete the `LLM` field from the `G3Plugin` struct in `src/g3lib/plugin.go`.** Remove this single line:

```go
	LLM         *G3LLMMetadata      `json:"llm,omitempty"       validate:"omitempty"`       // (Optional) Additive metadata for LLM/MCP consumers.
```

The `Reporter` field directly above stays as the struct's last field.

- [ ] **Step 4: Build `g3lib` and `g3api` to confirm both compile.** From `src/`:

```bash
cd src && make ../bin/g3api
```

Expected: builds clean, no errors. (This binary links `g3api` + `g3lib`, covering Tasks 1 and 2.) If a "declared and not used" or "undefined" error mentions `PluginContract`, `G3LLMMetadata`, `LLM`, or `buildPluginContract`, a reference was missed — grep `src/` for the symbol and remove it.

---

### Task 3: Remove the Python SDK `describe()` and `PluginContract`

**Files:**
- Modify: `sdk/python/g3client/api/plugins.py` (delete `describe()` ~18-21; fix import line 6)
- Modify: `sdk/python/g3client/types.py` (delete `PluginContract` dataclass ~146-162)

**Interfaces:**
- Consumes: nothing.
- Produces: removes `PluginsResource.describe()` and the `PluginContract` dataclass. `PluginInfo`, `PluginsResource.list()`, and the `scanner`/`manager` facades are untouched, so Knife's `manager` contract is unaffected.

- [ ] **Step 1: Delete the `describe()` method from `sdk/python/g3client/api/plugins.py`.** Remove:

```python
    def describe(self) -> list[PluginContract]:
        # REST-MIGRATION: future GET /plugins/describe
        rows = self._t.request("POST", "/plugin/describe", json={}) or []
        return [PluginContract.from_raw(r) for r in rows]
```

`list()` above stays.

- [ ] **Step 2: Drop the now-unused `PluginContract` import in the same file.** Change line 6 from:

```python
from ..types import PluginContract, PluginInfo
```

to:

```python
from ..types import PluginInfo
```

- [ ] **Step 3: Delete the `PluginContract` dataclass from `sdk/python/g3client/types.py`.** Remove the whole block (including the blank separator line preceding it so `PluginInfo` and the next type keep their two-blank-line spacing):

```python
@dataclass(frozen=True)
class PluginContract:
    name: str
    summary: str
    accepts: tuple[str, ...]
    produces: tuple[str, ...]
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, d: dict[str, Any]) -> "PluginContract":
        return cls(
            name=d.get("name", ""),
            summary=d.get("summary", ""),
            accepts=tuple(d.get("accepts", ()) or ()),
            produces=tuple(d.get("produces", ()) or ()),
            raw=d,
        )
```

`PluginContract` is not re-exported in `g3client/__init__.py`'s `__all__`, so no further export edits are needed.

- [ ] **Step 4: Verify no stray `PluginContract`/`describe` references remain in the Python client.** Run:

```bash
grep -rn "PluginContract\|/plugin/describe" sdk/python/
```

Expected: no output. (The user runs the actual `import g3client` smoke check per project conventions.)

---

### Task 4: Clean stale references in plugins and docs

**Files:**
- Modify: `plugins/debug/passthrough/passthrough.g3p` (line 6)
- Modify: `plugins/debug/error/error.g3p` (line 6)
- Modify: `plugins/debug/force-exec/force-exec.g3p` (line 9)
- Modify: `docs/future/http-routing-and-rest-migration.md` (sections ~51 and ~191)

**Interfaces:**
- Consumes: nothing.
- Produces: documentation/comment cleanup only; no code symbols.

- [ ] **Step 1: Remove the stale `llm:`-block comment from each debug `.g3p`.** In all three files delete the line:

```jsonnet
    // Intentionally no `llm:` block: debug-only plugin, not exposed via /plugin/describe.
```

(`force-exec.g3p` has it at line 9; the other two at line 6.) The `llm:` mechanism no longer exists, so the comment is meaningless. Leave surrounding lines intact.

- [ ] **Step 2: Mark-done-in-place in the future doc — the dedicated section.** In `docs/future/http-routing-and-rest-migration.md`, find the `### \`/plugin/describe\` removed` section and prepend a done note as the first line of its body, so it reads:

```markdown
### `/plugin/describe` removed

> **✅ Done (2026-06-25):** removed standalone ahead of the migration — handler/route, `g3lib` `PluginContract`/`G3LLMMetadata`/`G3Plugin.LLM`, and the Python SDK `describe()`/`PluginContract` are all deleted. See `docs/superpowers/specs/2026-06-25-remove-plugin-describe-design.md`.

`POST /plugin/describe` (the LLM-contract list) is **phased out**. ...
```

(Keep the existing paragraph as-is below the note.)

- [ ] **Step 3: Mark-done on the endpoint-table reference.** Find the parenthetical line near the Plugins/config table:

```markdown
(`POST /plugin/describe` — the LLM-contract list — is **removed**; LLM tooling moves to a separate project. See *Direction (2026-06-24)*.)
```

Append `✅ Done 2026-06-25.` to it:

```markdown
(`POST /plugin/describe` — the LLM-contract list — is **removed**; LLM tooling moves to a separate project. See *Direction (2026-06-24)*. ✅ Done 2026-06-25.)
```

- [ ] **Step 4: Final sweep.** From the repo root run:

```bash
grep -rn "plugin/describe\|PluginContract\|G3LLMMetadata" src/ sdk/ plugins/
```

Expected: no output (all references gone). Matches inside `docs/` are expected and fine (the future doc and this plan/spec deliberately mention the removed endpoint).

---

## Handoff to user

All edits done, no commits made (git is user-owned). The user reviews the diff and commits the whole change as one batch. Suggested verification before committing: `cd src && make ../bin/g3api` (Go build) and an `import g3client` smoke check (Python).
