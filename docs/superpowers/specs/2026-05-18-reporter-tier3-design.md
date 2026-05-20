# Reporter Plugins — Tier 3 Design

Brainstormed 2026-05-18.

## Context

Tier 1 and Tier 2 of the reporter plugin system shipped server-side
dispatch (sync `/scan/reporter`, then async + generic artifacts download).
Mid-Tier-3 brainstorming surfaced two architectural issues:

1. **Server-side scan scripts had no `report` directive.** A script could
   declare tools and pipelines but not a reporter — meaning a scan
   submitted via `g3cli scan` could not request a report at the same
   time. Server- and (eventual) local-CLI behavior would diverge on the
   same script.

2. **Reporter tasks wrote manifests they didn't need.** The Tier 1 worker
   wrote `manifest.json` for reporter tasks mechanically (copied from the
   tool-task code path). The manifest's reason for existing — the
   useful-vs-forensic `Work[].Artifacts` distinction — does not apply to
   reporters, where everything the container writes is the report. The
   accidental presence of `manifest.json` in every reporter slot also
   killed `BundleTaskSlot`'s single-file download path; every reporter
   bundle was a 2-file zip.

3. **`/scan/task/artifacts` used disk-first manifest presence as its
   terminal-state signal.** This worked, but coupled lifecycle decisions
   to filesystem state — a poor fit for distributed filesystems and
   redundant with the SQL log markers that `/scan/tasks/status` already
   trusts for the same job.

The dispatcher refactor
([2026-05-18-scanner-as-dispatcher-design.md](2026-05-18-scanner-as-dispatcher-design.md))
landed first to unblock (1) — the scanner now has a `dispatchTask`
helper that handles both tool and reporter dispatches through one
canonical path. With that foundation in place, Tier 3 adds scripted
reporter dispatch on top of it and resolves (2) and (3) as
companion cleanups.

**Tier 3 is server-side only.** Local CLI reporter integration (the
original Tier 3 working title) is deferred to a later tier; once Tier 3
ships, the local CLI path becomes a smaller piece of work because the
underlying contracts (manifest semantics, lifecycle source of truth,
script syntax) are settled.

## Goal

Three changes, all server-side, all building on the dispatcher refactor:

1. **`report <tool>[:<preset>]` directive in scan scripts**, parsed by
   `g3lib/script.go` and dispatched by `g3scanner`'s ScanRunner after
   the pipeline completes, using the existing `dispatchTask(kind:
   "report", ...)` helper.
2. **Drop `WriteManifest` for reporter tasks** in `g3worker`. Reporter
   slots contain only what the reporter container wrote. Restores the
   `BundleTaskSlot` single-file download path for the common case
   (reporter produces one output file).
3. **Switch `POST /scan/task/artifacts` from disk-first manifest check
   to Redis → SQL log fallback**, mirroring `/scan/tasks/status`'s
   lifecycle source. Filesystem participates in the bundling step only,
   never in the lifecycle check. Tool name comes from the SQL
   `[g3:dispatch]` marker — uniform across kinds, no more manifest
   parsing in the endpoint.

## Non-goals

- **Local CLI reporter integration** (the original Tier 3 working
  title). Deferred. The `g3 scan` script `report` directive proposed
  in earlier brainstorming, `--artifacts` flags on `g3 scan` / `g3
  run` / `g3 report`, and `g3 report <tool>` invoking the docker
  plugin all wait for a future tier. The current Tier 3 establishes
  the contracts; local CLI consumes them later.

- **Multi-reporter scripts.** At most one `report` directive per
  script (multiple → parse error). Multi-report scripts require a
  per-reporter output mapping that's its own design pass; not in
  Tier 3 scope.

- **Reporter task synchronous completion in `g3scanner`.** The scanner
  fires-and-forgets the reporter dispatch (same as `/scan/task/dispatch`
  does from g3api). The scan transitions to `FINISHED` when the
  pipeline + merger phase is done, regardless of reporter state. The
  reporter task shows up as an independent task in
  `/scan/tasks/status`, transitioning through `DISPATCHED → RUNNING →
  DONE` on its own timeline.

- **Tool-task manifest changes.** Tool tasks still write `manifest.json`
  for the same reason as before — the `Work[].Artifacts` machinery
  serves a real purpose for them (useful-vs-forensic distinction,
  downstream magenta integration). Only reporter tasks lose the
  manifest write.

- **Backward-compat shim for old `/scan/task/artifacts` callers.** The
  endpoint's response matrix changes slightly (404 vs 425 split is
  tightened — 404 now requires affirmative "task never existed"
  evidence). The body messages change. Same code, no client migration
  story — there are no production clients yet at this stage of the
  project.

## Design heuristic

Two principles, both inherited and reinforced from prior work:

1. **Filesystem is data; database is lifecycle.** The slot directory
   holds artifact bytes; Redis + SQL hold task state. Endpoint
   decisions consult lifecycle storage first, then act on the
   filesystem only after deciding the action is appropriate.

2. **One canonical state-reconstruction path.** Both `/scan/tasks/status`
   and `/scan/task/artifacts` now lookup task state through the same
   helpers (`GetTaskState` + `ReconstructTaskStateFromLogs`). Adding a
   new endpoint that needs task state means calling those same helpers;
   no endpoint invents its own scheme.

## Component 1: `report` directive in scan scripts

### Script syntax

```
report <tool>[:<preset>]
```

Constraints enforced at parse time:

- The directive must be the **last** directive in the script. Anywhere
  earlier → parse error: `"report directive must be the last line of the
  script"`.
- At most **one** `report` directive per script. A second → parse error:
  `"only one report directive per script is allowed"`.
- `<tool>` must exist in plugin metadata AND have a non-nil `Reporter`
  phase. Otherwise → parse error: `"tool <name> does not implement a
  reporter"`.
- `<preset>`, if given:
  - Plugin has `reporter: {}` with no commands → parse error: `"tool
    <name> declares no reporter presets"`.
  - Plugin has commands, but `<preset>` doesn't match a declared name
    → parse error: `"unknown preset for tool <name>: <preset>"`.

Same validation rules and same error messages as the
`/scan/task/dispatch` HTTP endpoint, so script writers and API clients
get identical feedback.

### Parsed shape

`ParsedScript` in [src/g3lib/script.go:22](../../../src/g3lib/script.go#L22)
gains an optional `Report` field:

```go
type ParsedScript struct {
    Targets   []string        `json:"targets,omitempty"   validate:"omitempty"`
    Imports   []ParsedImport  `json:"imports,omitempty"   validate:"omitempty,dive"`
    Mode      string          `json:"mode,omitempty"      validate:"omitempty"`
    Pipelines [][]string      `json:"pipelines,omitempty" validate:"omitempty"`
    Report    *ParsedReport   `json:"report,omitempty"    validate:"omitempty"`
}

type ParsedReport struct {
    Tool   string `json:"tool"             validate:"required"`
    Preset string `json:"preset,omitempty"`
}
```

The script's `String()` method (used for debug logging) gets an extra
clause to emit `report <tool>[:<preset>]` when `Report` is non-nil.

### ScanRunner integration

In `g3scanner.go`, after the pipeline completes, the merger phase
finishes, and the report info is saved to Redis (current code path
ends at `g3scanner.go:1107+`), add:

```go
// If the script declared a reporter, dispatch it now. The reporter task
// runs independently of the scan completion — scan transitions to
// FINISHED regardless of reporter state.
if parsed.Report != nil {
    reporterTaskID := uuid.NewString()
    if err := dispatchTask(
        mq_client, rdb_client, scan_sql_db,
        msg.ScanID, reporterTaskID, "report", parsed.Report.Tool,
        "", 0, parsed.Report.Preset,
    ); err != nil {
        log.Error("Failed to dispatch script-declared reporter: " + err.Error())
        // Non-fatal: scan still completes. The error is logged but does
        // not flip the scan to ERROR — pipeline work succeeded; the
        // reporter is a downstream artifact that can be re-requested.
    }
}

// (Existing SendScanCompleted call follows, unchanged.)
```

The reporter dispatch uses the exact same canonical helper introduced
in the dispatcher refactor — script-driven and API-driven dispatches
remain bit-identical at the MQTT and SQL level.

### Lifecycle observation

Clients observing a scan via `/scan/tasks/status` see:

1. Tool tasks for each pipeline step (DISPATCHED → RUNNING → DONE).
2. The reporter task (DISPATCHED → RUNNING → DONE), appearing **after**
   the scan transitions to FINISHED.

The reporter task's lifecycle is decoupled from the scan's lifecycle —
which matches Tier 2's API-driven async semantics. A client that wants
the report polls `/scan/tasks/status` until the reporter task is
terminal, then calls `/scan/task/artifacts`.

## Component 2: Drop `WriteManifest` for reporter tasks

### What changes

In `g3worker.go`'s reporter handler (around lines 974+):

- Remove the `g3lib.WriteManifest(outSlot, g3lib.G3Manifest{...})` call.
- Remove the surrounding `manifestWriteErr` variable and the
  manifest-write-failure → ERROR branch in the terminal state decision
  (it becomes unreachable code once the write is gone).
- The terminal state for a reporter task is now determined solely by
  `runErr` from `RunPluginReporter` (`context.Canceled` → CANCELED,
  any other non-nil → ERROR, nil → DONE).

Tool tasks ([g3worker.go:738](../../../src/g3worker/g3worker.go#L738))
are **unchanged** — they still write the manifest because the
`Work[].Artifacts` machinery serves a real purpose for them.

### Downstream effects

| Caller | Behavior change |
| --- | --- |
| `BundleTaskSlot` for reporter slots | Slot contains only what the reporter wrote. The 0/1/many rule now functions as designed: single-file output → clean single-file download; multi-file → zip. |
| Tier 2 `/scan/task/artifacts` for reporter slots | Pre-cleanup: 2-file zip was the only outcome (manifest.json + report.md). Post-cleanup + Section 3: single-file path fires naturally for the common case. |
| Magenta integration | Unaffected. Magenta walks tool task slots (which still have manifests) to dispatch parsers. Reporter task slots are output-only; magenta never reads them. |
| `/scan/tasks/status` reporter task entries | Unchanged. Lifecycle markers (`[g3:start]`, `[g3:done]`) are written by the same code path as before, independent of the manifest write. |

### Spec updates

The Tier 1 design doc
([2026-05-16-reporter-plugins-design.md](2026-05-16-reporter-plugins-design.md))
needs amendment:

- "Component 3: Worker / MQTT integration" worker-flow pseudocode
  drops the `WriteManifest` step for reporter tasks.
- Add a brief note explaining the asymmetry: tool tasks write
  manifests (useful/forensic distinction), reporter tasks do not
  (everything-is-useful).

## Component 3: Artifacts endpoint Redis → SQL fallback

### New decision flow for `POST /scan/task/artifacts`

```
1. Decode + validate request body (unchanged from Tier 2).
2. Resolve task lifecycle state and tool name in one pass:
   a. GetTaskState(rdb, scan_id, task_id):
      - "DONE" / "ERROR" / "CANCELED" → terminal; tool name still
        needs lookup (Redis hash carries it via the "tool" field —
        already populated by SetTaskDispatched). Fetch alongside
        state in a single HGet, or fall through to step 2b for
        uniformity.
      - "DISPATCHED" / "RUNNING" → 425 + body "task is still <STATE>"
        + Retry-After: 2.
      - "" or error → fall through to step 2b.
   b. ReconstructTaskStateFromLogs(sql, scan_id, task_id):
      - Returns state + tool name for the single task.
      - DONE / ERROR / CANCELED → terminal, proceed to step 3.
      - WAITING / RUNNING (started, not done) → 425 + body "task is
        not yet complete" + Retry-After: 2.
      - State "" (no markers found at all) → 404 + body "task not found".
3. Stat the slot dir at <G3_ARTIFACTS_ROOT>/<scan_id>/<task_id>/:
   - Doesn't exist → 404 + body "task produced no output".
   - Exists → call BundleTaskSlot(slotDir, toolName, taskID, &buf);
     stream the result to the response writer with Content-Type,
     Content-Disposition headers.
```

### Response matrix (replaces Tier 2's matrix)

| Lifecycle lookup | Slot on disk | Status | Body / headers |
| --- | --- | --- | --- |
| Terminal (Redis or SQL) | Has ≥1 file | 200 | bundle per BundleTaskSlot rules; `Content-Type`, `Content-Disposition`, `X-G3-Task-ID` |
| Terminal (Redis or SQL) | Empty or absent | 404 | `"task produced no output"` |
| DISPATCHED/RUNNING in Redis | n/a | 425 | `"task is still <STATE>"` + `Retry-After: 2` |
| WAITING/RUNNING via SQL only | n/a | 425 | `"task is not yet complete"` + `Retry-After: 2` |
| No record in Redis or SQL | n/a | 404 | `"task not found"` |
| Malformed request / non-uuid | n/a | 400 | `"Bad request."` |

The 404 vs 425 split is now: 404 requires **affirmative evidence the
task never existed in this scan** (no Redis hash AND no SQL markers).
Every other "not ready" case is 425.

### Helper additions

```go
// ReconstructTaskStateFromLogs returns the state and tool name for a
// single task, reconstructed from SQL log markers. Returns ("", "", nil)
// if no markers for this task exist. Mirrors
// ReconstructTaskStatesFromLogs's parsing logic but scoped to one task.
func ReconstructTaskStateFromLogs(db SQLDBClient, scanID, taskID string) (state, tool string, err error)
```

Implementation in `g3lib/sql.go`: same parsing logic as the existing
plural function, narrowed to a single task via
`WHERE scanid=? AND taskid=? AND text LIKE '[g3:%'` and yielding the
single-row result. About 50 lines including the parsing state machine
reused from the plural function (or factored into a shared internal
helper, both reasonable).

### Code change scope

| File | Change |
| --- | --- |
| `src/g3lib/sql.go` | Add `ReconstructTaskStateFromLogs(db, scanID, taskID) (state, tool string, err error)`. |
| `src/g3api/g3api.go` | Replace the disk-first manifest check in `/scan/task/artifacts` with the Redis → SQL fallback chain. Drop the manifest-tool-extraction block (the `os.ReadFile(manifestPath)` + `json.Unmarshal(&manifest)` lines). Net diff: ~30 lines simpler. |
| `docs/superpowers/specs/2026-05-18-reporter-tier2-design.md` | Update Component 1 ("`POST /scan/task/artifacts`") to reflect the new lookup chain. The disk-first framing is replaced; the 404/425 split is tightened (404 now requires both Redis and SQL to be silent). |

### What stays unchanged

- The bundle response shape (single file or zip per Tier 1's
  `BundleTaskSlot` rules).
- Headers (`Content-Type`, `Content-Disposition`, `X-G3-Task-ID`).
- The 425 + `Retry-After: 2` pattern (still the right hint for
  "not ready yet").
- Tier 2's "Redis absence is not a failure signal" rule — reinforced,
  in fact, because now an absence-of-Redis explicitly falls through
  to SQL rather than producing 404.

## Cross-cutting concerns

### Sequence of cleanups

Components 2 and 3 are independently shippable but logically paired:

- **Component 3 alone** (Redis → SQL fallback without dropping manifest)
  would still leave the dead-code single-file branch in `BundleTaskSlot`
  for reporter tasks (manifest still always there → always zip).
- **Component 2 alone** (drop manifest without Redis → SQL fallback)
  would break the artifacts endpoint for reporter tasks — `manifest.json`
  presence is currently the terminal-state signal.

So both must ship together. Components 1 (script directive) is
genuinely independent and could ship separately, but the plan groups
all three into one tier for tight scope and a single round of spec
updates.

### Existing dispatcher behavior

The dispatcher refactor's `dispatchTask` helper does write
`[g3:dispatch]` log markers for reporter tasks (via `SaveLogLine`) —
this is already implemented. Component 3's SQL fallback depends on
those markers being present; the dispatcher refactor satisfied that
dependency.

### Backward compatibility

`/scan/task/dispatch` (the dispatcher refactor's endpoint) is
unaffected. `/scan/task/artifacts` response codes shift slightly
(stricter 404 → 425 conversion for "no signal" cases). There are no
production clients to migrate.

The legacy `POST /scan/report` (in-process MarkdownReporter) is
untouched — still serves the no-plugin Markdown report via the
in-process Go reporter.

## Configuration and deployment

No new environment variables. No new MongoDB / Redis / MariaDB schema
changes. No new MQTT topics. No new Docker images. No plugin metadata
changes. All three Tier 3 components are internal-code changes.

## Rollout

Single ship. All three components land together along with the spec
amendments to Tier 1 and Tier 2 design docs. Build verification across
all six g3 binaries at the end.

## Future work (out of scope for Tier 3)

- **Local CLI reporter integration** (the original Tier 3 working
  title — `g3 scan` script `report` directive in-process,
  `--artifacts` flag on `g3 scan` / `g3 run` / `g3 report`,
  `g3 report <tool>` invoking the docker plugin locally). The
  contracts settle in Tier 3; local CLI consumes them in a future tier
  with a smaller surface area.

- **Multi-reporter scripts.** Allow multiple `report` directives per
  script with a per-reporter output mapping or sequential naming. Not
  needed for Tier 3 use cases; pairs naturally with the local CLI
  work above.

- **Reporter task surfacing in `g3 tools`.** Reporters should appear
  in the plugin lister output. Pure UX polish; bundled with the local
  CLI tier.

- **Retire the in-process `MarkdownReporter`.** Once magenta (or
  another plugin reporter) reaches parity with the built-in markdown
  output, the legacy `POST /scan/report` and `g3lib/report.go` can
  be removed. Not yet — parity is not yet established.

- **Reporter result caching.** A repeated dispatch for the same
  scan/tool/preset triple currently produces a new task. A cache
  layer keyed on the request body's hash could short-circuit this.
  Speculative; revisit when there's a real workload showing
  re-dispatch as a hot path.
