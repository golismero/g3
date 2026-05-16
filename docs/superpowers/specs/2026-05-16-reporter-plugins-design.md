# Reporter Plugins — Design

Brainstormed 2026-05-16.

## Context

g3 today has three plugin phases — `commands` (tool execution), `importer`
(parse raw tool output into G3Data), `merger` (deduplicate issues per tool) —
all running through the existing per-plugin Docker contract documented in
[CLAUDE.md](../../../CLAUDE.md) and implemented in
[src/g3lib/plugin.go](../../../src/g3lib/plugin.go).

Reporting today lives in-process: a Go `MarkdownReporter` in
[src/g3lib/report.go](../../../src/g3lib/report.go) is invoked by both the
`g3 report` CLI and the `g3api /scan/report` endpoint, builds a Markdown
document directly from G3Data plus per-plugin i18n templates, and returns it
synchronously. There is no Docker contract for report producers; report
generation is fixed to the built-in Markdown reporter.

Two prior design decisions set the stage for this work:

1. **The reporting layer moves to magenta** (golismero/magenta) — per the
   architectural direction memo from the 2026-04 rescue planning, g3 produces
   JSON and magenta produces text. The in-process Markdown reporter is the
   transitional fallback; the new reporter plugin type is the path forward.
2. **Shared artifacts volume exists** ([prior spec](2026-05-14-shared-artifacts-volume-design.md)) —
   plugins write raw tool outputs into `<G3_ARTIFACTS_ROOT>/<scanid>/<taskid>/`,
   each task's slot accompanied by a `manifest.json` mapping output files to the
   tool that produced them. Reporters consume this tree.

A placeholder plugin scaffold exists at
[plugins/report/magenta/](../../../plugins/report/magenta/) — `magenta.g3p`
declares `reporter: {}`, a `Dockerfile` clones magenta and wires `g3r.sh` as
`/usr/bin/g3r`, and `g3r.sh` is a one-line `echo "placeholder"`. This spec
fills in everything around that scaffold.

## Goal

Define a fourth plugin phase — **reporter** — that lets external Dockerized
tools (starting with magenta) consume a finished scan's full output and emit a
downloadable report. The phase has its own validator, its own MQTT dispatch
topic family, its own worker handler, and a new g3api endpoint to trigger it
synchronously.

Implement enough of the supporting infrastructure that magenta is wired up end
to end: a real `g3r.sh` wrapper that calls magenta against `/input` + `/output`
mounts, and a new `POST /scan/reporter` endpoint that streams the resulting
file or zip.

## Non-goals

- Retiring the in-process `MarkdownReporter`. It stays alongside the new
  mechanism as a fallback; magenta and the built-in reporter are not yet at
  feature parity, and keeping both lets users opt in incrementally.
- Local CLI integration (`g3 report magenta:executive`). Deferred — `g3` in
  local mode destroys artifacts after each step, so reporter plugins (which
  need the artifact tree) can't work there yet. Resolving that is a Tier 3
  concern.
- Async API. The synchronous endpoint is shipped first; the async kickoff +
  generic artifacts-download endpoint is a Tier 2 concern (outlined below).
- A `task_kind` discriminator column on the task table. Not needed because
  reporter task IDs are addressable by every existing task-status endpoint
  unchanged.
- Constraining `.g3p` files to declare only one phase. A plugin could in
  principle declare both `commands` and `reporter`; nothing in this design
  breaks in that case. The shared-image idiom already in the tree
  (`nmap.g3p`, `nmap-fast.g3p`, `nmap-full.g3p` all pointing at the same
  image) is the recommended pattern, but it is not enforced.

## Design heuristic

Each plugin phase widens its input and narrows its output:

| Phase | Input | Output | Runs |
| --- | --- | --- | --- |
| `commands` | one G3Data object (per target) | G3Data array | per-target, parallel, in workers |
| `importer` | one raw tool output file (stdin) | G3Data array | once per imported file, no MQTT |
| `merger` | the issues from one tool (stdin) | deduplicated G3Data array | once per tool, no MQTT |
| `reporter` | the entire scan (mounted) | files in a slot | once per request, in workers via MQTT |

Reporter is the first phase that's both **scan-wide** in its input and
**file-producing** in its output. It rides the existing worker pipeline (so
deployments scale reporting horizontally for free over the artifacts volume)
but it does **not** participate in scan progress accounting.

## Architecture

```
client ──POST /scan/reporter──▶ g3api ──MQTT report/<tool>──▶ g3worker
                                                                 │
                              ┌──────────────────────────────────┘
                              ▼
                  RunPluginReporter()  ──docker run──▶  reporter container
                              │                                  │
                              │                ┌─── reads /input:ro
                              │                │     (scan tree + data.json)
                              │                │
                              │                └─── writes /output:rw
                              │                      (this task's slot)
                              ▼
                       WriteManifest() ──▶ <scanid>/<reportertaskid>/manifest.json
                              │
                              ▼
                       MQTT response ──▶ g3api ──▶ BundleTaskSlot()
                                                       │
                                                       ▼
                                            HTTP response body
                                            (single file or zip)
```

## Component 1: Plugin schema

A new optional `Reporter` field on `G3Plugin`, parallel to `Commands`,
`Importer`, `Merger`. New Go types in
[src/g3lib/plugin.go](../../../src/g3lib/plugin.go):

```go
type G3ReporterCommand struct {
    Name      string   `json:"name"                validate:"required,alphanum_dash"`
    Command   []string `json:"command,omitempty"`                              // expanded against env vars only
    DockerOpt []string `json:"dockeropt,omitempty"`                            // expanded against env vars only
}

type G3ReporterPhase struct {
    Default  string              `json:"default,omitempty"`
    Commands []G3ReporterCommand `json:"commands,omitempty" validate:"omitempty,dive"`
}

// extends G3Plugin:
//     Reporter    *G3ReporterPhase   `json:"reporter,omitempty"  validate:"omitempty"`
```

### .g3p shape

Minimal (a one-mode reporter):

```jsonnet
{
    url: "https://github.com/golismero/magenta",
    description: { en: "Magenta Reporter ..." },
    reporter: {},
}
```

Multiple presets with a default:

```jsonnet
{
    url: "https://github.com/golismero/magenta",
    description: { en: "Magenta Reporter ..." },
    reporter: {
        default: "executive",
        commands: [
            { name: "full",      command: ["--preset", "full"]      },
            { name: "executive", command: ["--preset", "executive"] },
        ],
    },
}
```

### Validation rules added in g3config

- `commands` is optional. If present, non-empty; each `name` is required,
  alphanumeric + dash/underscore, unique within the plugin.
- `default`, if present, must reference an existing command name.
- No `condition`, `fingerprint`, `returns`, or `_artifacts` claims — reporters
  don't emit G3Data and don't run conditionally against per-target inputs.
- `command` and `dockeropt` templates are expanded against environment
  variables only (same rule as importer/merger), never against G3Data.
- The existing image-existence check (Docker images known locally or
  resolvable via `crane`) still applies.

### Preset resolution

The caller's `preset` field is always optional. Resolution order:

1. Caller-supplied `preset` field (validated against declared command names).
2. `default` from the .g3p, if set.
3. First command in `commands`.
4. If `reporter: {}` with no commands: no preset at all — the container
   entrypoint runs with no extra args.

A caller-supplied `preset` against a plugin with `reporter: {}` is a 400
(the plugin has no preset selector and a passed preset is meaningless).

## Component 2: Container contract

A reporter container runs once per `/scan/reporter` request and sees:

### Mounts

| Path | Mode | Host path | Purpose |
| --- | --- | --- | --- |
| `/input` | `ro` | `<G3_ARTIFACTS_HOST_ROOT>/<scanid>/` | The scan's full artifact tree — every other task's slot, every `manifest.json`, all raw tool outputs, plus the two scan-wide files the worker writes just before starting the container (see below). |
| `/output` | `rw` | `<G3_ARTIFACTS_HOST_ROOT>/<scanid>/<reportertaskid>/` | The reporter's own slot — same shape as any other task's slot, co-located with tool tasks. |
| `/resources` | `ro` | `./resources` | Same as the existing tool/importer/merger plugin contract. |

### Entrypoint

Default `/usr/bin/g3r`. Overridable via `dockeropt: ["--entrypoint", "..."]`,
the same way `g3i` / `g3m` are overridable today for importer/merger phases.

### No stdin envelope

The reporter contract is purely filesystem-driven. The preset choice is
already encoded in the container's command-line arguments (the worker
materializes the selected command from `commands[].command` via
`BuildReporterCommand`); the data lives on disk in `/input`; there is
nothing else the container needs from the caller at runtime. Stdin is not
read.

Stdout/stderr are treated as task log lines and captured into the SQL log
table identically to any worker task. Exit code 0 = success, non-zero =
failure. No structured-output expectation — the slot is the output channel.

### Disk inputs in `/input`

The worker writes two scan-wide files into `<scanid>/` (the root of the
container's `/input` mount) immediately before invoking the reporter:

| File | Source | Contents |
| --- | --- | --- |
| `data.json` | streamed from MongoDB via `WriteScanDataToFile(mdb, scanID, path)` | JSON array of every G3Data object the scan produced — the raw, undeduplicated record. |
| `report.json` | `LoadReportInfo(rdb, scanID)` → marshaled to disk | The existing `G3Report` struct (ScanID + deduplicated issue IDs). Reporters that want post-dedup issue lists read this; reporters doing their own dedup ignore it and read `data.json`. |

Both files are scan-wide and live at the root of `/input` (sibling to the
per-task subdirs) so the filename convention "task-specific files live in
`<taskid>/`; scan-wide aggregates live at the scan root" is unambiguous.

Both writes are idempotent and content-deterministic for a given scan state:
concurrent reporter tasks against the same scan race benignly on these
files. Both writes are streaming where possible — `data.json` uses a
MongoDB cursor → JSON encoder → file pipeline so the worker never
materializes the full data array in memory.

### Output discovery

After the worker has written `manifest.json` for the reporter task and
reported terminal state, g3api enumerates the reporter task's slot
(`<scanid>/<reportertaskid>/`). All regular files are counted, **including**
`manifest.json`:

- **0 files** → 404, body: `"task produced no output"` (impossible in
  practice since the worker always writes `manifest.json` — a 0 case means
  the slot was reaped or the task_id is wrong).
- **Exactly 1 regular file, no subdirs** → stream as-is. Content-Type sniffed
  via Go's `mime.TypeByExtension` (fallback `application/octet-stream`).
  Filename: `<stem>-<taskid>.<ext>` where stem/ext split on the file's last
  dot.
- **>1 file, or any subdir** → zip the slot contents (including
  `manifest.json`), stream as `application/zip` with filename
  `<tool>-<taskid>.zip`. The zip writer targets the HTTP response body
  directly, so the whole bundle is never materialized in worker memory.

The manifest is included in bundles deliberately: it carries
`plugin`/`tool`/`preset`/`exit_status`/timestamps that a downstream consumer
will likely want. It costs a few hundred bytes.

## Component 3: Worker / MQTT integration

### New MQTT topic family

| Today | Added |
| --- | --- |
| Pub `tool/<name>` / Sub `$share/g3worker/tool/<name>` | Pub `report/<name>` / Sub `$share/g3worker/report/<name>` |

g3worker's plugin selection ([src/g3worker/g3worker.go:358-388](../../../src/g3worker/g3worker.go#L358-L388))
is extended so every selected plugin whose metadata has a non-nil `Reporter`
also generates a `report/<name>` subscription. The MQTT share-group semantics
give horizontal scaling for free: any worker with magenta in its selected list
can pick up a magenta report task.

### New task message type

```go
const MSG_REPORT G3MESSAGETYPE = "report"

type G3ReportTask struct {            // MessageType: MSG_REPORT
    G3TaskMessage                     // includes ScanID + TaskID
    Tool   string  `json:"tool"   validate:"required"`
    Preset string  `json:"preset"`                       // resolved name; "" only if plugin has reporter:{}
}

type ReportTaskHandler func(MessageQueueClient, G3ReportTask)
```

A new message type rather than extending `G3Task` keeps the validator tight:
`G3Task.DataID` is `required,mongodb` and `G3Task.Index` is the per-target
subcommand index — a reporter has neither, and loosening those for the common
case would be a regression.

The wire shape carries no `lang`, `title`, or per-call config: those are
either properties of the scan (and so already live with the scan) or are
intentionally deferred to the future expansion of `G3Report`. Nothing on
this message is per-call customization beyond the preset selector.

### Worker handler

Mirrors the existing tool dispatch path
([src/g3worker/g3worker.go:520-720](../../../src/g3worker/g3worker.go#L520-L720)):

```
on G3ReportTask:
    markRunning(scanID, taskID, workerID)

    // 1. Materialize the reporter task's output slot.
    outSlot := <artifactsRoot>/<scanID>/<reportertaskID>/        // worker-side path
    hostOut := <artifactsHostRoot>/<scanID>/<reportertaskID>/    // for docker -v
    hostIn  := <artifactsHostRoot>/<scanID>/                     // for docker -v
    mkdir(outSlot)

    // 2. Stream scan-wide inputs into <scanID>/ for the reporter to consume.
    //    Both writes are idempotent and content-deterministic; concurrent
    //    reporter tasks against the same scan race benignly.
    WriteScanDataToFile(mdb, scanID,
                       <artifactsRoot>/<scanID>/data.json)         // streams via cursor
    report := LoadReportInfo(rdb, scanID)
    writeJSON(<artifactsRoot>/<scanID>/report.json, report)

    // 3. Dispatch the container. No stdin envelope — preset is encoded in
    //    the command-line args; data is on disk.
    parsed := BuildReporterCommand(plugin, preset)
    err    := RunPluginReporter(ctx, plugin, parsed,
                                hostIn, hostOut, stderr)

    // 4. Write manifest, same path as today's tool tasks.
    files := EnumerateSlot(outSlot)
    WriteManifest(outSlot, G3Manifest{
        ScanID: scanID, TaskID: reportertaskID,
        Plugin: plugin.Name, Tool: plugin.Name,
        ExitStatus: statusFromErr(err),
        Files: files,
        Work: [{ Cmd: shellquote.Join(parsed.Command), Artifacts: nil }],
    })

    // 5. Mark terminal, send empty response (no MongoDB data flows back).
    markTerminal(...); SendEmptyResponse(...)
```

### New g3lib functions

| Existing | Added |
| --- | --- |
| `BuildToolCommand` / `BuildImporterCommand` / `BuildMergerCommand` | `BuildReporterCommand(plugin, presetName)` |
| `RunPluginCommand` / `RunPluginImporter` / `RunPluginMerger` | `RunPluginReporter(ctx, plugin, parsed, hostInDir, hostOutDir, stderr)` |
| — | `WriteScanDataToFile(mdb, scanID, path) error` (streams via MongoDB cursor) |
| — | `BundleTaskSlot(slotDir, tool, taskID, w io.Writer) (filename, contentType string, err error)` (streams output into `w`) |

`RunPluginReporter` is a small variant of `runPluginInternal`: it builds two
`-v` mounts instead of one, it does not write stdin (the contract has no
envelope), and it does **not** parse stdout as G3Data — the slot enumeration
is the output channel.

`BundleTaskSlot` streams: for the single-file case it copies the slot file
into `w`; for the multi-file case it constructs a zip directly on `w` via
`archive/zip`. Neither path materializes the bundle in memory. The function
implements the 0/1/many discovery rule from Component 2 and is reusable: it's
the same logic the Tier 2 generic artifacts endpoint will call.

### Task tracking integration

Reporter task state changes flow through the existing
`SetTaskRunning` / `SetTaskTerminal` / `SaveLogLine` paths, so the existing
WebSocket task channel and the `/scan/tasks/status` endpoint surface them for
free. No SQL schema change, no migration.

Reporter tasks do **not** update `totalScanSteps` or progress percentages —
the scan is already at 100% before the report is requested. They simply appear
in the task table as additional rows, with `tool=<plugin-name>` (e.g.
`magenta`) and a UUID task_id.

### Cancellation

Reuses the existing cancellation tracker: a reporter task can be cancelled
via the per-task cancel topic, the container is stopped, the slot is kept for
diagnostics. Scan-delete sends `G3CancelTask` for any in-flight reporter
tasks on that scan — same code path as cancelling any tool task.

## Component 4: g3api endpoint

### New endpoint, separate from legacy `/scan/report`

The existing `POST /scan/report`
([src/g3api/g3api.go:839](../../../src/g3api/g3api.go#L839)) stays untouched
— same body, same JSON response from the in-process `MarkdownReporter`. A
**new** endpoint is added:

```
POST /scan/reporter
```

Two endpoints rather than overloading one: each has exactly one response
shape (JSON for the in-process Markdown reporter, file/zip for the plugin
runner), each can evolve independently (the async flag in Tier 2 lands only
on the new endpoint), and the deprecation path is clean if the in-process
reporter is ever retired.

### Request shape

```jsonc
POST /scan/reporter
{
    "scan_id": "<uuid>",
    "tool":    "magenta",       // REQUIRED
    "preset":  "executive"      // OPTIONAL — resolved per Component 1
}
```

That's the entire request. No `lang`, no `title`, no `config`. Per-call
customization is intentionally minimal — anything richer is either a
property of the scan (and lives there) or belongs in the future expansion
of `G3Report` rather than in per-request fields.

### Validation (before any MQTT publish)

| Failure | Status |
| --- | --- |
| Malformed JSON, missing required field | 400 |
| `tool` not in plugin metadata | 400 |
| `tool` plugin has no `reporter` phase | 400 |
| `preset` set but plugin has `reporter: {}` (no commands) | 400 |
| `preset` set but no command with that name | 400 |

### Response shape

| Outcome | Status | Body | Headers |
| --- | --- | --- | --- |
| FINISHED, slot has files | 200 | the file or zip | `Content-Type` per Component 2; `Content-Disposition: attachment; filename=...`; `X-G3-Task-ID: <taskid>` |
| ERROR (non-zero exit, RunPluginReporter failure) | 500 | `"reporter task failed; see task logs"` | `X-G3-Task-ID: <taskid>` |
| CANCELED | 503 | `"reporter task was canceled"` | `X-G3-Task-ID: <taskid>` |
| Slot empty after FINISHED | 404 | `"task produced no output"` | `X-G3-Task-ID: <taskid>` |

All non-200 bodies are short, generic messages — log lines belong in the
SQL log table, not in HTTP response bodies. Clients with the task ID can
retrieve full diagnostics through the existing `/scan/logs?task_id=X`
endpoint.

The `X-G3-Task-ID` header is set on every reporter-path response —
including errors and cancellations. That's the forward-compat hook for the
Tier 2 async path: a client whose HTTP connection drops (server-side
timeout, network blip, whatever) **already has the task_id** and can pick
the bundle up later via `/scan/task/artifacts?task_id=X` (Tier 2) once the
worker eventually finishes.

HTTP-layer timeouts (Go server, reverse proxy) bound how long the
connection is held; nothing in g3api enforces a custom application-level
timeout. The synchronous behavior is transitional — Tier 2's `?async=true`
flag is the long-term answer for slow reports.

### Dispatch flow

```
1. Resolve preset name per Component 1 rules.
2. Generate reportertaskid (UUIDv4).
3. INSERT into the existing task tracking table — same schema as today,
   no new columns.
4. Publish G3ReportTask to MQTT topic report/<tool>.
5. Wait on the worker's response channel until terminal state.
6. On FINISHED: BundleTaskSlot(slot, tool, taskid, w) → streams body
   directly into the response writer.
   On ERROR/CANCELED: per the table above.
```

### Edge cases

- **Concurrent reports for the same scan** — each call gets its own
  reporter task ID, its own slot, its own row. No serialization. They share
  `<scanid>/data.json` writes; content is deterministic, race is benign.
- **Scan deleted mid-report** — scan-delete sends `G3CancelTask` for any
  in-flight reporter tasks on that scan. Falls out of the existing
  cancellation machinery, no new code path needed.
- **Legacy `/scan/report` callers** — unaffected. The endpoint stays, the
  body shape stays, the response stays.

## Magenta wrapper

Out of scope for this design. Replacing the placeholder
[plugins/report/magenta/g3r.sh](../../../plugins/report/magenta/g3r.sh) is
listed as a Tier 1 implementation step, but the actual flags depend on
magenta's CLI surface and must be confirmed against the magenta repo
itself. The wrapper layer (entrypoint at `/usr/bin/g3r`, shell or python
script) follows the same pattern as the existing `g3p.sh` / `g3i.py` /
`g3m.py` for tool/importer/merger phases — its job is to bridge g3's
filesystem contract (`/input` and `/output` mounts) to whatever magenta
expects.

`magenta.g3p` is left as `reporter: {}` for the initial implementation; if
magenta exposes presets at the CLI level, they can be declared in commands
without any code change on the g3 side.

## Configuration and deployment

No new environment variables. No new volumes — the existing
`volumes/artifacts` mount serves the reporter's `/input` and `/output`
views via different host subpaths. HTTP-layer timeouts (Go server, reverse
proxy) bound how long `/scan/reporter` will hold a connection open; no
application-layer timeout is configured.

No mandatory new compose services — existing g3worker services that
include `magenta` in their `G3_WORKER_PLUGINS` will automatically subscribe
to `report/magenta` once the worker code is updated.

### Deploying a magenta worker

For deployments that want a dedicated reporter worker (e.g. if magenta
turns out to be CPU-heavy), spin up a g3worker service with
`G3_WORKER_PLUGINS=magenta`. The share-group MQTT semantics handle work
distribution.

**Note: deployment changes are user-owned, not agent-owned.** If a
dedicated magenta worker service is added to `docker-compose.yml` or to a
production deployment, the project author will do that work directly.
Tier 1 implementation should not modify compose files to add reporter-only
worker services.

## Rollout tiers

Outlined per the tiered-plans preference: every tier described, only Tier 1
detailed.

### Tier 1 — Core reporter pipeline (server-side, synchronous, magenta-only)

| File | Change |
| --- | --- |
| [src/g3lib/plugin.go](../../../src/g3lib/plugin.go) | Add `G3ReporterCommand`, `G3ReporterPhase`; extend `G3Plugin.Reporter`; add `BuildReporterCommand`, `RunPluginReporter` (no stdin envelope). |
| [src/g3config/g3config.go](../../../src/g3config/g3config.go) | Validate the reporter phase (unique names, `default` references an existing name, no condition/fingerprint/returns). |
| [src/g3lib/task.go](../../../src/g3lib/task.go) | Add `MSG_REPORT` constant, `G3ReportTask` struct (Tool + Preset only), `ReportTaskHandler` type, `SubscribeAsReporter` and `SendReportTask` helpers. |
| [src/g3worker/g3worker.go](../../../src/g3worker/g3worker.go) | Subscribe to `report/<name>` for selected plugins with a non-nil `Reporter`; new handler that streams `data.json` from MongoDB, materializes `report.json` from Redis, invokes `RunPluginReporter`, writes `manifest.json`, marks terminal. |
| [src/g3lib/manifest.go](../../../src/g3lib/manifest.go) | Add `BundleTaskSlot(slotDir, tool, taskID, w)` (streams to writer) next to the existing `EnumerateSlot`. |
| [src/g3lib/datastore.go](../../../src/g3lib/datastore.go) (or wherever scan-scoped MongoDB reads live) | Add `WriteScanDataToFile(mdb, scanID, path)` — cursor-driven streaming write. |
| [src/g3api/g3api.go](../../../src/g3api/g3api.go) | New `POST /scan/reporter` handler with the dispatch flow, `X-G3-Task-ID` header on every response. The existing `/scan/report` endpoint is untouched. |
| [plugins/report/magenta/g3r.sh](../../../plugins/report/magenta/g3r.sh) | Replace placeholder with a real wrapper. Exact magenta CLI flags are out of scope for this design — to be determined against the magenta repo at implementation time. |
| [plugins/report/magenta/magenta.g3p](../../../plugins/report/magenta/magenta.g3p) | Keep as `reporter: {}` unless magenta exposes CLI-level presets. |

Out of scope: async API, local-CLI integration, additional reporters,
retention policies, preset discovery API, generic artifacts download
endpoint.

### Tier 2 — Async API + generic artifacts download

Reporter tasks are **already** queryable through every existing task
endpoint and the WebSocket task channel the moment Tier 1 ships — they
appear in `/scan/tasks`, status is fetched via `/scan/tasks/status`,
state changes push over the existing WebSocket task channel. No new
monitoring surface is needed.

Tier 2 adds exactly two pieces:

- **`GET /scan/task/artifacts?task_id=X`** — generic, task-scoped
  artifacts download endpoint, using the same `BundleTaskSlot` logic
  introduced in Tier 1. Works for **any** terminal task with a non-empty
  slot, not just reporter tasks — unlocks downloading e.g. `nmap.xml`
  from a tool task for free.
- **`?async=true` query flag on `POST /scan/reporter`** — when set, the
  endpoint returns `{ task_id }` immediately rather than blocking on the
  worker. The async client lifecycle reuses what already exists: poll
  `/scan/tasks/status?task_id=X` (or subscribe to the WebSocket task
  channel) until terminal, then GET `/scan/task/artifacts?task_id=X`.

No new task table columns required.

### Tier 3 — Local CLI integration

- Resolve the artifact-destruction issue in local `g3` mode (options: a
  `--keep-artifacts` flag, a tempdir held across the report invocation,
  or a redesigned `g3 report` lifecycle).
- Wire `g3 report <tool>[:<preset>]` to local `docker run` of the reporter
  plugin, mirroring the way `g3 run <tool>` works today for the tool phase.
- Reconsider whether the in-process `MarkdownReporter` can finally be
  retired, or stays as the no-`<tool>` default in `g3 report`.

### Tier 4 — Polish

- Reporters surface alongside tools in `g3 tools` and the equivalent
  g3api plugin-listing endpoint — they're plugins, so they appear in the
  plugin listings. If visual distinction is needed in the output, that's
  a marker in the existing format rather than a new CLI flag or endpoint.
- Multi-language report support beyond `en`.
- Retention policy for reporter task slots (separate TTL from raw tool
  artifacts?).
- Additional reporters shipping in `plugins/report/` (HTML, PDF, raw JSON
  dump, SARIF, …).

## Future work / out of scope for this design

- **Generic artifacts retention.** Currently the per-scan artifact tree
  persists until the scan is deleted. Reporter outputs land in the same
  tree under per-reporter-task subdirs; a future policy might want to
  expire those separately from raw tool outputs.
- **Reporter result caching.** A `POST /scan/reporter` against the same
  `scan_id` + `tool` + `preset` triple currently spawns a fresh task each
  time. A cache layer that returns the prior task's slot when inputs
  haven't changed is plausible but unscoped; the request body's hash
  would be the obvious cache key.
- **Reporter agents.** Per the architectural direction memo, reporter
  plugins are the substrate where reporting agents would eventually live.
  This design is agent-agnostic — the filesystem contract (`/input` for
  data, `/output` for the slot, manifest as the result protocol) doesn't
  constrain whether the reporter is a fixed pipeline or a more dynamic
  system.
- **Per-task data export filtering.** The worker dumps the entire scan's
  G3Data into `data.json`. For very large scans this is wasteful; a
  future optimization could let the reporter declare an interest filter
  (e.g. "only issues at severity ≥ HIGH") to scope the dump.

- **Per-command access flags.** Today the worker unconditionally writes
  both `data.json` and `report.json` before invoking the container.
  A future schema extension could add `artifacts: bool`, `issues: bool`,
  `data: bool` flags on `G3ReporterCommand`, all defaulting to true, so a
  reporter that only needs deduped issues (`issues: true`, others false)
  avoids paying for the full data export. Default-true keeps this purely
  additive — existing plugins don't need to change when the flags land.
  Deferred for scope reasons; the default-true semantics mean introducing
  the flags later is a no-migration change.

- **Expanding `G3Report`.** The struct has commented-out fields
  (`Title`, `Author`, `Client`) hinting at planned scan-level metadata.
  Expanding `G3Report` to carry richer information that reporters can
  consume from `/input/report.json` is a separate concern with its own
  callers (the in-process `MarkdownReporter` hardcodes some of this
  today, which is unfinished work in its own right). A future plan
  should treat that as its own scope.
