# Shared Artifacts Volume — Design

Tracking GitHub issue [golismero/g3#9](https://github.com/golismero/g3/issues/9).

## Context

Plugins in g3 currently communicate with the rest of the stack through exactly one
channel: JSON on stdin/stdout. A plugin runs a tool, parses its output, and emits
`G3Data` JSON. The *raw* tool output — nmap's XML, a tool's console text, the file a
user uploaded for import — is either discarded or, in the case of console output,
mixed into the SQL logs table. There is no place for a plugin to deposit a file and
no way for a downstream consumer (notably [magenta](https://github.com/golismero/magenta),
the reporting project) to retrieve it.

This design adds a **shared artifacts volume**: a scan-keyed directory tree where
plugins write whatever files they want, the worker records what each plugin produced,
and consumers read directly from the filesystem.

### Established architectural direction

From the April 2026 architecture work: g3api is internal-only (no users, no per-scan
ACL — a single shared service credential). magenta is a separate project that consumes
g3's output and produces text reports. Issue #9 was scoped at a high level then —
"plugins write raw tool outputs to a scan-keyed directory `{scanid}/{taskid}/`; magenta
and others read from there" — and this spec refines the *how*.

### Design heuristic

The driving heuristic for this design: **when in doubt, make the infrastructure do the
work, not the code.** g3 code takes no position on what backs the artifacts volume.
It only ever sees POSIX paths.

## Goal

Give every plugin a simple, isolated place to write artifacts; record what was written;
make uploaded import files first-class scan artifacts; and tie artifact retention to the
scan lifecycle — all without g3 owning a storage abstraction or taking a position on
single- vs multi-host deployment.

## Non-goals

- An HTTP read endpoint for artifacts (for remote clients like g3tui). Consumers mount
  the volume directly for now. A read API is a future, separate brainstorm.
- Per-plugin `g3p.sh` changes to split tool console output into artifact files. That is
  plugin-side work, tracked separately. This spec only provides the *place* to write.
- Removing the legacy `./volumes/tmp` mount on g3api.
- Integrity hashes in the manifest, a retention TTL for terminal-state scans, or
  artifact size limits.
- Writing parsed `G3Data` JSON or final reports into the tree. MongoDB stays the
  authoritative store for parsed data; magenta owns reports.

---

## Architecture

A new shared volume — the **artifacts root** — holds a scan-keyed tree:

```
<artifacts-root>/
├── _uploads/                          # staging area, scan-agnostic
│   ├── <uuid>.bin                     # uploaded file contents
│   └── <uuid>.txt                     # original filename metadata
└── <scanid>/
    ├── imports/
    │   ├── <uuid>.bin                 # relocated uploads, now scan-keyed
    │   └── <uuid>.txt
    └── <taskid>/
        ├── manifest.json              # worker-written, always present
        └── <whatever the plugin wrote>
```

The filesystem layout *is* the scan → task → artifact index. There are no new database
columns and no metadata sidecar answering "which task produced this file" — the path
encodes it.

g3 code only ever sees POSIX paths under the artifacts root. What backs the volume is a
deployment decision:

- **Single host** — the operator bind-mounts a local directory (`./volumes/artifacts`)
  into every container that needs it. Same pattern g3 already uses for `./config`.
- **Multi host** — the operator mounts a shared filesystem at the same path on every
  host: NFS, CephFS, JuiceFS, s3fs, Mountpoint-for-S3, an rclone mount — anything
  POSIX-shaped. g3 neither knows nor cares.

There is no storage-backend interface in g3lib. The abstraction is the OS mount, not
Go code.

---

## Component 1: The worker's per-task slot

### What it does

Before launching a plugin container for a task, the worker materializes that task's
artifact directory and bind-mounts **only that subdirectory** into the plugin container
at `/artifacts`. The plugin gets a clean, writable directory and knows nothing about
scan IDs, task IDs, or sibling tasks. The bind-mount scope makes cross-task access
impossible.

### How it works

In the plugin-execution path — [`runPluginInternal`](../../../src/g3lib/plugin.go) and
its caller in [`g3worker.go`](../../../src/g3worker/g3worker.go):

1. Resolve the task's slot path: `<G3_ARTIFACTS_ROOT>/<scanid>/<taskid>`.
2. `os.MkdirAll(slot, 0o755)` before `docker run`.
3. Append to the `docker run` arguments:
   `-v <G3_ARTIFACTS_HOST_ROOT>/<scanid>/<taskid>:/artifacts:rw`.
4. The plugin container sees `/artifacts/` — empty, writable, its own.

Only the tool-execution path mounts `/artifacts`. Importers and mergers run inside the
worker/g3api against stdin/stdout and do not need it. (Importers interact with the tree
only through upload relocation — see Component 3.)

### Host-path parity (critical constraint)

The worker shells out to `docker run` against the **host's** Docker daemon (the socket
is bind-mounted). The `-v` source path is therefore interpreted by the host, not by the
worker container. The worker's own view of the path (used for `MkdirAll` and manifest
writing) and the host's view (used for `docker run -v`) must both be correct.

Two environment variables make this explicit rather than relying on the fragile
relative-path behavior the current `./resources` mount depends on:

- **`G3_ARTIFACTS_ROOT`** — the path the worker and g3api *processes* read and write
  (`MkdirAll`, manifest, upload relocation, cleanup). Default: `/app/artifacts`.
- **`G3_ARTIFACTS_HOST_ROOT`** — the path the worker passes to `docker run -v` as the
  bind-mount source. Defaults to the value of `G3_ARTIFACTS_ROOT`.

The supported deployment requires the artifacts root be mounted at the **same absolute
path** on the host and inside the worker container, so the two variables hold the same
value and parity holds by construction. `G3_ARTIFACTS_HOST_ROOT` exists as an escape
hatch for operators who deliberately break that parity; the default path matches the
compose `G3HOME=/app` convention.

### Failure handling

- **Artifacts root missing or unwritable at worker startup** — fail fast with a clear
  error. This is infrastructure misconfiguration; do not limp along with a disabled
  subsystem.
- **`MkdirAll` fails for a task** — the task fails (`ERROR` terminal state) and the
  failure is logged. A worker that cannot write artifacts is a broken worker.

---

## Component 2: The manifest

### What it does

After a plugin container exits, the worker writes `manifest.json` into the task's slot
directory. It is written **always** — even when the plugin produced no files — so every
task that ran has a consistent, machine-readable record. Consumers read `manifest.json`
to map files back to the tool that produced them. No `.g3p` changes and no plugin
cooperation are required.

The manifest is the **magenta integration contract.** magenta's own integration design
(`docs/g3-integration-discussion.md` in the magenta repo) settled on exactly this shape:
g3 hands magenta a directory of tool output files plus a manifest, and the manifest is
what lets magenta tell `nmap.xml` from a generic `out.xml`. (magenta matches input files
by filename prefix — `<tool>.*` — but g3 will *not* rename or copy files to fit that
convention; magenta gains a g3-manifest-aware input path instead. See *Future work*.)

### How it works

The worker writes the manifest after the plugin process returns and before the task is
marked terminal. The worker enumerates the slot directory to discover what the plugin
actually wrote — the plugin does not self-report.

`tool` and `cmd` are lifted from the G3Data objects the plugin emitted (the worker
already receives these as the `outputArray` return of `RunPluginCommand`). Both are
guaranteed available: g3lib's output normalization in `runPluginInternal` injects
`_tool` (defaulting to the plugin name) and `_cmd` (defaulting to the dispatched command
line) onto every object, and injects a dummy object when the tool emits nothing — so
there is always at least one object carrying them. `_cmd` is also guaranteed to be a
*string*: `runPluginInternal` normalizes non-string `_cmd` shapes (e.g. a plugin that
emitted a token array) before the data is returned, so the manifest just reads an
already-normalized value.

`manifest.json` fields:

| Field          | Source                                                        |
|----------------|---------------------------------------------------------------|
| `scan_id`      | The task's scan ID.                                           |
| `task_id`      | The task's task ID.                                           |
| `plugin`       | g3 plugin name (`G3Plugin.Name`) — identifies *which variant* ran (e.g. `nmap-fast`). |
| `tool`         | `_tool` from the emitted G3Data — the canonical tool name magenta resolves (e.g. `nmap`). Equals `plugin` for most plugins; diverges for variant plugins like the nmap trio. |
| `cmd`          | `_cmd` from the emitted G3Data — the command line, normalized to a string by g3lib. |
| `exit_status`  | Tool exit status.                                             |
| `started_at`   | Task start timestamp.                                         |
| `ended_at`     | Task end timestamp.                                           |
| `files`        | List of `{name, size, modified}`, one per file the plugin left in `/artifacts/`. Empty list if none. |

`manifest.json` itself is excluded from the `files` enumeration.

### Failure handling

- **Plugin writes nothing** — not an error. Manifest is written with an empty `files`
  list.
- **Manifest write fails** — the plugin's real output is already on disk; do not lose it
  over a manifest failure. Log the error and mark the task result accordingly.

---

## Component 3: Upload relocation

### What it does

Uploaded files (used for the import flow) move out of `/tmp` and into the artifacts
tree. They begin life in a scan-agnostic staging area because an upload happens *before*
any scan exists, then move into the scan's directory when a scan consumes them — at
which point they are scan-keyed and die with the scan.

### How it works

**`POST /upload`** ([g3api.go, upload handler](../../../src/g3api/g3api.go)) — change the
destination from `/tmp/<uuid>.bin` + `/tmp/<uuid>.txt` to
`<G3_ARTIFACTS_ROOT>/_uploads/<uuid>.bin` + `<uuid>.txt`. The `.bin`/`.txt` pair is
unchanged (`.txt` holds the original filename). The handler still returns the bare
uuid — **no API contract change**.

**`POST /scan` importer path** ([g3api.go, import loop](../../../src/g3api/g3api.go)) —
currently opens `/tmp/<uuid>.bin` directly. New behavior: before opening, `os.Rename`
the `.bin`/`.txt` pair from `_uploads/` into
`<G3_ARTIFACTS_ROOT>/<scanid>/imports/`, then open from the new location. `os.Rename`
within a single volume is atomic and free. The imported file is now scan-keyed.

### Orphan uploads

A file uploaded but never referenced by a scan stays in `_uploads/` indefinitely — the
one case not covered by scan-lifecycle retention (Component 4). The design adds an
optional, lightweight age-based sweep:

- **`G3_UPLOAD_TTL`** — on g3api startup and every N hours thereafter, a goroutine
  ticker deletes `_uploads/` entries older than this duration.
- **`G3_UPLOAD_TTL=0`** (the default) disables the sweep entirely. g3api never deletes
  from `_uploads/` on age; orphan cleanup is the operator's responsibility (cron,
  storage-level lifecycle rules, etc.). This is the default because it adds no surprise
  background deletion and matches the infrastructure-does-the-work heuristic.
- The shipped compose `.env` sets an explicit `G3_UPLOAD_TTL=24h` as the recommended
  value for the demo stack.

This is the only artifact-cleanup code g3 owns that is not a direct response to a
`DELETE /scan` call, and it is opt-in.

---

## Component 4: Lifecycle and cleanup

### What it does

Artifact retention is tied to the scan lifecycle. While a scan exists in MongoDB, its
artifacts exist. When a scan is deleted, its artifacts are deleted. Operators control
artifact retention with the same lever they already use for scan retention — there is
no new TTL, no new daemon.

### How it works

**`DELETE /scan/<id>`** ([g3api.go:635](../../../src/g3api/g3api.go#L635)) — the handler
is already a chain of best-effort deletes (report info, task states, logs, Mongo data,
scan progress) that log errors and continue, accumulating into `reterr`. Add one more
step in the same style:

```
os.RemoveAll(<G3_ARTIFACTS_ROOT>/<scanid>)
```

This removes the task tree and `imports/` in a single call. On failure it contributes
to `reterr` exactly like the existing steps, and the handler returns an error status
without aborting the other deletions.

---

## Configuration and deployment

### Environment variables

| Variable                 | Default          | Purpose                                                    |
|--------------------------|------------------|------------------------------------------------------------|
| `G3_ARTIFACTS_ROOT`      | `/app/artifacts` | Path the g3api/g3worker processes read and write.          |
| `G3_ARTIFACTS_HOST_ROOT` | = `G3_ARTIFACTS_ROOT` | Path the worker passes to `docker run -v` (host's view). |
| `G3_UPLOAD_TTL`          | `0` (disabled)   | Age threshold for the `_uploads/` orphan sweep. `0` = off. |

These are documented in `.env` alongside the existing environment variables.

### docker-compose.yml

- Add `./volumes/artifacts:/app/artifacts` to the **g3api** service and to **every
  g3worker** service. g3scanner does not need it.
- The `./volumes/artifacts/.gitignore` already staged in the repo is the volume's
  anchor.
- Ship `G3_UPLOAD_TTL=24h` in the demo `.env`.
- The current `./volumes/tmp` mount on g3api can be removed once nothing writes to
  `/tmp` — out of scope for this spec.

---

## Affected code

| File                          | Change                                                                 |
|-------------------------------|------------------------------------------------------------------------|
| `src/g3lib/plugin.go`         | `runPluginInternal` / tool-command path: mkdir the task slot, add the `-v` mount for `/artifacts`. |
| `src/g3worker/g3worker.go`    | Resolve scan/task slot path; write `manifest.json` after the plugin exits (lifting `tool`/`cmd` from the `RunPluginCommand` output array); fail the task on `MkdirAll` error. |
| `src/g3api/g3api.go`          | Upload handler writes to `_uploads/`; import loop relocates into `<scanid>/imports/`; `/scan/delete` removes `<scanid>/`; `_uploads/` orphan sweep goroutine. |
| `src/g3lib/` (env constants)  | New constants for `G3_ARTIFACTS_ROOT`, `G3_ARTIFACTS_HOST_ROOT`, `G3_UPLOAD_TTL`. |
| `docker-compose.yml`          | Mount `./volumes/artifacts` into g3api and each g3worker.              |
| `.env`                        | Document the three new variables.                                      |

The `manifest.json` struct most naturally lives in g3lib so the worker can marshal it
and future consumers within the g3 codebase can unmarshal it.

---

## Error handling summary

| Situation                              | Behavior                                                              |
|-----------------------------------------|-----------------------------------------------------------------------|
| Artifacts root missing/unwritable at startup | g3api and g3worker fail fast with a clear error.                 |
| `MkdirAll` fails for a task             | Task → `ERROR` terminal state, logged.                                |
| Plugin writes no files                  | Not an error; manifest written with empty `files` list.               |
| Manifest write fails                    | Log the error, mark task result accordingly; do not discard the plugin's actual output. |
| `os.RemoveAll` fails on scan delete     | Logged into `reterr`; handler returns error status, other deletions still run. |
| Plugin writes garbage / oversized files | Out of scope; bind-mount scope already contains blast radius to one task dir. Disk quotas are an infrastructure concern. |

No fake fallbacks: a misconfigured or unwritable artifacts volume surfaces as an error,
it is never silently disabled.

---

## Verification

Per the project convention, automated tests are written by the maintainer; the
agent-side verification surface is **build + lint**:

- `g3lib`, `g3api`, and `g3worker` compile.
- `golangci-lint` stays green (no new `errcheck` suppressions — every `os.*` call in the
  new code handles its error).

Manual verification points for the maintainer:

1. `POST /upload` lands the file in `<root>/_uploads/<uuid>.{bin,txt}`.
2. Running a scan that imports that upload relocates it to
   `<root>/<scanid>/imports/<uuid>.{bin,txt}` and leaves `_uploads/` empty for that uuid.
3. A tool task produces `<root>/<scanid>/<taskid>/manifest.json` plus whatever the
   plugin wrote; the manifest's `files` list matches the directory contents.
4. A task whose plugin writes nothing still produces a `manifest.json` with an empty
   `files` list.
5. `DELETE /scan/<id>` removes `<root>/<scanid>/` entirely.
6. With `G3_UPLOAD_TTL=0`, an old file in `_uploads/` is never touched by g3api; with a
   positive value, it is swept after the threshold.
7. Multi-host smoke test: with the artifacts root on a shared mount, a plugin run on
   worker host A produces a task dir readable from host B.

---

## Future work

- HTTP read API on g3api (or the future BFF) so remote clients can browse and download
  artifacts without mounting the volume.
- Per-plugin `g3p.sh` changes to route tool console output into `/artifacts/` instead of
  the SQL logs table.
- Retiring the `./volumes/tmp` mount once `/tmp` is unused.
- Optional manifest integrity hashes; optional terminal-state retention TTL.
- **magenta gains a g3-manifest-aware input path** — so it reads `manifest.json` directly
  instead of relying on its filename-prefix convention. This is magenta-side work and
  keeps g3 from having to rename or copy files into a magenta-shaped layout.
- **A g3 "reporter" plugin type** — a new plugin category (parallel to command / importer
  / merger) that dockerizes magenta and owns any g3↔magenta glue. This is where any
  residual tool-identity mapping or artifact filtering lives, keeping the g3 core ignorant
  of magenta.
