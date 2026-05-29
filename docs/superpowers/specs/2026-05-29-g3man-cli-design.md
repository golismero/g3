# g3man — CLI for the managed g3api surface

**Status:** design approved, implementation plan to follow.
**Related:** [docs/superpowers/specs/2026-05-27-knife-g3-tool-integration-design.md](2026-05-27-knife-g3-tool-integration-design.md), [docs/future/http-routing-and-rest-migration.md](../../future/http-routing-and-rest-migration.md).

## Goal

A standalone CLI that drives the managed half of g3api: creating managed scans, populating them with targets/data/imports, dispatching individual tools on demand, polling their per-task status, and downloading their artifacts. JSON-first output, scriptable, intended primarily as a debug / inspection tool for humans building agentic clients (knife, the Python client library) against the managed API.

g3man is the human-facing counterpart to the Python client library being built in Tier 4 of the knife integration. The Python library is for LLM agents; g3man is for engineers debugging by hand.

## Non-goals

- **Orchestrated scans.** `/scan/start`, `/scan/stop`, `/scan/report` belong to g3cli. g3man refuses to operate on non-`MANAGED` scans (see §6).
- **WebSocket streaming.** `/ws` and live `/scan/progress` updates are excluded. Managed-scan top-level status is frozen at `MANAGED` and never changes on its own. Per-task status changes via polling `/scan/tasks/status`.
- **Tabular / Markdown output.** No `simpletable`, no rendered reports, no progress bars. JSON in, JSON out.
- **CLI flag overrides for env vars.** `G3_API_BASEURL` and `G3_API_TOKEN` are env-only, matching g3cli.
- **Persistent state.** No `~/.g3man/`, no "last-used scan" cache. Every invocation is stateless.

## 1. Module layout and build integration

New Go module mirroring [src/g3cli/](../../../src/g3cli/):

```
src/g3man/
├── g3man.go      # main package, single file using Kong (~600–800 lines projected)
├── go.mod        # module golismero.com/g3man, with:
│                 #   replace golismero.com/g3lib => ../g3lib
│                 #   replace golismero.com/g3log => ../g3log
└── go.sum
```

**Dependencies** (subset of g3cli's):
- `github.com/alecthomas/kong` — CLI parser.
- `github.com/willabides/kongplete` — shell completion hook.
- `github.com/go-playground/validator/v10` — request struct validation (transitively via g3lib).
- `golismero.com/g3lib`, `golismero.com/g3log`.

**Deliberately excluded** (vs g3cli):
- `github.com/gorilla/websocket` — no streaming.
- `github.com/alexeyco/simpletable` — no human tables.
- `github.com/wcharczuk/go-chart` — no reports.

**Build integration:**
- `src/Makefile` — add a `../bin/g3man` rule following the existing per-binary pattern.
- Root `Makefile` — `bin` builds it; `install` creates a `/usr/bin/g3man` symlink alongside `g3`, `g3cli`, etc.
- `.github/workflows/CI.yml` — release matrix entry for `g3man` across linux/darwin/windows × amd64/arm64, with `-ldflags "-X main.Version=..."` for tagged builds.
- `golangci-lint` covers `src/g3man/` like every other module.

**Documentation touches:**
- `README.md` — short `## g3man` section.
- `CLAUDE.md` — one-line addition to the binary table.

## 2. Command surface

**Principle:** verbs name *user intent*, not URL paths. The internal HTTP call evolves during the [HTTP routing & REST migration](../../future/http-routing-and-rest-migration.md); the CLI surface does not. The "after migration" column below is informational — it documents which future endpoint each verb maps to, so that the migration's per-verb retrofit is a known mechanical edit.

| Command | Action | Today's endpoint | After REST migration |
|---|---|---|---|
| `g3man new` | Create managed scan. Prints scan ID. | `POST /scan/create` | `POST /scans/managed` |
| `g3man ls` | List managed scans (client-filtered to `MANAGED`). `-q` → IDs only. | `POST /scan/progress` | `GET /scans` |
| `g3man rm <id>...` | Delete managed scan(s). Prompts unless `-f`. | `POST /scan/delete` (per id) | `DELETE /scans/{id}` |
| `g3man target <id> <t>...` | Add canonicalized targets. | `POST /scan/target/add` | `POST /scans/{id}/targets` |
| `g3man get <id> [dataid]...` | Get data by ID. `-q` → data IDs only. | `POST /scan/data` (with `DataIDs`) | `POST /scans/{id}/data/filter` |
| `g3man output <id> <taskid>` | All data produced by a task. `-q` → data IDs only. | `POST /scan/data` (with `TaskID`) | `GET /scans/{id}/data?taskid={tid}` |
| `g3man put <id> [-i file]` | Insert raw G3Data (stdin or file). | `POST /scan/data/insert` | `POST /scans/{id}/data` |
| `g3man upload <path>` | Multipart upload. Prints `{fileid}`. | `POST /file/upload` | `POST /files` |
| `g3man import <id> <tool> <fid>` | Run importer on uploaded file. | `POST /scan/import` | `POST /scans/{id}/import` |
| `g3man run <id> <tool> [-i file]` | Dispatch tool task. Prints `{task_id}`. | `POST /scan/task/dispatch` | `POST /scans/{id}/tasks` |
| `g3man ps <id>` | Task list with state. `-q` → task IDs only. Mirrors g3cli's `ps <scanid>` drill-down. | `POST /scan/tasks/status` | `GET /scans/{id}/tasks` |
| `g3man cancel <id> <tid>...` | Cancel task(s). | `POST /scan/task/cancel` | `POST /scans/{id}/tasks/{tid}/stop` (per tid) |
| `g3man fetch <id> <tid>` | Download artifact bundle to `-o`. | `POST /scan/task/artifacts` | `GET /scans/{id}/tasks/{tid}/artifacts` |
| `g3man logs <id> [tid]...` | Fetch logs. | `POST /scan/logs` | `GET /scans/{id}/logs` (`?taskid=`) |
| `g3man tools` | List registered plugins. `-q` → plugin names only. | `POST /plugin/list` | `GET /plugins` |
| `g3man describe` | All plugins' LLM contracts. | `POST /plugin/describe` | `GET /plugins/describe` |
| `g3man env` | Shared `G3_ENV_*` map. | `POST /config/env` | `GET /config/env` |
| `g3man completions {bash,zsh,fish}` | Emit shell completion snippet. | — | — |

**Verbs dropped from the earlier draft:**
- `scan list` (IDs-only `/scan/list`), `scan tasks` (IDs-only `/scan/tasks`), `scan datalist` (IDs-only `/scan/datalist`) — all replaced by `-q` collapsing the full-response output to IDs client-side, matching g3cli's `ps` behavior at [g3cli.go:792-797](../../../src/g3cli/g3cli.go#L792-L797). The IDs-only API endpoints remain in g3api as bandwidth-saving polling helpers for g3tui-class consumers.

**Naming notes:**
- `get` / `put` — read/write paired ("get data" / "put data"). Symmetric.
- `output` — distinct from `get`: returns everything one task produced (uses the new `?taskid=` filter introduced in the knife plan's Tier 1). Separate verb because UUIDs can't be disambiguated positionally.
- `target`, `run`, `fetch`, `cancel` — concrete verbs, no URL flavor. `cancel` maps to the future migration's `POST .../stop` without renaming.

## 3. Auth, env vars, process scaffolding

**Required environment variables:**
- `G3_API_BASEURL` — HTTP base URL of g3api.
- `G3_API_TOKEN` — shared bearer token.

**Not required:** `G3_API_WSURL` (no streaming endpoints).

**Loading and validation** — mirrors g3cli's `main()` at [g3cli.go:151-186](../../../src/g3cli/g3cli.go#L151-L186):

```go
g3lib.LoadDotEnvFile()
log.InitLogger()
if ll := os.Getenv("G3_CMD_LOG_LEVEL"); ll != "" { log.SetLogLevel(ll) }
if CLI.Quiet { log.SetLogLevel("CRITICAL") }
if cmdctx.BaseURL = os.Getenv(G3_API_BASEURL); cmdctx.BaseURL == "" { log.Critical(...); os.Exit(1) }
if cmdctx.Token   = os.Getenv(G3_API_TOKEN);   cmdctx.Token   == "" { log.Critical(...); os.Exit(1) }
```

The `completions` subcommand short-circuits before the env-var checks (same as g3cli at [g3cli.go:145-148](../../../src/g3cli/g3cli.go#L145-L148)).

**Cancellation context** — pattern from [g3cli.go:195-215](../../../src/g3cli/g3cli.go#L195-L215):
1st `os.Interrupt` → `cancel()` (lets in-flight ctx-aware HTTP requests bail), 2nd → `os.Exit(1)`. g3man uses the accurate log message `"Interrupt received!"` instead of g3cli's mislabeled `"SIGTERM received!"` (the listener is `signal.Notify(signalChan, os.Interrupt)`, i.e. SIGINT, not SIGTERM).

**Transport** — every call goes through `g3lib.MakeApiRequest(ctx, baseURL, path, token, req)`. No new HTTP client code.

**Per-call managed-scan precheck** — implemented as a small helper:

```go
// Every per-scan command calls this before its real request. Fetches the scan's
// progress row, errors out if status != MANAGED. Will collapse to a single
// GET /scans/{scanid} call after the REST migration.
func requireManagedScan(ctx CmdContext, scanid string) error { ... }
```

Three lines of work per verb. Exempt: `new` (creates the managed scan) and `upload` (scan-agnostic).

## 4. I/O conventions

**Output — stdout:**
- All JSON-returning commands print the API response `data` field to stdout.
- Default: compact JSON (`json.Marshal`), matching g3api's wire format.
- `-b/--beautify`: indented JSON (`json.MarshalIndent`, two-space indent), matching g3cli's `export` at [g3cli.go:1143-1146](../../../src/g3cli/g3cli.go#L1143-L1146).
- `-q/--quiet` on list-style commands (`ls`, `ps`, `get`, `output`, `tools`): collapses output to newline-separated IDs, matching g3cli's `ps` at [g3cli.go:792-797](../../../src/g3cli/g3cli.go#L792-L797). On non-list commands, `-q` only silences logs.

**Output — file (every command):**
- `-o <path>` with `default:"-"` (stdout), matching the universal g3 / g3cli convention ([g3cli.go:51, 59, 65, 69, 80, 85, 91](../../../src/g3cli/g3cli.go#L51), [g3.go:31](../../../src/g3/g3.go#L31)).
- `fetch` writes the binary artifact bundle to whatever `-o` resolves to. Default is stdout (i.e. terminal sees garbage if not redirected) — same Unix-standard behavior as `curl`. No special-case enforcement.

**Input — JSON bodies (`put`, `run`):**
- `-i/--input <path>` with `default:"-"` and `type:"existingfile"`, matching g3cli's `scan` at [g3cli.go:50](../../../src/g3cli/g3cli.go#L50). Stdin by default; file when given.
- No `-d` inline-JSON flag.
- Body validated server-side via the matching `Req*.Decode` + `validator.Struct`.

**Errors — stderr:**
- API error envelope (`{"status":"error","data":"..."}` from `SendApiError`) printed as `Error: <data>` via `log.Critical`.
- Transport / ctx-cancel errors: same `log.Critical` prefix.
- Argument errors: Kong's `parser.FatalIfErrorf` (its own format).
- Managed-precheck rejection: `scan <id> is not managed (status: <X>) — use g3cli for orchestrated scans`. Distinct, actionable.

**Exit codes:** `0` success, `1` any error. Matches g3cli (single non-zero). Finer taxonomy deferred until a real consumer needs it.

**`rm` confirmation prompt** — mirrors g3cli's `Rm` at [g3cli.go:1296-1315](../../../src/g3cli/g3cli.go#L1296-L1315) exactly:
- `-f/--force` skips the prompt.
- Without `-f`: `g3lib.AskForConfirmation` with the count-aware "This is IRREVERSIBLE!" message.
- On "no", returns `user cancelled the operation` and exits non-zero.

**TTY detection:** none. Behavior is deterministic across TTY / pipe / redirect.

## 5. Top-level flags

| Flag | Scope | Behavior |
|---|---|---|
| `-q, --quiet` | Top-level | Silences logs (level → CRITICAL). On list verbs, also collapses output to IDs. |
| `-b, --beautify` | Top-level | Pretty-print JSON output (`MarshalIndent`). |
| `--version` | Top-level | Print version and exit. Linker-set via `-X main.Version=...`. |
| `-o, --output` | All commands | Output path. `-` = stdout. Default `-`. Declared per-command struct, matching the g3cli/g3 convention. |
| `-i, --input` | `put`, `run` | Input path. `-` = stdin. Default `-`. |
| `-f, --force` | `rm` | Skip the irreversible-deletion confirmation prompt. |

## 6. Managed-scan enforcement

g3man refuses to operate on any scan whose status is not `MANAGED`. Enforcement is two-layered:

1. **`ls` filters client-side.** `/scan/progress` returns every scan today ([sql.go:357-384](../../../src/g3lib/sql.go#L357-L384) has no status filter); g3man drops everything that isn't `MANAGED` before emitting.
2. **Every per-scan command pre-checks status.** Before sending its real request, the verb calls `requireManagedScan` (fetches `/scan/progress`, finds the row, errors out if `status != MANAGED`). Adds one round-trip per call — acceptable for a debug tool, prevents silent half-working behavior on orchestrated scans (where writes 409 server-side but reads succeed regardless).

Server-side write endpoints are already gated by g3api's `requireManagedScan` helper (added in the knife integration's Tier 2); the client-side precheck is belt-and-suspenders for consistent UX, not security.

**Commands not running the per-call precheck:**
- `ls` — uses the client-side filter from §6.1 instead (no scan ID argument to check).
- `new`, `upload`, `tools`, `describe`, `env`, `completions` — none operate on an existing scan ID.

## 7. Tier outline

The implementation plan that follows this spec details Tier 1 and outlines Tiers 2–5 (per the project's tiered-plan convention: outline all, detail current).

- **Tier 1 — Skeleton.** `src/g3man/` module + `go.mod` with `replace` directives. Kong CLI scaffolding with top-level flags (`-q`, `-b`, `--version`), env-var loading, ctx-cancel on SIGINT (accurate log message), `completions` wired through `g3lib.EmitShellCompletion`. Added to `src/Makefile` and root `Makefile` `bin` target. Builds and lints clean with zero functional verbs.
- **Tier 2 — Read verbs + managed precheck.** `requireManagedScan` helper. `ls`, `ps`, `logs`, `get`, `output`, `tools`, `describe`, `env`, `fetch`. `-q` collapses list outputs to IDs.
- **Tier 3 — Write verbs.** `new`, `rm` (with confirmation + `-f`), `target`, `put`, `upload`, `import`, `run`, `cancel`. `-i` reads JSON bodies on `put` and `run`.
- **Tier 4 — Build / install / CI / docs.** `make install` symlink, CI release matrix entry, golangci-lint coverage, README + CLAUDE.md updates.
- **Tier 5 (deferred, optional) — g3cli managed-blind filter.** Modify [g3cli.go](../../../src/g3cli/g3cli.go) `Ls.Run`, `Ps.Run`, `Logs.Run`, `Export.Run`, `Report.Run` to filter out `MANAGED` scans client-side. After this lands, g3cli and g3man are partitioned by scan status — neither sees the other half. Touches g3cli, not g3man; grouped here for the symmetry. Can also become a follow-up PR if scope concerns surface.

## 8. Open questions

None blocking. Items to revisit during implementation:

- **Single-plugin `describe <tool>`** — today `/plugin/describe` returns all contracts. When the deferred per-plugin endpoint lands (see [routing doc](../../future/http-routing-and-rest-migration.md) lines 226-228), `describe <tool>` becomes a one-line switch. Until then: `describe` only.
- **REST migration retrofit** — when the migration ships, g3man's per-verb HTTP-request functions update (path templates, methods, body→path-param moves). Help text, completions, and user scripts are unaffected.

---

*Written 2026-05-29 during a brainstorming session, after design approval across all five sections.*
