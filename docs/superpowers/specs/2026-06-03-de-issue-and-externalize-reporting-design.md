# De-Issue Golismero & Externalize Reporting to Magenta — Design

Brainstormed 2026-06-03.

## Context

Golismero currently does two jobs that this design moves out of the core:

1. **Built-in Markdown reporting.** `src/g3lib/report.go` renders a Markdown
   report (severity pie chart via `go-chart`, per-severity tables, issue
   sections) from `_type:"issue"` G3Data objects, using per-plugin i18n
   templates. It is reachable from the local CLI (`g3 report`), the remote
   CLI (`g3cli report` → `POST /scan/report`), a bare `report` directive in
   server scan scripts (`runBuiltinReport` in `g3scanner`), and the TUI
   report pane.

2. **Issue production inside plugins.** Several plugins parse their tool
   output into `_type:"issue"` findings: `hydra`, `nikto`/`nikto-slow`, and
   `testssl` emit *only* issues; `nmap` emits `host` assets *plus* one
   secondary "plaintext ports" issue. Each issue-producing plugin carries an
   importer (`g3i.py`), a per-plugin merger (`g3m.py`) for issue dedup, and an
   `i18n/` template directory consumed exclusively by the built-in reporter.

The strategic direction (see
[docs/future/knife-integration-design.md](../../future/knife-integration-design.md)
§4.3–§4.4 and the "Retire the in-process MarkdownReporter" future-work item in
[2026-05-18-reporter-tier3-design.md](2026-05-18-reporter-tier3-design.md)) is
to make **Magenta** the sole owner of issue parsing and reporting. Magenta is
already a registered reporter plugin
([plugins/report/magenta/](../../../plugins/report/magenta/)); it reads raw
artifact files from `/input` via filename-prefix matching (`<tool>.*`) and
does **not** consume Golismero's `issue` objects. The server-side reporter
plugin machinery (dispatch → worker → `/scan/task/artifacts`) already shipped
in the reporter-plugins Tiers 1–3.

This design executes the cut-over: remove the built-in reporter and i18n,
stop Golismero's plugins from producing issues (refactoring them into pure
asset/artifact producers), and route every `report` surface to Magenta.

## Goal

Golismero plugins do **tool execution + artifact generation + asset G3Data
(for chaining)** only. Reporting and issue production move entirely to Magenta.

Concretely:

1. Remove the built-in `MarkdownReporter` and everything that exists solely to
   serve it (including all i18n).
2. Refactor the issue-producing plugins so they emit their **input asset,
   enriched** (the nmap pattern) instead of `issue` objects, plus add a new
   `credential` asset type for hydra.
3. Rewire every `report` entry point (server scripts, `g3cli`, local `g3`,
   TUI) to dispatch the **Magenta** plugin.

## Guiding principle: removing the reporter ≠ removing issue support

The engine's `_type:"issue"` plumbing is **retained**. Magenta will become the
sole *producer* of issue objects (with its own, different schema) and may feed
them back into Golismero, so Golismero must still be able to *store and handle*
issues. We are removing the built-in **reporter**, not the issue **type**.

**Retained, untouched:**
- `IsValidData`'s `_type=="issue"` severity validation
  ([common.go](../../../src/g3lib/common.go)).
- Datastore issue queries `LoadIssues` / `GetIssueIDs` / `GetScanIssueTools`
  ([datastore.go:154-218](../../../src/g3lib/datastore.go#L154)).
- The engine merger-phase machinery (`BuildMergerCommand`, the `g3scanner`
  merger loop) — kept **dormant** after per-plugin mergers are removed.
- `G3Report` / `SaveReportInfo` / `LoadReportInfo` / `DeleteReportInfo`
  ([kvstore.go:22-96](../../../src/g3lib/kvstore.go#L22)) and
  `ReporterStdinStream`
  ([datastore.go:343-448](../../../src/g3lib/datastore.go#L343)).
- The entire reporter-plugin path: `/scan/task/dispatch`,
  `/scan/task/artifacts`, `BuildReporterCommand`, `RunPluginReporter`, the
  worker `SubscribeAsReporter` handler.

## Non-goals (explicitly deferred)

- **Magenta as issue *producer*.** Wiring Magenta's per-task artifact parsing
  to emit `issue` G3Data back into Mongo (knife §4.3) is future work. After
  this change, *nothing* produces `issue` objects in the interim — the engine
  simply remains capable of handling them. Accepted.
- **Magenta as issue *deduplicator*.** Magenta will eventually own issue
  dedup (replacing the per-plugin mergers conceptually). Not now.
- **Local-artifact persistence.** No new machinery to persist local-mode
  artifact slots. For local `g3 report`, the **user** is responsible for
  having produced artifacts into a directory of their choice and passing that
  directory to the report job. (The current local slot is ephemeral; see
  "Local report" below.)
- **nikto `url` discovery (open item).** Whether nikto should additionally
  emit `url` assets for genuinely chainable hits (e.g. autodiscovered `.git`
  directories, backups) is tracked as an investigation, not designed here.
- **Removing the dormant merger machinery.** Left in place per the guiding
  principle; a future cleanup once Magenta owns dedup.

## Component 1 — Remove the built-in reporter

**Delete outright:**

| File / location | What |
| --- | --- |
| [src/g3lib/report.go](../../../src/g3lib/report.go) | Entire file (the `MarkdownReporter`). |
| `src/g3lib/go.mod` / `go.sum` | The `github.com/wcharczuk/go-chart` dependency (used only by `report.go`). |
| [g3api.go](../../../src/g3api/g3api.go) `POST /scan/report` handler (~1021-1096) | Plus its `LoadG3Strings`/`LoadPluginTemplates` startup calls (~295-298) and the pass-through to the handler. |
| [g3scanner.go](../../../src/g3scanner/g3scanner.go) `runBuiltinReport` (~1284-1406) + the bare-`report` in-process branch (~1185-1196) | Plus the `LoadG3Strings`/`LoadPluginTemplates` calls in `g3scanner` main (~113-114) and their pass-through to `ScanRunner`. |
| [g3/g3.go](../../../src/g3/g3.go) `ReportCmd.Run` body (~961-1005) | Rewired to Magenta, not just deleted — see Component 4. |
| [g3cli/g3cli.go](../../../src/g3cli/g3cli.go) `ReportCmd.Run` body (~1017-1079) | Rewired to Magenta — see Component 4. |

**Keep (corrected from initial brainstorm):**

- **TUI `<img>` fallback** ([report.go:356-406](../../../src/g3tui/internal/ui/report.go#L356)).
  Magenta also emits base64 pie-chart `<img>` blocks; Glamour drops raw HTML,
  so the `htmlImgWithPRe`/`htmlImgRe` rewrite-to-`*[Image: …]*` fallback stays.
  Changes: (a) update the comment to reference Magenta instead of the built-in
  template; (b) rewire `ReportPane.fetchCmd` off the deleted `/scan/report`
  (`cli.GetReport`) onto the dispatch + `/scan/task/artifacts` flow.

## Component 2 — De-issue the plugins

**Unifying pattern:** every refactored tool emits its **input asset, enriched**
— exactly how `nmap` already emits the `host` it received plus `services`. The
enriched object is a new G3Data node distinguished by its own `_fp`, so no
dedup/upsert is needed. For the formerly issue-only tools, the enrichment is an
`_artifacts` stamp (the raw output files Magenta will parse). The importer
(`g3i.py`) shrinks to a tiny echo: read the input object, re-emit it with
`_artifacts` (and tool-specific `_fp`) filled in.

| Plugin | After change |
| --- | --- |
| **testssl** | Tiny `g3i.py` echoes input `host` + stamps `_artifacts:["testssl.<slug>.<port>.json","…txt"]`, `_fp:["testssl <host:port>"]`. Delete `g3m.py`, `i18n/`. `.g3p`: commands & importer `returns:"host"`; remove `merger`; `llm.produces:["host"]`. |
| **nikto** / **nikto-slow** | Same echo-importer over its input (`url`/`host`) + `_artifacts:["nikto.txt","nikto.csv"]`. Delete `g3m.py`, `i18n/`. `.g3p`: remove `merger`; adjust `returns`/`llm.produces`. **Open item:** optionally also emit `url` assets for chainable discoveries. |
| **hydra** | Echo input `host` enriched, **plus emit `credential` objects** (`{host,port,service,login,password}`, `_fp:["hydra <host:port>"]`). Delete `g3m.py`, `i18n/`. `.g3p`: remove `merger`; `llm.produces:["host","credential"]`. |
| **nmap** | Keep `host` emission. Remove the plaintext-ports `issue` block ([g3i.py:466-479](../../../plugins/recon/nmap/g3i.py#L466)). Delete `nmap/g3m.py`, `i18n/`; remove `merger` from `nmap.g3p`; drop `"issue"` from `llm.produces` in `nmap.g3p`, `nmap-fast.g3p`, `nmap-full.g3p`. |

**`credential` asset type.** A plain asset type — `IsValidData`'s `^[a-z]+$`
type regex already accepts it; no special validation (unlike `issue`'s
severity check). Document its conventional fields
(`host`, `port`, `service`, `login`, `password`). No consumer exists yet;
it is forward-looking for the authenticated-tool / confirmation lane (knife
§6.4). Add it to the `_type` taxonomy documentation alongside
`host`/`url`/`domain`/`cidr`/`issue`/`nil`.

**Empty-output safety.** A tool whose run yields nothing to enrich still
behaves correctly: the engine already supports `_type:"nil"` placeholders and
empty importer output. Artifact files remain on disk regardless of G3Data
output, so Magenta can still parse them.

## Component 3 — Remove i18n (reporter-only, confirmed)

i18n is a straight-line dependency of the built-in reporter; no other binary,
endpoint, CLI path, or Python script consumes it.

| Delete | Location |
| --- | --- |
| All 5 `i18n/` directories | root `i18n/` + `plugins/{recon/nmap,attack/nikto,recon/testssl,attack/hydra}/i18n/` |
| Generated template/string config | `config/g3strings.json`, `config/g3templates.json` |
| `LoadG3Strings`, `G3TranslatedStrings`, constants | [common.go:32-36,170-199](../../../src/g3lib/common.go#L32) |
| `LoadPluginTemplates`, `G3PluginTemplates(Cache)` | [plugin.go:107-161](../../../src/g3lib/plugin.go#L107) |
| `ParseLanguageFiles`, `ParsePluginTemplates`, `golang.org/x/text/language`+`/display` usage | [g3config.go:14-15,27-148](../../../src/g3config/g3config.go#L27) |

**Keep:** `template.go`'s `ExpandTemplate`/`BuildTemplate` — used by tool
conditions, command building, and fingerprints, **not** reporter-only.

**Flatten `Description`.** Change `G3Plugin.Description` from
`map[string]string` → `string` ([plugin.go:79](../../../src/g3lib/plugin.go#L79)),
populated with the English text. Update read sites: `G3Plugin.String()`
(plugin.go:92), `/plugin/list` (g3api.go ~1457), local plugin listings
(g3.go ~456,650), and the `g3config` auto-fill (g3config.go ~347). Plugin
**identity** (`Name`, `URL`, `Description`) is otherwise preserved — it lives
in the plugin registry, separate from the i18n templates being removed.

## Component 4 — Route every `report` surface to Magenta

| Surface | Before | After |
| --- | --- | --- |
| **Server scan script** | bare `report` → `runBuiltinReport` (in-process). `report <tool>` → dispatch plugin. | bare `report` ≡ `report magenta`; the existing `report <tool>` dispatch path is unchanged. |
| **`g3cli report`** | `POST /scan/report` → in-process Markdown. | Dispatch Magenta via `POST /scan/task/dispatch {kind:"report",tool:"magenta"}`, poll `/scan/tasks/status` until terminal, download via `POST /scan/task/artifacts` — wrapped behind the same `g3cli report` UX. |
| **`g3 report` (local)** | In-process `MarkdownReporter`. | Docker-run Magenta locally via the existing `BuildReporterCommand` + `RunPluginReporter`, mounting a **user-supplied** artifacts directory as `/input` and the output dir as `/output`. New flag on the local report path: `--artifacts <dir>` (the user's responsibility to populate). |
| **TUI report pane** | `cli.GetReport` → `/scan/report`. | Dispatch + `/scan/task/artifacts`; `<img>` text fallback retained (Component 1). |

Validation messages for bare-`report`/`report magenta` reuse the existing
`/scan/task/dispatch` checks so script and API feedback stay identical.

### Local report — artifact directory contract

Local mode currently creates an ephemeral slot
(`CreateEphemeralArtifactSlot`) that is `RemoveAll`-ed immediately after a
plugin exits, so there is no persistent local artifact tree to report on
automatically. Per the non-goal, we do **not** add persistence. Instead,
`g3 report --artifacts <dir>` treats `<dir>` as the already-populated `/input`
for Magenta. How the user populates `<dir>` (e.g. directing `g3 run` output
there) is out of scope for this change.

## Phased plan (single spec, staged execution)

1. **Reporter + i18n removal** (Components 1 & 3). Self-contained; engine
   issue-handling untouched. Build-verify all six binaries.
2. **Plugin de-issue refactor** (Component 2, minus `credential`): testssl,
   nikto/nikto-slow, nmap → echo-importers; delete per-plugin mergers, i18n,
   and issue code; update `.g3p` files. Re-run `g3config`.
3. **`credential` type**: define + document; hydra echo-importer emits it.
4. **`report` → Magenta rewire** (Component 4): server bare-`report`, then
   `g3cli report`, then local `g3 report`, then TUI pane.

The nikto `url` second-look rides alongside step 2 as an investigation; it
does not block the phase.

## Verification

- All six Go binaries build (`g3`, `g3api`, `g3cli`, `g3config`, `g3scanner`,
  `g3worker`); `g3tui` builds.
- `g3config` re-registers all plugins with no merger/i18n references and the
  flattened `Description`.
- A server scan with `report magenta` (and bare `report`) produces a Magenta
  report via dispatch + `/scan/task/artifacts`.
- A scan exercising the refactored plugins shows enriched assets (host with
  `_artifacts`; hydra `credential` objects) and **no** `_type:"issue"` objects
  emitted by Golismero.
- `g3 report --artifacts <dir>` Docker-runs Magenta against `<dir>` and writes
  the report.
- TUI report pane renders a Magenta report (with `*[Image: …]*` chart
  fallback) via the new dispatch path.

## Open items

- **nikto `url` assets.** Review nikto's currently-ignored findings
  (`.git`, backups, admin paths) for genuinely chainable URLs worth emitting
  as `url` G3Data. Resolve during phase 2.
- **Dormant merger machinery.** Engine merger phase remains after all
  per-plugin mergers are removed; revisit for removal once Magenta owns dedup.
