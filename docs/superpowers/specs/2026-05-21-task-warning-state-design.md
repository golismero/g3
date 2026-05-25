# Task WARNING State Design

Brainstormed 2026-05-21.

## Context

A testssl task (scan `6a043dc6…`, task `e3b3b6f9…`) ran to completion but
logged a non-fatal error mid-run:

```
DNS CAA RR (experimental)    Error: error sending query: Could not send or receive, because of network error
```

The results were fine — that error is testssl's own outbound DNS probe
(`--phone-out` / CAA RR lookup) failing, not a problem reaching the
target. But nothing in g3 surfaces "this run is worth a second look."
The investigation surfaced a more general gap:

1. **The task lifecycle has no "completed with warnings" concept.** A
   task is DONE, CANCELED, or ERROR. There is no state for "produced
   usable results, but something happened that the user should look at."

2. **Plugin wrappers swallow the tool's exit code.** Every wrapper ends
   with an explicit `exit 0` ([nmap g3p.sh](../../../plugins/recon/nmap/g3p.sh),
   etc.) or ignores `returncode` in Python ([testssl g3p.py](../../../plugins/recon/testssl/g3p.py),
   [hydra g3p.py](../../../plugins/attack/hydra/g3p.py)). The shell wrappers are
   even inconsistent: a tool failure in a piped wrapper (`tool | tee …`)
   is masked by `tee`'s exit status, while a tool failure in a
   non-piped wrapper trips `set -e` → container non-zero → ERROR. So
   today a broken nikto becomes ERROR but a broken nmap becomes DONE,
   purely as an artifact of whether a `tee` happens to be on the line.

3. **The worker discards stdout on a non-zero exit.**
   [`runPluginInternal`](../../../src/g3lib/plugin.go#L617) returns early
   when the container exits non-zero, before parsing stdout. So
   "the tool failed but still produced valid results" is currently
   unrepresentable — the data is thrown away.

4. **Worker diagnostics are operator-only.** When the worker drops a
   malformed G3Data object it logs via `log.Error`
   ([g3worker.go:826/828](../../../src/g3worker/g3worker.go#L826)) — the
   worker's own stdout, not the SQL task log. End users reading task
   logs through the API never see why an object was rejected.

## Goal

Add a fourth task terminal state, **WARNING**, meaning "the task produced
usable results but something happened that warrants reading its logs; the
pipeline continued." Derive it in the worker from signals it already has,
without changing the plugin output contract. Surface it in the TUI so a
user can spot tasks needing attention without reading every log, and
route the worker's own diagnostics into the user-visible task log.

### The state model

**Task state and pipeline fuel are decoupled.** The pipeline only cares
about *fuel* (does the task produce actionable data the scanner can chain
on); the task state is a *user-facing severity verdict*, independent of
fuel. They align most of the time and deliberately diverge for hard
contract breaches (see below). The scanner never reads task state — it
advances on the data IDs a task reports via `SendResponse`
([task.go:446](../../../src/g3lib/task.go#L446)).

Four terminal states:

- **CANCELED** — user/operator stopped it. Short-circuits everything (a
  task canceled mid-run is CANCELED even if it had accumulated a
  warning). The *only* state that does not seed the negative-result cache
  (see heuristic 2), because an interrupted task hasn't *determined*
  anything — a future run should retry.
- **ERROR** — a serious problem the user must investigate. Two sources:
  - a **hard contract breach** — artifact-claim violation — regardless
    of how much data was produced; or
  - a **soft problem signal with zero actionable results** — the tool
    failed/complained and left nothing to chain on (unparseable stdout
    lands here too: no parse → no actionable objects).
- **WARNING** — a soft problem signal **and** ≥1 actionable result. The
  tool complained but produced usable output; logs warrant a look.
- **DONE** — no problem signal.

### Fuel vs. state

These are computed and acted on separately:

- **Fuel** (non-canceled tasks): always `SaveData` the sanitized output
  (actionable objects, or a single nil placeholder when there are none)
  and `SendResponse`. The pipeline continues iff ≥1 actionable object was
  produced — the scanner skips nils
  ([g3scanner.go:579](../../../src/g3scanner/g3scanner.go#L579),
  [:883](../../../src/g3scanner/g3scanner.go#L883)). A hard-ERROR task
  with actionable data therefore **still feeds the pipeline** — its data
  is not thrown away just because the artifact claim was bad.
- **State**: the verdict above, surfaced to the user via the terminal
  marker, never read by the scanner.

This intentionally gives up the tidy `ERROR ⟺ no fuel` equivalence: a
hard contract breach is ERROR *and* can carry fuel. The trade is
deliberate — discarding good data to preserve a slogan is worse than
keeping it, and folding contract breaches into WARNING would bury a real
plugin bug under "minor trouble" (warning fatigue).

### Two derived quantities

- **Soft problem signal** = the container exited non-zero (the wrapper's
  exit code — we own the wrapper) **OR** ≥1 emitted object was dropped by
  `IsValidData`. (Collapsed to a single `error` return plus a dropped
  count; see Tier 1a.)
- **Hard contract breach** = artifact-claim validation failed. Forces
  ERROR irrespective of actionable count. (Unparseable stdout is *not*
  modeled as a hard breach — it yields zero actionable objects and so
  reaches ERROR via the no-fuel branch, needing no special case.)
- **Actionable result count** = objects that pass `IsValidData` **AND**
  are non-nil (`_type != "nil"`). Exactly the set the scanner will act
  on.

## Non-goals

- **ERROR actively halting the pipeline.** The scanner advances on
  *data*, not on task state. An ERROR task with no actionable output
  reports only a nil (which the scanner skips), so the pipeline starves
  naturally; an ERROR task *with* actionable data feeds the pipeline like
  any other. We are **not** adding scanner coupling to make a terminal
  state stop dispatch. "Pipeline stops here" stays an emergent property
  of producing no fuel, never a function of the state label.

- **Changing the plugin output contract.** Plugins still emit a JSON
  array of G3Data on stdout. The only behavioral ask of a wrapper is
  that it stop forcing `exit 0` and instead let a deliberate non-zero
  through when something noteworthy happened (Tier 4).

- **Local-CLI parity for the new states.** WARNING is a server/worker
  concept — it lives in the per-task terminal state (Redis + `[g3:done]`
  marker) and the TUI. The local CLI (`g3 run` / `g3 report` / `g3
  import`) and the scanner's merger phase have no task-state machine and
  keep their current **fail-hard** semantics: a non-zero plugin exit
  there is a hard error (`if err != nil { return }`), not a WARNING.
  This is a **deliberate, accepted asymmetry** — the same plugin can land
  as WARNING under a worker but as a hard error via `g3 run`. Local-CLI
  parity, if ever wanted, is a separate effort (it needs a state surface
  the pipe model doesn't have).

- **Retry/transient-error handling in the framework.** Transient errors
  a wrapper can resolve by retrying are the wrapper's job and must not
  reach the worker as a signal. WARNING is for "results obtained but
  something *might* be degraded and needs human eyes," not for
  auto-resolved hiccups and not for cosmetic noise.

- **A scan-level WARNING rollup.** Whether a scan with one WARNING task
  surfaces a scan-level indicator is deferred. This is moot for safety:
  scan status is decoupled from worker-task states (the scanner never
  receives them — see Tier 2), so a WARNING task cannot flip the scan
  regardless.

- **Dropping nil objects at the worker.** See the invariant below — nils
  are counted-out, never dropped.

## Design heuristics

1. **State and fuel are decoupled.** Fuel (does the scanner advance) is
   purely data-driven — actionable, non-nil result count. State is a
   severity verdict for the user. The scanner reads only the data a task
   reports, never its state, so a hard-ERROR task with actionable data
   keeps the pipeline moving while still flagging the breach.

2. **Nils are counted-out, never dropped — and every non-canceled empty
   result seeds the cache.** *(Load-bearing invariant — do not
   "optimize" this away.)* The worker injects a `_type:"nil"`
   placeholder when a non-canceled run yields no actionable output
   ([plugin.go:629](../../../src/g3lib/plugin.go#L629)) and persists it
   with the command's `_fp`. The scanner uses that fingerprint as a
   **negative-result cache**: `GetFingerprintMatchesIDs`
   ([g3scanner.go:931](../../../src/g3scanner/g3scanner.go#L931),
   [datastore.go:132](../../../src/g3lib/datastore.go#L132)) finds it and
   skips re-running a command that already produced nothing. This now
   includes ERROR (errors reaching the worker are *definitive* — the
   plugin owns transient retries — so caching them prevents inconsistent
   incidental re-runs across parallel pipelines). Excluding nils from the
   *count* is required; excluding them from *persistence/transmission*
   would break the cache. CANCELED is the sole exception: it neither
   saves nor seeds, because an interrupted task determined nothing.

3. **Classification lives in the wrapper.** We own every wrapper and the
   contract forbids invoking tools directly, so the exit code the worker
   sees is always one we authored. Deciding which tool conditions are
   benign (→ exit 0) vs noteworthy (→ non-zero) is normal wrapper
   authoring, done once per plugin. The framework carries one ordinal
   severity; richer per-target detail lives in the logs/data.

4. **Verdict via the terminal marker; detail via the task log.** The
   authoritative state flows through `SetTaskTerminal` + the
   `[g3:done] state=…` SQL marker (what
   [`ReconstructTaskStateFromLogs`](../../../src/g3lib/sql.go#L465)
   parses). Human-readable "why" goes into the SQL task log as
   `[g3:warn] …` lines, co-located with the plugin's own output and
   visible through the API.

---

## Tier 1 — Worker classification (detailed)

The whole behavioral change lives in `g3lib/plugin.go` and
`g3worker/g3worker.go`. No new states are *plumbed* yet (Tier 2); this
tier makes the worker compute and emit `"WARNING"` as a `markTerminal`
string and write `[g3:warn]` log lines. Because `markTerminal` already
takes a free-form state string, a WARNING string will reach Redis and the
`[g3:done]` marker without any plumbing change — it simply won't be
*rendered* specially until Tier 3, and the artifacts endpoint must learn
about it in Tier 2.

### 1a. Parse stdout regardless of exit code; single error return

`runPluginInternal` currently returns early on a non-zero exit and reuses
the `err` variable for the JSON unmarshal, which would clobber the exit
signal if the early return were removed.

Current ([plugin.go:617-632](../../../src/g3lib/plugin.go#L617)):

```go
if cancelled || err != nil {
    return outputArray, err            // outputArray still empty here
}
endTime := time.Now().Unix()
raw := stdout.Bytes()
err = json.Unmarshal(raw, &outputArray)   // reuses err — clobbers exit error
if err == nil && len(outputArray) == 0 {
    dummy := G3Data{}
    dummy["_type"] = "nil"
    outputArray = append(outputArray, dummy)
}
```

Target shape — **one orthogonal split: the error signal, and the output
(actionable or not)**:

- Cancellation still short-circuits and returns `ctx.Err()` — unchanged.
- On a non-cancel exit, collapse the container-wait error and the JSON
  parse error into a **single returned `error`**. The signature stays
  `(outputArray []G3Data, err error)` — no `waitErr`/`parseErr` split,
  so `RunPluginCommand` / `RunPluginImporter` / `RunPluginMerger` and the
  worker all see one error value. A parse failure surfaces as that error
  (and yields zero actionable output → ERROR via Tier 1b's no-fuel
  branch). Don't let the unmarshal silently overwrite a non-nil exit error:
  if the wait already errored, keep it; otherwise the parse error is the
  error.
- **Inject the nil placeholder for any empty parse, unconditionally** —
  the `waitErr == nil` gate is gone. Every non-canceled empty result
  (success *or* error) gets one nil placeholder so the worker can seed
  the negative-result cache (heuristic 2). The worker, not this function,
  decides save/send vs. the canceled no-op.

The enrich loop ([plugin.go:633-668](../../../src/g3lib/plugin.go#L633))
stays as-is — it stamps `_type`, `_tool`, `_fp`, `_cmd`, `_start`,
`_end`. It now also runs on the failure path, which is what lets a
"failed but produced data" run carry proper fingerprints into WARNING.

### 1b. Classify in the worker

The worker's terminal decision today is the switch at
[g3worker.go:726-851](../../../src/g3worker/g3worker.go#L726). It already:

- treats `context.Canceled` as CANCELED,
- treats a non-nil run error as ERROR
  ([:773](../../../src/g3worker/g3worker.go#L773)),
- validates artifact claims and upgrades to ERROR on failure
  ([:788](../../../src/g3worker/g3worker.go#L788)),
- filters objects through `IsValidData` into `sanitizedOutput`
  ([:821-833](../../../src/g3worker/g3worker.go#L821)),
- saves and sends `sanitizedOutput`
  ([:836-852](../../../src/g3worker/g3worker.go#L836)).

Restructure the post-run decision so **fuel and state are computed
separately**. CANCELED keeps its current short-circuit (no save, no
send → `SendEmptyResponse`). The build-command-failure and
manifest-write-failure branches are pre-/post-execution infra failures
with no plugin output and stay as today (`ERROR` + `SendEmptyResponse`,
no save). The new logic replaces the final DONE-only tail:

```
// (after CANCELED short-circuit and manifest write, as today)

// Build sanitizedOutput via IsValidData exactly as today (821-833),
// logging each reject — but ALSO mirror each reject into the SQL task
// log as a [g3:warn] line (see 1c).
droppedCount := len(outputArray) - len(sanitizedOutput)

// Partition sanitized output. Nils never count as fuel; if a plugin
// MIXED real data with nils, that's a bug smell — log it (see 1c) and
// drop the nils. If there's no actionable object, normalize to exactly
// one nil placeholder (cache seed).
actionable, nils := partition(sanitizedOutput)   // by _type == "nil"
var toPersist []G3Data
if len(actionable) > 0 {
    if len(nils) > 0 { /* [g3:warn] mixed nil+data (1c) */ }
    toPersist = actionable
} else {
    toPersist = []G3Data{ singleNilPlaceholder }   // collapse 0/1/many nils → 1
}

// Hard contract breach forces ERROR regardless of actionable count.
// (Parse failure needs no special case: it yields zero actionable
// objects, so it lands on ERROR via the no-fuel branch below.)
hardBreach := g3lib.ValidateArtifactClaims(actionable, manifestFiles) != nil

softSignal := err != nil || droppedCount > 0

// --- FUEL (state-independent): every non-canceled task persists + sends.
//     Seeds the negative-result cache for empty results (incl. ERROR).
//     Pipeline advances iff len(actionable) > 0 (scanner skips nils).
SaveData(toPersist)                  // assigns _id
SendResponse(persistentSubsetOf(toPersist))

// --- STATE (severity verdict for the user).
switch {
case hardBreach:
    markTerminal(scanID, taskID, "ERROR")     // loud; fuel still flowed above
case softSignal && len(actionable) == 0:
    markTerminal(scanID, taskID, "ERROR")     // no fuel, tool complained
case softSignal:
    markTerminal(scanID, taskID, "WARNING")   // fuel + something to see
default:
    markTerminal(scanID, taskID, "DONE")
}
```

Notes:

- **Fuel is unconditional for non-canceled tasks.** Today's ERROR paths
  call `SendEmptyResponse` and never `SaveData`; now the post-run fork
  always saves + sends, which is what seeds the cache on ERROR
  (heuristic 2) and feeds actionable data even under a hard breach. Only
  CANCELED retains `SendEmptyResponse` + no-save.
- **`actionable` is what `SaveData`/`SendResponse` carry when present;**
  nils are dropped in the mixed case (logged) and collapsed to one
  placeholder in the empty case. The placeholder is the cache seed.
- **Artifact-claim validation now runs whenever the plugin produced
  output** (not only the old success path), and a violation forces ERROR
  while leaving the actionable data in `toPersist` — the breach is
  flagged loudly without discarding usable results.
- Unparseable stdout yields the collapsed error **and** zero actionable
  objects, so it lands on ERROR via the `softSignal && len(actionable)
  == 0` branch and produces no fuel — no special-casing needed.
- **Manifest interaction.** The manifest is written unconditionally
  ([g3worker.go:737](../../../src/g3worker/g3worker.go#L737)) and its
  `ExitStatus` is currently derived from a small switch that runs
  `ValidateArtifactClaims` only on the success arm
  ([:726-736](../../../src/g3worker/g3worker.go#L726)). Fold that
  validation into the single place the fork already computes
  `hardBreach`, and set `ExitStatus` to mirror the final verdict
  (`success` / `warning` / `error` / `canceled`) so the forensic record
  agrees with the terminal marker. One source of truth for the verdict,
  written to both Redis (via `markTerminal`) and the manifest.

### 1c. Surface diagnostics in the task log

Today the `IsValidData` rejection is logged operator-side only
([g3worker.go:826/828](../../../src/g3worker/g3worker.go#L826)). Mirror a
concise marker into the SQL task log via `SaveLogLine` (the same sink as
`[g3:done]`/`[g3:cancel]`), using a parseable prefix. **Tag with the tool
name, not the task ID** — the task ID is implicit in the task log, and
tool name lets a user grep one tool's warnings across many tasks (the
likely workflow):

- Per dropped object: `[g3:warn] tool=<name> dropped malformed object: <reason>`
- **Mixed nil + actionable data only:** when the parsed output contains
  ≥1 nil **and** ≥1 non-nil object — a bug smell, since a plugin that
  produced real data shouldn't also emit nils:
  `[g3:warn] tool=<name> emitted nil alongside actionable data`.
  Empty / all-nil / single-nil outputs are normalized to one placeholder
  silently (indistinguishable from a clean empty run — no log).
- A single summary line at the verdict, carrying the error text verbatim
  (no categorized enum, per the single-error-signal simplification):
  `[g3:warn] tool=<name> <error text or "dropped N objects">`

Keep these **informational**. The authoritative verdict is still the
`[g3:done] state=<WARNING|ERROR>` marker written by `markTerminal`.

### Tier 1 files

| File | Change |
| --- | --- |
| `src/g3lib/plugin.go` | Parse + enrich on the failure path; collapse to a single `error` return (keep exit error over a later parse error); inject the nil placeholder unconditionally for any empty parse. Signature unchanged (`[]G3Data, error`). The parse-on-error output is **consumed only by the worker** — all other call sites (`g3.go` ×5, `g3api.go:497`, `g3scanner.go:1099`) already do `if err != nil { return }` and discard the array, so they are unaffected. |
| `src/g3worker/g3worker.go` | Partition sanitized output into actionable/nils; in the mixed case log + drop nils, in the empty case collapse to one placeholder; **always `SaveData` + `SendResponse` for non-canceled** (seeds cache, feeds fuel); compute `hardBreach`/`softSignal`; replace the DONE-only tail with the hard-ERROR / no-fuel-ERROR / WARNING / DONE state fork; mirror rejects + verdict into `SaveLogLine` as `[g3:warn]` lines tagged with the tool name. |

### Tier 1 verification

`go build ./...` in `src/g3lib` and `src/g3worker`, then a cross-binary
build sweep. (Tests and runtime verification are user-owned.)

---

## Tier 2 — Terminal-state plumbing (outline)

Make `"WARNING"` a first-class terminal state everywhere a state string
is matched, so it is treated as a results-producing terminal outcome
(like DONE) rather than falling through to an error/`default` branch.

- **`src/g3api/g3api.go`** — the `/scan/task/artifacts` switches
  ([:949](../../../src/g3api/g3api.go#L949),
  [:977](../../../src/g3api/g3api.go#L977)) must add `"WARNING"` to the
  terminal cases alongside `DONE`/`ERROR`/`CANCELED`/`FINISHED`, or a
  WARNING task hits `default:` → 500.
- **`src/g3lib/sql.go`** — confirm `ReconstructTaskStateFromLogs` /
  `ReconstructTaskStatesFromLogs` pass `state=WARNING` through verbatim
  (they read the marker's `state=` field, so this should be free; verify
  no whitelist filters it).
- **No scan-level rollup work.** Confirmed: scan status is decoupled
  from worker-task states. `G3Response`
  ([task.go:108](../../../src/g3lib/task.go#L108)) carries only data IDs,
  no state field — the scanner never sees a task's terminal state. Scan
  status is orchestration-driven: `SendScanFailed` fires only on
  scanner-side failures (missing plugin, build/dispatch error, bad mode),
  and `SendScanCompleted` (→ FINISHED) fires on pipeline completion
  regardless of task outcomes. So WARNING needs no scan-level handling —
  there is no aggregation that could flip the scan. (Cheap one-time check
  during Tier 2: confirm g3api's scan-status handling likewise derives
  from the `Send*` messages, not from task states.)

## Tier 3 — TUI surfacing (outline)

The user-facing payoff: spot tasks needing log attention at a glance.

- **`src/g3tui/internal/ui/scandetail.go`** — add a `"WARNING"` case to
  the task-state switches
  ([:541](../../../src/g3tui/internal/ui/scandetail.go#L541),
  [:576-584](../../../src/g3tui/internal/ui/scandetail.go#L576),
  [:641-649](../../../src/g3tui/internal/ui/scandetail.go#L641)) with a
  distinct glyph/color (e.g. amber `⚠`), positioned between DONE and
  ERROR in severity.
- **`src/g3tui/internal/ui/styles.go`** — a WARNING style token.
- Consider a filter/affordance to jump to WARNING tasks' logs (the
  `[g3:warn]` lines from Tier 1c make this greppable). Polish; can defer.

## Tier 4 — Per-wrapper exit-code normalization (outline)

A wrapper has exactly **two binary levers and chooses neither the
terminal state nor WARNING-vs-ERROR** — the worker derives those (Tier 1):

1. **Exit code** — `0` (nothing to flag) or non-zero (a soft signal worth
   the user's attention). This is the only active decision a wrapper makes
   for this feature.
2. **Whether it emits actionable data** — normally just whatever the
   importer yields; a wrapper suppresses output only when it deliberately
   wants a hard stop.

The worker turns the pair into a state: `0` → DONE (data or not);
`non-zero + data` → WARNING; `non-zero + no data` → ERROR. So WARNING vs
ERROR is never a wrapper decision — it falls out of whether any data
survived. "Force a hard stop" is the deliberate `non-zero + suppress
output` combo, and nothing else needs per-wrapper state logic.

Without this tier, no plugin produces WARNING (the always-`exit 0`
wrappers) or it fires noisily (whatever the tool's raw codes happen to
mean). Per-plugin authoring; audit all wrappers for the **exit-code
decision only**:

- **Shell, piped** (`nmap`, `subfinder`, `wafw00f`): the exit code is
  currently `tee`'s, masking the tool; recover the tool's real status
  (`PIPESTATUS` / `set -o pipefail` or restructure) before deciding 0 vs
  non-zero. All three exit `0` even on negative results (host down / zero
  subdomains / no WAF), so any recovered non-zero is a genuine failure.
- **Shell, non-piped** (`dig`): `set -e` already propagates, and dig's
  codes are clean (0 = answer incl. NXDOMAIN; 1/8/9/10 = real failure,
  9 = no reply), so it is already correct — leave as-is (optionally make
  the rule explicit rather than `set -e`-implicit).
- **`nikto` — split into its own plan, NOT in this Tier 4.** Its exit
  code was a 2020–2024 regression (exit 1 on any findings) fixed only in
  nikto 2.6.0 (2026-02). Relying on it requires pinning ≥2.6.0, which the
  current `apk add nikto` (floating, likely 2.5.0) doesn't do — so the
  nikto work is a Dockerfile refactor (install from the 2.6.0 source tag,
  since Alpine's image lags/maintained inconsistently) **plus** importer
  compatibility (2.6.0's release notes flag JSON/XML report-format changes;
  our wrapper uses CSV, so confirm CSV is unaffected or adapt) **plus** the
  exit-code mapping. Too large for this mechanical tier; tracked as a
  separate plan (see Future work).
- **Python** (`testssl`, `hydra`): stop forcing `exit 0`; capture each
  invocation's `returncode` and fold the per-target loop as "any non-zero
  → non-zero", while emitting whatever results the importer yields. Both
  tools' exit codes are already well-behaved (0 = clean, non-zero = real
  failure), so no per-code threshold is needed — just propagate. The
  wrapper does not aggregate states; WARNING vs ERROR falls out of whether
  any data survived. Note the motivating testssl case was a red herring:
  testssl exits 0 even when a sub-test like the CAA-DNS probe fails (the
  original ERROR was a manifest-generation bug, not the exit code), so it
  lands as DONE — exactly right. hydra likewise returns 0 whether or not
  credentials were found.
- **debug plugins** (`error`, `force-exec`, `passthrough`): `error`
  already exits non-zero with no output → ERROR; the others need no
  change. Useful as manual exercises for the new states.

The audit output is a per-wrapper table of **"native condition → {exit 0,
exit non-zero}"** (plus, for the rare hard-stop case, whether to suppress
output) — not a state table. That becomes the Tier 4 implementation plan.

## Configuration and deployment

No new environment variables, no schema changes, no new MQTT topics, no
new Docker images, no plugin-metadata (`.g3p`) changes. Tiers 1-3 are
internal code; Tier 4 edits wrapper scripts inside existing plugin
images (rebuild affected plugin images).

## Rollout

Tier 1 is shippable alone (worker emits WARNING; it reaches Redis/SQL but
renders like an unknown terminal state until Tier 2/3). Recommended order:
Tier 1 → Tier 2 (so the artifacts endpoint doesn't 500 on a WARNING task)
→ Tier 3 (visibility) → Tier 4 (plugins actually start producing the
signal, one wrapper at a time). Tiers 1+2 should land together so no
endpoint can encounter an unhandled WARNING state.

## Future work (out of scope)

- **Nikto exit-code adoption (own plan).** Three coupled changes: (1)
  refactor `plugins/attack/nikto/Dockerfile` to install nikto from the
  2.6.0 source tag (the version where the exit-1-on-findings regression
  is fixed) instead of the floating `apk add nikto`; (2) verify/adapt the
  importer for nikto 2.6.0's report format (release notes flag JSON/XML
  changes — our wrapper uses CSV, confirm it still parses); (3) then map
  the now-reliable exit code (0 → benign, non-zero → real error) and drop
  the `set -e`-aborts-clean-scans behavior. Larger than this tier's
  mechanical scope; deliberately carved out of Tier 4.
- **Scan-level WARNING aggregation / indicator.** Would require giving
  the scanner visibility into per-task states it currently never receives
  (a new field on `G3Response` or a separate aggregation pass). Not
  needed now; revisit if a use case appears.
- **Operator-tunable WARNING strictness.** Deliberately deferred, not
  speculative-only: strictness is encoded in each wrapper's exit-code
  mapping (Tier 4), so there is no single framework point to tune. A knob
  would be per-wrapper logic interpreting a forwarded env var — real
  quirks to iron out, not a one-liner. Plan it separately if it earns its
  keep.

Explicitly **not** pursuing: importer-level per-target sentinels. From
the pipeline's perspective every task is a single target; multi-target
detail stays in the logs. The pipeline never needs to know.
