# g3client

Python client library for [`g3api`](../../src/g3api) — the Golismero3 pentesting
framework. Golismero-only; no LLM concerns.

The library is layered in three tiers, each built strictly on the one below:

| Tier | Module | What it is |
|------|--------|------------|
| 1 | `g3client.api` | Thin, resource-grouped wrappers over every `g3api` endpoint. One method per call, no hidden behaviour. |
| 2 | `g3client.scanner` | High-level helper for **orchestrated** scans (the `g3cli`/`g3tui` flow): `Scanner.scan()` launches, waits, and returns a report. |
| 3 | `g3client.manager` | High-level helper for **managed** scans: `Manager` tracks scan/task IDs, launches tools, and `run()` drives one tool to completion. |

Tiers 2 and 3 use `g3client.api` exclusively — they never touch HTTP directly. See
[docs/design/g3client-architecture.md](../../docs/design/g3client-architecture.md) for the
language-agnostic design (and the blueprint for future ports such as a Go client).

> The `api` tier's method **names** track the upcoming
> [REST migration](../../docs/future/http-routing-and-rest-migration.md) while their
> **bodies** call today's endpoints, so that migration becomes a per-method edit with no
> change to your code. Every such site is tagged `# REST-MIGRATION:` in the source.

## Requirements

- Python ≥ 3.10
- [`requests`](https://pypi.org/project/requests/) (the only dependency)

## Install

```bash
cd clients/python
pip install -e .
```

## Configuration

Construct a client with explicit credentials, or let it fall back to environment
variables:

| Argument | Environment fallback | Meaning |
|----------|----------------------|---------|
| `base_url` | `G3_API_BASEURL` | Base URL of the g3api server, e.g. `https://g3.internal/api` |
| `token` | `G3_API_TOKEN` | Bearer token sent as `Authorization: Bearer <token>` |
| `artifacts_root` | `G3_ARTIFACTS_ROOT` | Local directory for downloaded artifacts (defaults to `<tempdir>/g3client`) |

```python
from g3client import ApiClient, Scanner, Manager

# Explicit:
api = ApiClient("https://g3.internal/api", "TOKEN")

# Or from the environment (G3_API_BASEURL / G3_API_TOKEN):
scanner = Scanner.from_credentials()
manager = Manager.from_credentials()
```

## Quick start

A runnable version of the examples below lives in
[`examples/quickstart.py`](examples/quickstart.py).

### Tier 2 — orchestrated scan (`Scanner`)

Launch a scan, stream progress, and get a report back. `report` names the reporter
plugin and an optional preset (`"tool"`, `"tool:preset"`, or a `(tool, preset)` tuple) —
the report *format* is just a reporter preset.

```python
from g3client import Scanner

scanner = Scanner.from_credentials()  # reads G3_API_BASEURL / G3_API_TOKEN

report = scanner.scan(
    targets=["https://scanme.example.com"],
    pipeline=["nmap", "nikto | testssl"],   # tools, or piped chains
    mode="parallel",                          # or "sequential"
    report="magenta:json",                    # reporter tool[:preset], or None
    on_progress=lambda p: print(f"  {p.status} {p.progress or 0}% {p.message}"),
    on_log=lambda lines: print(f"  +{len(lines)} log line(s)"),
    timeout=1800,
)

print("scan:", report.scanid, "->", report.status)
if report.report_bytes is not None:
    print(report.report_bytes.decode("utf-8", "replace"))
elif report.report_path is not None:
    print("report saved under:", report.report_path)
```

`scan()` raises `TaskTimeout` on deadline, `TaskFailed` on a terminal `ERROR` scan, and
`TaskCancelled` if the scan is canceled. Pass a raw `script="..."` instead of
`targets`/`pipeline` to drive the scan with a hand-written g3 script.

### Tier 3 — managed scan (`Manager`)

Own a managed scan, add a target, and run a single tool to completion — downloading its
artifacts and collecting the G3Data it produced.

```python
from g3client import Manager

mgr = Manager.from_credentials()             # creates a fresh managed scan
try:
    objs = mgr.add_targets(["scanme.example.com"])
    dataid = objs[0]["_id"]                   # the id the server assigned the target

    outcome = mgr.run(
        "nmap",
        dataid,
        on_status=lambda s: print("  scan:", s.scan_status),
        timeout=1800,
    )

    print("state:", outcome.state)            # worst-wins: ERROR > WARNING > DONE
    print("produced:", len(outcome.data), "G3Data object(s)")
    print("artifacts:", outcome.artifacts_dir)
    if outcome.error_msg:
        print("errors:", outcome.error_msg)
finally:
    mgr.dispose()                             # delete the managed scan
```

To re-attach to an existing managed scan (e.g. after a restart), pass its id:
`Manager.from_credentials(scanid="...")`. For finer control, `launch()` dispatches a tool
asynchronously and returns task IDs, `poll()` / `wait()` track status, `fetch_artifacts()`
downloads a bundle, and `results()` returns a task's G3Data.

### Tier 1 — direct API access (`ApiClient`)

When you want raw, one-call-per-method access (or are building your own orchestration):

```python
from g3client import ApiClient

api = ApiClient.from_credentials() if False else ApiClient("https://g3.internal/api", "TOKEN")

for plugin in api.plugins.list():
    print(plugin.name, "-", plugin.description)

scan_id = api.scans.create_managed()
data_ids = api.scans.targets.add(scan_id, ["scanme.example.com"])
task_ids = api.scans.tasks.dispatch(scan_id, kind="tool", tool="nmap", dataid=data_ids[0])
status = api.scans.tasks.status(scan_id)      # -> ScanTasksStatus
api.scans.delete(scan_id)
```

Resource groups: `api.scans` (+ `.targets`, `.data`, `.tasks`, `.imports`, `.logs`),
`api.plugins`, `api.files`, `api.config`.

## Errors

All exceptions derive from `g3client.ClientError`:

| Exception | Raised when |
|-----------|-------------|
| `ApiError(status_code, message)` | The server returned an error envelope or a non-2xx status. |
| `TaskTimeout(task_ids, last_states)` | Polling hit its deadline before tasks went terminal. |
| `TaskCancelled(task_ids)` | A task (or scan) reached `CANCELED`. |
| `TaskFailed(task_ids, error_msg)` | A task (or scan) reached a terminal `ERROR`. |
| `ScanGone(scanid)` | The scan vanished mid-poll (e.g. deleted server-side). |
| `TaskGone(scanid, taskid)` | A tracked task vanished mid-poll (e.g. its scan was deleted). |

## Notes

- **Synchronous** by design, with all network I/O behind a single `Transport` seam and all
  waiting behind one injectable-clock `poll_until` helper — so an async variant can be
  added later without changing the resource or orchestration surfaces.
- **Artifacts** download as a single file when a task emits one, or as a zip (extracted
  with zip-slip protection) when it emits several; downloads stream to a temp file and are
  renamed atomically.

## License

GPL-3.0-or-later.
