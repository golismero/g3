# graphql-cop plugin — design

Date: 2026-06-29
Status: approved for implementation

## Goal

Add a Golismero3 attack plugin that runs [graphql-cop](https://github.com/dolevf/graphql-cop)
(v1.16) against any URL target and collects its findings as **artifacts only**. The
plugin emits no pipeline fuel and parses no issues — it is a black-box artifact
generator, modelled on the existing `nikto` plugin.

Out of scope (YAGNI): an importer (`g3i.py`) that turns graphql-cop results into
G3Data issues, a merger (`g3m.py`), or any per-test issue emission. The plugin
only produces the raw JSON report plus a status log.

## Why a wrapper (and why subprocess, not import)

graphql-cop's `-o json` writes the JSON array to **stdout**, but lines 110/113 of
`graphql-cop.py` also print human status text ("…does not seem to be running
GraphQL", "Running a forced scan…") to the **same** stdout stream, unconditionally
— there is no quiet/JSON-only flag, and `-o` cannot target a file. So raw stdout is
a mix of status text and one JSON line (see `samples/graphqlcop.error.json`). This
is unchanged in the current 1.16 release.

We run the real tool as a **subprocess** rather than importing its libraries.
graphql-cop exposes its tests (`lib.tests`) but **not** its driver loop — endpoint
list, path iteration, `is_graphql` gating, force handling, result sorting are all
top-level script code in a hyphen-named file (not importable). Importing would mean
owning a fork of that driver and re-auditing it on every upstream bump, and would
break the framework's "wrap the tool as a black box" pattern (nikto, hydra). The
only thing subprocess costs us is splitting one stdout stream, which a single
`json.loads` check solves robustly.

## Components

```
plugins/attack/graphqlcop/
  graphqlcop.g3p   # Jsonnet plugin definition (condition, command, returns)
  Dockerfile       # python:3-alpine + graphql-cop 1.16 + the g3p.py wrapper
  g3p.py           # entrypoint wrapper: run tool, split output, emit artifacts
  Makefile         # build/pull ghcr.io/golismero/graphqlcop
```

### graphqlcop.g3p

Single command (graphql-cop takes the full scheme-qualified URL via `-t`, so no
http/https split is needed the way nikto needs `-ssl`):

- `condition`: target has a `.url` whose `.scheme` is `http` or `https`.
- `fingerprint`: `["graphqlcop {{.url}}"]` — dedup key.
- `command`: `["-t", "{{.url}}"]` — per-target args passed to the entrypoint as `$@`.
- `returns: "nil"` — artifact-only, no fuel for the pipeline.
- `image: "ghcr.io/golismero/graphqlcop"` — explicit, matching nikto.

The constant `-o json` is supplied by the wrapper, not the `.g3p`, so the tool
always emits JSON regardless of how it is invoked.

### g3p.py (entrypoint)

Plain `python3` (guaranteed present in the base image; no `jq` dependency). Logic:

1. `os.makedirs("/artifacts", exist_ok=True)`.
2. `subprocess.run(["python3", "/app/graphql-cop.py", "-o", "json", *argv[1:]],
   cwd="/app", capture_output=True, text=True)`. (`cwd=/app` because the script
   imports `config`, `version`, `lib` relative to its directory.)
3. **Split stdout by content, not position:** for each line, the JSON report is the
   first line that starts with `[` and parses via `json.loads` into a `list`;
   everything else is a status line. Positional `tail -n 1` is rejected because on
   a crash (exit 1) graphql-cop never prints the JSON line, so the last line would
   be status text mislabelled as JSON.
4. Write artifacts:
   - `/artifacts/graphqlcop.json` ← the parsed JSON array (`[]` if none found).
   - `/artifacts/graphqlcop.txt` ← the status lines (may be empty).
5. Echo the status lines **and** the tool's own stderr to our stderr, so Golismero
   captures them as log lines.
6. Emit the worker's artifact claim on stdout as a JSON **array** (the worker
   unmarshals stdout into `[]g3lib.G3Data`):
   `[{"_artifacts": ["graphqlcop.json", "graphqlcop.txt"]}]`.
7. `sys.exit(proc.returncode)` — propagate graphql-cop's own exit code.

### Exit-code semantics (from source audit of 1.16)

- `0` = ran to completion. This is the common case **even when** the target is
  unreachable, no path is GraphQL, or GraphQL was found with no issues (all network
  errors are swallowed in `lib/utils.py`). "Not GraphQL" is therefore **not** a
  failure — it yields `[]` + status text, exit 0.
- `1` = genuine failure only: a usage error (no `-t` / missing scheme — both avoided
  because the wrapper always passes a scheme-qualified `-t <url>`), or an unhandled
  exception mid-scan (traceback to stderr).

The wrapper preserves this code, so a non-zero status is a true failure the worker
should surface. The exit code is captured from the subprocess directly, never
through a pipe, so it cannot be masked.

### Dockerfile

Fixes the skeleton (`apk install git` is invalid; entrypoint was empty; Makefile
named `testssl`):

- `FROM python:3-alpine`, `WORKDIR /app`.
- `ARG BUILD_VERSION=1.16`, `ARG GRAPHQLCOP_URL=https://github.com/dolevf/graphql-cop.git`.
- Install git as a virtual build dep, `git clone --depth 1 --branch ${BUILD_VERSION}`
  into `/app`, `pip install --no-cache-dir -r requirements.txt`, remove `.git` and
  the git build dep.
- `COPY --chmod=0755 g3p.py /usr/bin/g3p`, `ENTRYPOINT ["/usr/bin/g3p"]`.

## Data flow

```
worker → docker run …/graphqlcop -t <url>
  └ /usr/bin/g3p (g3p.py)
      └ python3 /app/graphql-cop.py -o json -t <url>   (cwd=/app)
          stdout: status lines + one JSON array line
      split → /artifacts/graphqlcop.json  (pure JSON)
            → /artifacts/graphqlcop.txt   (status lines)
            → stderr: status lines + tool stderr  (Golismero logs)
      stdout: [{"_artifacts":["graphqlcop.json","graphqlcop.txt"]}]
      exit:   graphql-cop's own return code
```

## Testing / validation

Without Docker available in-repo, validate the moving parts directly:

1. `jsonnet`-evaluate `graphqlcop.g3p` to confirm it produces valid JSON (or rely
   on `g3config`'s evaluator).
2. Lint `g3p.py` with `python3 -m py_compile`.
3. Exercise the stdout-splitting logic against the four `samples/graphqlcop.*.json`
   fixtures (including `error.json`, the mixed text+`[]` case) and assert that the
   JSON side parses and the status side captures the human lines.
```
