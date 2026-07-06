# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Golismero3 is an open-source pentesting framework that orchestrates security tools (nmap, nikto, hydra, testssl, etc.) via a distributed microservices architecture. It supports both local CLI usage (Unix pipes) and remote server mode (HTTP API + WebSocket).

## Build Commands

```bash
make all        # Build Go binaries, Docker image, plugins, and Python deps
make bin        # Build only Go binaries to /bin/
make docker     # Build g3 Docker image
make plugins    # Build all plugin Docker images
make install    # Install symlinks to /usr/bin/
make clean      # Clean compiled binaries
make misc       # Install Python dependencies from misc/requirements.txt
```

To build a single binary (from `src/`):
```bash
cd src && make ../bin/g3        # or g3api, g3cli, g3config, g3scanner, g3worker
```

Each binary lives in its own Go module under `src/<name>/` with a `go.mod` that uses `replace` directives to reference the shared modules (`g3lib`, `g3`) locally. The one naming exception is the local CLI: its source module is `src/g3bin/` (it still builds the `g3`/`g3.exe` binary), because the plain `g3` name now belongs to the shared client/server module.

## Running

**Local mode** (Unix pipe style):
```bash
g3 target 192.168.1.1 | g3 run nmap | g3 report -o report.md
```

**Server mode** (Docker Compose demo stack):
```bash
docker compose up          # Starts mongo, mariadb, mosquitto, redis, nginx + app services
docker compose up -d       # Detached
```

Configuration is driven by `.env` (multiplel documented environment variables covering infrastructure details, API keys, and internal API, scanner, and worker settings).

## Architecture

### Binaries

| Binary | Role |
|--------|------|
| `g3` | Local CLI — accepts scan commands, pipes JSON data through tools |
| `g3api` | HTTP/WebSocket server — manages scan lifecycle, exposes REST API on :8080 |
| `g3cli` | Client for g3api — remote scan operations |
| `g3tui` | Fully interactive terminal UI for remote scans |
| `g3config` | Discovers and registers plugins into `config/` |
| `g3scanner` | Orchestrates scan pipelines; monitors pending tasks across workers |
| `g3worker` | Executes individual tools inside Docker containers; reads tasks from MQTT |

### Data Flow

```
User (CLI / HTTP)
  → g3api → MongoDB (scan storage)
           → MQTT → g3scanner (workflow orchestration)
                      → g3worker (runs tool in Docker container)
                           → MariaDB (execution logs)
```

### Shared Libraries

- **`src/g3/`** — Shared data model and helpers used by both client and server (formerly `g3model`). This is the home for code common to the two sides, and is expected to grow as client-side logic currently duplicated in the clients (and in `g3lib`) migrates here.
  - **`src/g3/log/`** — Logging wrapper imported by all binaries (formerly the standalone `g3log` module, now a subpackage of `g3`). Imported under the `log` alias, so call sites read `log.SetLogLevel`, `log.LogLevel`, etc.
- **`src/g3lib/`** — Core types and logic: `common.go` (G3Data, G3Plugin), `task.go` (G3Task, CancelTracker), `api.go` (WebSocket), `report.go`, `script.go`, `datastore.go`, `sql.go`, `jwt.go`. Trending toward a **server-only** module as shared client/server code moves into `g3`.

### Plugin System

Plugins live under `plugins/*/`. Each plugin directory contains:
- `<name>.g3p` — Jsonnet plugin definition (commands, conditions, fingerprints, importers, reporters). Jsonnet is a JSON superset (comments, trailing commas, `|||` multiline text blocks, plus variables/imports/std library if ever needed); `g3config` evaluates each file to JSON.
- `Dockerfile` — Containerized tool
- `g3i.py` — Importer: parses raw tool output → G3Data JSON
- `g3r.py` — Reporter: synthesizes findings into a downloadable report (reporter plugins only, e.g. Magenta)
- `g3p.sh` — Container entrypoint

`g3config` scans plugin directories and writes a registry to `config/`.

Tool plugins emit raw findings (via commands/importers) but do **not** synthesize `_type:issue` objects — issue generation is exclusively the job of the reporter plugin (Magenta), which reads the accumulated scan data and produces the final vulnerability report. There is no separate merger phase; the scanner saves scan metadata and dispatches the reporter directly at the end of a scan.

Plugin Docker images default to `ghcr.io/golismero/<plugin-name>` when a `.g3p` omits the `image:` field (see `src/g3config/g3config.go`). A `.g3p` can override with any image reference — local tag, third-party registry, fork namespace — so private deployments and forks don't need to patch the framework. Multiple plugins can also share one image (the three `nmap.g3p` variants all point to `ghcr.io/golismero/nmap`).

### Key Technologies

- **Go 1.25**, Kong (CLI), gorilla/websocket, golang-jwt, go-playground/validator, go-chart
- **Python 3** for plugin importer/reporter scripts
- **MongoDB** — scan data; **MariaDB** — execution logs; **MQTT (Mosquitto)** — task queue
- **Docker** — plugin isolation (worker mounts Docker socket to launch containers)
