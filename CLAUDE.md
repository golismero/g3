# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Golismero3 is an open-source pentesting framework that orchestrates security tools (nmap, nikto, hydra, testssl, etc.) via a distributed microservices architecture. It supports both local CLI usage (Unix pipes) and remote server mode (HTTP API + WebSocket).

## Build Commands

```bash
make all        # Build Go binaries, Docker image, plugins, and Python deps
make bin        # Build only Go binaries to /bin/
make docker     # Build golismero3/g3bin Docker image
make plugins    # Build all plugin Docker images
make install    # Install symlinks to /usr/bin/ (g3, g3api, g3cli, g3config, g3scanner, g3worker)
make clean      # Clean compiled binaries
make misc       # Install Python dependencies from misc/requirements.txt
```

To build a single binary (from `src/`):
```bash
cd src && make ../bin/g3        # or g3api, g3cli, g3config, g3scanner, g3worker
```

Each binary lives in its own Go module under `src/<name>/` with a `go.mod` that uses `replace` directives to reference `g3lib` and `g3log` locally.

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

Configuration is driven by `.env` (77 documented environment variables covering MongoDB, MariaDB, MQTT, Redis, Vulners, VirusTotal, API, scanner, and worker settings).

## Architecture

### Binaries

| Binary | Role |
|--------|------|
| `g3` | Local CLI — accepts scan commands, pipes JSON data through tools |
| `g3api` | HTTP/WebSocket server — manages scan lifecycle, exposes REST API on :8080 |
| `g3cli` | Client for g3api — remote scan operations |
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
                           → Redis (report cache)
```

### Shared Libraries

- **`src/g3lib/`** — Core types and logic: `common.go` (G3Data, G3Plugin), `task.go` (G3Task, CancelTracker), `api.go` (WebSocket), `report.go`, `script.go`, `datastore.go`, `sql.go`, `jwt.go`
- **`src/g3log/`** — Logging wrapper used by all binaries

### Plugin System

Plugins live under `plugins/*/`. Each plugin directory contains:
- `<name>.g3p` — JSON5 plugin definition (commands, conditions, fingerprints, importers, mergers)
- `Dockerfile` — Containerized tool
- `g3i.py` — Importer: parses raw tool output → G3Data JSON
- `g3m.py` — Merger: deduplicates results across runs
- `g3p.sh` — Container entrypoint

`g3config` scans plugin directories and writes a registry to `config/`.

### Key Technologies

- **Go 1.25**, Kong (CLI), gorilla/websocket, golang-jwt, go-playground/validator, go-chart
- **Python 3** for plugin importer/merger scripts
- **MongoDB** — scan data; **MariaDB** — execution logs; **Redis** — report cache; **MQTT (Mosquitto)** — task queue
- **Docker** — plugin isolation (worker mounts Docker socket to launch containers)
