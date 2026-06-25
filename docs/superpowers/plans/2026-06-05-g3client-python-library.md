# g3client Python Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a layered Python client library (`g3client`) for `g3api` with a thin resource-grouped transport tier (`api`) and two high-level orchestration tiers (`scanner`, `manager`), modeled on the future REST shape so the eventual API migration is a per-method edit.

**Architecture:** A single `Transport` seam speaks HTTP; `g3client.api` exposes resource-grouped one-line wrappers over it; `g3client.scanner` (orchestrated scans) and `g3client.manager` (managed scans) are pure orchestration recipes built only on `api` and a shared `poll_until` helper. Sync now, with the `Transport`/`poll_until` seams isolated for a later async variant.

**Tech Stack:** Python ≥3.10, `requests`, `dataclasses`, `setuptools`. Lint: `ruff` (correctness only). No third-party async, no LLM dependencies.

**Spec:** [docs/superpowers/specs/2026-06-05-g3client-python-library-design.md](../specs/2026-06-05-g3client-python-library-design.md)

---

## Execution conventions for this plan (override skill defaults)

These reflect durable project conventions and **replace** the writing-plans skill's TDD/commit template:

- **Tests are user-owned.** Do **not** write tests or run binaries/live servers. Per-task verification is `ruff check <file>` plus, at tier boundaries, a `python -c "import g3client..."` smoke check. The design (injected clock in `poll_until`, single `Transport` seam) keeps everything unit-testable for the user later.
- **Git is user-owned.** Do **not** run `git add`/`commit`/`push`. Each tier ends with a **Tier checkpoint** noting that the user commits the tier as one batch. Push through tasks within a tier without stopping for per-task commits.
- **No formatting enforcement.** Use `ruff check` (correctness lints) only — never `ruff format`/`black`/import sorters.
- **Tiered detail.** Tier 0 and Tier 1 are fully detailed below. Tiers 2–3 and the architecture doc are outlined; **detail and approve each with the user before executing it.**

---

## File Structure

```
sdk/python/
├── pyproject.toml                   # package metadata; dep: requests
├── README.md                        # usage overview
└── g3client/
    ├── __init__.py                  # version + top-level re-exports
    ├── _transport.py                # Transport: the only HTTP code (async seam)
    ├── _polling.py                  # poll_until() reusable loop
    ├── errors.py                    # ClientError hierarchy
    ├── types.py                     # frozen value types + terminal-state sets
    ├── api/                         # Tier 1 — resource-grouped wrappers
    │   ├── __init__.py              # ApiClient composition root + design-rule docstring
    │   ├── scans.py                 # ScansResource + Targets/Data/Tasks/Imports/Logs
    │   ├── plugins.py               # PluginsResource
    │   ├── files.py                 # FilesResource
    │   └── config.py                # ConfigResource
    ├── scanner/                     # Tier 2 — orchestrated scans (OUTLINED)
    │   └── __init__.py
    └── manager/                     # Tier 3 — managed scans (OUTLINED)
        └── __init__.py
```

Responsibilities: `_transport.py` owns all networking; `api/*` owns endpoint mapping (one resource per file region); `scanner`/`manager` own flow only. Files split by responsibility so each stays small and reviewable.

---

# TIER 0 — Foundation (DETAILED)

## Task 0.1: Package scaffold

**Files:**
- Create: `sdk/python/pyproject.toml`
- Create: `sdk/python/README.md`
- Create: `sdk/python/g3client/__init__.py`

- [ ] **Step 1: Create `sdk/python/pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "g3client"
version = "0.1.0"
description = "Python client library for the Golismero3 (g3api) pentesting framework."
readme = "README.md"
requires-python = ">=3.10"
license = { text = "GPL-3.0-or-later" }
authors = [{ name = "Golismero" }]
dependencies = ["requests>=2.28"]

[project.urls]
Homepage = "https://github.com/golismero"

[tool.setuptools.packages.find]
include = ["g3client", "g3client.*"]
```

- [ ] **Step 2: Create `sdk/python/README.md`**

```markdown
# g3client

Python client library for `g3api` (Golismero3). Golismero-only; no LLM concerns.

## Tiers

- `g3client.api` — thin, resource-grouped wrappers over every g3api endpoint.
- `g3client.scanner` — high-level helper for orchestrated scans (`scan()`).
- `g3client.manager` — high-level helper for managed scans (`Manager.run()`).

## Configuration

Pass `base_url`/`token` explicitly, or set `G3_API_BASEURL` / `G3_API_TOKEN`
(and optionally `G3_ARTIFACTS_ROOT`).

```python
from g3client import ApiClient, Scanner, Manager

api = ApiClient("https://g3.internal/api", "TOKEN")
```

See `docs/design/g3client-architecture.md` for the language-agnostic design.
```

- [ ] **Step 3: Create `sdk/python/g3client/__init__.py`**

```python
"""g3client — Python client library for g3api (Golismero3)."""
from __future__ import annotations

__version__ = "0.1.0"

from .errors import (
    ApiError,
    ClientError,
    TaskCancelled,
    TaskFailed,
    TaskTimeout,
)

# Tier re-exports are added as each tier lands:
#   from .api import ApiClient
#   from .scanner import Scanner
#   from .manager import Manager

__all__ = [
    "__version__",
    "ClientError",
    "ApiError",
    "TaskTimeout",
    "TaskCancelled",
    "TaskFailed",
]
```

- [ ] **Step 4: Lint**

Run: `ruff check sdk/python/g3client/__init__.py`
Expected: passes (errors module created in Task 0.2; if run before, expect an unresolved-import note — proceed, the tier smoke check covers it).

## Task 0.2: Error hierarchy

**Files:**
- Create: `sdk/python/g3client/errors.py`

- [ ] **Step 1: Create `errors.py`**

```python
"""Exception hierarchy for g3client. Every error derives from ClientError."""
from __future__ import annotations


class ClientError(Exception):
    """Base class for every g3client error."""


class ApiError(ClientError):
    """The server returned an error envelope or a non-2xx HTTP status."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"[{status_code}] {message}")
        self.status_code = status_code
        self.message = message


class TaskTimeout(ClientError):
    """Polling reached its deadline before all tasks became terminal."""

    def __init__(self, task_ids: tuple[str, ...], last_states: dict[str, str]) -> None:
        super().__init__("timed out waiting for tasks: " + ", ".join(task_ids))
        self.task_ids = task_ids
        self.last_states = last_states


class TaskCancelled(ClientError):
    """One or more tasks reached the CANCELED state."""

    def __init__(self, task_ids: tuple[str, ...]) -> None:
        super().__init__("tasks canceled: " + ", ".join(task_ids))
        self.task_ids = task_ids


class TaskFailed(ClientError):
    """One or more tasks reached a terminal ERROR state."""

    def __init__(self, task_ids: tuple[str, ...], error_msg: str) -> None:
        super().__init__("tasks failed: " + ", ".join(task_ids) + ": " + error_msg)
        self.task_ids = task_ids
        self.error_msg = error_msg
```

- [ ] **Step 2: Lint**

Run: `ruff check sdk/python/g3client/errors.py`
Expected: PASS.

## Task 0.3: Value types

**Files:**
- Create: `sdk/python/g3client/types.py`

- [ ] **Step 1: Create `types.py`**

```python
"""Immutable value types returned across the g3client surface.

Each type keeps the original server dict in `raw` for forward-compatibility:
new server fields are reachable without a library change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# A task in one of these states will not change further.
TASK_TERMINAL_STATES = frozenset({"DONE", "WARNING", "ERROR", "CANCELED"})

# A scan in one of these statuses will not change further.
SCAN_TERMINAL_STATES = frozenset({"FINISHED", "ERROR", "CANCELED"})


@dataclass(frozen=True)
class ScanProgress:
    scanid: str
    status: str
    progress: Optional[int]
    message: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, d: dict[str, Any]) -> "ScanProgress":
        return cls(
            scanid=d.get("scanid", ""),
            status=d.get("status", "UNKNOWN"),
            progress=d.get("progress"),
            message=d.get("message", ""),
            raw=d,
        )

    @property
    def is_terminal(self) -> bool:
        return self.status in SCAN_TERMINAL_STATES


@dataclass(frozen=True)
class TaskStatus:
    task_id: str
    tool: str
    worker: str
    state: str
    dispatched_at: Optional[int]
    started_at: Optional[int]
    completed_at: Optional[int]
    error_msg: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, d: dict[str, Any]) -> "TaskStatus":
        return cls(
            task_id=d.get("taskid", ""),
            tool=d.get("tool", ""),
            worker=d.get("worker", ""),
            state=d.get("state", "UNKNOWN"),
            dispatched_at=d.get("dispatch_ts"),
            started_at=d.get("start_ts"),
            completed_at=d.get("complete_ts"),
            error_msg=d.get("error_msg", ""),
            raw=d,
        )

    @property
    def is_terminal(self) -> bool:
        return self.state in TASK_TERMINAL_STATES


@dataclass(frozen=True)
class ScanTasksStatus:
    scan_status: str
    tasks: tuple[TaskStatus, ...]
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, d: dict[str, Any]) -> "ScanTasksStatus":
        return cls(
            scan_status=d.get("scan_status", "UNKNOWN"),
            tasks=tuple(TaskStatus.from_raw(t) for t in d.get("tasks", []) or []),
            raw=d,
        )


@dataclass(frozen=True)
class PluginInfo:
    name: str
    url: str
    description: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, d: dict[str, Any]) -> "PluginInfo":
        return cls(
            name=d.get("name", ""),
            url=d.get("url", ""),
            description=d.get("description", ""),
            raw=d,
        )


@dataclass(frozen=True)
class PluginContract:
    name: str
    summary: str
    accepts: tuple[str, ...]
    produces: tuple[str, ...]
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, d: dict[str, Any]) -> "PluginContract":
        return cls(
            name=d.get("name", ""),
            summary=d.get("summary", ""),
            accepts=tuple(d.get("accepts", ()) or ()),
            produces=tuple(d.get("produces", ()) or ()),
            raw=d,
        )
```

> Note: `RunOutcome` (Tier 3) and `ScanReport` (Tier 2) are added in their tiers.

- [ ] **Step 2: Lint**

Run: `ruff check sdk/python/g3client/types.py`
Expected: PASS.

## Task 0.4: Transport (the HTTP seam)

**Files:**
- Create: `sdk/python/g3client/_transport.py`

- [ ] **Step 1: Create `_transport.py`**

```python
"""The single network seam for g3client.

ALL HTTP access in the library passes through Transport. To add an async variant
later, implement an AsyncTransport exposing the same `request` and `download`
methods; no resource or orchestration code needs to change.
"""
from __future__ import annotations

import os
import time
import zipfile
from pathlib import Path
from typing import Any, Optional

import requests

from .errors import ApiError, ClientError

DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF = 0.5
_DOWNLOAD_CHUNK = 64 * 1024


class Transport:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not base_url:
            raise ClientError("base_url is required (pass it or set G3_API_BASEURL)")
        if not token:
            raise ClientError("token is required (pass it or set G3_API_TOKEN)")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self._session = session or requests.Session()
        self._session.headers["Authorization"] = "Bearer " + token

    def _url(self, path: str) -> str:
        return self.base_url + "/" + path.lstrip("/")

    def _send(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict[str, Any]] = None,
        files: Optional[dict[str, Any]] = None,
        stream: bool = False,
    ) -> requests.Response:
        url = self._url(path)
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                return self._session.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    files=files,
                    timeout=self.timeout,
                    stream=stream,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.retries:
                    time.sleep(DEFAULT_BACKOFF * (2 ** attempt))
                    continue
        raise ApiError(0, "transport error: " + str(last_exc))

    @staticmethod
    def _envelope(resp: requests.Response) -> Any:
        try:
            payload = resp.json()
        except ValueError:
            raise ApiError(resp.status_code, "non-JSON response: " + repr(resp.text[:200]))
        status = payload.get("status")
        data = payload.get("data")
        if resp.status_code >= 400 or status == "error":
            msg = data if isinstance(data, str) else (payload.get("message") or str(data))
            raise ApiError(resp.status_code, msg or "unknown error")
        return data

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict[str, Any]] = None,
        files: Optional[dict[str, Any]] = None,
    ) -> Any:
        return self._envelope(self._send(method, path, json=json, params=params, files=files))

    def download(self, method: str, path: str, dest: Path, *, json: Any = None) -> Path:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        resp = self._send(method, path, json=json, stream=True)
        if resp.status_code >= 400:
            self._envelope(resp)  # raises ApiError with the server message
        filename = _filename_from_disposition(resp.headers.get("Content-Disposition", "")) or "artifact.bin"
        tmp = dest / (filename + ".tmp")
        try:
            with tmp.open("wb") as fh:
                for chunk in resp.iter_content(_DOWNLOAD_CHUNK):
                    if chunk:
                        fh.write(chunk)
            content_type = resp.headers.get("Content-Type", "")
            if filename.endswith(".zip") or "zip" in content_type:
                with zipfile.ZipFile(tmp) as zf:
                    _safe_extract_zip(zf, dest)
                tmp.unlink()
                return dest
            target = dest / filename
            tmp.replace(target)
            return target
        except Exception:
            tmp.unlink(missing_ok=True)
            raise


def _filename_from_disposition(header: str) -> str:
    for part in header.split(";"):
        part = part.strip()
        if part.lower().startswith("filename="):
            return os.path.basename(part[len("filename="):].strip().strip('"'))
    return ""


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    dest_abs = Path(dest).resolve()
    for member in zf.namelist():
        target = (Path(dest) / member).resolve()
        try:
            target.relative_to(dest_abs)
        except ValueError as exc:
            raise ClientError("refusing to extract path-traversing zip member: " + repr(member)) from exc
    zf.extractall(dest)
```

- [ ] **Step 2: Lint**

Run: `ruff check sdk/python/g3client/_transport.py`
Expected: PASS.

## Task 0.5: Polling helper

**Files:**
- Create: `sdk/python/g3client/_polling.py`

- [ ] **Step 1: Create `_polling.py`**

```python
"""Reusable poll-until-predicate loop used by all orchestration tiers.

Pure and seam-friendly: the clock and sleep are injectable so callers can unit-test
deterministically and an async variant can supply async sleeps. Raises the builtin
TimeoutError on deadline; domain tiers translate it to TaskTimeout with their IDs.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_WAIT_TIMEOUT = 1800.0


def poll_until(
    fetch: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    interval: float = DEFAULT_POLL_INTERVAL,
    timeout: float = DEFAULT_WAIT_TIMEOUT,
    on_poll: Optional[Callable[[Any], None]] = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Any:
    """Call `fetch` immediately, then every `interval` seconds, until
    `predicate(result)` is true; return that result. `on_poll` (if given) is invoked
    with every result. Raises TimeoutError if `timeout` elapses first.
    """
    deadline = clock() + timeout
    while True:
        result = fetch()
        if on_poll is not None:
            on_poll(result)
        if predicate(result):
            return result
        if clock() >= deadline:
            raise TimeoutError("poll_until deadline exceeded")
        sleep(interval)
```

- [ ] **Step 2: Lint**

Run: `ruff check sdk/python/g3client/_polling.py`
Expected: PASS.

## Tier 0 checkpoint

- [ ] **Smoke check (no test files — just import):**

Run: `cd sdk/python && python -c "import g3client; from g3client._transport import Transport; from g3client._polling import poll_until; from g3client import types; print(g3client.__version__)"`
Expected: prints `0.1.0`, no traceback.

- [ ] **Hand off to user to commit Tier 0** (git is user-owned). Suggested message: `feat(g3client): foundation — packaging, transport, polling, errors, types`.

---

# TIER 1 — `g3client.api` (DETAILED)

Resource-grouped wrappers. **Method names track the future REST shape; bodies target today's endpoints.** Every emulated/gap site carries a `# REST-MIGRATION:` comment.

## Task 1.1: Scans resource and nested sub-resources

**Files:**
- Create: `sdk/python/g3client/api/scans.py`

- [ ] **Step 1: Create `api/scans.py`**

```python
"""Scans resource and its nested sub-resources.

REST-MIGRATION: method names follow docs/future/http-routing-and-rest-migration.md.
Bodies call today's POST endpoints; migrating = swap the path string (and move path
fields into the path). No caller changes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Sequence

from .._transport import Transport
from ..types import ScanProgress, ScanTasksStatus, TaskStatus


class ScansResource:
    def __init__(self, transport: Transport, artifacts_root: Path) -> None:
        self._t = transport
        self.targets = TargetsResource(transport)
        self.data = DataResource(transport)
        self.tasks = TasksResource(transport, artifacts_root)
        self.imports = ImportsResource(transport)
        self.logs = LogsResource(transport)

    def create(self, script: str, scanid: Optional[str] = None) -> str:
        # REST-MIGRATION: future POST /scans
        body: dict[str, Any] = {"script": script}
        if scanid:
            body["scanid"] = scanid
        return self._t.request("POST", "/scan/start", json=body)

    def create_managed(self) -> str:
        # REST-MIGRATION: future POST /scans/managed
        return self._t.request("POST", "/scan/create", json={})

    def list(self) -> list[str]:
        # REST-MIGRATION: future GET /scans/list
        return self._t.request("POST", "/scan/list", json={}) or []

    def progress(self) -> list[ScanProgress]:
        # REST-MIGRATION: future GET /scans
        rows = self._t.request("POST", "/scan/progress", json={}) or []
        return [ScanProgress.from_raw(r) for r in rows]

    def get(self, scanid: str) -> Optional[ScanProgress]:
        # REST-MIGRATION: future GET /scans/{scanid}. Today: filter the progress table.
        for p in self.progress():
            if p.scanid == scanid:
                return p
        return None

    def stop(self, scanid: str) -> str:
        # REST-MIGRATION: future POST /scans/{scanid}/stop
        return self._t.request("POST", "/scan/stop", json={"scanid": scanid})

    def delete(self, scanid: str) -> None:
        # REST-MIGRATION: future DELETE /scans/{scanid}
        self._t.request("POST", "/scan/delete", json={"scanid": scanid})


class TargetsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def add(self, scanid: str, targets: Sequence[str]) -> list[str]:
        # REST-MIGRATION: future POST /scans/{scanid}/targets. Returns inserted data IDs.
        return self._t.request(
            "POST",
            "/scan/target/add",
            json={"scanid": scanid, "targets": list(targets)},
        ) or []


class DataResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def insert(self, scanid: str, data: Sequence[dict[str, Any]]) -> list[str]:
        # REST-MIGRATION: future POST /scans/{scanid}/data
        return self._t.request(
            "POST",
            "/scan/data/insert",
            json={"scanid": scanid, "data": list(data)},
        ) or []

    def list(self, scanid: str) -> list[str]:
        # REST-MIGRATION: future GET /scans/{scanid}/data/list
        return self._t.request("POST", "/scan/datalist", json={"scanid": scanid}) or []

    def get(
        self,
        scanid: str,
        *,
        dataids: Optional[Sequence[str]] = None,
        taskid: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        # REST-MIGRATION: future GET /scans/{scanid}/data; the dataids form becomes
        # POST /scans/{scanid}/data/filter (the only POST-as-search endpoint).
        body: dict[str, Any] = {"scanid": scanid}
        if taskid:
            body["taskid"] = taskid
        if dataids:
            body["dataids"] = list(dataids)
        return self._t.request("POST", "/scan/data", json=body) or []


class TasksResource:
    def __init__(self, transport: Transport, artifacts_root: Path) -> None:
        self._t = transport
        self._artifacts_root = artifacts_root

    def dispatch(
        self,
        scanid: str,
        *,
        kind: str,
        tool: str,
        dataid: Optional[str] = None,
        preset: Optional[str] = None,
    ) -> list[str]:
        # REST-MIGRATION: future POST /scans/{scanid}/tasks. Returns task IDs, no wait.
        body: dict[str, Any] = {"scanid": scanid, "kind": kind, "tool": tool}
        if dataid:
            body["dataid"] = dataid
        if preset:
            body["preset"] = preset
        resp = self._t.request("POST", "/scan/task/dispatch", json=body) or {}
        return list(resp.get("task_ids", []))

    def status(self, scanid: str) -> ScanTasksStatus:
        # REST-MIGRATION: future GET /scans/{scanid}/tasks
        resp = self._t.request("POST", "/scan/tasks/status", json={"scanid": scanid}) or {}
        return ScanTasksStatus.from_raw(resp)

    def list(self, scanid: str) -> list[str]:
        # REST-MIGRATION: future GET /scans/{scanid}/tasks/list
        return self._t.request("POST", "/scan/tasks", json={"scanid": scanid}) or []

    def get(self, scanid: str, taskid: str) -> Optional[TaskStatus]:
        # REST-MIGRATION: future GET /scans/{scanid}/tasks/{taskid}. Today: filter status().
        for t in self.status(scanid).tasks:
            if t.task_id == taskid:
                return t
        return None

    def stop(self, scanid: str, taskids: Sequence[str]) -> None:
        # REST-MIGRATION: future POST /scans/{scanid}/tasks/{taskid}/stop (per id)
        self._t.request(
            "POST",
            "/scan/task/cancel",
            json={"scanid": scanid, "taskids": list(taskids)},
        )

    def artifacts(self, scanid: str, taskid: str, dest: Optional[Path] = None) -> Path:
        # REST-MIGRATION: future GET /scans/{scanid}/tasks/{taskid}/artifacts
        out = Path(dest) if dest is not None else self._artifacts_root / scanid / taskid
        return self._t.download(
            "POST",
            "/scan/task/artifacts",
            out,
            json={"scanid": scanid, "taskid": taskid},
        )


class ImportsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def create(self, scanid: str, tool: str, fileid: str) -> list[str]:
        # REST-MIGRATION: future POST /scans/{scanid}/import
        return self._t.request(
            "POST",
            "/scan/import",
            json={"scanid": scanid, "tool": tool, "fileid": fileid},
        ) or []


class LogsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def get(self, scanid: str, taskid: Optional[str] = None) -> Any:
        # REST-MIGRATION: future GET /scans/{scanid}/logs
        # Server returns a list (scan-level) or a {scanid, taskid, lines:[...]} object
        # (task-level). Returned as-is; the scanner/manager tiers shape it.
        return self._t.request("POST", "/scan/logs", json={"scanid": scanid, "taskid": taskid or ""})
```

- [ ] **Step 2: Lint**

Run: `ruff check sdk/python/g3client/api/scans.py`
Expected: PASS.

## Task 1.2: Plugins, files, config resources

**Files:**
- Create: `sdk/python/g3client/api/plugins.py`
- Create: `sdk/python/g3client/api/files.py`
- Create: `sdk/python/g3client/api/config.py`

- [ ] **Step 1: Create `api/plugins.py`**

```python
"""Plugins resource."""
from __future__ import annotations

from .._transport import Transport
from ..types import PluginContract, PluginInfo


class PluginsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def list(self) -> list[PluginInfo]:
        # REST-MIGRATION: future GET /plugins
        rows = self._t.request("POST", "/plugin/list", json={}) or []
        return [PluginInfo.from_raw(r) for r in rows]

    def describe(self) -> list[PluginContract]:
        # REST-MIGRATION: future GET /plugins/describe
        rows = self._t.request("POST", "/plugin/describe", json={}) or []
        return [PluginContract.from_raw(r) for r in rows]
```

- [ ] **Step 2: Create `api/files.py`**

```python
"""Files resource (upload)."""
from __future__ import annotations

from pathlib import Path
from typing import Union

from .._transport import Transport


class FilesResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def upload(self, path: Union[str, Path]) -> str:
        # REST-MIGRATION: future POST /files. Returns a file id for use in imports.
        p = Path(path)
        with p.open("rb") as fh:
            return self._t.request("POST", "/file/upload", files={"file": (p.name, fh)})
```

- [ ] **Step 3: Create `api/config.py`**

```python
"""Config resource (deployment capabilities)."""
from __future__ import annotations

from typing import Any

from .._transport import Transport


class ConfigResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def env(self) -> dict[str, Any]:
        # REST-MIGRATION: future GET /config/env
        return self._t.request("POST", "/config/env", json={}) or {}
```

- [ ] **Step 4: Lint**

Run: `ruff check sdk/python/g3client/api/plugins.py sdk/python/g3client/api/files.py sdk/python/g3client/api/config.py`
Expected: PASS.

## Task 1.3: ApiClient composition root

**Files:**
- Create: `sdk/python/g3client/api/__init__.py`
- Modify: `sdk/python/g3client/__init__.py` (add `ApiClient` re-export)

- [ ] **Step 1: Create `api/__init__.py`**

```python
"""Tier 1: thin, resource-grouped wrappers over every g3api endpoint.

DESIGN RULE — read before editing:
    Method NAMES track the FUTURE REST resource shape described in
    docs/future/http-routing-and-rest-migration.md. Method BODIES target today's
    POST-everything endpoints. The eventual migration is a per-method transport edit
    (change the path string; move path fields into the path); no caller of these
    methods changes. Sites that emulate a not-yet-existing endpoint, or that will
    collapse once the new endpoint lands, are marked `# REST-MIGRATION:`.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional

import requests

from .._transport import Transport
from .config import ConfigResource
from .files import FilesResource
from .plugins import PluginsResource
from .scans import ScansResource


class ApiClient:
    """Resource-grouped client over g3api. Construct with explicit credentials or
    fall back to G3_API_BASEURL / G3_API_TOKEN / G3_ARTIFACTS_ROOT."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        *,
        artifacts_root: Optional[str] = None,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        base_url = base_url or os.environ.get("G3_API_BASEURL", "")
        token = token or os.environ.get("G3_API_TOKEN", "")
        self.transport = Transport(base_url, token, timeout=timeout, session=session)

        root = artifacts_root or os.environ.get("G3_ARTIFACTS_ROOT")
        self.artifacts_root = Path(root) if root else Path(tempfile.gettempdir()) / "g3client"

        self.scans = ScansResource(self.transport, self.artifacts_root)
        self.plugins = PluginsResource(self.transport)
        self.files = FilesResource(self.transport)
        self.config = ConfigResource(self.transport)


__all__ = ["ApiClient"]
```

- [ ] **Step 2: Add `ApiClient` re-export to `g3client/__init__.py`**

Replace the commented re-export block with the active import. The relevant region becomes:

```python
from .api import ApiClient

# Tier re-exports are added as each tier lands:
#   from .scanner import Scanner
#   from .manager import Manager

__all__ = [
    "__version__",
    "ApiClient",
    "ClientError",
    "ApiError",
    "TaskTimeout",
    "TaskCancelled",
    "TaskFailed",
]
```

- [ ] **Step 3: Lint**

Run: `ruff check sdk/python/g3client/api/__init__.py sdk/python/g3client/__init__.py`
Expected: PASS.

## Tier 1 checkpoint

- [ ] **Smoke check (import + resource wiring; no live server):**

Run:
```bash
cd sdk/python && python -c "
from g3client import ApiClient
c = ApiClient('https://example.test/api', 'tok')
assert hasattr(c.scans, 'create') and hasattr(c.scans.tasks, 'dispatch')
assert hasattr(c.scans.tasks, 'artifacts') and hasattr(c.plugins, 'describe')
assert hasattr(c.files, 'upload') and hasattr(c.config, 'env')
print('api wiring OK')
"
```
Expected: prints `api wiring OK`, no traceback. (No network call is made — construction only wires resources.)

- [ ] **Hand off to user to commit Tier 1.** Suggested message: `feat(g3client): Tier 1 api — resource-grouped g3api wrappers`.

---

# TIER 2 — `g3client.scanner` (OUTLINED — detail before executing)

**Detail and approve with the user before starting.** Per the tiered-plan workflow.

**Files:**
- Create: `sdk/python/g3client/scanner/__init__.py` (`Scanner`)
- Modify: `sdk/python/g3client/types.py` (add `ScanReport`)
- Modify: `sdk/python/g3client/__init__.py` (re-export `Scanner`)

**Public surface:**
```python
class Scanner:
    def __init__(self, api: ApiClient) -> None: ...
    @classmethod
    def from_credentials(cls, base_url=None, token=None, **kw) -> "Scanner": ...
    def scan(self, *, targets, pipeline, mode="parallel", imports=None,
             report=None, on_progress=None, on_log=None,
             timeout=1800) -> ScanReport: ...
```

**Recipe (composed only from `api`; mirrors g3cli/g3tui — spec §7):**
1. For each `(tool, path)` in `imports`: `fileid = api.files.upload(path)`; remember `(tool, fileid)`.
2. Build the script DSL from `mode` / `targets` / imports / `pipeline` (helper `_build_script`). Accept a raw `script=` escape hatch.
3. `scanid = api.scans.create(script)`.
4. `poll_until(fetch=lambda: api.scans.get(scanid), predicate=lambda p: p.is_terminal, on_poll=on_progress, timeout=timeout)`. If `on_log`, also fetch `api.scans.logs.get(scanid)` per round and emit only entries past a tracked high-water timestamp.
5. If `report`: parse `tool[:preset]`; `tids = api.scans.tasks.dispatch(scanid, kind="report", tool=tool, preset=preset)`; `poll_until` on `api.scans.tasks.get(scanid, tids[0])` until terminal; `path = api.scans.tasks.artifacts(scanid, tids[0])`; read bytes.
6. Return `ScanReport(scanid, status, report_path, report_bytes, task_ids)`.

**New type:** `ScanReport(scanid: str, status: str, report_path: Optional[Path], report_bytes: Optional[bytes], task_ids: tuple[str, ...])`.

**Edge cases to detail:** timeout → translate `TimeoutError` to `TaskTimeout`; scan terminal `ERROR`/`CANCELED` → raise `TaskFailed`/`TaskCancelled` before attempting the report; `report=None` → return with no report.

**Verification:** `ruff check`; tier smoke check constructs a `Scanner` and asserts `scan` is callable (no live server).

---

# TIER 3 — `g3client.manager` (OUTLINED — detail before executing)

**Detail and approve with the user before starting.**

**Files:**
- Create: `sdk/python/g3client/manager/__init__.py` (`Manager`)
- Modify: `sdk/python/g3client/types.py` (add `RunOutcome`)
- Modify: `sdk/python/g3client/__init__.py` (re-export `Manager`)

**Public surface (spec §8):**
```python
class Manager:
    def __init__(self, api: ApiClient, scanid: Optional[str] = None) -> None: ...  # creates managed scan if scanid is None
    scan_id: str
    def add_targets(self, targets) -> list[dict]: ...        # targets.add + data.get to return G3Data
    def insert_data(self, data) -> list[str]: ...
    def import_file(self, tool, path) -> list[str]: ...       # files.upload + imports.create
    def launch(self, tool, dataid, preset=None) -> list[str]: ...  # async dispatch; tracks ids
    def poll(self) -> ScanTasksStatus: ...
    def wait(self, task_ids, *, on_status=None, timeout=1800) -> dict[str, TaskStatus]: ...
    def fetch_artifacts(self, task_id, dest=None) -> Path: ...
    def results(self, task_id) -> list[dict]: ...             # data.get(taskid=...)
    def run(self, tool, dataid, *, preset=None, on_status=None, dest=None, timeout=1800) -> RunOutcome: ...
    def dispose(self) -> None: ...                             # scans.delete
```

**`run()` recipe:** `launch` → `wait` (poll_until terminal via `api.scans.tasks.status`) → on `CANCELED` raise `TaskCancelled`, on `ERROR` set state → `fetch_artifacts` → `results` → return `RunOutcome`. State aggregated **worst-wins** (`ERROR > WARNING > DONE`).

**New type:** `RunOutcome(state: str, data: list[dict], artifacts_dir: Path, error_msg: str, task_ids: tuple[str, ...])`.

**Internal tracking:** `scan_id`, `_launched: dict[str, str]` (task_id → tool). `wait`/`poll` translate `poll_until`'s `TimeoutError` to `TaskTimeout` carrying tracked IDs and last states.

**Verification:** `ruff check`; tier smoke check constructs `Manager(api, scanid="x")` (no managed-scan creation when scanid passed) and asserts the surface exists.

---

# DELIVERABLE — Architecture doc (OUTLINED — detail before executing)

**File:** Create `docs/design/g3client-architecture.md` (new `docs/design/` dir).

Language-neutral; contents per spec §10: three-layer model + dependency rule; resource taxonomy → future-REST mapping (the Tier-1 table as canonical vocabulary); the two orchestration recipes as numbered language-independent steps; polling contract; value-type fields; error taxonomy; envelope/auth/download contracts; a cordoned-off "what is language-specific" section. Explicitly framed as the blueprint for a future **Go client (for g3cli/g3tui)** and other ports. The agnostic-core sections (layers, resource map, polling, errors, envelope) can be drafted as early as the end of Tier 1; the recipe sections finalize with Tiers 2–3.

**Verification:** prose only — no lint/build.

---

## Self-Review

**Spec coverage:** Tier 1 maps every row of spec §6.1 (verified 1:1 against the table). Tier 0 covers §5 (transport, polling, errors, types). Tiers 2–3 cover §7/§8. Architecture doc covers §10. Out-of-scope items (§2) are respected: no LLM, no async impl, no other-language clients. Salvage (§11) is realized in `_transport` (download/zip), `_polling`, `errors`, and worst-wins aggregation (deferred to `RunOutcome` in Tier 3).

**Placeholder scan:** No TBD/TODO; every detailed step carries complete code. Tier 2/3/doc are explicitly *outlined* (not placeholders) per the tiered-plan workflow and must be detailed before execution.

**Type consistency:** `ScanProgress`, `TaskStatus`, `ScanTasksStatus`, `PluginInfo`, `PluginContract` are defined in Task 0.3 and consumed with matching constructors/fields in Tasks 1.1–1.2. `tasks.status()` returns `ScanTasksStatus` and `tasks.get()` reads `.tasks`/`.task_id` consistently. `Transport.request`/`download` signatures match all call sites. `RunOutcome`/`ScanReport` are introduced in their own tiers and not referenced earlier.
