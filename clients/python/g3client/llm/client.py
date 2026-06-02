"""Synchronous, engagement-scoped client for the managed g3api surface."""

from __future__ import annotations

import os
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, ClassVar, Mapping, Optional, Sequence

import requests

from .errors import ApiError, ClientError, TaskCancelled, TaskTimeout
from .types import (
    PluginContract,
    RunResult,
    TaskStatus,
)


# Environment variable names.
ENV_BASEURL = "G3_API_BASEURL"
ENV_TOKEN = "G3_API_TOKEN"
ENV_ARTIFACTS_ROOT = "G3_ARTIFACTS_ROOT"

# Defaults / tunables.
DEFAULT_TIMEOUT = 30.0  # seconds per HTTP request
DEFAULT_POLL_INTERVAL = 2.0  # seconds between /scan/tasks/status polls
DEFAULT_WAIT_TIMEOUT = 1800.0  # seconds, overall ceiling for run() polling
_DOWNLOAD_CHUNK = 64 * 1024

# State priority for the combined RunResult.state. CANCELED is handled
# out-of-band as a raised TaskCancelled exception and does not appear here.
_STATE_PRIORITY = {"DONE": 0, "WARNING": 1, "ERROR": 2}


def _resolve_config() -> tuple[str, str, Path]:
    """Read connection + artifacts-root configuration from environment.

    Raises ClientError if either required variable is missing. Returns the
    canonical base URL (trailing slash stripped), the bearer token, and the
    artifacts root path.
    """
    base_url = os.environ.get(ENV_BASEURL)
    token = os.environ.get(ENV_TOKEN)
    if not base_url:
        raise ClientError(f"missing required environment variable: {ENV_BASEURL}")
    if not token:
        raise ClientError(f"missing required environment variable: {ENV_TOKEN}")
    raw_root = os.environ.get(ENV_ARTIFACTS_ROOT)
    if raw_root:
        artifacts_root = Path(raw_root)
    else:
        artifacts_root = Path(tempfile.gettempdir()) / "g3client"
    return base_url.rstrip("/"), token, artifacts_root


class Client:
    """Synchronous, engagement-scoped client for the managed g3api surface.

    Multiton keyed by the caller-chosen `key` string. Constructing `Client(k)`
    twice with the same `k` returns the same in-process instance.

    Configuration is read once per-instance from environment variables (see
    g3client.llm.__init__ docstring). The constructor eagerly creates a
    managed scan on g3 the first time a key is seen; subsequent constructions
    for the same key are O(0) — no HTTP traffic.

    Persistence across process restarts is supported via the `bind` /
    `unbind` / `keys` class methods and the `scan_id` property; caller stores
    `(key, scan_id)` pairs in its own DB and rehydrates the multiton on
    startup.
    """

    _instances: ClassVar[dict[str, "Client"]] = {}
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __new__(cls, key: str) -> "Client":
        with cls._lock:
            existing = cls._instances.get(key)
            if existing is not None:
                return existing
            instance = super().__new__(cls)
            # Per-instance lock + init flag set up here so __init__ can run
            # exactly once per key even under racing constructions.
            instance._init_lock = threading.Lock()
            instance._initialized = False
            instance._key = key
            cls._instances[key] = instance
            return instance

    def __init__(self, key: str) -> None:
        # __init__ runs on every constructor call (even when __new__ returned
        # a cached instance). Gate the actual setup with a per-instance lock.
        with self._init_lock:
            if self._initialized:
                return
            base_url, token, artifacts_root = _resolve_config()
            self._base = base_url
            self._timeout = DEFAULT_TIMEOUT
            self._session = requests.Session()
            self._session.headers["Authorization"] = "Bearer " + token
            self._artifacts_root = artifacts_root
            self._tools_cache: Optional[tuple[PluginContract, ...]] = None
            # Eager scan creation. On failure, evict so a retry can recreate.
            try:
                self._scan_id = self._call("/scan/create")
            except Exception:
                with type(self)._lock:
                    type(self)._instances.pop(key, None)
                raise
            self._initialized = True

    # ---------------------------------------- multiton / persistence

    @classmethod
    def bind(cls, key: str, scan_id: str) -> None:
        """Register an existing scan_id under `key` without creating a new
        scan on g3. Knife uses this to rehydrate the multiton map from its
        own DB after a process restart. No g3-side verification — a stale
        scan_id surfaces as a clean ApiError on the next call against the
        resulting client.
        """
        with cls._lock:
            if key in cls._instances:
                raise ValueError(f"key already bound: {key!r}")
            base_url, token, artifacts_root = _resolve_config()
            instance = super().__new__(cls)
            instance._init_lock = threading.Lock()
            instance._initialized = True
            instance._key = key
            instance._base = base_url
            instance._timeout = DEFAULT_TIMEOUT
            instance._session = requests.Session()
            instance._session.headers["Authorization"] = "Bearer " + token
            instance._artifacts_root = artifacts_root
            instance._tools_cache = None
            instance._scan_id = scan_id
            cls._instances[key] = instance

    @classmethod
    def unbind(cls, key: str) -> None:
        """Evict `key` from the multiton map without deleting the scan on
        g3. Inverse of `bind`. Useful for clean handoff or testing.
        """
        with cls._lock:
            cls._instances.pop(key, None)

    @classmethod
    def keys(cls) -> list[str]:
        """All currently mapped keys (debug / introspection)."""
        with cls._lock:
            return list(cls._instances.keys())

    @property
    def scan_id(self) -> str:
        """The underlying scan_id. Knife persists this to its DB so it can
        later rehydrate via `Client.bind`.
        """
        return self._scan_id

    @property
    def key(self) -> str:
        """The caller-supplied multiton key."""
        return self._key

    @property
    def artifacts_root(self) -> Path:
        """Root directory under which artifact trees are laid out as
        `<root>/<scan_id>/<task_id>/...`.
        """
        return self._artifacts_root

    # ---------------------------------------- HTTP internals

    def _post(
        self,
        path: str,
        payload: Any = None,
        *,
        stream: bool = False,
    ) -> requests.Response:
        url = self._base + path
        try:
            return self._session.post(
                url,
                json=payload if payload is not None else {},
                timeout=self._timeout,
                stream=stream,
            )
        except requests.RequestException as exc:
            raise ClientError(f"HTTP transport failure on {path}: {exc}") from exc

    def _envelope(self, response: requests.Response) -> Any:
        """Parse the {status, data} response envelope. Raises ApiError on
        `status == "error"` or unexpected shape.
        """
        try:
            payload = response.json()
        except ValueError as exc:
            raise ApiError(
                response.status_code,
                f"non-JSON response: {response.text[:200]}",
            ) from exc
        if not isinstance(payload, dict):
            raise ApiError(
                response.status_code,
                f"unexpected response shape: {payload!r}",
            )
        status = payload.get("status")
        data = payload.get("data")
        if status == "error":
            raise ApiError(response.status_code, str(data) if data else "unknown")
        if status != "success":
            raise ApiError(
                response.status_code,
                f"unexpected envelope status {status!r}",
            )
        if not response.ok:
            raise ApiError(response.status_code, "non-2xx with success envelope")
        return data

    def _call(self, path: str, payload: Any = None) -> Any:
        return self._envelope(self._post(path, payload))

    # ---------------------------------------- data-flow API (LLM-facing)

    def add_target(self, target: str) -> dict[str, Any]:
        """Canonicalize and add a single target string. Returns the resulting
        G3Data object (with `_id` populated by the server's BuildTargets).
        """
        objs = self.add_targets([target])
        if not objs:
            # Defensive: BuildTargets either produces an object or rejects
            # the input with 400. Should be unreachable.
            raise ClientError("add_target produced no object")
        return objs[0]

    def add_targets(self, targets: Sequence[str]) -> list[dict[str, Any]]:
        """Canonicalize and add target strings. Returns the resulting G3Data
        objects (each with `_id` populated). Two round trips:
        /scan/target/add to insert, then /scan/data to fetch the full
        objects.
        """
        ids = self._call(
            "/scan/target/add",
            {
                "scanid": self._scan_id,
                "targets": list(targets),
            },
        )
        if not ids:
            return []
        objs = self._call(
            "/scan/data",
            {
                "scanid": self._scan_id,
                "dataids": list(ids),
            },
        )
        return list(objs)

    def run(self, data: dict[str, Any], tool: str) -> RunResult:
        """Run a tool against a G3Data object. Returns a self-contained
        RunResult. Hides scan IDs, task IDs, polling, and multi-task
        fan-out from the caller.

        Behaviour:
          1. If `data` lacks `_id`, inserts via /scan/data/insert and
             **mutates `data["_id"]` in place** so subsequent run()s skip
             the insert.
          2. POSTs /scan/task/dispatch (no index — server auto-evaluates
             conditions and returns a list of task IDs, one per matching
             command).
          3. Polls /scan/tasks/status in a single loop until all spawned
             tasks reach a terminal state, or until DEFAULT_WAIT_TIMEOUT
             elapses (raises TaskTimeout).
          4. If any task ended CANCELED: raises TaskCancelled.
          5. Otherwise: fetches G3Data per task via /scan/data?taskid and
             downloads artifacts per task into
             `<artifacts_root>/<scan_id>/<task_id>/`.
          6. Aggregates state with `ERROR > WARNING > DONE` worst-wins.
          7. Returns the RunResult.
        """
        # Insert-if-needed; embed _id back into the caller's dict. The "no _id"
        # path is defensive: legitimate LLM use cases never reach it because
        # all G3Data the LLM holds came from add_target / a previous run() /
        # import_file, which all populate _id. It exists as an escape hatch for
        # caller-side compatibility layers that may inject pre-known objects
        # (those callers should know to call `_insert_data` via the underscore
        # API or to construct objects the server will accept).
        if "_id" not in data:
            ids = self._insert_data([data])
            if not ids:
                raise ClientError("_insert_data returned no IDs for object")
            data["_id"] = ids[0]
        dataid = data["_id"]

        # Auto-dispatch — server picks all matching command indices.
        dispatch = self._call(
            "/scan/task/dispatch",
            {
                "scanid": self._scan_id,
                "kind": "tool",
                "tool": tool,
                "dataid": dataid,
            },
        )
        task_ids = tuple(dispatch.get("task_ids") or ())
        if not task_ids:
            raise ClientError(f"dispatch returned no task_ids for tool {tool}")

        # Wait for all spawned tasks via a single polling loop.
        statuses = self._wait_for_all(task_ids, timeout=DEFAULT_WAIT_TIMEOUT)

        # Cancellation check before aggregation. CANCELED on a managed task
        # can only come from external operator intervention; surface as an
        # exception rather than as a louder RunResult.state. Operator-side
        # forensics (data from sibling tasks that completed before the
        # cancellation arrived) remains recoverable via the operational API
        # using client.scan_id.
        cancelled = tuple(tid for tid, st in statuses.items() if st.state == "CANCELED")
        if cancelled:
            raise TaskCancelled(cancelled)

        # Aggregate G3Data + artifacts.
        all_data: list[dict[str, Any]] = []
        for tid in task_ids:
            all_data.extend(self.task_results(tid))

        scan_dir = self._artifacts_root / self._scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        for tid in task_ids:
            try:
                self.task_artifacts(tid, scan_dir)
            except ApiError as exc:
                # 404 means no artifacts produced; OK.
                if exc.status_code != 404:
                    raise

        # Worst-wins state aggregation.
        states = [statuses[tid].state for tid in task_ids]
        combined_state = max(
            (s for s in states if s in _STATE_PRIORITY),
            key=lambda s: _STATE_PRIORITY[s],
            default="DONE",
        )
        combined_error = "; ".join(
            statuses[tid].error_msg for tid in task_ids if statuses[tid].error_msg
        )

        return RunResult(
            state=combined_state,
            data=all_data,
            artifacts_dir=scan_dir,
            error_msg=combined_error,
            task_ids=task_ids,
        )

    # ---------------------------------------- operational / power-user

    def dispose(self) -> None:
        """Delete the managed scan on g3 and evict this client from the
        multiton map. Knife calls this on engagement teardown.
        """
        try:
            self._call("/scan/delete", {"scanid": self._scan_id})
        finally:
            with type(self)._lock:
                type(self)._instances.pop(self._key, None)

    def _insert_data(self, data: Sequence[Mapping[str, Any]]) -> list[str]:
        """Insert raw G3Data objects (validated server-side). Returns the
        inserted Mongo IDs.

        Underscored deliberately: the LLM-facing surface does not include
        raw-G3Data insertion. The only ways an LLM should acquire G3Data
        are `add_target` (canonicalises a string), `run` (returns objects
        produced by a tool), and `import_file` (parses tool output). This
        method exists for caller-side compatibility layers that may need to
        inject pre-known objects from the caller's own data model, and for
        `run`'s defensive "no _id" branch. Server-side `IsValidData`
        rejects malformed envelopes regardless of caller.
        """
        return list(
            self._call(
                "/scan/data/insert",
                {
                    "scanid": self._scan_id,
                    "data": list(data),
                },
            )
        )

    def import_file(
        self,
        tool: str,
        path: str | os.PathLike[str],
    ) -> list[str]:
        """Upload a local file and run a plugin's importer on it. Returns
        the IDs of the data objects the importer produced.
        """
        file_path = Path(path)
        url = self._base + "/file/upload"
        try:
            with file_path.open("rb") as fp:
                response = self._session.post(
                    url,
                    files={"file": (file_path.name, fp)},
                    timeout=self._timeout,
                )
        except requests.RequestException as exc:
            raise ClientError(f"HTTP transport failure on /file/upload: {exc}") from exc
        file_id = self._envelope(response)
        return list(
            self._call(
                "/scan/import",
                {
                    "scanid": self._scan_id,
                    "tool": tool,
                    "fileid": file_id,
                },
            )
        )

    def task_status(self, task_id: str) -> TaskStatus:
        """Single-poll status for one task. KeyError if the task is absent
        from /scan/tasks/status (expired, never existed, or wrong scan).
        """
        statuses = self._all_task_statuses()
        if task_id not in statuses:
            raise KeyError(task_id)
        return statuses[task_id]

    def _all_task_statuses(self) -> dict[str, TaskStatus]:
        """Fetch all task statuses for the scan in one round trip."""
        payload = self._call("/scan/tasks/status", {"scanid": self._scan_id}) or {}
        return {
            entry["taskid"]: _task_status_from_dict(entry)
            for entry in (payload.get("tasks", []) or [])
            if "taskid" in entry
        }

    def wait_for_task(
        self,
        task_id: str,
        *,
        timeout: float = DEFAULT_WAIT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> TaskStatus:
        """Poll task_status until terminal, or raise TaskTimeout."""
        deadline = time.monotonic() + timeout
        while True:
            status = self.task_status(task_id)
            if status.is_terminal:
                return status
            if time.monotonic() >= deadline:
                raise TaskTimeout((task_id,), {task_id: status.state})
            time.sleep(poll_interval)

    def _wait_for_all(
        self,
        task_ids: tuple[str, ...],
        *,
        timeout: float,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> dict[str, TaskStatus]:
        """Poll /scan/tasks/status in a single loop until every id in
        `task_ids` is terminal. Returns the per-task last-observed status.
        Raises TaskTimeout if any tasks remain non-terminal at `timeout`.
        """
        deadline = time.monotonic() + timeout
        remaining = set(task_ids)
        latest: dict[str, TaskStatus] = {}
        while remaining:
            statuses = self._all_task_statuses()
            for tid in list(remaining):
                if tid in statuses:
                    latest[tid] = statuses[tid]
                    if statuses[tid].is_terminal:
                        remaining.discard(tid)
            if not remaining:
                break
            if time.monotonic() >= deadline:
                last_states = {
                    tid: (latest[tid].state if tid in latest else "UNKNOWN")
                    for tid in remaining
                }
                raise TaskTimeout(tuple(remaining), last_states)
            time.sleep(poll_interval)
        return latest

    def task_results(self, task_id: str) -> list[dict[str, Any]]:
        """All G3Data objects produced by a specific dispatched task."""
        return list(
            self._call(
                "/scan/data",
                {
                    "scanid": self._scan_id,
                    "taskid": task_id,
                },
            )
            or []
        )

    def task_artifacts(
        self,
        task_id: str,
        dest_dir: str | os.PathLike[str],
    ) -> Path:
        """Stream a task's artifact bundle to `<dest_dir>/<task_id>/`.

        Single-file bundles pass through with the server-supplied filename;
        ZIP bundles are extracted in place after a path-traversal check.
        Returns the directory path.
        """
        out_dir = Path(dest_dir) / task_id
        out_dir.mkdir(parents=True, exist_ok=True)
        url = self._base + "/scan/task/artifacts"
        try:
            response = self._session.post(
                url,
                json={"scanid": self._scan_id, "taskid": task_id},
                timeout=self._timeout,
                stream=True,
            )
        except requests.RequestException as exc:
            raise ClientError(
                f"HTTP transport failure on /scan/task/artifacts: {exc}"
            ) from exc
        if not response.ok:
            self._envelope(response)  # raises ApiError

        content_type = (response.headers.get("Content-Type") or "").lower()
        filename = _filename_from_disposition(
            response.headers.get("Content-Disposition")
        )
        tmp = tempfile.NamedTemporaryFile(
            mode="wb",
            dir=out_dir,
            delete=False,
            prefix=".g3-download-",
            suffix=".tmp",
        )
        tmp_path = Path(tmp.name)
        try:
            with tmp:
                for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK):
                    if chunk:
                        tmp.write(chunk)
            if "zip" in content_type:
                with zipfile.ZipFile(tmp_path) as zf:
                    _safe_extract_zip(zf, out_dir)
                tmp_path.unlink()
            else:
                target = out_dir / (filename or "artifact.bin")
                tmp_path.replace(target)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise
        return out_dir

    def list_tools(self) -> tuple[PluginContract, ...]:
        """All plugins' LLM contracts (from /plugin/describe). Cached after
        the first call; invalidate with `refresh_tool_cache`.
        """
        if self._tools_cache is None:
            raw = self._call("/plugin/describe") or []
            self._tools_cache = tuple(_contract_from_dict(item) for item in raw)
        return self._tools_cache

    def describe_tool(self, name: str) -> PluginContract:
        """Look up one plugin's contract by name. Raises KeyError if the
        plugin is unknown or has opted out of LLM exposure.
        """
        for tool in self.list_tools():
            if tool.name == name:
                return tool
        raise KeyError(name)

    def refresh_tool_cache(self) -> None:
        """Drop the in-memory tool-contract cache; next `list_tools` /
        `describe_tool` call will refetch from the server.
        """
        self._tools_cache = None

    def get_env(self) -> dict[str, str]:
        """Read-only shared deployment flags (the G3_ENV_* environment
        variables on the g3 deployment, surfaced via /config/env).
        """
        return dict(self._call("/config/env") or {})


# ------------------------------------------------------------------- helpers


def _contract_from_dict(item: Mapping[str, Any]) -> PluginContract:
    return PluginContract(
        name=item["name"],
        summary=item.get("summary", "") or "",
        accepts=tuple(item.get("accepts") or ()),
        produces=tuple(item.get("produces") or ()),
    )


def _task_status_from_dict(entry: Mapping[str, Any]) -> TaskStatus:
    return TaskStatus(
        task_id=entry["taskid"],
        tool=entry.get("tool", "") or "",
        worker=entry.get("worker", "") or "",
        state=entry.get("state", "") or "",
        dispatched_at=entry.get("dispatch_ts") or None,
        started_at=entry.get("start_ts") or None,
        completed_at=entry.get("complete_ts") or None,
        error_msg=entry.get("error_msg", "") or "",
        raw=dict(entry),
    )


def _filename_from_disposition(header: Optional[str]) -> Optional[str]:
    """Extract `filename="..."` from a Content-Disposition header, or None."""
    if not header:
        return None
    for part in header.split(";"):
        part = part.strip()
        if part.startswith("filename="):
            value = part[len("filename=") :].strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            return value
    return None


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Like ZipFile.extractall but refuses path-traversal (zip-slip)
    members. Python's stdlib gained a `data_filter` argument in 3.12; this
    keeps the same defence working on 3.10 and 3.11.
    """
    dest_abs = dest.resolve()
    for member in zf.namelist():
        target = (dest / member).resolve()
        try:
            target.relative_to(dest_abs)
        except ValueError as exc:
            raise ClientError(
                f"refusing to extract path-traversing zip member: {member!r}"
            ) from exc
    zf.extractall(dest)
