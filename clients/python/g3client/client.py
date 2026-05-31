"""Synchronous client for the managed half of g3api."""

from __future__ import annotations

import os
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

import requests

from .errors import G3ApiError, G3ClientError, G3TaskTimeout
from .types import PluginContract, PluginOperation, TaskStatus


DEFAULT_TIMEOUT = 30.0  # seconds, per HTTP request
DEFAULT_POLL_INTERVAL = 2.0  # seconds, between wait_for_task polls
DEFAULT_WAIT_TIMEOUT = 600.0  # seconds, overall ceiling for wait_for_task
_DOWNLOAD_CHUNK = 64 * 1024


class G3Client:
    """Synchronous client for the managed g3api endpoints.

    Scan-scoped and data-only: the caller supplies scan IDs and data IDs. The
    only state held across calls is an in-process tool-contract cache, which
    can be invalidated via `refresh_tool_cache()`.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        verify: bool | str = True,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers["Authorization"] = "Bearer " + token
        self._session.verify = verify
        self._tools_cache: Optional[tuple[PluginContract, ...]] = None

    # ------------------------------------------------------------------ HTTP

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
            raise G3ClientError(f"HTTP transport failure on {path}: {exc}") from exc

    def _envelope(self, response: requests.Response) -> Any:
        """Parse the {status, data} response envelope.

        Raises G3ApiError on `status == "error"` or unexpected shape. Returns
        the unwrapped `data` field on success.
        """
        try:
            payload = response.json()
        except ValueError as exc:
            raise G3ApiError(
                response.status_code,
                f"non-JSON response: {response.text[:200]}",
            ) from exc
        if not isinstance(payload, dict):
            raise G3ApiError(
                response.status_code,
                f"unexpected response shape: {payload!r}",
            )
        status = payload.get("status")
        data = payload.get("data")
        if status == "error":
            raise G3ApiError(response.status_code, str(data) if data else "unknown")
        if status != "success":
            raise G3ApiError(
                response.status_code,
                f"unexpected envelope status {status!r}",
            )
        if not response.ok:
            raise G3ApiError(response.status_code, "non-2xx with success envelope")
        return data

    def _call(self, path: str, payload: Any = None) -> Any:
        return self._envelope(self._post(path, payload))

    # --------------------------------------------------- managed scan lifecycle

    def create_managed_scan(self) -> str:
        """Create a new managed scan. Returns the scan ID."""
        return self._call("/scan/create")

    def delete_scan(self, scan_id: str) -> None:
        """Delete a scan along with all its data and artifacts."""
        self._call("/scan/delete", {"scanid": scan_id})

    # ------------------------------------------------------------- seed data

    def add_targets(self, scan_id: str, targets: Sequence[str]) -> list[str]:
        """Canonicalize and add target strings. Returns the new data IDs."""
        return list(
            self._call(
                "/scan/target/add",
                {
                    "scanid": scan_id,
                    "targets": list(targets),
                },
            )
        )

    def insert_data(
        self,
        scan_id: str,
        data: Sequence[Mapping[str, Any]],
    ) -> list[str]:
        """Insert raw G3Data objects (validated server-side). Returns IDs."""
        return list(
            self._call(
                "/scan/data/insert",
                {
                    "scanid": scan_id,
                    "data": list(data),
                },
            )
        )

    def import_file(
        self,
        scan_id: str,
        tool: str,
        path: str | os.PathLike[str],
    ) -> list[str]:
        """Upload a file then run a plugin's importer on it. Returns the IDs
        of the data objects the importer produced.
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
            raise G3ClientError(
                f"HTTP transport failure on /file/upload: {exc}"
            ) from exc
        file_id = self._envelope(response)
        return list(
            self._call(
                "/scan/import",
                {
                    "scanid": scan_id,
                    "tool": tool,
                    "fileid": file_id,
                },
            )
        )

    # ---------------------------------------------- tool contract + shared cfg

    def list_tools(self) -> tuple[PluginContract, ...]:
        """All plugins' LLM contracts. Cached after the first call."""
        if self._tools_cache is None:
            raw = self._call("/plugin/describe") or []
            self._tools_cache = tuple(_contract_from_dict(item) for item in raw)
        return self._tools_cache

    def describe_tool(self, name: str) -> PluginContract:
        """Look up one plugin's contract by name. KeyError if unknown."""
        for tool in self.list_tools():
            if tool.name == name:
                return tool
        raise KeyError(name)

    def refresh_tool_cache(self) -> None:
        """Drop the in-memory cache; next list_tools/describe_tool refetches."""
        self._tools_cache = None

    def get_env(self) -> dict[str, str]:
        """Read-only shared deployment flags (G3_ENV_*)."""
        return dict(self._call("/config/env") or {})

    # -------------------------------------------- task dispatch + lifecycle

    def run_tool(
        self,
        scan_id: str,
        tool: str,
        dataid: str,
        *,
        index: int = 0,
    ) -> str:
        """Dispatch a single tool task. Returns the task ID."""
        data = self._call(
            "/scan/task/dispatch",
            {
                "scanid": scan_id,
                "kind": "tool",
                "tool": tool,
                "dataid": dataid,
                "index": index,
            },
        )
        # /scan/task/dispatch wraps the UUID in a {"task_id": "..."} object
        # (the same value is also sent via the X-G3-Task-ID response header).
        return data["task_id"]

    def task_status(self, scan_id: str, task_id: str) -> TaskStatus:
        """Single-poll status for one task. KeyError if the task is absent
        from /scan/tasks/status (expired, never existed, or wrong scan).
        """
        payload = self._call("/scan/tasks/status", {"scanid": scan_id}) or {}
        for entry in payload.get("tasks", []) or []:
            if entry.get("taskid") == task_id:
                return _task_status_from_dict(entry)
        raise KeyError(task_id)

    def wait_for_task(
        self,
        scan_id: str,
        task_id: str,
        *,
        timeout: float = DEFAULT_WAIT_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> TaskStatus:
        """Poll task_status until terminal or until `timeout` elapses
        (raising G3TaskTimeout).
        """
        deadline = time.monotonic() + timeout
        while True:
            status = self.task_status(scan_id, task_id)
            if status.is_terminal:
                return status
            if time.monotonic() >= deadline:
                raise G3TaskTimeout(task_id, status.state)
            time.sleep(poll_interval)

    def task_results(self, scan_id: str, task_id: str) -> list[dict[str, Any]]:
        """All G3Data objects produced by a specific dispatched task."""
        return list(
            self._call(
                "/scan/data",
                {
                    "scanid": scan_id,
                    "taskid": task_id,
                },
            )
            or []
        )

    def task_artifacts(
        self,
        scan_id: str,
        task_id: str,
        dest_dir: str | os.PathLike[str],
    ) -> Path:
        """Stream the task's artifact bundle to `<dest_dir>/<task_id>/`.

        The bundle is either a single file (passed through with the
        server-supplied filename) or a ZIP (extracted in place after a
        path-traversal check). Returns the directory path.
        """
        out_dir = Path(dest_dir) / task_id
        out_dir.mkdir(parents=True, exist_ok=True)

        url = self._base + "/scan/task/artifacts"
        try:
            response = self._session.post(
                url,
                json={"scanid": scan_id, "taskid": task_id},
                timeout=self._timeout,
                stream=True,
            )
        except requests.RequestException as exc:
            raise G3ClientError(
                f"HTTP transport failure on /scan/task/artifacts: {exc}"
            ) from exc
        if not response.ok:
            # Surface the JSON error envelope.
            self._envelope(response)  # raises G3ApiError

        content_type = (response.headers.get("Content-Type") or "").lower()
        filename = _filename_from_disposition(
            response.headers.get("Content-Disposition")
        )

        # Stream to a temp file in the destination directory so the final
        # rename / extract operation is atomic on the same filesystem.
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


# --------------------------------------------------------------------- helpers


def _contract_from_dict(item: Mapping[str, Any]) -> PluginContract:
    operations = tuple(
        PluginOperation(
            index=op.get("index", 0),
            description=op.get("description", "") or "",
            produces=op.get("produces", "") or "",
        )
        for op in (item.get("operations") or [])
    )
    return PluginContract(
        name=item["name"],
        summary=item.get("summary", "") or "",
        accepts=tuple(item.get("accepts") or ()),
        produces=item.get("produces", "") or "",
        operations=operations,
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
    """Extract the `filename="..."` value from a Content-Disposition header."""
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
    """Like ZipFile.extractall but refuses path traversal (zip-slip)."""
    dest_abs = dest.resolve()
    for member in zf.namelist():
        target = (dest / member).resolve()
        try:
            target.relative_to(dest_abs)
        except ValueError as exc:
            raise G3ClientError(
                f"refusing to extract path-traversing zip member: {member!r}"
            ) from exc
    zf.extractall(dest)
