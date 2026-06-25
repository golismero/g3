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

    def create(self, script: str) -> str:
        # REST-MIGRATION: future POST /scans
        return self._t.request("POST", "/scan/start", json={"script": script})

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
        return (
            self._t.request(
                "POST",
                "/scan/target/add",
                json={"scanid": scanid, "targets": list(targets)},
            )
            or []
        )


class DataResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def insert(self, scanid: str, data: Sequence[dict[str, Any]]) -> list[str]:
        # REST-MIGRATION: future POST /scans/{scanid}/data
        return (
            self._t.request(
                "POST",
                "/scan/data/insert",
                json={"scanid": scanid, "data": list(data)},
            )
            or []
        )

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
        resp = (
            self._t.request("POST", "/scan/tasks/status", json={"scanid": scanid}) or {}
        )
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
        return (
            self._t.request(
                "POST",
                "/scan/import",
                json={"scanid": scanid, "tool": tool, "fileid": fileid},
            )
            or []
        )


class LogsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def get(self, scanid: str, taskid: Optional[str] = None) -> Any:
        # REST-MIGRATION: future GET /scans/{scanid}/logs
        # Server returns a list (scan-level) or a {scanid, taskid, lines:[...]} object
        # (task-level). Returned as-is; the scanner/manager tiers shape it.
        return self._t.request(
            "POST", "/scan/logs", json={"scanid": scanid, "taskid": taskid or ""}
        )
