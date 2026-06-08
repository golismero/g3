"""Immutable value types returned across the g3client surface.

Each type keeps the original server dict in `raw` for forward-compatibility:
new server fields are reachable without a library change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
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
class ScanReport:
    """Result of an orchestrated scan (Tier 2 `Scanner.scan`).

    `report_path`/`report_bytes` are populated only when a reporter was requested;
    `report_bytes` stays None when the artifact was a directory (e.g. an unpacked zip).
    """

    scanid: str
    status: str
    report_path: Optional[Path]
    report_bytes: Optional[bytes]
    task_ids: tuple[str, ...]


@dataclass(frozen=True)
class RunOutcome:
    """Result of a synchronous managed run (Tier 3 `Manager.run`).

    `state` is the worst-wins aggregate (`ERROR > WARNING > DONE`) across every task a
    single dispatch fanned out to; `error_msg` joins their non-empty messages; `data`
    is the concatenated G3Data those tasks produced; `artifacts_dir` is the common
    parent holding the per-task artifact slots; `task_ids` are all dispatched ids.
    """

    state: str
    data: list[dict[str, Any]]
    artifacts_dir: Path
    error_msg: str
    task_ids: tuple[str, ...]


@dataclass(frozen=True)
class PluginInfo:
    name: str
    category: str
    url: str
    description: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, d: dict[str, Any]) -> "PluginInfo":
        return cls(
            name=d.get("name", ""),
            category=d.get("category", ""),
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
