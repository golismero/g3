"""Tier 3: managed scans.

`Manager` owns a single *managed* scan and drives it externally, bypassing the
scan orchestrator: add targets / insert data / import files, launch tools
asynchronously, poll their status, download per-task artifacts, and collect
produced G3Data. `run()` is the synchronous headline — dispatch one tool, wait
to completion, download artifacts, and collect results into a `RunOutcome`.

It is composed EXCLUSIVELY from `g3client.api` (Tier 1) and the shared `poll_until`
helper — no HTTP, no `Transport`, no manual endpoint calls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union

from .._polling import DEFAULT_POLL_INTERVAL, poll_until
from ..api import ApiClient
from ..errors import TaskCancelled, TaskFailed, TaskGone, TaskTimeout
from ..types import RunOutcome, ScanTasksStatus, TaskStatus

# Worst-wins state aggregation across a dispatch fan-out (salvaged from the old
# client). Higher number wins; states not listed (e.g. CANCELED) are handled out of
# band before aggregation.
_STATE_PRIORITY = {"DONE": 0, "WARNING": 1, "ERROR": 2}


class Manager:
    """High-level helper for managed scans, built only on `ApiClient`."""

    def __init__(self, api: ApiClient, scanid: Optional[str] = None) -> None:
        self._api = api
        # Create a fresh managed scan, or re-attach to an existing one.
        self.scan_id: str = scanid if scanid is not None else api.scans.create_managed()
        # Everything this manager has launched: task_id -> tool.
        self._launched: dict[str, str] = {}

    @classmethod
    def from_credentials(
        cls,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        *,
        scanid: Optional[str] = None,
        **kw: Any,
    ) -> "Manager":
        """Build the underlying `ApiClient` from credentials/env, then wrap it."""
        return cls(ApiClient(base_url, token, **kw), scanid=scanid)

    def add_targets(self, targets: Sequence[str]) -> list[dict[str, Any]]:
        """Add scan targets, returning the inserted G3Data objects (with `_id`)."""
        api = self._api
        dataids = api.scans.targets.add(self.scan_id, targets)
        if not dataids:
            return []
        return api.scans.data.get(self.scan_id, dataids=dataids)

    def insert_data(self, data: Sequence[dict[str, Any]]) -> list[str]:
        """Insert raw G3Data objects, returning their data IDs."""
        return self._api.scans.data.insert(self.scan_id, data)

    def import_file(self, tool: str, path: Union[str, Path]) -> list[str]:
        """Upload a tool output file and import it, returning produced data IDs."""
        api = self._api
        fileid = api.files.upload(path)
        return api.scans.imports.create(self.scan_id, tool, fileid)

    def launch(self, tool: str, dataid: str, preset: Optional[str] = None) -> list[str]:
        """Dispatch a tool asynchronously; return (and record) its task IDs.

        A single dispatch can fan out to several tasks (one per matched
        command/condition); all of them are tracked in the launched map.
        """
        tids = self._api.scans.tasks.dispatch(
            self.scan_id, kind="tool", tool=tool, dataid=dataid, preset=preset
        )
        for tid in tids:
            self._launched[tid] = tool
        return tids

    def poll(self) -> ScanTasksStatus:
        """Return the current status of every task in this scan."""
        return self._api.scans.tasks.status(self.scan_id)

    def wait(
        self,
        task_ids: Sequence[str],
        *,
        on_status: Optional[Callable[[ScanTasksStatus], None]] = None,
        timeout: float = 1800,
    ) -> dict[str, TaskStatus]:
        """Poll until every id in `task_ids` is present and terminal.

        `on_status` (if given) is invoked each round with the `ScanTasksStatus`.
        Returns `{task_id: TaskStatus}` for the requested ids, built from the final
        snapshot. Raises `TaskTimeout` (carrying the unfinished ids) on deadline,
        and `TaskGone` if a tracked task disappears mid-poll (e.g. its scan was
        deleted server-side).
        """
        wanted = tuple(task_ids)
        api = self._api
        # Capture the most recent snapshot so the except block never makes a
        # fresh network call (which could raise and mask the original TimeoutError).
        last_seen: dict[str, ScanTasksStatus] = {}
        seen_ids: set[str] = set()  # wanted task ids ever observed present

        def fetch() -> ScanTasksStatus:
            return api.scans.tasks.status(self.scan_id)

        def ready(status: ScanTasksStatus) -> bool:
            by_id = {t.task_id: t for t in status.tasks}
            return all(tid in by_id and by_id[tid].is_terminal for tid in wanted)

        def on_poll(status: ScanTasksStatus) -> None:
            last_seen["snap"] = status
            if on_status is not None:
                on_status(status)
            # A freshly-dispatched task may not appear immediately (keep polling),
            # but once observed, a later disappearance means the task (or its
            # scan) was removed server-side — surface it rather than wait.
            present = {t.task_id for t in status.tasks}
            for tid in wanted:
                if tid in present:
                    seen_ids.add(tid)
                elif tid in seen_ids:
                    raise TaskGone(self.scan_id, tid)

        try:
            final = poll_until(
                fetch,
                ready,
                interval=DEFAULT_POLL_INTERVAL,
                timeout=timeout,
                on_poll=on_poll,
            )
        except TimeoutError:
            snap = last_seen.get("snap")
            last = (
                _last_states(snap, wanted)
                if snap is not None
                else {tid: "UNKNOWN" for tid in wanted}
            )
            raise TaskTimeout(task_ids=wanted, last_states=last) from None

        by_id = {t.task_id: t for t in final.tasks}
        return {tid: by_id[tid] for tid in wanted if tid in by_id}

    def fetch_artifacts(self, task_id: str, dest: Optional[Path] = None) -> Path:
        """Download a task's artifact bundle; return the local path."""
        return self._api.scans.tasks.artifacts(self.scan_id, task_id, dest=dest)

    def results(self, task_id: str) -> list[dict[str, Any]]:
        """Return the G3Data objects produced by a task."""
        return self._api.scans.data.get(self.scan_id, taskid=task_id)

    def run(
        self,
        tool: str,
        dataid: str,
        *,
        preset: Optional[str] = None,
        on_status: Optional[Callable[[ScanTasksStatus], None]] = None,
        dest: Optional[Union[str, Path]] = None,
        timeout: float = 1800,
    ) -> RunOutcome:
        """Synchronously run one tool: launch, wait, download artifacts, collect data.

        A dispatch may fan out to several tasks; this aggregates across all of them.
        Raises `TaskFailed` if dispatch produced no task, `TaskCancelled` if any task
        was canceled, and `TaskTimeout` on deadline.
        """
        tids = self.launch(tool, dataid, preset)
        if not tids:
            raise TaskFailed((), "dispatch returned no task id")

        statuses = self.wait(tids, on_status=on_status, timeout=timeout)

        canceled = tuple(tid for tid, s in statuses.items() if s.state == "CANCELED")
        if canceled:
            raise TaskCancelled(canceled)

        # Worst-wins state aggregation and joined error messages.
        # At this point only DONE / WARNING / ERROR are expected; CANCELED is
        # raised above before we reach here.
        state_list = list(statuses.values())
        combined_state = state_list[0].state  # will be overwritten by highest-priority
        best = -1
        errs: list[str] = []
        for s in state_list:
            rank = _STATE_PRIORITY.get(s.state, -1)
            if rank > best:
                best = rank
                combined_state = s.state
            if s.error_msg:
                errs.append(s.error_msg)
        # If somehow none of the states were in the priority map, fall back to the
        # first observed state rather than a hardcoded "DONE".
        if best == -1:
            combined_state = state_list[0].state
        combined_err = "; ".join(errs)

        # Per-task artifact slots live under a common parent; download each.
        dest_root = Path(dest) if dest is not None else None
        for tid in tids:
            slot = (dest_root / tid) if dest_root is not None else None
            self.fetch_artifacts(tid, dest=slot)
        artifacts_dir = (
            dest_root
            if dest_root is not None
            else self._api.artifacts_root / self.scan_id
        )

        # Aggregate produced data across every task.
        all_data: list[dict[str, Any]] = []
        for tid in tids:
            all_data.extend(self.results(tid))

        return RunOutcome(
            state=combined_state,
            data=all_data,
            artifacts_dir=artifacts_dir,
            error_msg=combined_err,
            task_ids=tuple(tids),
        )

    def dispose(self) -> None:
        """Delete the managed scan this manager owns."""
        self._api.scans.delete(self.scan_id)


def _last_states(status: ScanTasksStatus, wanted: Sequence[str]) -> dict[str, str]:
    """Map each wanted task id to its last observed state, or "UNKNOWN" if absent."""
    by_id = {t.task_id: t.state for t in status.tasks}
    return {tid: by_id.get(tid, "UNKNOWN") for tid in wanted}
