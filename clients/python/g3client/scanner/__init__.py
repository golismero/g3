"""Tier 2: orchestrated scans.

`Scanner` reproduces, in Python, the end-to-end g3cli/g3tui flow: upload imports,
build the script DSL, launch the scan, wait for completion (with optional progress
and incremental-log callbacks), then dispatch a reporter task and download its
artifact.

It is composed EXCLUSIVELY from `g3client.api` (Tier 1) and the shared `poll_until`
helper — no HTTP, no `Transport`, no manual endpoint calls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union

from .._polling import DEFAULT_POLL_INTERVAL, poll_until
from ..api import ApiClient
from ..errors import ScanGone, TaskCancelled, TaskFailed, TaskTimeout
from ..types import ScanProgress, ScanReport

# Report specifier accepted by `scan(report=...)`: "tool", "tool:preset", or a tuple.
ReportSpec = Union[str, "tuple[str, Optional[str]]"]


class Scanner:
    """High-level helper for orchestrated scans, built only on `ApiClient`."""

    def __init__(self, api: ApiClient) -> None:
        self.api = api

    @classmethod
    def from_credentials(
        cls,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        **kw: Any,
    ) -> "Scanner":
        """Build the underlying `ApiClient` from credentials/env, then wrap it."""
        return cls(ApiClient(base_url, token, **kw))

    def scan(
        self,
        *,
        targets: Optional[Sequence[str]] = None,
        pipeline: Optional[Sequence[str]] = None,
        mode: str = "parallel",
        imports: Optional[Sequence[tuple[str, Union[str, Path]]]] = None,
        report: Optional[ReportSpec] = None,
        script: Optional[str] = None,
        on_progress: Optional[Callable[[ScanProgress], None]] = None,
        on_log: Optional[Callable[[list[dict[str, Any]]], None]] = None,
        timeout: float = 1800,
    ) -> ScanReport:
        """Launch an orchestrated scan and wait for it to finish.

        If `script` is given it is used verbatim and `targets`/`pipeline`/`mode`/
        `imports` are ignored. Otherwise the script DSL is built from those args
        (imports are uploaded first and referenced by file id).

        Raises `TaskTimeout` on deadline, `TaskFailed` on a terminal ERROR scan,
        `TaskCancelled` on a CANCELED scan, and `ScanGone` if the scan is deleted
        server-side mid-run.
        """
        api = self.api

        # 1. Build (or accept) the script.
        if script is None:
            uploaded: list[tuple[str, str]] = []
            for tool, path in imports or []:
                fileid = api.files.upload(path)
                uploaded.append((tool, fileid))
            script = _build_script(mode, targets, uploaded, pipeline)

        # 2. Create the scan.
        scanid = api.scans.create(script)

        # 3. Wait for the scan to reach a terminal status.
        last_seen = {"progress": None}  # latest ScanProgress observed
        log_mark = {"count": 0}  # count of log entries already emitted

        seen = {"v": False}  # has the scan ever been observed in the progress table?

        def fetch_scan() -> Optional[ScanProgress]:
            progress = api.scans.get(scanid)
            if progress is None:
                # Distinguish "not registered yet" from "deleted": before the
                # scanner writes the first progress row, a fresh scan is briefly
                # absent (keep polling). Once observed, a later disappearance
                # means it was removed server-side — surface it, don't wait.
                if seen["v"]:
                    raise ScanGone(scanid)
                return None
            seen["v"] = True
            return progress

        def on_poll(progress: Optional[ScanProgress]) -> None:
            if progress is None:
                return
            last_seen["progress"] = progress
            if on_progress is not None:
                on_progress(progress)
            if on_log is not None:
                _emit_new_logs(api, scanid, log_mark, on_log)

        try:
            final = poll_until(
                fetch_scan,
                lambda p: p is not None and p.is_terminal,
                interval=DEFAULT_POLL_INTERVAL,
                timeout=timeout,
                on_poll=on_poll,
            )
        except TimeoutError:
            last = last_seen["progress"]
            last_status = last.status if last is not None else "UNKNOWN"
            raise TaskTimeout(task_ids=(), last_states={scanid: last_status}) from None

        status = final.status
        if status == "ERROR":
            raise TaskFailed((), final.message)
        if status == "CANCELED":
            raise TaskCancelled(())

        # 4. No report requested → done.
        if not report:
            return ScanReport(scanid, status, None, None, ())

        # 5. Dispatch the reporter as a post-scan task and download its artifact.
        tool, preset = _parse_report(report)
        tids = api.scans.tasks.dispatch(scanid, kind="report", tool=tool, preset=preset)
        if not tids:
            raise TaskFailed((), "reporter dispatch returned no task id")
        report_tid = tids[0]

        report_seen = {"v": False}

        def fetch_task() -> Any:
            task = api.scans.tasks.get(scanid, report_tid)
            if task is None:
                # The report task vanished — its scan was deleted mid-report.
                if report_seen["v"]:
                    raise ScanGone(scanid)
                return None
            report_seen["v"] = True
            return task

        try:
            task = poll_until(
                fetch_task,
                lambda t: t is not None and t.is_terminal,
                interval=DEFAULT_POLL_INTERVAL,
                timeout=timeout,
            )
        except TimeoutError:
            raise TaskTimeout(
                task_ids=tuple(tids), last_states={scanid: status}
            ) from None

        if task.state == "ERROR":
            raise TaskFailed(tuple(tids), task.error_msg)
        if task.state == "CANCELED":
            raise TaskCancelled(tuple(tids))

        path = api.scans.tasks.artifacts(scanid, report_tid)
        report_bytes: Optional[bytes] = None
        if path.is_file():
            report_bytes = path.read_bytes()

        return ScanReport(scanid, status, path, report_bytes, tuple(tids))


def _build_script(
    mode: Optional[str],
    targets: Optional[Sequence[str]],
    imports: Sequence[tuple[str, str]],
    pipeline: Optional[Sequence[str]],
) -> str:
    """Render the g3 script DSL, matching `ParsedScript.String()` in src/g3lib/script.go.

    Layout: a `mode` line, then blocks (separated by a blank line) of `target`,
    `import <tool> "<fileid>"`, and pipeline lines. No `report` line — reporting is
    a separate post-scan task.
    """
    blocks: list[str] = []

    if mode:
        blocks.append("mode " + mode)

    if targets:
        blocks.append("\n".join("target " + t for t in targets))

    if imports:
        blocks.append(
            "\n".join(
                "import " + tool + ' "' + fileid + '"' for tool, fileid in imports
            )
        )

    if pipeline:
        blocks.append("\n".join(pipeline))

    return "\n\n".join(blocks) + "\n"


def _parse_report(report: ReportSpec) -> tuple[str, Optional[str]]:
    """Normalize a report spec to `(tool, preset)`.

    Accepts `"tool"`, `"tool:preset"`, or a `(tool, preset)` tuple.
    """
    if isinstance(report, tuple):
        tool = report[0]
        preset = report[1] if len(report) > 1 else None
        return tool, (preset or None)
    if ":" in report:
        tool, preset = report.split(":", 1)
        return tool, (preset or None)
    return report, None


def _emit_new_logs(
    api: ApiClient,
    scanid: str,
    log_mark: dict[str, Any],
    on_log: Callable[[list[dict[str, Any]]], None],
) -> None:
    """Fetch scan-level logs and emit only entries not yet emitted (index-based)."""
    entries = api.scans.logs.get(scanid)
    if not isinstance(entries, list):
        return
    seen = log_mark["count"]
    if len(entries) <= seen:
        return
    fresh = entries[seen:]
    log_mark["count"] = len(entries)
    on_log(fresh)
