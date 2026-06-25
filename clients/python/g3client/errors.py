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


class ScanGone(ClientError):
    """The scan vanished from the server mid-operation (e.g. it was deleted).

    Distinct from a transport/HTTP error: it means the scan was observed and
    then disappeared, so polling should stop and surface it rather than wait.
    """

    def __init__(self, scanid: str) -> None:
        super().__init__("scan no longer exists: " + scanid)
        self.scanid = scanid


class TaskGone(ClientError):
    """A tracked task vanished from the server mid-operation (e.g. its scan was
    deleted).

    Distinct from a transport/HTTP error: the task was observed and then
    disappeared, so polling should stop and surface it rather than wait.
    """

    def __init__(self, scanid: str, taskid: str) -> None:
        super().__init__("task no longer exists: " + taskid + " (scan " + scanid + ")")
        self.scanid = scanid
        self.taskid = taskid
