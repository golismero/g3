"""Exception hierarchy for g3client."""


class G3ClientError(Exception):
    """Base class for all g3client errors."""


class G3ApiError(G3ClientError):
    """The server returned an error envelope or a non-2xx HTTP status."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"g3api {status_code}: {message}")
        self.status_code = status_code
        self.message = message


class G3TaskTimeout(G3ClientError):
    """wait_for_task() exceeded its timeout while the task was still running."""

    def __init__(self, task_id: str, last_state: str) -> None:
        super().__init__(
            f"task {task_id} did not reach terminal state (still {last_state!r})"
        )
        self.task_id = task_id
        self.last_state = last_state
