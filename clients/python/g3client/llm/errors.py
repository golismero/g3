"""Exception hierarchy for g3client.llm."""


class ClientError(Exception):
    """Base for all g3client.llm errors."""


class ApiError(ClientError):
    """The server returned an error envelope or a non-2xx HTTP status."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"g3api {status_code}: {message}")
        self.status_code = status_code
        self.message = message


class TaskTimeout(ClientError):
    """One or more spawned tasks did not reach a terminal state before
    the polling timeout. Carries the un-finished task IDs and their last
    observed states so the caller can decide how to recover.
    """

    def __init__(
        self,
        task_ids: tuple[str, ...],
        last_states: dict[str, str],
    ) -> None:
        super().__init__(
            f"task(s) {list(task_ids)} did not reach terminal state "
            f"(last observed: {last_states!r})"
        )
        self.task_ids = task_ids
        self.last_states = last_states


class TaskCancelled(ClientError):
    """One or more spawned tasks were CANCELED externally during run().

    Cancellation of a managed task can only come from operator/system
    intervention (the LLM has no cancel primitive), so the right
    LLM-visible behaviour is "the call failed; the operator stopped you" —
    an exception, not a partial result to inspect. Any forensic data on
    non-cancelled siblings is still recoverable via the operational API
    using `client.scan_id`.
    """

    def __init__(self, task_ids: tuple[str, ...]) -> None:
        super().__init__(f"task(s) {list(task_ids)} were cancelled externally")
        self.task_ids = task_ids
