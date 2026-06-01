"""Typed data classes for g3client.llm."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# State strings the worker emits via the Redis task hash. A task is terminal
# once its state is in this set. Mirrors src/g3lib/task.go (RUNNING / DONE /
# WARNING / ERROR / CANCELED).
TASK_TERMINAL_STATES: frozenset[str] = frozenset(
    {"DONE", "WARNING", "ERROR", "CANCELED"}
)


@dataclass(frozen=True)
class PluginContract:
    """LLM-facing tool contract (from /plugin/describe).

    Slim by design: only the fields the LLM needs to choose between tools
    and to understand what shapes of object flow in and out. Author-populated
    in each plugin's `.g3p` `llm:` block; no auto-derivation server-side.
    """

    name: str
    summary: str
    accepts: tuple[str, ...]
    produces: tuple[str, ...]


@dataclass(frozen=True)
class TaskStatus:
    """Single-task status snapshot.

    `raw` preserves the full server payload so newer server-side fields stay
    accessible even before this dataclass is updated.
    """

    task_id: str
    tool: str = ""
    worker: str = ""
    state: str = ""
    dispatched_at: Optional[int] = None
    started_at: Optional[int] = None
    completed_at: Optional[int] = None
    error_msg: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.state in TASK_TERMINAL_STATES


@dataclass(frozen=True)
class RunResult:
    """Result of a Client.run() call.

    Self-contained: state + data + artifacts. The LLM receives one of these
    from a tool call; scan IDs, task IDs, polling, and multi-task fan-out
    are not visible. Per-task identity is preserved via `task_ids` (for
    drill-down) and each result G3Data's `_taskid` field (for demuxing the
    `data` array).
    """

    state: str
    data: list[dict[str, Any]]
    artifacts_dir: Path
    error_msg: str = ""
    task_ids: tuple[str, ...] = ()
