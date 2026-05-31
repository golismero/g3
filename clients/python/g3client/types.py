"""Typed data classes for g3client responses."""

from dataclasses import dataclass, field
from typing import Any, Optional


# State strings emitted by g3worker via the Redis task hash. A task is
# considered terminal once its state is in this set. Mirrors the server-side
# enum (RUNNING / DONE / WARNING / ERROR / CANCELED — see src/g3lib/task.go
# and the 4-tier WARNING-state design).
TASK_TERMINAL_STATES: frozenset[str] = frozenset(
    {"DONE", "WARNING", "ERROR", "CANCELED"}
)


@dataclass(frozen=True)
class PluginOperation:
    """One command variant a plugin exposes (`run_tool`'s `index` selects it)."""

    index: int
    description: str = ""
    produces: str = ""


@dataclass(frozen=True)
class PluginContract:
    """LLM-facing contract for one plugin (from `/plugin/describe`)."""

    name: str
    summary: str = ""
    accepts: tuple[str, ...] = ()
    produces: str = ""
    operations: tuple[PluginOperation, ...] = ()


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
