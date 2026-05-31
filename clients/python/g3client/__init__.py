"""g3client — Python wrapper for the managed g3api surface (golismero3).

Synchronous, scan-scoped, data-only. Wraps:
    /scan/create, /scan/target/add, /scan/data/insert, /scan/import,
    /scan/task/dispatch, /scan/tasks/status, /scan/data (with _taskid filter),
    /scan/task/artifacts, /scan/delete, /file/upload, /plugin/describe,
    /config/env.
"""

from .client import G3Client
from .errors import G3ApiError, G3ClientError, G3TaskTimeout
from .primer import G3DATA_PRIMER
from .types import (
    TASK_TERMINAL_STATES,
    PluginContract,
    PluginOperation,
    TaskStatus,
)

__all__ = [
    "G3Client",
    "G3ApiError",
    "G3ClientError",
    "G3TaskTimeout",
    "G3DATA_PRIMER",
    "PluginContract",
    "PluginOperation",
    "TaskStatus",
    "TASK_TERMINAL_STATES",
]
