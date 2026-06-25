"""g3client — Python client library for g3api (Golismero3)."""

from __future__ import annotations

__version__ = "0.1.0"

from .errors import (
    ApiError,
    ClientError,
    ScanGone,
    TaskCancelled,
    TaskFailed,
    TaskGone,
    TaskTimeout,
)

from .api import ApiClient
from .scanner import Scanner
from .manager import Manager

__all__ = [
    "__version__",
    "ApiClient",
    "Scanner",
    "Manager",
    "ClientError",
    "ApiError",
    "TaskTimeout",
    "TaskCancelled",
    "TaskFailed",
    "ScanGone",
    "TaskGone",
]
