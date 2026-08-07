"""g3client — Python client library for g3api (Golismero3)."""

from __future__ import annotations

__version__ = "0.1.0"

from .api import ApiClient
from .errors import (
    ApiError,
    ClientError,
    ScanGone,
    TaskCancelled,
    TaskFailed,
    TaskGone,
    TaskTimeout,
)
from .manager import Manager
from .scanner import Scanner

__all__ = [
    "ApiClient",
    "ApiError",
    "ClientError",
    "Manager",
    "ScanGone",
    "Scanner",
    "TaskCancelled",
    "TaskFailed",
    "TaskGone",
    "TaskTimeout",
    "__version__",
]
