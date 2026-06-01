"""g3client.llm — Python tool-bridge for golismero3 LLM integration.

Synchronous, engagement-scoped, data-flow oriented. Knife wraps `Client.run`
and `Client.add_target(s)` as @mcp.tool functions; scan IDs, task IDs,
polling, multi-task fan-out, and artifact download are all hidden inside
this module.

Typical use from knife:

    from g3client.llm import Client, DATA_PRIMER

    # engagement_id is knife's per-engagement key; persistence handled via
    # Client.bind/unbind from knife's DB.
    client = Client(engagement_id)
    url_obj = client.add_target("https://example.com/")
    result = client.run(url_obj, "nikto")
    # result.data, result.state, result.artifacts_dir

Configuration is from environment variables, read on first construction:
    G3_API_BASEURL          (required)  e.g. https://g3.internal/api
    G3_API_TOKEN            (required)  bearer token
    G3_ARTIFACTS_ROOT       (optional)  default: <tempdir>/g3client
"""
from .client import Client
from .errors import ApiError, ClientError, TaskCancelled, TaskTimeout
from .primer import DATA_PRIMER
from .types import (
    TASK_TERMINAL_STATES,
    PluginContract,
    RunResult,
    TaskStatus,
)

__all__ = [
    "Client",
    "ApiError",
    "ClientError",
    "TaskCancelled",
    "TaskTimeout",
    "DATA_PRIMER",
    "PluginContract",
    "RunResult",
    "TaskStatus",
    "TASK_TERMINAL_STATES",
]
