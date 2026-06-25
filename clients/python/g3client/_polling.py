"""Reusable poll-until-predicate loop used by all orchestration tiers.

Pure and seam-friendly: the clock and sleep are injectable so callers can unit-test
deterministically and an async variant can supply async sleeps. Raises the builtin
TimeoutError on deadline; domain tiers translate it to TaskTimeout with their IDs.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_WAIT_TIMEOUT = 1800.0


def poll_until(
    fetch: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    interval: float = DEFAULT_POLL_INTERVAL,
    timeout: float = DEFAULT_WAIT_TIMEOUT,
    on_poll: Optional[Callable[[Any], None]] = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Any:
    """Call `fetch` immediately, then every `interval` seconds, until
    `predicate(result)` is true; return that result. `on_poll` (if given) is invoked
    with every result. Raises TimeoutError if `timeout` elapses first.
    """
    deadline = clock() + timeout
    while True:
        result = fetch()
        if on_poll is not None:
            on_poll(result)
        if predicate(result):
            return result
        if clock() >= deadline:
            raise TimeoutError("poll_until deadline exceeded")
        sleep(interval)
