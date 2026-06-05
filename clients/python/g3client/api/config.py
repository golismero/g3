"""Config resource (deployment capabilities)."""

from __future__ import annotations

from typing import Any

from .._transport import Transport


class ConfigResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def env(self) -> dict[str, Any]:
        # REST-MIGRATION: future GET /config/env
        return self._t.request("POST", "/config/env", json={}) or {}
