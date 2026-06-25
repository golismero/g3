"""Plugins resource."""

from __future__ import annotations

from .._transport import Transport
from ..types import PluginInfo


class PluginsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def list(self) -> list[PluginInfo]:
        # REST-MIGRATION: future GET /plugins
        rows = self._t.request("POST", "/plugin/list", json={}) or []
        return [PluginInfo.from_raw(r) for r in rows]
