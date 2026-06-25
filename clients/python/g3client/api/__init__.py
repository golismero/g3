"""Tier 1: thin, resource-grouped wrappers over every g3api endpoint.

DESIGN RULE — read before editing:
    Method NAMES track the FUTURE REST resource shape described in
    docs/future/http-routing-and-rest-migration.md. Method BODIES target today's
    POST-everything endpoints. The eventual migration is a per-method transport edit
    (change the path string; move path fields into the path); no caller of these
    methods changes. Sites that emulate a not-yet-existing endpoint, or that will
    collapse once the new endpoint lands, are marked `# REST-MIGRATION:`.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional

import requests

from .._transport import Transport
from .config import ConfigResource
from .files import FilesResource
from .plugins import PluginsResource
from .scans import ScansResource


class ApiClient:
    """Resource-grouped client over g3api. Construct with explicit credentials or
    fall back to G3_API_BASEURL / G3_API_TOKEN / G3_ARTIFACTS_ROOT."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        *,
        artifacts_root: Optional[str] = None,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        base_url = base_url or os.environ.get("G3_API_BASEURL", "")
        token = token or os.environ.get("G3_API_TOKEN", "")
        self.transport = Transport(base_url, token, timeout=timeout, session=session)

        root = artifacts_root or os.environ.get("G3_ARTIFACTS_ROOT")
        self.artifacts_root = (
            Path(root) if root else Path(tempfile.gettempdir()) / "g3client"
        )

        self.scans = ScansResource(self.transport, self.artifacts_root)
        self.plugins = PluginsResource(self.transport)
        self.files = FilesResource(self.transport)
        self.config = ConfigResource(self.transport)


__all__ = ["ApiClient"]
