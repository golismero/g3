"""Files resource (upload)."""

from __future__ import annotations

from pathlib import Path
from typing import Union

from .._transport import Transport


class FilesResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def upload(self, path: Union[str, Path]) -> str:
        # REST-MIGRATION: future POST /files. Returns a file id for use in imports.
        p = Path(path)
        with p.open("rb") as fh:
            return self._t.request("POST", "/file/upload", files={"file": (p.name, fh)})
