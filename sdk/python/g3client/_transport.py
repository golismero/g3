"""The single network seam for g3client.

ALL HTTP access in the library passes through Transport. To add an async variant
later, implement an AsyncTransport exposing the same `request` and `download`
methods; no resource or orchestration code needs to change.
"""

from __future__ import annotations

import os
import time
import zipfile
from pathlib import Path
from typing import Any, Optional

import requests

from .errors import ApiError, ClientError

DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF = 0.5
_DOWNLOAD_CHUNK = 64 * 1024


class Transport:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not base_url:
            raise ClientError("base_url is required (pass it or set G3_API_BASEURL)")
        if not token:
            raise ClientError("token is required (pass it or set G3_API_TOKEN)")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self._session = session or requests.Session()
        self._session.headers["Authorization"] = "Bearer " + token

    def _url(self, path: str) -> str:
        return self.base_url + "/" + path.lstrip("/")

    def _send(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict[str, Any]] = None,
        files: Optional[dict[str, Any]] = None,
        stream: bool = False,
    ) -> requests.Response:
        url = self._url(path)
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                return self._session.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    files=files,
                    timeout=self.timeout,
                    stream=stream,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.retries:
                    time.sleep(DEFAULT_BACKOFF * (2**attempt))
                    continue
        raise ApiError(0, "transport error: " + str(last_exc))

    @staticmethod
    def _envelope(resp: requests.Response) -> Any:
        try:
            payload = resp.json()
        except ValueError:
            raise ApiError(
                resp.status_code, "non-JSON response: " + repr(resp.text[:200])
            )
        status = payload.get("status")
        data = payload.get("data")
        if resp.status_code >= 400 or status == "error":
            msg = (
                data if isinstance(data, str) else (payload.get("message") or str(data))
            )
            raise ApiError(resp.status_code, msg or "unknown error")
        return data

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict[str, Any]] = None,
        files: Optional[dict[str, Any]] = None,
    ) -> Any:
        return self._envelope(
            self._send(method, path, json=json, params=params, files=files)
        )

    def download(self, method: str, path: str, dest: Path, *, json: Any = None) -> Path:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        resp = self._send(method, path, json=json, stream=True)
        if resp.status_code >= 400:
            self._envelope(resp)  # raises ApiError with the server message
        filename = (
            _filename_from_disposition(resp.headers.get("Content-Disposition", ""))
            or "artifact.bin"
        )
        tmp = dest / (filename + ".tmp")
        try:
            with tmp.open("wb") as fh:
                for chunk in resp.iter_content(_DOWNLOAD_CHUNK):
                    if chunk:
                        fh.write(chunk)
            content_type = resp.headers.get("Content-Type", "")
            if filename.endswith(".zip") or "zip" in content_type:
                with zipfile.ZipFile(tmp) as zf:
                    _safe_extract_zip(zf, dest)
                tmp.unlink()
                return dest
            target = dest / filename
            tmp.replace(target)
            return target
        except Exception:
            tmp.unlink(missing_ok=True)
            raise


def _filename_from_disposition(header: str) -> str:
    for part in header.split(";"):
        part = part.strip()
        if part.lower().startswith("filename="):
            return os.path.basename(part[len("filename=") :].strip().strip('"'))
    return ""


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    dest_abs = Path(dest).resolve()
    for member in zf.namelist():
        target = (Path(dest) / member).resolve()
        try:
            target.relative_to(dest_abs)
        except ValueError as exc:
            raise ClientError(
                "refusing to extract path-traversing zip member: " + repr(member)
            ) from exc
    zf.extractall(dest)
