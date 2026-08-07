"""Scanner event-handler surface: on_progress/on_log are overridable methods."""

from __future__ import annotations

import pytest
from g3client.scanner import Scanner
from g3client.types import ScanProgress


class FakeLogs:
    def __init__(self, entries):
        self.entries = entries
        self.calls = 0

    def get(self, scanid, taskid=None):
        self.calls += 1
        return self.entries


class FakeScans:
    def __init__(self, progress, logs):
        self._progress = progress
        self.logs = logs
        self.created = []

    def create(self, script):
        self.created.append(script)
        return "scan-1"

    def get(self, scanid):
        return self._progress


class FakeApi:
    """Just enough of ApiClient for a no-report orchestrated scan that finishes
    on the first poll (so poll_until never sleeps)."""

    def __init__(self, status="FINISHED", entries=None):
        progress = ScanProgress.from_raw(
            {"scanid": "scan-1", "status": status, "progress": 100, "message": "done"}
        )
        self.scans = FakeScans(progress, FakeLogs(entries or []))


def test_on_progress_method_receives_progress():
    seen = []

    class MyScanner(Scanner):
        def on_progress(self, progress):
            seen.append(progress)

    MyScanner(FakeApi()).scan(targets=["example.com"])

    assert [p.status for p in seen] == ["FINISHED"]
    assert all(isinstance(p, ScanProgress) for p in seen)


def test_on_log_method_receives_entries():
    entries = [{"line": "a"}, {"line": "b"}]
    seen = []

    class MyScanner(Scanner):
        def on_log(self, fresh):
            seen.extend(fresh)

    MyScanner(FakeApi(entries=entries)).scan(targets=["example.com"])

    assert seen == entries


def test_logs_not_fetched_when_on_log_not_overridden():
    api = FakeApi(entries=[{"line": "a"}])

    # Base Scanner does not override on_log -> the log endpoint must not be hit.
    Scanner(api).scan(targets=["example.com"])

    assert api.scans.logs.calls == 0


def test_scan_no_longer_accepts_callback_kwargs():
    with pytest.raises(TypeError):
        Scanner(FakeApi()).scan(targets=["example.com"], on_progress=lambda p: None)
