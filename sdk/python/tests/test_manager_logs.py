"""Manager.logs(): fetch scan-level or per-task logs, normalized to a flat list."""

from __future__ import annotations

from g3client.manager import Manager


class FakeLogs:
    def __init__(self, responses):
        # responses: {taskid_or_None: server_response}
        self.responses = responses
        self.calls = []

    def get(self, scanid, taskid=None):
        self.calls.append((scanid, taskid))
        return self.responses.get(taskid)


class FakeScans:
    def __init__(self, logs):
        self.logs = logs


class FakeApi:
    def __init__(self, logs):
        self.scans = FakeScans(logs)


def test_logs_scan_level_returns_entry_list():
    entries = [{"line": "a"}, {"line": "b"}]
    api = FakeApi(FakeLogs({None: entries}))

    manager = Manager(api, scanid="scan-1")

    assert manager.logs() == entries
    assert api.scans.logs.calls == [("scan-1", None)]


def test_logs_task_level_normalizes_lines_envelope():
    lines = [{"line": "x"}, {"line": "y"}]
    api = FakeApi(
        FakeLogs({"task-9": {"scanid": "scan-1", "taskid": "task-9", "lines": lines}})
    )

    manager = Manager(api, scanid="scan-1")

    assert manager.logs("task-9") == lines
    assert api.scans.logs.calls == [("scan-1", "task-9")]


def test_logs_empty_when_server_returns_none():
    api = FakeApi(FakeLogs({None: None}))

    manager = Manager(api, scanid="scan-1")

    assert manager.logs() == []
