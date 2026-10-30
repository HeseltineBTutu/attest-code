"""Quota-path annotation on timeout, crash, and cleanup failure (mocked)."""

from __future__ import annotations

import pytest

from attest_core import scopes
from attest_core.bounds import run_bounded
from attest_core.pidns_probes import probe_pid
from attest_core.supervision import SupervisedExit, WorkerPhase
from attest_spec import AttemptOutcome


def _quota_mocks(monkeypatch: pytest.MonkeyPatch, counters: dict[str, int]) -> None:
    monkeypatch.setattr("attest_core.bounds.supports_containment", lambda: True)
    monkeypatch.setattr(scopes, "supports_quotas", lambda: True)
    monkeypatch.setattr(scopes, "launch_env", lambda: {"XDG_RUNTIME_DIR": "/x"})
    monkeypatch.setattr(scopes, "find_scope", lambda unit: "/sys/x.scope")
    monkeypatch.setattr(scopes, "read_scope_events", lambda path: dict(counters))
    monkeypatch.setattr(scopes, "terminate_scope_by_unit", lambda unit, limits: None)


def _supervise_as(monkeypatch: pytest.MonkeyPatch, result: SupervisedExit) -> None:
    monkeypatch.setattr("attest_core.bounds.supervise_worker", lambda proc, paths, **kw: result)


def test_timeout_annotates_counters(monkeypatch: pytest.MonkeyPatch) -> None:
    _quota_mocks(monkeypatch, {"oom": 0, "oom_kill": 0, "pids_max": 0, "throttled_usec": 5})
    _supervise_as(monkeypatch, SupervisedExit(WorkerPhase.REAPED, 0, True, "t"))
    report = run_bounded(probe_pid, 30.0, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "deadline" in report.detail
    assert "throttled_usec=" not in report.detail
    assert "throttled_usec=5" in report.resources


def test_crash_annotates_counters(monkeypatch: pytest.MonkeyPatch) -> None:
    _quota_mocks(monkeypatch, {"oom": 0, "oom_kill": 3, "pids_max": 0, "throttled_usec": 0})
    _supervise_as(monkeypatch, SupervisedExit(WorkerPhase.REAPED, 5, False, "x"))
    report = run_bounded(probe_pid, 30.0, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "worker crashed (exit code 5)" in report.detail
    assert "oom_kill=" not in report.detail
    assert "oom_kill=3" in report.resources


def test_cleanup_failure_annotates_counters(monkeypatch: pytest.MonkeyPatch) -> None:
    _quota_mocks(monkeypatch, {"oom": 0, "oom_kill": 0, "pids_max": 9, "throttled_usec": 0})
    _supervise_as(monkeypatch, SupervisedExit(WorkerPhase.CLEANUP_FAILED, 0, False, "x"))
    report = run_bounded(probe_pid, 30.0, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "worker cleanup failed" in report.detail
    assert "pids_max=" not in report.detail
    assert "pids_max=9" in report.resources
