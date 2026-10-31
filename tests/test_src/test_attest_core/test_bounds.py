"""Bounded workers: real deadlines, termination, and crash reports."""

from __future__ import annotations

import functools
import time
from pathlib import Path

import pytest

from apps.demo_api import CRASH_MARKER
from attest_core.bounds import run_bounded
from attest_spec import AttemptOutcome
from examples.admin_authorization import run_target_attempt

SCOPE = ("/admin/users", "/admin/settings")


def test_bounded_pass() -> None:
    report = run_bounded(functools.partial(run_target_attempt, "repaired", SCOPE), 30.0)
    assert report.outcome == AttemptOutcome.PASS


def test_bounded_violation() -> None:
    report = run_bounded(functools.partial(run_target_attempt, "vulnerable", SCOPE), 30.0)
    assert report.outcome == AttemptOutcome.VIOLATION


def test_hanging_worker_is_terminated() -> None:
    start = time.monotonic()
    report = run_bounded(functools.partial(run_target_attempt, "hanging", SCOPE), 2.0)
    elapsed = time.monotonic() - start
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "deadline" in report.detail
    assert elapsed < 60.0


def test_crashing_worker_is_reported() -> None:
    report = run_bounded(functools.partial(run_target_attempt, "crashing", SCOPE), 30.0)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "crashed" in report.detail
    assert CRASH_MARKER in report.detail


def test_hanging_worker_never_emits_crash_marker() -> None:
    report = run_bounded(functools.partial(run_target_attempt, "hanging", SCOPE), 2.0)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert CRASH_MARKER not in report.detail


def test_worker_error_is_reported() -> None:
    report = run_bounded(functools.partial(run_target_attempt, "bogus", SCOPE), 30.0)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "ValueError" in report.detail


def test_non_positive_timeout_raises() -> None:
    with pytest.raises(ValueError, match="positive"):
        run_bounded(functools.partial(run_target_attempt, "repaired", SCOPE), 0.0)


def test_snapshot_self_check_failure_is_infra(tmp_path: Path) -> None:
    report = run_bounded(
        functools.partial(run_target_attempt, "repaired", SCOPE),
        30.0,
        snapshot_root=tmp_path / "no-such-snapshot",
    )
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "self-check" in report.detail
