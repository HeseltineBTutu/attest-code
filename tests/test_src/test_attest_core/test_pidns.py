"""M2 PID-namespace lifecycle battery: init semantics, teardown kills.

Proves checks run as PID-namespace init (PID 1), detached setsid
descendants die with the namespace on both normal completion and
init crash, timeouts terminate promptly via the init SIGTERM handler,
and every abnormal path maps to infrastructure failure, never a
verdict. Survivor checks scan host command lines for a unique token;
vacuity is excluded by requiring in-probe proof the sleeper lived.
"""

from __future__ import annotations

import functools
import os
import secrets
import shutil
import time
from pathlib import Path

import pytest

import attest_core.supervision as supervision
from attest_core.bounds import run_bounded
from attest_core.ns_setup import supports_containment
from attest_core.pidns_probes import (
    probe_crash_sleeper,
    probe_detached_sleeper,
    probe_exit,
    probe_hang,
    probe_pid,
)
from attest_spec import AttemptOutcome

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="M2 user+mount+PID+network namespaces unavailable"
)


@pytest.fixture(scope="session")
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("m2-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _host_marker_pids(token: str) -> list[int]:
    """Host PIDs whose command line still carries the sleeper token."""
    found: list[int] = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                cmdline = handle.read().decode("utf-8", "replace")
        except OSError:
            continue
        if token in cmdline:
            found.append(int(pid))
    return found


def _eventually_no_marker(token: str, timeout: float = 5.0) -> None:
    """Poll until the teardown cascade observably completes."""
    deadline = time.monotonic() + timeout
    while _host_marker_pids(token):
        assert time.monotonic() < deadline, f"sleeper survived teardown: {token}"
        time.sleep(0.05)


@NEEDS_CONTAINMENT
def test_worker_runs_as_pidns_init(src_tree: Path) -> None:
    report = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "pid:1"


@NEEDS_CONTAINMENT
def test_detached_descendant_reaped_on_completion(src_tree: Path) -> None:
    token = f"m2sleeper{secrets.token_hex(4)}"
    probe = functools.partial(probe_detached_sleeper, token)
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == f"sleeper-alive:{token}"
    _eventually_no_marker(token)


@NEEDS_CONTAINMENT
def test_init_crash_kills_descendants(src_tree: Path) -> None:
    token = f"m2sleeper{secrets.token_hex(4)}"
    probe = functools.partial(probe_crash_sleeper, token)
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert f"SLEEPER_ALIVE:{token}" in report.detail
    _eventually_no_marker(token)


@NEEDS_CONTAINMENT
def test_contained_timeout_is_prompt(src_tree: Path) -> None:
    start = time.monotonic()
    report = run_bounded(probe_hang, 3.0, snapshot_root=src_tree, contained=True)
    elapsed = time.monotonic() - start
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "deadline" in report.detail
    assert elapsed < 3.0 + 2.0


@NEEDS_CONTAINMENT
def test_runner_crash_is_infra_not_failed(src_tree: Path) -> None:
    probe = functools.partial(probe_exit, 5)
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "exited 5" in report.detail


def test_runner_setup_failure_is_infra(tmp_path: Path) -> None:
    broken = tmp_path / "broken-snap"
    (broken / "src").mkdir(parents=True)
    report = run_bounded(probe_pid, 30.0, snapshot_root=broken, contained=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    # Refused before spawning: no interpreter starts on a snapshot
    # without first-party sources. Bootstrap/C2 checks remain behind
    # this fail-fast for snapshot races. Needs no namespaces.
    assert "snapshot incomplete" in report.detail


@NEEDS_CONTAINMENT
def test_interrupted_contained_supervision(
    src_tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(_pgid: int) -> bool:
        raise KeyboardInterrupt("stop-contained")

    monkeypatch.setattr(supervision, "group_has_members", _boom)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    with pytest.raises(KeyboardInterrupt, match="stop-contained"):
        run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True)
    assert list(tmp_path.glob("attest-work-*")) == []
