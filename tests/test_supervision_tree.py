"""S2 group lifecycle: real descendants time out, escalate, and are reaped.

Skips explicitly where process groups are unsupported.
"""

from __future__ import annotations

import functools
import signal
import time
from pathlib import Path

from supervision_harness import (
    NEEDS_GROUPS,
    SLEEP_SECONDS,
    eventually_dead,
    grouped_quick_exit,
    ignore_term_and_hang,
    kill_all,
    read_pids,
    spawn_child_and_hang,
    spawn_child_and_return,
    spawn_grandchild_tree,
    spawn_termproof_child_and_hang,
    wait_for_pidfile,
)

import attest_core.tree_inspection as tree_inspection
from attest_core.bounds import _worker_main, run_bounded
from attest_core.process_group import signal_group
from attest_core.sandbox import (
    build_worker_environ,
    cleanup_workdir,
    guarded_spawn,
    prepare_workdir,
)
from attest_core.supervision import WorkerPhase, supervise_worker
from attest_spec import AttemptOutcome


@NEEDS_GROUPS
def test_tree_termination_on_timeout(tmp_path: Path) -> None:
    pid_dir = tmp_path / "pids"
    pid_dir.mkdir()
    paths = prepare_workdir()
    try:
        env = build_worker_environ()
        with guarded_spawn(
            _worker_main,
            (functools.partial(spawn_child_and_hang, str(pid_dir)), paths, None),
            environ=env,
            cwd=paths.root,
        ) as proc:
            assert proc.pid is not None
            supervised = supervise_worker(proc, paths, timeout_seconds=8, grace_seconds=1.0)
            assert supervised.phase is WorkerPhase.REAPED
            assert supervised.timed_out
            assert proc.exitcode is not None
        children = read_pids(pid_dir)
        assert len(children) == 1
        assert eventually_dead(children[0])
    finally:
        kill_all(pid_dir)
        cleanup_workdir(paths.root)


@NEEDS_GROUPS
def test_grandchild_termination_on_timeout(tmp_path: Path) -> None:
    pid_dir = tmp_path / "pids"
    pid_dir.mkdir()
    paths = prepare_workdir()
    try:
        env = build_worker_environ()
        with guarded_spawn(
            _worker_main,
            (functools.partial(spawn_grandchild_tree, str(pid_dir)), paths, None),
            environ=env,
            cwd=paths.root,
        ) as proc:
            supervised = supervise_worker(proc, paths, timeout_seconds=10, grace_seconds=1.0)
            assert supervised.phase is WorkerPhase.REAPED
            assert supervised.timed_out
        assert eventually_dead(wait_for_pidfile(pid_dir, "child.pid"))
        assert eventually_dead(wait_for_pidfile(pid_dir, "grandchild.pid"))
    finally:
        kill_all(pid_dir)
        cleanup_workdir(paths.root)


@NEEDS_GROUPS
def test_termproof_worker_escalates_to_kill() -> None:
    start = time.monotonic()
    report = run_bounded(ignore_term_and_hang, 6.0, grace_seconds=1.0)
    elapsed = time.monotonic() - start
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "deadline" in report.detail
    assert elapsed < SLEEP_SECONDS


@NEEDS_GROUPS
def test_termproof_child_escalates_to_kill(tmp_path: Path) -> None:
    pid_dir = tmp_path / "pids"
    pid_dir.mkdir()
    try:
        report = run_bounded(
            functools.partial(spawn_termproof_child_and_hang, str(pid_dir)),
            8.0,
            grace_seconds=1.0,
        )
        assert report.outcome == AttemptOutcome.INFRA_FAILURE
        assert "deadline" in report.detail
        children = read_pids(pid_dir)
        assert len(children) == 1
        assert eventually_dead(children[0])
    finally:
        kill_all(pid_dir)


@NEEDS_GROUPS
def test_exit_with_live_child_is_cleanup_failure(tmp_path: Path) -> None:
    pid_dir = tmp_path / "pids"
    pid_dir.mkdir()
    try:
        report = run_bounded(
            functools.partial(spawn_child_and_return, str(pid_dir)), 30.0, grace_seconds=1.0
        )
        assert report.outcome == AttemptOutcome.INFRA_FAILURE
        assert "cleanup failed" in report.detail
        assert "remain" in report.detail
        children = read_pids(pid_dir)
        assert len(children) == 1
        assert eventually_dead(children[0])
    finally:
        kill_all(pid_dir)


@NEEDS_GROUPS
def test_supervise_exited_worker_and_repeat_supervision(tmp_path: Path) -> None:
    paths = prepare_workdir()
    try:
        env = build_worker_environ()
        with guarded_spawn(grouped_quick_exit, (paths,), environ=env, cwd=paths.root) as proc:
            first = supervise_worker(proc, paths, timeout_seconds=30, grace_seconds=1.0)
            assert first.phase is WorkerPhase.REAPED
            assert not first.timed_out
            assert first.exitcode == 0
            second = supervise_worker(proc, paths, timeout_seconds=30, grace_seconds=1.0)
            assert second.phase in (WorkerPhase.REAPED, WorkerPhase.CLEANUP_FAILED)
            assert second.exitcode == 0
    finally:
        cleanup_workdir(paths.root)


@NEEDS_GROUPS
def test_group_signal_tolerates_dead_group() -> None:
    paths = prepare_workdir()
    try:
        env = build_worker_environ()
        with guarded_spawn(grouped_quick_exit, (paths,), environ=env, cwd=paths.root) as proc:
            out = supervise_worker(proc, paths, timeout_seconds=30, grace_seconds=0.5)
            assert out.phase is WorkerPhase.REAPED
        pgid = int(paths.pgid.read_text(encoding="ascii").strip())
        signal_group(pgid, signal.SIGKILL)
        assert tree_inspection.group_has_members(pgid) is False
    finally:
        cleanup_workdir(paths.root)
