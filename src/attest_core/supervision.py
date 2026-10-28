"""Process-tree supervision orchestration (S2): wait, escalate, reap, verify.

The parent waits with a deadline, then escalates group SIGTERM →
group SIGKILL, reaps the direct child, and verifies the tree is gone
before any result is accepted. Cleanup failures are explicit and can
never yield a clean result.

A process group is ordinary supervision, not an unbreakable boundary:
a hostile descendant may detach into another session. Windows and
platforms without process groups use documented single-process
supervision instead.
"""

from __future__ import annotations

import contextlib
import dataclasses
import enum
import signal
import time
from multiprocessing.context import SpawnProcess

from attest_core.process_group import (
    signal_group,
    supports_process_groups,
    verified_pgid,
)
from attest_core.sandbox import SandboxWorkdir
from attest_core.tree_inspection import group_has_members

TREE_SETTLE_SECONDS = 2.0
"""Bounded window for transient group membership to clear after reaping."""

_POLL_INTERVAL_SECONDS = 0.02


class WorkerPhase(enum.Enum):
    """Supervision lifecycle; only REAPED accepts the attempt as clean."""

    CREATED = "created"
    RUNNING = "running"
    TERMINATING = "terminating"
    KILLING = "killing"
    REAPED = "reaped"
    CLEANUP_FAILED = "cleanup_failed"


@dataclasses.dataclass(frozen=True)
class SupervisedExit:
    """Terminal supervision outcome; failures stay infrastructure-grade."""

    phase: WorkerPhase
    exitcode: int | None
    timed_out: bool
    detail: str


def _tree_quiet(proc: SpawnProcess, pgid: int | None) -> bool:
    if proc.is_alive():
        return False
    proc.join()
    return pgid is None or not group_has_members(pgid)


def _wait_tree_gone(proc: SpawnProcess, pgid: int | None, budget_seconds: float) -> bool:
    deadline = time.monotonic() + max(0.0, budget_seconds)
    while True:
        if _tree_quiet(proc, pgid):
            if pgid is None:
                return True
            # Precautionary final sweep: a descendant forked during the last
            # observation could otherwise escape it. No-op when truly empty.
            signal_group(pgid, signal.SIGKILL)
            if _tree_quiet(proc, pgid):
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_INTERVAL_SECONDS)


def supervise_worker(
    proc: SpawnProcess,
    paths: SandboxWorkdir,
    *,
    timeout_seconds: float,
    grace_seconds: float,
) -> SupervisedExit:
    """Wait with a deadline, escalate, reap, and verify the tree is gone.

    Group-capable path: TERM the verified group, then KILL it, then
    require verified emptiness. Anything unverified — missing handshake,
    surviving members — is CLEANUP_FAILED, never clean. Without group
    support the direct child alone is supervised (documented limit).
    Safe to call again on an exited worker; never blocks unboundedly.
    A BaseException during supervision best-effort KILLs the
    already-verified group once, then re-raises; never returns a
    result after interruption.
    """
    if timeout_seconds <= 0 or grace_seconds <= 0:
        raise ValueError("timeout_seconds and grace_seconds must be positive")
    grouped = supports_process_groups()
    verified: int | None = None
    try:
        proc.join(timeout_seconds)
        if proc.is_alive():
            # No handshake yet means the worker never reached its check
            # callable: only trusted startup/imports ran, which cannot spawn
            # descendants, so reaping the direct child completes cleanup.
            # Anything still present afterwards is a real failure.
            pgid = verified_pgid(paths, proc) if grouped else None
            verified = pgid
            if pgid is not None:
                signal_group(pgid, signal.SIGTERM)
            proc.terminate()
            if _wait_tree_gone(proc, pgid, grace_seconds):
                return SupervisedExit(
                    WorkerPhase.REAPED, proc.exitcode, True, "terminated after deadline"
                )
            if pgid is not None:
                signal_group(pgid, signal.SIGKILL)
            proc.kill()
            if _wait_tree_gone(proc, pgid, grace_seconds):
                return SupervisedExit(
                    WorkerPhase.REAPED, proc.exitcode, True, "killed after deadline"
                )
            return SupervisedExit(
                WorkerPhase.CLEANUP_FAILED,
                proc.exitcode,
                True,
                "timed out; supervised processes remain",
            )
        proc.join()
        exitcode = proc.exitcode
        if not grouped:
            return SupervisedExit(WorkerPhase.REAPED, exitcode, False, "reaped")
        pgid = verified_pgid(paths, proc)
        if pgid is None:
            return SupervisedExit(
                WorkerPhase.CLEANUP_FAILED,
                exitcode,
                False,
                "supervision handshake missing or invalid",
            )
        verified = pgid
        if _wait_tree_gone(proc, pgid, TREE_SETTLE_SECONDS):
            return SupervisedExit(WorkerPhase.REAPED, exitcode, False, "reaped")
        signal_group(pgid, signal.SIGTERM)
        if not _wait_tree_gone(proc, pgid, grace_seconds):
            signal_group(pgid, signal.SIGKILL)
            _wait_tree_gone(proc, pgid, grace_seconds)
        return SupervisedExit(
            WorkerPhase.CLEANUP_FAILED, exitcode, False, "supervised processes remain after exit"
        )
    except BaseException:
        if verified is not None:
            with contextlib.suppress(BaseException):
                signal_group(verified, signal.SIGKILL)
        raise
