"""Bounded worker execution: real wall-clock deadlines per attempt.

Each attempt runs in a spawned subprocess. A worker that exceeds its
deadline is terminated; a worker that dies is reported as crashed. Both
classify as infrastructure failures (INCONCLUSIVE), never as violations.

This is execution bounding, not a security sandbox: the worker runs with
the operator's privileges and must only execute verifier-owned check code.
The worker callable must be picklable (a top-level function reference).
"""

from __future__ import annotations

import multiprocessing
from collections.abc import Callable
from multiprocessing.connection import Connection

from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome

_TERMINATE_GRACE_SECONDS = 10


def _worker_main(func: Callable[[], AttemptReport], conn: Connection) -> None:
    try:
        conn.send(("ok", func()))
    except Exception as exc:
        conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()


def _crashed(exitcode: object) -> AttemptReport:
    return AttemptReport(AttemptOutcome.INFRA_FAILURE, (), f"worker crashed (exit code {exitcode})")


def run_bounded(func: Callable[[], AttemptReport], timeout_seconds: float) -> AttemptReport:
    """Run one attempt with a wall-clock deadline, terminating on expiry."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    ctx = multiprocessing.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_worker_main, args=(func, child_conn), daemon=True)
    proc.start()
    child_conn.close()
    try:
        if parent_conn.poll(timeout_seconds):
            try:
                kind, payload = parent_conn.recv()
            except EOFError:
                proc.join(_TERMINATE_GRACE_SECONDS)
                return _crashed(proc.exitcode)
            proc.join(_TERMINATE_GRACE_SECONDS)
            if kind == "ok" and isinstance(payload, AttemptReport):
                return payload
            return AttemptReport(AttemptOutcome.INFRA_FAILURE, (), f"worker error: {payload}")
        if proc.is_alive():
            proc.terminate()
            proc.join(_TERMINATE_GRACE_SECONDS)
            if proc.is_alive():
                proc.kill()
                proc.join(_TERMINATE_GRACE_SECONDS)
            return AttemptReport(
                AttemptOutcome.INFRA_FAILURE,
                (),
                f"worker exceeded {timeout_seconds:g}s deadline and was terminated",
            )
        proc.join(_TERMINATE_GRACE_SECONDS)
        return _crashed(proc.exitcode)
    finally:
        parent_conn.close()
        if proc.is_alive():
            proc.kill()
            proc.join(_TERMINATE_GRACE_SECONDS)
