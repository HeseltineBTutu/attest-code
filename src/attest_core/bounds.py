"""Bounded worker execution: real wall-clock deadlines per attempt.

Each attempt runs in a spawned subprocess under the S1 sandbox policy:
minimal environment, controlled working directory, per-attempt
bytecode cache, and a bounded JSON result file instead of pickle IPC. A
worker that exceeds its deadline is terminated; a worker that dies, or
whose result is missing or invalid, is reported as crashed or failed.
All classify as infrastructure failures (INCONCLUSIVE), never as
violations.

This is execution bounding plus exposure reduction, not a security
sandbox: the worker runs with the operator's privileges and must only
execute verifier-owned check code. The worker callable must be
picklable (a top-level function reference); only parent-to-child
pickling remains, which is trusted-direction data.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from pathlib import Path

from attest_core.envelope import (
    MAX_DETAIL_CHARS,
    MAX_RESULT_BYTES,
    SandboxEnvelopeError,
    decode_attempt_report,
    encode_attempt_report,
    encode_error,
    read_result_file,
    write_result_file,
)
from attest_core.origin import OriginError, check_origins, report_worker_origins
from attest_core.process_group import establish_worker_group
from attest_core.sandbox import (
    TERMINATE_GRACE_SECONDS,
    SandboxWorkdir,
    build_worker_environ,
    cleanup_workdir,
    enter_worker_context,
    failure_suffix,
    guarded_spawn,
    prepare_workdir,
    register_cleanup,
)
from attest_core.supervision import WorkerPhase, supervise_worker
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome


def _clip(text: str) -> str:
    """Bound worker-side diagnostic text with an explicit truncation marker."""
    if len(text) > MAX_DETAIL_CHARS:
        return text[:MAX_DETAIL_CHARS] + "[truncated]"
    return text


def _finish(paths: SandboxWorkdir, payload: str) -> None:
    if len(payload.encode("utf-8")) > MAX_RESULT_BYTES:
        payload = encode_error(f"worker result exceeds {MAX_RESULT_BYTES} bytes")
    write_result_file(paths.result, payload)


def _worker_main(
    func: Callable[[], AttemptReport], paths: SandboxWorkdir, snapshot_root: Path | None
) -> None:
    establish_worker_group(paths)
    enter_worker_context(paths)
    try:
        if snapshot_root is not None:
            try:
                check_origins(report_worker_origins(), snapshot_root, actor="attempt worker")
            except OriginError as exc:
                _finish(paths, encode_error(_clip(f"worker origin self-check failed: {exc}")))
                return
        try:
            report = func()
        except Exception as exc:
            _finish(paths, encode_error(_clip(f"{type(exc).__name__}: {exc}")))
            return
        _finish(paths, encode_attempt_report(report))
    except Exception as exc:
        with contextlib.suppress(OSError):
            _finish(paths, encode_error(f"worker result failed: {type(exc).__name__}"))


def _crashed(exitcode: object, suffix: str) -> AttemptReport:
    return AttemptReport(
        AttemptOutcome.INFRA_FAILURE, (), f"worker crashed (exit code {exitcode}){suffix}"
    )


def run_bounded(
    func: Callable[[], AttemptReport],
    timeout_seconds: float,
    *,
    snapshot_root: Path | None = None,
    grace_seconds: float = TERMINATE_GRACE_SECONDS,
) -> AttemptReport:
    """Run one attempt with a wall-clock deadline, terminating on expiry.

    The worker starts with a minimal environment and controlled working
    directory, writes a bounded JSON result file, and is supervised to
    completion: on timeout the supervised tree is terminated (escalating
    to kill), and a result is only accepted from a reaped worker whose
    tree is verified gone. When a snapshot root is given, the worker
    verifies its own first-party origins resolve beneath it before
    running checks; anything else fails the attempt as an infrastructure
    failure.
    """
    if timeout_seconds <= 0 or grace_seconds <= 0:
        raise ValueError("timeout_seconds and grace_seconds must be positive")
    paths = prepare_workdir()
    register_cleanup(paths.root)
    try:
        env = build_worker_environ({"PYTHONPYCACHEPREFIX": str(paths.pycache)})
        with guarded_spawn(
            _worker_main, (func, paths, snapshot_root), environ=env, cwd=paths.root
        ) as proc:
            supervised = supervise_worker(
                proc, paths, timeout_seconds=timeout_seconds, grace_seconds=grace_seconds
            )
            if supervised.phase is WorkerPhase.CLEANUP_FAILED:
                return AttemptReport(
                    AttemptOutcome.INFRA_FAILURE,
                    (),
                    f"worker cleanup failed: {supervised.detail}" + failure_suffix(paths),
                )
            if supervised.timed_out:
                return AttemptReport(
                    AttemptOutcome.INFRA_FAILURE,
                    (),
                    f"worker exceeded {timeout_seconds:g}s deadline and was terminated"
                    + failure_suffix(paths),
                )
            if supervised.exitcode != 0:
                return _crashed(supervised.exitcode, failure_suffix(paths))
            try:
                return decode_attempt_report(read_result_file(paths.result))
            except SandboxEnvelopeError as exc:
                return AttemptReport(
                    AttemptOutcome.INFRA_FAILURE,
                    (),
                    f"worker result invalid: {exc}" + failure_suffix(paths),
                )
    finally:
        cleanup_workdir(paths.root)
