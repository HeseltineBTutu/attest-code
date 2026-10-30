"""Bounded worker execution: real wall-clock deadlines per attempt.

Each attempt runs in a spawned subprocess under the S1 sandbox policy
(minimal env, controlled workdir, per-attempt pycache, bounded JSON
result file). Deadline expiry terminates the tree (escalating to kill);
dead workers and missing/invalid results report as crashes or failures.
All classify as infrastructure failures, never violations. The worker
runs with operator privileges and must only execute verifier-owned
check code; the callable must be a picklable top-level reference, so
only parent-to-child pickling remains (trusted direction).
"""

from __future__ import annotations

import contextlib
import pickle
import secrets
from collections.abc import Callable
from pathlib import Path

from attest_core import scopes
from attest_core.contain import ContainedError, run_contained
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
from attest_core.ns_setup import supports_containment
from attest_core.origin import OriginError, check_origins, report_worker_origins
from attest_core.process_group import establish_worker_group
from attest_core.resource_evidence import collect_resources, with_resources
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
    func: Callable[[], AttemptReport],
    paths: SandboxWorkdir,
    snapshot_root: Path | None,
    contained: bool = False,
    scope_unit: str | None = None,
    bus_env: dict[str, str] | None = None,
    seccomp: bool = False,
) -> None:
    establish_worker_group(paths)
    if contained:
        try:
            run_contained(
                payload=pickle.dumps(func),
                snapshot_root=snapshot_root,
                paths=paths,
                scope_unit=scope_unit,
                bus_env=bus_env,
                seccomp=seccomp,
            )
        except ContainedError as exc:
            _finish(paths, encode_error(_clip(f"contained execution failed: {exc}")))
        return
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


def _infra(detail: str) -> AttemptReport:
    return AttemptReport(AttemptOutcome.INFRA_FAILURE, (), detail)


def run_bounded(
    func: Callable[[], AttemptReport],
    timeout_seconds: float,
    *,
    snapshot_root: Path | None = None,
    grace_seconds: float = TERMINATE_GRACE_SECONDS,
    contained: bool = False,
    quotas: bool = False,
    seccomp: bool = False,
) -> AttemptReport:
    """Run one attempt with a wall-clock deadline, terminating on expiry.

    The worker starts minimal (environment, workdir, result file) and is
    supervised to completion; timeouts terminate the tree (escalating to
    kill), and results are accepted only from a reaped worker whose tree
    is verified gone. Snapshot roots add origin self-checks; anything
    else fails as infrastructure failure. contained=True (Linux opt-in)
    runs checks in user+mount+PID+network namespaces; quotas=True adds
    a per-attempt systemd scope; seccomp=True adds a syscall denylist
    (both require contained=True). Unsupported hosts fail closed.
    """
    if timeout_seconds <= 0 or grace_seconds <= 0:
        raise ValueError("timeout_seconds and grace_seconds must be positive")
    if quotas and not contained:
        raise ValueError("quotas=True requires contained=True")
    if seccomp and not contained:
        raise ValueError("seccomp=True requires contained=True")
    paths = prepare_workdir()
    register_cleanup(paths.root)
    scope_unit: str | None = None
    bus_env: dict[str, str] | None = None
    try:
        if quotas:
            if not supports_containment() or not scopes.supports_quotas():
                return _infra("quota execution unsupported on this host")
            bus_env = scopes.launch_env()
            if bus_env is None:
                return _infra("quota execution unsupported on this host: no user bus address")
            scope_unit = f"attest-scope-{secrets.token_hex(8)}.scope"
        args = (func, paths, snapshot_root, contained, scope_unit, bus_env, seccomp)
        env = build_worker_environ({"PYTHONPYCACHEPREFIX": str(paths.pycache)})
        with guarded_spawn(_worker_main, args, environ=env, cwd=paths.root) as proc:
            supervised = supervise_worker(
                proc, paths, timeout_seconds=timeout_seconds, grace_seconds=grace_seconds
            )
            resources = collect_resources(scope_unit)
            if supervised.phase is WorkerPhase.CLEANUP_FAILED:
                detail = f"worker cleanup failed: {supervised.detail}" + failure_suffix(paths)
                return with_resources(_infra(detail), resources)
            if supervised.timed_out:
                detail = f"worker exceeded {timeout_seconds:g}s deadline and was terminated"
                return with_resources(_infra(detail + failure_suffix(paths)), resources)
            if supervised.exitcode != 0:
                crashed = _crashed(supervised.exitcode, failure_suffix(paths))
                return with_resources(crashed, resources)
            if scope_unit is not None:
                scope_error = scopes.terminate_scope_by_unit(scope_unit, scopes.QuotaLimits())
                scope_unit = None
                if scope_error is not None:
                    detail = f"scope teardown failed: {scope_error}{failure_suffix(paths)}"
                    return with_resources(_infra(detail), resources)
            try:
                report = decode_attempt_report(read_result_file(paths.result))
                return with_resources(report, resources)
            except SandboxEnvelopeError as exc:
                detail = f"worker result invalid: {exc}" + failure_suffix(paths)
                return with_resources(_infra(detail), resources)
    finally:
        if scope_unit is not None:
            scopes.terminate_scope_by_unit(scope_unit, scopes.QuotaLimits())
        cleanup_workdir(paths.root)
