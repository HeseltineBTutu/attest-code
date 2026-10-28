"""S2 supervision failure paths: unverifiable trees and spawn errors.

Runs on every platform; no process-group support required.
"""

from __future__ import annotations

import signal
from multiprocessing.context import SpawnProcess
from pathlib import Path
from typing import cast

import pytest
from supervision_harness import NEEDS_GROUPS, quick_pass

import attest_core.supervision as supervision
from attest_core.bounds import run_bounded
from attest_core.sandbox import SandboxWorkdir
from attest_spec import AttemptOutcome


def test_unverifiable_tree_is_cleanup_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervision, "group_has_members", lambda pgid: True)
    report = run_bounded(quick_pass, 10.0, grace_seconds=0.2)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "cleanup failed" in report.detail


def test_failed_spawn_cleans_workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    with pytest.raises(AttributeError, match="pickle"):
        run_bounded(lambda: None, 30.0)  # type: ignore[return-value,arg-type]
    assert list(tmp_path.glob("attest-work-*")) == []


def test_supervision_exception_still_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(pgid: object) -> bool:
        raise RuntimeError("supervision exploded")

    monkeypatch.setattr(supervision, "group_has_members", _boom)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    with pytest.raises(RuntimeError, match="exploded"):
        run_bounded(quick_pass, 30.0, grace_seconds=0.2)
    assert list(tmp_path.glob("attest-work-*")) == []


class _StubProc:
    """Minimal process double for deterministic exception-path tests."""

    def __init__(
        self, *, alive_then_dead: bool = False, join_exc: BaseException | None = None
    ) -> None:
        self.pid: int | None = 424242
        self.exitcode: int | None = None
        self._alive_then_dead = alive_then_dead
        self._join_exc = join_exc
        self._alive_calls = 0

    def is_alive(self) -> bool:
        self._alive_calls += 1
        if self._alive_then_dead:
            return self._alive_calls == 1
        return True

    def join(self, timeout: float | None = None) -> None:
        if self._join_exc is not None:
            raise self._join_exc

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None


def test_baseexception_kills_verified_group_and_reraises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc = _StubProc(alive_then_dead=True)
    signals: list[tuple[int, signal.Signals]] = []

    def _record(pgid: int, signum: signal.Signals) -> None:
        signals.append((pgid, signum))

    def _verified(_paths: SandboxWorkdir, _proc: SpawnProcess) -> int | None:
        return 424242

    def _boom(_pgid: int) -> bool:
        raise KeyboardInterrupt("stop-123")

    def _grouped() -> bool:
        return True

    monkeypatch.setattr(supervision, "supports_process_groups", _grouped)
    monkeypatch.setattr(supervision, "verified_pgid", _verified)
    monkeypatch.setattr(supervision, "signal_group", _record)
    monkeypatch.setattr(supervision, "group_has_members", _boom)
    with pytest.raises(KeyboardInterrupt, match="stop-123"):
        supervision.supervise_worker(
            cast(SpawnProcess, proc),
            cast(SandboxWorkdir, object()),
            timeout_seconds=10.0,
            grace_seconds=1.0,
        )
    assert signals == [(424242, signal.SIGTERM), (424242, signal.SIGKILL)]


def test_baseexception_before_verification_signals_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc = _StubProc(join_exc=KeyboardInterrupt("early-stop"))
    signals: list[tuple[int, signal.Signals]] = []
    verify_calls: list[None] = []

    def _record(pgid: int, signum: signal.Signals) -> None:
        signals.append((pgid, signum))

    def _verified(_paths: SandboxWorkdir, _proc: SpawnProcess) -> int | None:
        verify_calls.append(None)
        return 424242

    def _grouped() -> bool:
        return True

    monkeypatch.setattr(supervision, "supports_process_groups", _grouped)
    monkeypatch.setattr(supervision, "verified_pgid", _verified)
    monkeypatch.setattr(supervision, "signal_group", _record)
    with pytest.raises(KeyboardInterrupt, match="early-stop"):
        supervision.supervise_worker(
            cast(SpawnProcess, proc),
            cast(SandboxWorkdir, object()),
            timeout_seconds=10.0,
            grace_seconds=1.0,
        )
    assert signals == []
    assert verify_calls == []


def test_baseexception_cleanup_error_does_not_mask_original(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc = _StubProc(alive_then_dead=True)
    signals: list[tuple[int, signal.Signals]] = []

    def _flaky(pgid: int, signum: signal.Signals) -> None:
        signals.append((pgid, signum))
        if signum == signal.SIGKILL:
            raise RuntimeError("cleanup boom")

    def _verified(_paths: SandboxWorkdir, _proc: SpawnProcess) -> int | None:
        return 424243

    def _boom(_pgid: int) -> bool:
        raise KeyboardInterrupt("original-456")

    def _grouped() -> bool:
        return True

    monkeypatch.setattr(supervision, "supports_process_groups", _grouped)
    monkeypatch.setattr(supervision, "verified_pgid", _verified)
    monkeypatch.setattr(supervision, "signal_group", _flaky)
    monkeypatch.setattr(supervision, "group_has_members", _boom)
    with pytest.raises(KeyboardInterrupt, match="original-456"):
        supervision.supervise_worker(
            cast(SpawnProcess, proc),
            cast(SandboxWorkdir, object()),
            timeout_seconds=10.0,
            grace_seconds=1.0,
        )
    assert signals == [(424243, signal.SIGTERM), (424243, signal.SIGKILL)]


@NEEDS_GROUPS
def test_run_bounded_propagates_keyboardinterrupt_without_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(_pgid: int) -> bool:
        raise KeyboardInterrupt("probe-stop")

    monkeypatch.setattr(supervision, "group_has_members", _boom)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    with pytest.raises(KeyboardInterrupt, match="probe-stop"):
        run_bounded(quick_pass, 30.0, grace_seconds=0.2)
    assert list(tmp_path.glob("attest-work-*")) == []
