"""Runner protocol: version probing, strict parsing, mismatch fails closed."""

from __future__ import annotations

from pathlib import Path

import pytest

import attest_core.contained_runner as runner_mod
from attest_core import runner_protocol
from attest_core.bounds import run_bounded
from attest_core.contain import ContainedError, run_contained
from attest_core.pidns_probes import probe_pid
from attest_core.sandbox import SandboxWorkdir
from attest_spec import AttemptOutcome


def _snapshot_with_runner(root: Path, body: str) -> Path:
    snap = root / "snap"
    mod = snap / "src" / "attest_core"
    mod.mkdir(parents=True)
    (mod / "contained_runner.py").write_text(body, encoding="utf-8")
    return snap


def _workdir(root: Path) -> SandboxWorkdir:
    return SandboxWorkdir(
        root=root,
        result=root / "r",
        stdout=root / "o",
        stderr=root / "e",
        pycache=root / "c",
        pgid=root / "g",
    )


def test_live_runner_advertises_current_protocol() -> None:
    live = Path(__file__).resolve().parents[3]
    assert runner_protocol.snapshot_protocol(live) == runner_protocol.RUNNER_PROTOCOL_VERSION
    assert runner_protocol.is_supported(runner_protocol.RUNNER_PROTOCOL_VERSION)


def test_legacy_protocol_detected(tmp_path: Path) -> None:
    snap = _snapshot_with_runner(tmp_path, "RUNNER_PROTOCOL_VERSION = 1\n")
    assert runner_protocol.snapshot_protocol(snap) == 1
    assert not runner_protocol.is_supported(1)


@pytest.mark.parametrize("body", ["x = 1\n", "RUNNER_PROTOCOL_VERSION = '2'\n", "def broken(:\n"])
def test_unknown_protocol_is_zero(tmp_path: Path, body: str) -> None:
    snap = _snapshot_with_runner(tmp_path, body)
    assert runner_protocol.snapshot_protocol(snap) == 0
    assert not runner_protocol.is_supported(0)


def test_newer_protocol_unsupported(tmp_path: Path) -> None:
    snap = _snapshot_with_runner(tmp_path, "RUNNER_PROTOCOL_VERSION = 99\n")
    assert runner_protocol.snapshot_protocol(snap) == 99
    assert not runner_protocol.is_supported(99)


def test_missing_runner_is_protocol_zero(tmp_path: Path) -> None:
    snap = tmp_path / "snap"
    (snap / "src" / "attest_core").mkdir(parents=True)
    assert runner_protocol.snapshot_protocol(snap) == 0


def test_run_contained_refuses_legacy_snapshot(tmp_path: Path) -> None:
    snap = _snapshot_with_runner(tmp_path, "RUNNER_PROTOCOL_VERSION = 1\n")
    with pytest.raises(ContainedError, match="protocol v1"):
        run_contained(payload=b"{}", snapshot_root=snap, paths=_workdir(tmp_path))


def test_contained_mismatch_is_infra_not_failed(tmp_path: Path) -> None:
    snap = _snapshot_with_runner(tmp_path, "RUNNER_PROTOCOL_VERSION = 1\n")
    report = run_bounded(probe_pid, 30.0, snapshot_root=snap, contained=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "protocol" in report.detail


def test_runner_rejects_bad_arities() -> None:
    assert runner_mod.main([]) == 2
    assert runner_mod.main(["a", "b"]) == 2
    assert runner_mod.main(["a", "b", "c", "d", "e", "f"]) == 2
    assert runner_mod.main(["/snap/src", "not-an-fd", "/stage"]) == 2


def test_runner_rejects_unknown_seccomp_flag() -> None:
    assert runner_mod.main(["/snap/src", "99", "/stage", "", "2"]) == 2
    assert runner_mod.main(["/snap/src", "99", "/stage", "", "yes"]) == 2


def test_runner_accepts_known_seccomp_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "_read_stdin_bounded", lambda: b"payload")
    calls: list[int] = []

    def _record(*args: object, **kwargs: object) -> int:
        calls.append(1)
        return 0

    monkeypatch.setattr(runner_mod, "run_mapped_child", _record)
    assert runner_mod.main(["/snap/src", "99", "/stage", "", ""]) == 0
    assert runner_mod.main(["/snap/src", "99", "/stage", "", "1"]) == 0
    assert len(calls) == 2
