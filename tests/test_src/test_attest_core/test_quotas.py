"""Quota-mode lifecycle: fail-closed selection, handoff, teardown (M3-A)."""

from __future__ import annotations

import contextlib
import pickle
import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from scope_helpers import pgid_members

import attest_core.contained_runner as contained_runner
import attest_core.supervision as supervision
from attest_core import scopes
from attest_core.bounds import run_bounded
from attest_core.contain import ContainedError, run_contained
from attest_core.ns_setup import supports_containment
from attest_core.pidns_probes import probe_pid
from attest_core.sandbox import SandboxWorkdir
from attest_spec import AttemptOutcome

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="user+mount+PID namespaces unavailable"
)


@pytest.fixture(scope="session")
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("quota-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _workdir(root: Path) -> SandboxWorkdir:
    return SandboxWorkdir(
        root=root,
        result=root / "r",
        stdout=root / "o",
        stderr=root / "e",
        pycache=root / "c",
        pgid=root / "g",
    )


def test_quotas_requires_contained() -> None:
    with pytest.raises(ValueError, match="contained"):
        run_bounded(probe_pid, 5.0, quotas=True)


def test_quotas_unsupported_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    func = Mock()
    monkeypatch.setattr(scopes, "supports_quotas", lambda: False)
    monkeypatch.setattr(
        "attest_core.bounds.guarded_spawn", Mock(side_effect=AssertionError("spawned"))
    )
    report = run_bounded(func, 5.0, snapshot_root=None, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "unsupported" in report.detail
    func.assert_not_called()


def test_invalid_scope_unit_fails_closed(tmp_path: Path) -> None:
    snap = tmp_path / "snap"
    (snap / "src" / "attest_core").mkdir(parents=True)
    with contextlib.suppress(FileNotFoundError), pytest.raises(ContainedError, match="exited"):
        run_contained(
            payload=pickle.dumps(probe_pid),
            snapshot_root=snap,
            paths=_workdir(tmp_path),
            scope_unit="not a unit",
            bus_env={"XDG_RUNTIME_DIR": "/nonexistent-bus-dir"},
        )


def test_launch_env_passes_bus_address_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.setenv("SECRET_LEAK", "nope")
    assert scopes.launch_env() == {
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "XDG_RUNTIME_DIR": "/run/user/1000",
    }


def test_launch_env_absent_without_bus(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert scopes.launch_env() is None


def test_quota_launch_splits_prefix_and_runner_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen_cmd: list[str] = []
    seen_env: dict[str, str] = {}

    def _spy_popen(cmd: list[str], **kwargs: Any) -> object:
        seen_cmd.extend(cmd)
        seen_env.update(kwargs["env"])
        raise RuntimeError("stop-after-capture")

    snap = tmp_path / "snap"
    (snap / "src" / "attest_core").mkdir(parents=True)
    monkeypatch.setattr(subprocess, "Popen", _spy_popen)
    bus = {"XDG_RUNTIME_DIR": "/run/user/1000"}
    with pytest.raises(RuntimeError, match="stop-after-capture"):
        run_contained(
            payload=b"{}",
            snapshot_root=snap,
            paths=_workdir(tmp_path),
            scope_unit="u.scope",
            bus_env=bus,
        )
    assert seen_env == bus
    assert seen_cmd[:4] == ["/usr/bin/systemd-run", "--user", "--quiet", "--scope"]
    dash = seen_cmd.index("--")
    assert seen_cmd[dash : dash + 4] == ["--", "/usr/bin/env", "-i", "LC_ALL=C.UTF-8"]


def test_quota_launch_without_bus_fails_closed(tmp_path: Path) -> None:
    snap = tmp_path / "snap"
    (snap / "src" / "attest_core").mkdir(parents=True)
    with pytest.raises(ContainedError, match="bus address"):
        run_contained(
            payload=b"{}", snapshot_root=snap, paths=_workdir(tmp_path), scope_unit="u.scope"
        )


@NEEDS_CONTAINMENT
def test_teardown_failure_rejects_result(src_tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("attest_core.bounds.supports_containment", lambda: True)
    monkeypatch.setattr(scopes, "supports_quotas", lambda: True)
    monkeypatch.setattr(scopes, "launch_env", lambda: {"XDG_RUNTIME_DIR": "/x"})
    monkeypatch.setattr(scopes, "terminate_scope_by_unit", lambda _u, _l: "boom")
    report = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "scope teardown failed" in report.detail


@NEEDS_CONTAINMENT
def test_interruption_terminates_scope(
    src_tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attest_core.bounds.supports_containment", lambda: True)
    monkeypatch.setattr(scopes, "supports_quotas", lambda: True)
    monkeypatch.setattr(scopes, "launch_env", lambda: {"XDG_RUNTIME_DIR": "/x"})
    calls: list[object] = []
    monkeypatch.setattr(scopes, "terminate_scope_by_unit", lambda u, _l: calls.append(u))

    def _boom(_pgid: int) -> bool:
        raise KeyboardInterrupt("stop-quota")

    monkeypatch.setattr(supervision, "group_has_members", _boom)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    with pytest.raises(KeyboardInterrupt, match="stop-quota"):
        run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert len(calls) == 1
    assert str(calls[0]).startswith("attest-scope-")
    assert list(tmp_path.glob("attest-work-*")) == []


def test_runner_main_rejects_misplaced_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contained_runner, "_read_stdin_bounded", lambda: b"payload")

    def _no_fork(*args: object, **kwargs: object) -> int:
        raise AssertionError("must not fork when misplaced")

    monkeypatch.setattr(contained_runner, "run_mapped_child", _no_fork)
    assert contained_runner.main(["/snap/src", "99", "/stage", "/sys/fs/cgroup"]) == 2


def test_runner_main_accepts_placed_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    with open("/proc/self/cgroup", encoding="ascii") as handle:
        own = handle.read().strip()
    assert own.startswith("0::/")
    leaf = own.rsplit("/", 1)[-1]
    assert leaf
    monkeypatch.setattr(contained_runner, "_read_stdin_bounded", lambda: b"payload")
    calls: list[object] = []

    def _fake_mapped(child_main: object, parent_close: object = ()) -> int:
        calls.append((child_main, parent_close))
        return 0

    monkeypatch.setattr(contained_runner, "run_mapped_child", _fake_mapped)
    before = pgid_members()
    assert contained_runner.main(["/snap/src", "99", "/stage", leaf]) == 0
    assert len(calls) == 1
    assert pgid_members() <= before
