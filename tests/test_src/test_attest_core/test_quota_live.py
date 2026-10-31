"""Live quota enforcement: end-to-end runs inside real scopes (M3-A)."""

from __future__ import annotations

import functools
import os
import secrets
import shutil
import tempfile
import time
from pathlib import Path

import pytest
from scope_helpers import NEEDS_QUOTAS

from attest_core import scopes
from attest_core.bounds import run_bounded
from attest_core.contain_probes import probe_big_detail
from attest_core.pidns_probes import probe_detached_sleeper, probe_exit, probe_hang, probe_pid
from attest_core.quota_probes import (
    probe_burn_cpu,
    probe_fork_many,
    probe_hog_memory,
    probe_no_cgroupfs,
)
from attest_core.resource_evidence import parse_resources
from attest_spec import AttemptOutcome


@pytest.fixture(scope="session")
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("quota-live-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _no_survivors(token: str) -> None:
    """Poll until no host command line carries the sleeper token."""
    deadline = time.monotonic() + 5.0
    while True:
        alive = False
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as handle:
                    if token in handle.read().decode("utf-8", "replace"):
                        alive = True
            except OSError:
                continue
        if not alive:
            return
        assert time.monotonic() < deadline, f"sleeper survived teardown: {token}"
        time.sleep(0.05)


@NEEDS_QUOTAS
def test_quota_no_cgroup_interface(src_tree: Path) -> None:
    report = run_bounded(
        probe_no_cgroupfs, 30.0, snapshot_root=src_tree, contained=True, quotas=True
    )
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "no-cgroup-interface"


@NEEDS_QUOTAS
def test_quota_normal_check_preserved(src_tree: Path) -> None:
    report = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "pid:1"


@NEEDS_QUOTAS
def test_quota_oom_is_infra_not_violation(src_tree: Path) -> None:
    report = run_bounded(
        probe_hog_memory, 60.0, snapshot_root=src_tree, contained=True, quotas=True
    )
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "exited" in report.detail


@NEEDS_QUOTAS
def test_quota_tasks_capped(src_tree: Path) -> None:
    report = run_bounded(probe_fork_many, 60.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail.startswith("forks-capped:")
    assert int(report.detail.split(":")[1]) < 70


@NEEDS_QUOTAS
def test_quota_cpu_burn_completes(src_tree: Path) -> None:
    report = run_bounded(probe_burn_cpu, 60.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "burned:4x2s"


@NEEDS_QUOTAS
def test_quota_timeout_terminates_and_cleans(
    src_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = scopes.terminate_scope_by_unit

    def _spy(unit: str, limits: scopes.QuotaLimits) -> str | None:
        calls.append(unit)
        return real(unit, limits)

    monkeypatch.setattr(scopes, "terminate_scope_by_unit", _spy)
    start = time.monotonic()
    report = run_bounded(probe_hang, 3.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "deadline" in report.detail
    assert time.monotonic() - start < 5.0
    assert len(calls) == 1


@NEEDS_QUOTAS
def test_quota_crash_is_infra_not_violation(src_tree: Path) -> None:
    probe = functools.partial(probe_exit, 5)
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "exited 5" in report.detail


@pytest.fixture
def token_tmpdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Unique-token TMPDIR so the runner family is host-identifiable.

    The worker stage lands under TMPDIR and the stage path rides the
    runner command line, which every fork descendant inherits. The
    stdlib tempdir is patched alongside the env var because it caches
    the default dir; env alone would be silently ignored mid-suite.
    """
    token = f"qscope{secrets.token_hex(4)}"
    staged = tmp_path / token
    staged.mkdir()
    monkeypatch.setenv("TMPDIR", str(staged))
    monkeypatch.setattr(tempfile, "tempdir", str(staged))
    return token


@NEEDS_QUOTAS
def test_quota_detached_descendant_reaped(src_tree: Path, token_tmpdir: str) -> None:
    probe = functools.partial(probe_detached_sleeper, token_tmpdir)
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == f"sleeper-alive:{token_tmpdir}"
    _no_survivors(token_tmpdir)


@NEEDS_QUOTAS
def test_quota_malformed_result_rejected(src_tree: Path) -> None:
    report = run_bounded(
        probe_big_detail, 30.0, snapshot_root=src_tree, contained=True, quotas=True
    )
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "invalid" in report.detail


@NEEDS_QUOTAS
def test_hardened_oom_reports_resources(src_tree: Path) -> None:
    report = run_bounded(
        probe_hog_memory,
        60.0,
        snapshot_root=src_tree,
        contained=True,
        quotas=True,
        seccomp=True,
    )
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "[resources]" not in report.detail
    assert "[resources]" in report.resources


@NEEDS_QUOTAS
def test_hardened_burn_reports_counters(src_tree: Path) -> None:
    report = run_bounded(
        probe_burn_cpu,
        60.0,
        snapshot_root=src_tree,
        contained=True,
        quotas=True,
        seccomp=True,
    )
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "burned:4x2s"
    assert "throttled_usec=" in report.resources
    assert "mem_peak=" in report.resources
    assert "pids_peak=" in report.resources
    assert "cpu_usec=" in report.resources
    assert "teardown=empty-verified" in report.resources
    parsed = parse_resources(report.resources)
    assert parsed["mem_peak"] is not None and parsed["mem_peak"] > 0
    assert parsed["cpu_usec"] is not None and parsed["cpu_usec"] > 0
