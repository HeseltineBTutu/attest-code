"""M4 compat matrix: existing batteries rerun with enforcement on.

Duplicates representative probes from the M1/M2/bootstrap/quota/netns
batteries with seccomp=True. Any failure here is a compatibility break
to investigate, never a reason to weaken the denylist. The abstract
Unix-socket probe is excluded: AF_UNIX creation is pinned allowed by
the seccomp controls, and nothing in the policy touches sockets.
"""

from __future__ import annotations

import functools
import shutil
import socket
import time
from pathlib import Path

import pytest
from scope_helpers import NEEDS_QUOTAS

from attest_core.bounds import run_bounded
from attest_core.contain_probes import probe_snapshot_write
from attest_core.netns_probes import (
    probe_loopback_private,
    probe_no_inherited_sockets,
    probe_no_route_out,
)
from attest_core.ns_setup import supports_containment
from attest_core.pidns_probes import probe_exit, probe_hang, probe_module_origins, probe_pid
from attest_core.quota_probes import probe_burn_cpu
from attest_spec import AttemptOutcome

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="user+mount+PID+network namespaces unavailable"
)


@pytest.fixture(scope="session")
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("m4-compat-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _host_loopback_listener() -> tuple[socket.socket, int]:
    """Bound+listening 127.0.0.1 socket; caller must close it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock, int(sock.getsockname()[1])


@NEEDS_CONTAINMENT
def test_enforced_snapshot_write_denied(src_tree: Path) -> None:
    report = run_bounded(
        probe_snapshot_write, 30.0, snapshot_root=src_tree, contained=True, seccomp=True
    )
    assert report.outcome == AttemptOutcome.PASS


@NEEDS_CONTAINMENT
def test_enforced_pidns_lifecycle(src_tree: Path) -> None:
    report = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, seccomp=True)
    assert report.outcome == AttemptOutcome.PASS


@NEEDS_CONTAINMENT
def test_enforced_crash_is_infra(src_tree: Path) -> None:
    probe = functools.partial(probe_exit, 5)
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True, seccomp=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "exited 5" in report.detail


@NEEDS_CONTAINMENT
def test_enforced_timeout_terminates(src_tree: Path) -> None:
    start = time.monotonic()
    report = run_bounded(probe_hang, 3.0, snapshot_root=src_tree, contained=True, seccomp=True)
    elapsed = time.monotonic() - start
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "deadline" in report.detail
    assert elapsed < 3.0 + 2.0


@NEEDS_CONTAINMENT
def test_enforced_origins(src_tree: Path) -> None:
    report = run_bounded(
        probe_module_origins, 30.0, snapshot_root=src_tree, contained=True, seccomp=True
    )
    assert report.outcome == AttemptOutcome.PASS


@NEEDS_QUOTAS
def test_enforced_quota_burn(src_tree: Path) -> None:
    report = run_bounded(
        probe_burn_cpu, 60.0, snapshot_root=src_tree, contained=True, quotas=True, seccomp=True
    )
    assert report.outcome == AttemptOutcome.PASS


@NEEDS_CONTAINMENT
def test_enforced_no_route_out(src_tree: Path) -> None:
    report = run_bounded(
        probe_no_route_out, 30.0, snapshot_root=src_tree, contained=True, seccomp=True
    )
    assert report.outcome == AttemptOutcome.PASS


@NEEDS_CONTAINMENT
def test_enforced_no_inherited_sockets(src_tree: Path) -> None:
    report = run_bounded(
        probe_no_inherited_sockets, 30.0, snapshot_root=src_tree, contained=True, seccomp=True
    )
    assert report.outcome == AttemptOutcome.PASS


@NEEDS_CONTAINMENT
def test_enforced_loopback_private(src_tree: Path) -> None:
    sock, port = _host_loopback_listener()
    try:
        probe = functools.partial(probe_loopback_private, port)
        report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True, seccomp=True)
    finally:
        sock.close()
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == f"lo-private:{port}"
