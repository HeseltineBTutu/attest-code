"""M3-B network-isolation battery: default-deny traffic enforcement.

Proves checks in a fresh network namespace cannot reach external,
private, metadata, DNS, host-loopback, or abstract-socket
destinations; that the workload's own loopback is private to it
(the same address+port binds twice); that no sockets are inherited;
and that M3-A quotas still hold in one combined attempt. Host-side
listeners stay bound while probes run so refusals prove isolation,
not absence.
"""

from __future__ import annotations

import contextlib
import functools
import secrets
import shutil
import socket
from pathlib import Path

import pytest
from scope_helpers import NEEDS_QUOTAS

from attest_core.bounds import run_bounded
from attest_core.netns_probes import (
    probe_abstract_unreachable,
    probe_dns_dead,
    probe_loopback_private,
    probe_metadata_unreachable,
    probe_net_and_tasks,
    probe_no_inherited_sockets,
    probe_no_route_out,
)
from attest_core.ns_setup import supports_containment
from attest_spec import AttemptOutcome

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="user+mount+PID+network namespaces unavailable"
)


def _can_bind_abstract() -> bool:
    """Whether this host can build the abstract-socket fixture (no residue)."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError:
        return False
    with contextlib.closing(sock):
        try:
            sock.bind("\0attest-netns-probe")
        except OSError:
            return False
    return True


NEEDS_ABSTRACT = pytest.mark.skipif(
    not _can_bind_abstract(), reason="abstract Unix sockets unavailable"
)


@pytest.fixture(scope="session")
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("m3b-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _host_loopback_listener() -> tuple[socket.socket, int]:
    """Bound+listening 127.0.0.1 socket; caller must close it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock, int(sock.getsockname()[1])


def _host_abstract_listener(token: str) -> socket.socket:
    """Bound+listening abstract Unix socket; caller must close it."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind("\0" + token)
    sock.listen(1)
    return sock


@NEEDS_CONTAINMENT
def test_netns_no_route_out(src_tree: Path) -> None:
    report = run_bounded(probe_no_route_out, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "no-route-out"


@NEEDS_CONTAINMENT
def test_netns_dns_dead(src_tree: Path) -> None:
    report = run_bounded(probe_dns_dead, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "dns-dead"


@NEEDS_CONTAINMENT
def test_netns_metadata_unreachable(src_tree: Path) -> None:
    report = run_bounded(probe_metadata_unreachable, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "metadata-unreachable"


@NEEDS_CONTAINMENT
def test_netns_host_loopback_private(src_tree: Path) -> None:
    sock, port = _host_loopback_listener()
    try:
        probe = functools.partial(probe_loopback_private, port)
        report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True)
    finally:
        sock.close()
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == f"lo-private:{port}"


@NEEDS_CONTAINMENT
@NEEDS_ABSTRACT
def test_netns_abstract_unreachable(src_tree: Path) -> None:
    token = f"attest-netns-{secrets.token_hex(4)}"
    sock = _host_abstract_listener(token)
    try:
        probe = functools.partial(probe_abstract_unreachable, token)
        report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True)
    finally:
        sock.close()
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "abstract-unreachable"


@NEEDS_CONTAINMENT
def test_netns_no_inherited_sockets(src_tree: Path) -> None:
    report = run_bounded(probe_no_inherited_sockets, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail.startswith("sockets:0/")


@NEEDS_QUOTAS
def test_netns_tasks_and_net_combined(src_tree: Path) -> None:
    report = run_bounded(
        probe_net_and_tasks, 60.0, snapshot_root=src_tree, contained=True, quotas=True
    )
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail.startswith("combined:")
