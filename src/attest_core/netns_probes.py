"""M3-B network probes: default-deny traffic enforcement in a fresh netns.

Each probe exercises one network boundary and reports PASS only when
the operating system denies it; unexpected reachability yields
VIOLATION with an ALLOWED marker. Probes run inside the contained
runner via ``run_bounded(..., contained=True)``; they are imported
there from the snapshot, so they must stay top-level and picklable
by reference. Shared markers come from :mod:`attest_core.contain_probes`.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import signal
import socket
import stat
import struct
import time
from collections.abc import Callable

from attest_core.contain_probes import mark_allowed, require_ns
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome

_SIOCGIFFLAGS = 0x8913
_SIOCSIFFLAGS = 0x8914
_IFF_UP = 0x1
_TIMEOUT = 5.0

_EXTERNAL = (("8.8.8.8", 53), ("1.1.1.1", 443), ("10.255.255.1", 80), ("192.168.255.1", 80))
_EXTERNAL6 = ("2606:4700:4700::1111", 443)
_METADATA = (("169.254.169.254", 80), ("100.100.100.200", 80), ("fd00:ec2::254", 80))


def _must_fail(label: str, func: Callable[..., object], *args: object) -> AttemptReport | None:
    """None when func raises OSError; ALLOWED report when it succeeds."""
    try:
        func(*args)
    except OSError:
        return None
    return mark_allowed(label)


def _tcp_connect(host: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(_TIMEOUT)
        sock.connect((host, port))


def _udp_sendto(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(_TIMEOUT)
        sock.sendto(b"\x00" * 12, (host, port))


def _unix_connect(address: str) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(_TIMEOUT)
        sock.connect(address)


def _interface_up(name: str) -> None:
    """Raise one interface in the workload's own netns (CAP_NET_ADMIN held)."""
    buf = bytearray(40)
    buf[: len(name)] = name.encode("ascii")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        fcntl.ioctl(sock.fileno(), _SIOCGIFFLAGS, buf)
        flags = struct.unpack_from("H", buf, 16)[0]
        struct.pack_into("H", buf, 16, flags | _IFF_UP)
        fcntl.ioctl(sock.fileno(), _SIOCSIFFLAGS, buf)


def probe_no_route_out() -> AttemptReport:
    """External, private, and IPv6 destinations must all be unreachable."""
    if (missing := require_ns()) is not None:
        return missing
    for host, port in (*_EXTERNAL, _EXTERNAL6):
        if (hit := _must_fail(f"route-to-{host}", _tcp_connect, host, port)) is not None:
            return hit
    if (hit := _must_fail("udp-to-resolver", _udp_sendto, "8.8.8.8", 53)) is not None:
        return hit
    return AttemptReport(AttemptOutcome.PASS, (), "no-route-out")


def probe_dns_dead() -> AttemptReport:
    """Name resolution must fail: no resolver is reachable."""
    if (missing := require_ns()) is not None:
        return missing
    if (hit := _must_fail("dns-resolved", socket.getaddrinfo, "example.com", 80)) is not None:
        return hit
    return AttemptReport(AttemptOutcome.PASS, (), "dns-dead")


def probe_metadata_unreachable() -> AttemptReport:
    """Cloud metadata endpoints must be unreachable."""
    if (missing := require_ns()) is not None:
        return missing
    for host, port in _METADATA:
        if (hit := _must_fail(f"route-to-{host}", _tcp_connect, host, port)) is not None:
            return hit
    return AttemptReport(AttemptOutcome.PASS, (), "metadata-unreachable")


def probe_loopback_private(port: int) -> AttemptReport:
    """Host loopback must be unreachable; own loopback stays private."""
    if (missing := require_ns()) is not None:
        return missing
    if (hit := _must_fail(f"host-loopback-{port}", _tcp_connect, "127.0.0.1", port)) is not None:
        return hit
    try:
        _interface_up("lo")
    except OSError:
        return mark_allowed("lo-up-failed")
    try:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as own:
            own.bind(("127.0.0.1", port))
            own.listen(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
                peer.settimeout(_TIMEOUT)
                peer.connect(("127.0.0.1", port))
    except OSError:
        return mark_allowed(f"loopback-not-private-{port}")
    return AttemptReport(AttemptOutcome.PASS, (), f"lo-private:{port}")


def probe_abstract_unreachable(token: str) -> AttemptReport:
    """Host abstract Unix sockets must be unreachable (netns-scoped)."""
    if (missing := require_ns()) is not None:
        return missing
    address = "\0" + token
    if (hit := _must_fail(f"abstract-{token}", _unix_connect, address)) is not None:
        return hit
    return AttemptReport(AttemptOutcome.PASS, (), "abstract-unreachable")


def probe_no_inherited_sockets() -> AttemptReport:
    """No file descriptor at check time may be a socket."""
    if (missing := require_ns()) is not None:
        return missing
    found = 0
    scanned = 0
    for fd in range(256):
        try:
            mode = os.fstat(fd).st_mode
        except OSError:
            continue
        scanned += 1
        if stat.S_ISSOCK(mode):
            found += 1
    if found:
        return mark_allowed(f"inherited-sockets:{found}")
    if scanned == 0:
        return mark_allowed("no-fds-visible")
    return AttemptReport(AttemptOutcome.PASS, (), f"sockets:0/{scanned}")


def probe_net_and_tasks() -> AttemptReport:
    """Tasks cap and network denial must hold in one quota attempt."""
    if (missing := require_ns()) is not None:
        return missing
    kids: list[int] = []
    denied = 0
    for _ in range(70):
        try:
            pid = os.fork()
        except OSError:
            denied += 1
            continue
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        kids.append(pid)
    for pid in kids:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    if (hit := _must_fail("route-combined", _tcp_connect, "8.8.8.8", 53)) is not None:
        return hit
    if denied == 0:
        return mark_allowed("tasks-uncapped-combined")
    return AttemptReport(AttemptOutcome.PASS, (), f"combined:{len(kids)}+net-denied")
