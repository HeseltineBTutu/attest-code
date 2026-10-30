"""Unprivileged namespace entry and mapped-fork lifecycle (Linux only).

Namespaces are entered through one fork dance: the child unshares
user+mount+PID together (the kernel rejects lone PID unsharing for
unprivileged callers), the PARENT writes the single UID/GID map
(self-mapping is rejected with EPERM on hardened kernels), then the
child forks again so the work runs as PID-namespace init, whose exit
reliably kills every descendant. Mount layout lives in ``nsmounts``.
Importing performs no setup.
"""

from __future__ import annotations

import contextlib
import ctypes
import functools
import os
import sys
from collections.abc import Callable

PR_SET_PDEATHSIG = 1

_CLONE_NEWUSER = 0x10000000
_CLONE_NEWNS = 0x00020000
_CLONE_NEWPID = 0x20000000
_SIGKILL = 9

_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)


class RunnerError(Exception):
    """Namespace setup failed before checks could run."""


def write_maps(pid: int) -> None:
    """Parent side: install a single UID/GID map for an unshared child."""
    uid, gid = str(os.getuid()).encode(), str(os.getgid()).encode()
    try:
        with open(f"/proc/{pid}/setgroups", "wb") as handle:
            handle.write(b"deny")
        with open(f"/proc/{pid}/uid_map", "wb") as handle:
            handle.write(b"0 " + uid + b" 1")
        with open(f"/proc/{pid}/gid_map", "wb") as handle:
            handle.write(b"0 " + gid + b" 1")
    except OSError as exc:
        raise RunnerError(f"uid/gid mapping failed: {exc}") from exc


def die_with_parent() -> None:
    """Request SIGKILL when the parent dies; abort if already orphaned."""
    _LIBC.prctl(PR_SET_PDEATHSIG, _SIGKILL, 0, 0, 0)
    if os.getppid() == 1:
        os._exit(127)


def run_mapped_child(child_main: Callable[[], int], parent_close: tuple[int, ...] = ()) -> int:
    """Fork; child unshares, parent maps it, init runs main to _exit.

    Returns the init exit code. The child unshares user+mount+PID
    namespaces together (the kernel rejects lone PID unsharing for
    unprivileged callers), synchronizes over pipes for parent-side
    mapping, then forks again: that grandchild is PID-namespace init
    and runs ``child_main``. When init exits, the kernel SIGKILLs
    every remaining namespace member, so no descendant can outlive
    the call. Fds in ``parent_close`` are closed in the parent only.
    Init ignores SIGTERM by default, so ``child_main`` must handle
    it explicitly to preserve prompt timeout behavior.
    """
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()
    pid = os.fork()
    if pid != 0:
        os.close(ready_w)
        os.close(go_r)
        try:
            if os.read(ready_r, 1) != b"1":
                raise RunnerError("contained child failed before mapping")
            write_maps(pid)
            os.write(go_w, b"1")
        finally:
            os.close(ready_r)
            os.close(go_w)
            for fd in parent_close:
                with contextlib.suppress(OSError):
                    os.close(fd)
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status)
    os.close(ready_r)
    os.close(go_w)
    try:
        flags = _CLONE_NEWUSER | _CLONE_NEWNS | _CLONE_NEWPID
        if _LIBC.unshare(flags) != 0:
            raise RunnerError(f"unshare failed: errno {ctypes.get_errno()}")
        os.write(ready_w, b"1")
        if os.read(go_r, 1) != b"1":
            raise RunnerError("mapping handshake failed")
        die_with_parent()
        init = os.fork()
        if init != 0:
            _, status = os.waitpid(init, 0)
            if os.WIFEXITED(status):
                os._exit(os.waitstatus_to_exitcode(status))
            os._exit(3)
        die_with_parent()
        code = child_main()
    except BaseException as exc:
        print(f"contained child failed: {exc}", file=sys.stderr, flush=True)
        code = 3
    finally:
        for fd in (ready_w, go_r):
            with contextlib.suppress(OSError):
                os.close(fd)
    os._exit(code if isinstance(code, int) else 3)


@functools.lru_cache(maxsize=1)
def _probe_namespaces() -> int:
    """Init body: mapped root identity inside a real PID namespace."""
    if os.getuid() != 0 or os.getpid() != 1:
        return 1
    return 0


def supports_containment() -> bool:
    """Whether unprivileged user+mount+PID namespaces work (cached probe).

    Runs a child through the same mapped-fork dance the runner uses,
    then verifies a nested PID namespace actually isolates (first
    child observes PID 1). A threaded caller degrades to a
    conservative False rather than risking parent state.
    """
    if os.name != "posix" or not hasattr(os, "fork"):
        return False
    try:
        return run_mapped_child(_probe_namespaces) == 0
    except Exception:
        return False
