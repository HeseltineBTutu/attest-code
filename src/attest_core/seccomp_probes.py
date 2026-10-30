"""M4 seccomp probes: denylist enforcement evidence from real children.

Each probe forks a child per attempted call and checks its status, so
a SIGSYS death is distinguished from environmental failure. Probes run
via ``run_bounded(..., contained=True, seccomp=True)`` from the snapshot
(top-level, picklable); markers come from ``contain_probes``.
"""

from __future__ import annotations

import ctypes
import os
import signal
import socket
import threading
from collections.abc import Callable

from attest_core.contain_probes import mark_allowed, require_ns
from attest_core.seccomp import POLICY
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome

_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
_CLONE_NEWUSER = 0x10000000
_ENOSYS = 38


_COLUMN = {"x86_64": 0, "aarch64": 1}[os.uname().machine]
_NR = {name: pair[_COLUMN] for name, *pair in POLICY}


def _raw(name: str, *args: int) -> int:
    """Call a libc symbol with integer args; return value or -1."""
    func = getattr(_LIBC, name)
    func.argtypes = [ctypes.c_ulong] * len(args)
    func.restype = ctypes.c_long
    return int(func(*args))


def _syscall(number: int, *args: int) -> int:
    """Raw syscall by number (clone/clone3/seccomp have no wrapper)."""
    call = _LIBC.syscall
    call.argtypes = [ctypes.c_long] * (len(args) + 1)
    call.restype = ctypes.c_long
    return int(call(number, *args))


def _attempt(invoker: Callable[..., int], *args: object) -> str:
    """Run invoker in a forked child; report 'sig:N' or 'exit:N'."""
    pid = os.fork()
    if pid != 0:
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            return f"sig:{os.WTERMSIG(status)}"
        return f"exit:{os.waitstatus_to_exitcode(status)}"
    try:
        code = invoker(*args)
    except BaseException:
        code = 125
    os._exit(code)


def _invoke_plain(name: str) -> int:
    """Attempt one plain-denied call by number; 1 when it returns."""
    _syscall(_NR[name], 0, 0, 0, 0, 0, 0)
    return 1


def _invoke_clone() -> int:
    """Raw clone with CLONE_NEWUSER must die; reap the accident if not."""
    ret = _syscall(_NR["clone"], _CLONE_NEWUSER | signal.SIGCHLD, 0, 0, 0, 0)
    if ret == 0:
        os._exit(74)
    if ret > 0:
        os.waitpid(ret, 0)
    return 1


def _clone3_errno() -> int:
    """Errno from a raw clone3(NULL, 0) attempt (glibc returns -1)."""
    ctypes.set_errno(0)
    _syscall(_NR["clone3"], 0, 0)
    return ctypes.get_errno()


def _invoke_clone3() -> int:
    """Raw clone3 must fail ENOSYS (0) rather than die or succeed."""
    return 0 if _clone3_errno() == _ENOSYS else 1


def _invoke_seccomp() -> int:
    """Invalid-op seccomp call must die (no libc wrapper exists)."""
    _syscall(_NR["seccomp"], 0xFFFFFFFF, 0, 0)
    return 1


def probe_denylist() -> AttemptReport:
    """Every policy rule must kill (SIGSYS) or fail closed (clone3 ENOSYS)."""
    if (missing := require_ns()) is not None:
        return missing
    dead = f"sig:{signal.SIGSYS}"
    failures: list[str] = []
    for name, _, _ in POLICY:
        if name == "clone":
            outcome = _attempt(_invoke_clone)
            ok = outcome == dead
        elif name == "clone3":
            outcome = _attempt(_invoke_clone3)
            ok = outcome == "exit:0"
        elif name == "seccomp":
            outcome = _attempt(_invoke_seccomp)
            ok = outcome == dead
        else:
            outcome = _attempt(_invoke_plain, name)
            ok = outcome == dead
        if not ok:
            failures.append(f"{name}={outcome}")
    if failures:
        return mark_allowed("survived:" + ",".join(failures))
    return AttemptReport(AttemptOutcome.PASS, (), f"denied:{len(POLICY)}")


def probe_allowed() -> AttemptReport:
    """Everyday runtime calls must keep working under enforcement."""
    if (missing := require_ns()) is not None:
        return missing
    pid = os.fork()
    if pid != 0:
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 3:
            return mark_allowed("fork-broke")
    else:
        os._exit(3)
    buf = ctypes.create_string_buffer(16)
    if _raw("prctl", 16, ctypes.addressof(buf), 0, 0, 0) != 0:
        return mark_allowed("prctl-broke")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return mark_allowed("socket-broke")
    sock.close()
    done: list[bool] = []
    worker = threading.Thread(target=lambda: done.append(True))
    worker.start()
    worker.join(timeout=10)
    if not done:
        return mark_allowed("thread-broke")
    pid = os.fork()
    if pid != 0:
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            return mark_allowed("exec-broke")
    else:
        try:
            os.execv("/nonexistent-attest-xyz", ["xyz"])
        except FileNotFoundError:
            os._exit(0)
        except BaseException:
            os._exit(127)
        os._exit(127)
    return AttemptReport(AttemptOutcome.PASS, (), "controls-ok")


def probe_inherit() -> AttemptReport:
    """A forked descendant must inherit the filter (dies on mount)."""
    if (missing := require_ns()) is not None:
        return missing
    outcome = _attempt(_invoke_plain, "mount")
    if outcome == f"sig:{signal.SIGSYS}":
        return AttemptReport(AttemptOutcome.PASS, (), "fork-inherited-sigsys")
    return mark_allowed(f"inherit-escaped:{outcome}")


def probe_fallback() -> AttemptReport:
    """clone3 must fail ENOSYS while fork keeps working after it."""
    if (missing := require_ns()) is not None:
        return missing
    if _clone3_errno() != _ENOSYS:
        return mark_allowed("clone3-unfiltered")
    pid = os.fork()
    if pid != 0:
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            return mark_allowed("fork-broke-after-enosys")
        return AttemptReport(AttemptOutcome.PASS, (), "enosys-then-fork-ok")
    os._exit(0)
