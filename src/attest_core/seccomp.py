"""Opt-in seccomp syscall denylist for contained checks (Linux only).

Default-allow filter installed by init after rlimits, before snapshot
imports. Denied calls die with SIGSYS (whole group); legacy clone is
argument-filtered on namespace-creation flags and clone3 fails with
ENOSYS so libc falls back to filterable clone. Categories: mount and
module loading, host control, kernel attack surface (BPF, userfaultfd,
perf, io_uring), keyrings, cross-process access, namespaces, and the
seccomp syscall itself. Unknown architectures and kernels without
KILL_PROCESS refuse installation: fail closed, never silent.
"""

from __future__ import annotations

import ctypes
import os

from attest_core.ns_setup import RunnerError

_SET_MODE_FILTER = 1
_GET_ACTION_AVAIL = 2
_RET_KILL_PROCESS = 0x80000000
_RET_ERRNO = 0x00050000
_RET_ALLOW = 0x7FFF0000
_PR_SET_NO_NEW_PRIVS = 38
_AUDIT_X86_64 = 0xC000003E
_AUDIT_AARCH64 = 0xC00000B7
_X32_BIT = 0x40000000
_NS_CLONE_MASK = 0x7E020080
_ENOSYS = 38

_OP_LD = 0x20
_OP_JEQ = 0x15
_OP_JSET = 0x45
_OP_RET = 0x06
_OP_AND = 0x54

_OFF_ARCH = 4
_OFF_NR = 0
_OFF_ARG0 = 16

# Deliberately absent: prctl is a 60-op multiplexer whose reachable ops
# are self-directed or caps-gated (no containment threat; blocking it
# whole risks breaking runtimes). Dead legacy numbers are omitted too.
POLICY = (
    ("mount", 165, 40),
    ("umount2", 166, 39),
    ("pivot_root", 155, 41),
    ("open_tree", 428, 428),
    ("move_mount", 429, 429),
    ("fsopen", 430, 430),
    ("fsmount", 432, 432),
    ("mount_setattr", 442, 442),
    ("open_tree_attr", 467, 467),
    ("init_module", 175, 105),
    ("delete_module", 176, 106),
    ("finit_module", 313, 273),
    ("kexec_load", 246, 104),
    ("kexec_file_load", 320, 294),
    ("reboot", 169, 142),
    ("swapon", 167, 224),
    ("swapoff", 168, 225),
    ("acct", 163, 89),
    ("syslog", 103, 116),
    ("sethostname", 170, 161),
    ("setdomainname", 171, 162),
    ("vhangup", 153, 58),
    ("chroot", 161, 51),
    ("personality", 135, 92),
    ("name_to_handle_at", 303, 264),
    ("open_by_handle_at", 304, 265),
    ("bpf", 321, 280),
    ("userfaultfd", 323, 282),
    ("perf_event_open", 298, 241),
    ("io_uring_setup", 425, 425),
    ("io_uring_enter", 426, 426),
    ("io_uring_register", 427, 427),
    ("add_key", 248, 217),
    ("request_key", 249, 218),
    ("keyctl", 250, 219),
    ("ptrace", 101, 117),
    ("process_vm_readv", 310, 270),
    ("process_vm_writev", 311, 271),
    ("unshare", 272, 97),
    ("setns", 308, 268),
    ("seccomp", 317, 277),
    ("clone", 56, 220),
    ("clone3", 435, 435),
)


class _Filter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint16), ("filter", ctypes.POINTER(_Filter))]


_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
_LIBC.syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p]
_LIBC.syscall.restype = ctypes.c_long
_LIBC.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_LIBC.prctl.restype = ctypes.c_int


def _arch_config() -> tuple[int, int, int, bool]:
    """(audit token, table column, seccomp nr, x32 rule?) or raise."""
    machine = os.uname().machine
    if machine == "x86_64":
        return (_AUDIT_X86_64, 0, 317, True)
    if machine == "aarch64":
        return (_AUDIT_AARCH64, 1, 277, False)
    raise RunnerError(f"seccomp unsupported on {machine}")


def build_insns(
    native: int, denied: list[int], clone: int | None, clone3: int | None, x32: bool
) -> list[tuple[int, int, int, int]]:
    """Classic-BPF denylist; all jump targets resolved arithmetically."""
    h = 4 if x32 else 3
    extra = (1 if clone3 is not None else 0) + (4 if clone is not None else 0)
    kill = h + len(denied) + extra + 2
    insns = [(_OP_LD, 0, 0, _OFF_ARCH), (_OP_JEQ, 0, kill - 2, native)]
    insns.append((_OP_LD, 0, 0, _OFF_NR))
    if x32:
        insns.append((_OP_JSET, kill - 4, 0, _X32_BIT))
    for number in denied:
        insns.append((_OP_JEQ, kill - len(insns) - 1, 0, number))
    if clone3 is not None:
        insns.append((_OP_JEQ, kill - len(insns) - 2, 0, clone3))
    if clone is not None:
        insns.append((_OP_JEQ, 0, 3, clone))
        insns.append((_OP_LD, 0, 0, _OFF_ARG0))
        insns.append((_OP_AND, 0, 0, _NS_CLONE_MASK))
        insns.append((_OP_JEQ, 0, kill - len(insns) - 1, 0))
    insns.append((_OP_RET, 0, 0, _RET_ALLOW))
    insns.append((_OP_RET, 0, 0, _RET_ERRNO | _ENOSYS))
    insns.append((_OP_RET, 0, 0, _RET_KILL_PROCESS))
    assert len(insns) == kill + 1, "BPF layout drift"
    return insns


def supports_seccomp() -> bool:
    """Whether the denylist could install here; queries only, never installs."""
    try:
        _, _, seccomp_nr, _ = _arch_config()
        action = ctypes.c_uint32(_RET_KILL_PROCESS)
        available = _LIBC.syscall(seccomp_nr, _GET_ACTION_AVAIL, 0, ctypes.byref(action)) == 0
        return bool(available)
    except Exception:
        return False


def install_denylist(omit: frozenset[str] = frozenset()) -> None:
    """Install the denylist on this thread; anything missing fails closed.

    Omit exists solely for the diagnostic harness (bisecting a SIGSYS
    death); production always installs the full policy.
    """
    token, column, seccomp_nr, x32 = _arch_config()
    numbers = {name: pair[column] for name, *pair in POLICY if name not in omit}
    for special in ("clone", "clone3"):
        if special not in numbers and special not in omit:
            raise RunnerError(f"seccomp policy lacks {special}")
    clone = numbers.pop("clone", None)
    clone3 = numbers.pop("clone3", None)
    program = build_insns(token, list(numbers.values()), clone, clone3, x32)
    array = (_Filter * len(program))(*[_Filter(*ins) for ins in program])
    fprog = _Program(len(program), array)
    if _LIBC.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise RunnerError(f"no-new-privs failed: errno {ctypes.get_errno()}")
    action = ctypes.c_uint32(_RET_KILL_PROCESS)
    if _LIBC.syscall(seccomp_nr, _GET_ACTION_AVAIL, 0, ctypes.byref(action)) != 0:
        raise RunnerError("KILL_PROCESS action unavailable")
    if _LIBC.syscall(seccomp_nr, _SET_MODE_FILTER, 0, ctypes.byref(fprog)) != 0:
        raise RunnerError(f"seccomp install failed: errno {ctypes.get_errno()}")
