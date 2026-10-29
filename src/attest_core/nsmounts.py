"""Private mount-root construction for contained workers (Linux only).

Builds the filesystem the checks observe: read-only binds of the
interpreter, stdlib, venv, and approved snapshot, plus a size-bounded
noexec tmpfs scratch, minimal ``/etc``, and selected ``/dev`` nodes.
No ``/proc`` is mounted (same-UID host processes would be visible
without hidepid, which cannot help within one UID). ``pivot_root``
detaches the host view; the old root is unmounted before checks run.
All failures raise RunnerError with the failing errno.
"""

from __future__ import annotations

import ctypes
import os

from attest_core.ns_setup import RunnerError

SCRATCH_MB = 64
"""Tmpfs scratch capacity: kernel-enforced, needs no cgroup."""

_MS_RDONLY = 1
_MS_NOSUID = 2
_MS_NODEV = 4
_MS_NOEXEC = 8
_MS_REMOUNT = 32
_MS_BIND = 4096
_MS_REC = 16384
_MS_PRIVATE = 1 << 18
_MNT_DETACH = 2

_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
_LIBC.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_char_p,
]
_LIBC.mount.restype = ctypes.c_int
_LIBC.pivot_root.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_LIBC.pivot_root.restype = ctypes.c_int
_LIBC.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
_LIBC.umount2.restype = ctypes.c_int

_PASSWD = b"root:x:0:0:root:/scratch:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n"
_GROUP = b"root:x:0:\nnobody:x:65534:\n"


def _mount(
    source: bytes | None,
    target: bytes,
    fstype: bytes | None,
    flags: int,
    data: bytes | None = None,
) -> None:
    if _LIBC.mount(source, target, fstype, flags, data) != 0:
        raise RunnerError(f"mount {target!r} failed: errno {ctypes.get_errno()}")


def _bind_ro(source: str, target: str) -> None:
    os.makedirs(target, exist_ok=True)
    _mount(source.encode(), target.encode(), None, _MS_BIND | _MS_REC)
    ro = _MS_BIND | _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV
    _mount(None, target.encode(), None, ro)


def _venv_root() -> str:
    """Locate the host venv owning this interpreter (pre-pivot only)."""
    import sys

    # Derive from the executable path, never sys.prefix: prefix reflects
    # getpath/site state that varies with interpreter flags, while the
    # executable unambiguously identifies the running venv. abspath, not
    # realpath: venv binaries are commonly symlinks into the base install.
    candidate = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
    if os.path.isfile(os.path.join(candidate, "pyvenv.cfg")):
        return candidate
    raise RunnerError(f"no venv owns this interpreter: {sys.executable}")


def build_root(snapshot_root: str, stage_dir: str) -> None:
    """Assemble the private root and pivot into it, detaching the host."""
    _mount(None, b"/", None, _MS_REC | _MS_PRIVATE)
    newroot = os.path.join(stage_dir, "nsroot")
    os.makedirs(newroot, mode=0o700, exist_ok=True)
    _mount(b"tmpfs", newroot.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV, b"mode=755")
    put_old = os.path.join(newroot, "old")
    os.makedirs(put_old, exist_ok=True)
    for name in ("usr", "usr/local", "venv", "snapshot", "etc", "dev"):
        os.makedirs(os.path.join(newroot, name), exist_ok=True)
    _bind_ro("/usr", os.path.join(newroot, "usr"))
    _bind_ro("/usr/local", os.path.join(newroot, "usr/local"))
    _bind_ro(_venv_root(), os.path.join(newroot, "venv"))
    _bind_ro(snapshot_root, os.path.join(newroot, "snapshot"))
    scratch = os.path.join(newroot, "scratch")
    os.makedirs(scratch, exist_ok=True)
    opts = f"size={SCRATCH_MB}M,mode=700,nr_inodes=16384".encode()
    _mount(b"tmpfs", scratch.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV | _MS_NOEXEC, opts)
    for sub in ("tmp", "pycache"):
        os.makedirs(os.path.join(scratch, sub), exist_ok=True)
    with open(os.path.join(newroot, "etc/passwd"), "wb") as handle:
        handle.write(_PASSWD)
    with open(os.path.join(newroot, "etc/group"), "wb") as handle:
        handle.write(_GROUP)
    for node in ("null", "zero", "urandom"):
        target = os.path.join(newroot, "dev", node)
        with open(target, "wb"):
            pass
        _mount(f"/dev/{node}".encode(), target.encode(), None, _MS_BIND)
    if _LIBC.pivot_root(newroot.encode(), put_old.encode()) != 0:
        raise RunnerError(f"pivot_root failed: errno {ctypes.get_errno()}")
    os.chdir("/")
    if _LIBC.umount2(b"/old", _MNT_DETACH) != 0:
        raise RunnerError(f"old-root detach failed: errno {ctypes.get_errno()}")
    os.chdir("/scratch")
