"""Fallible environment probes behind :func:`bench_env.collect_environment`.

Each collector returns a verified value or an explicit
``{"unavailable": reason}`` marker. Only documented per-call
failures (missing files, failed probes, git errors) become markers;
unexpected errors propagate to the caller.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
from pathlib import Path

from attest_core.git import GitError, relevant_status, repo_root, resolve_revision

_CPUINFO_PATH = "/proc/cpuinfo"
_MEMINFO_PATH = "/proc/meminfo"

_MAX_REASON_CHARS = 80
"""Longest failure reason kept in an unavailable marker (shared convention)."""

_MAX_STATUS_CHARS = 2000
"""Longest worktree-status text kept before truncation."""


def unavailable(reason: str) -> dict[str, str]:
    """Explicit marker for a field whose collection failed, with a reason."""
    return {"unavailable": reason[:_MAX_REASON_CHARS]}


def _read_text_file(path: str) -> str:
    """Read a small proc-style text file; OSError/UnicodeDecodeError pass through."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def resolve_base() -> Path:
    """Dependency-file anchor: git top level, or GitError when unavailable."""
    return repo_root(Path.cwd())


def collect_revision(base: Path) -> str | dict[str, str]:
    """Full HEAD commit id; unavailable when git cannot resolve it."""
    try:
        return resolve_revision(base, "HEAD")
    except GitError as exc:
        return unavailable(str(exc))


def collect_worktree(base: Path) -> dict[str, str]:
    """Clean/dirty state over the snapshot scope, with deltas when dirty."""
    try:
        status = relevant_status(base)
    except GitError as exc:
        return unavailable(str(exc))
    if not status.strip():
        return {"state": "clean"}
    if len(status) > _MAX_STATUS_CHARS:
        status = status[:_MAX_STATUS_CHARS] + "\n...(truncated)"
    return {"state": "dirty", "status": status}


def collect_lock_digest(base: Path, name: str) -> str | dict[str, str]:
    """SHA-256 of a dependency file, or an explicit absent/unreadable marker."""
    try:
        data = (base / name).read_bytes()
    except FileNotFoundError:
        return unavailable(f"absent:{name}")
    except OSError as exc:
        return unavailable(f"unreadable:{name}:{exc}")
    return hashlib.sha256(data).hexdigest()


def collect_python() -> dict[str, str]:
    """Interpreter implementation and version; unavailable when blank."""
    implementation = platform.python_implementation()
    version = platform.python_version()
    if not implementation.strip() or not version.strip():
        return unavailable("empty-implementation-or-version")
    return {"implementation": implementation, "version": version}


def collect_uv() -> str | dict[str, str]:
    """First line of ``uv --version``; unavailable without a working uv."""
    exe = shutil.which("uv")
    if exe is None:
        return unavailable("uv-not-on-path")
    try:
        proc = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return unavailable(f"uv-execution-failed:{exc}")
    if proc.returncode != 0:
        return unavailable(f"uv-exit-{proc.returncode}")
    lines = proc.stdout.splitlines()
    if not lines or not lines[0].strip():
        return unavailable("uv-empty-version-output")
    return lines[0].strip()


def collect_os() -> str | dict[str, str]:
    """Operating system name; unavailable when the platform reports blank."""
    system = platform.system()
    return system if system.strip() else unavailable("unknown-os")


def collect_kernel() -> str | dict[str, str]:
    """Kernel/release version; unavailable when the platform reports blank."""
    release = platform.release()
    return release if release.strip() else unavailable("unknown-kernel")


def collect_cpu_model() -> str | dict[str, str]:
    """First ``model name`` from cpuinfo; unavailable off-Linux or unparsable."""
    try:
        text = _read_text_file(_CPUINFO_PATH)
    except OSError as exc:
        return unavailable(f"cpuinfo-unreadable:{exc}")
    except UnicodeDecodeError as exc:
        return unavailable(f"cpuinfo-undecodable:{exc}")
    for line in text.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip() == "model name" and value.strip():
            return value.strip()
    return unavailable("model-name-not-found")


def _memtotal_from_meminfo() -> int | None:
    """Total RAM in bytes from MemTotal, or None when the key is absent."""
    for line in _read_text_file(_MEMINFO_PATH).splitlines():
        key, sep, rest = line.partition(":")
        if sep and key.strip() == "MemTotal":
            return int(rest.split()[0]) * 1024
    return None


def collect_memory_total_bytes() -> int | dict[str, str]:
    """Total RAM in bytes via meminfo, else POSIX sysconf; never zero."""
    try:
        total: int | None = _memtotal_from_meminfo()
    except (OSError, UnicodeDecodeError, ValueError):
        total = None
    if total is None:
        try:
            total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except (OSError, ValueError) as exc:
            return unavailable(f"memory-unknown:{exc}")
    if total <= 0:
        return unavailable("non-positive-memory-size")
    return total
