"""Portable sandbox core (S1): harden the worker execution boundary.

Attempt and probe workers run verifier-owned code in spawned processes.
This module reduces their exposure without claiming OS-enforced
isolation:

- minimal explicit worker environment (allowlist; secrets scrubbed),
- controlled working directory outside the live repository,
- JSON result files instead of pickle IPC (bounded, schema-validated),
- per-attempt bytecode-cache directories,
- bounded diagnostic capture with explicit truncation.

The parent applies the minimal environment and working directory around
`proc.start()`, so children start controlled; in-child enforcement is
belt-and-braces. Residuals: no CPU/memory/network/filesystem or
privilege isolation (deferred); unbounded worker *writes* can fill disk
before failing closed; a worker whose validated report lies is still
trusted (fundamental to any result channel — see security-model.md).
"""

from __future__ import annotations

import atexit
import contextlib
import dataclasses
import multiprocessing
import os
import shutil
import stat
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping
from multiprocessing.context import SpawnProcess
from pathlib import Path
from typing import Any

MAX_CAPTURE_BYTES = 65536
"""Largest captured worker stdout/stderr file read by the parent."""

CAPTURE_TAIL_CHARS = 2048
"""Diagnostic tail appended to infrastructure-failure details."""

TERMINATE_GRACE_SECONDS = 10
"""Join grace after terminate/kill before giving up on a worker."""

_WORKER_ENV_KEEP = frozenset({"PYTHONPYCACHEPREFIX"})
"""Non-secret variables a worker may inherit (plus explicit overrides)."""

_WIN32_ENV_KEEP = frozenset({"SYSTEMROOT", "TEMP", "TMP"})
"""Variables the Windows CRT/stdlib demonstrably require in children."""

_SPAWN_GUARD_STATE = threading.local()
"""Reentrancy flag: nested `guarded_spawn` would corrupt the parent's state."""


class SandboxError(Exception):
    """A worker sandbox precondition was violated; fail closed, never verdict."""


@dataclasses.dataclass(frozen=True)
class SandboxWorkdir:
    """Per-worker controlled directory: cwd, result, capture, cache, group id."""

    root: Path
    result: Path
    stdout: Path
    stderr: Path
    pycache: Path
    pgid: Path


def _allowed_env_keys() -> frozenset[str]:
    if os.name == "nt":
        return _WORKER_ENV_KEEP | _WIN32_ENV_KEEP
    return _WORKER_ENV_KEEP


def build_worker_environ(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the minimal worker environment from an allowlist.

    Only allowlisted keys survive from the parent; `overrides`
    (e.g. the per-attempt cache prefix) must also be allowlisted.
    Everything else — credentials, tokens, `PATH`, `PYTHONPATH` —
    is dropped rather than inherited.
    """
    allowed = _allowed_env_keys()
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    for key, value in (overrides or {}).items():
        if key not in allowed:
            raise ValueError(f"worker environment override is not allowlisted: {key}")
        env[key] = value
    return env


def enforce_worker_environ() -> None:
    """In-child re-enforcement of the environment allowlist (idempotent)."""
    allowed = _allowed_env_keys()
    for key in [key for key in os.environ if key not in allowed]:
        del os.environ[key]


def prepare_workdir() -> SandboxWorkdir:
    """Create a fresh controlled worker directory (mode 0700)."""
    root = Path(tempfile.mkdtemp(prefix="attest-work-"))
    cache = root / "pycache"
    cache.mkdir()
    return SandboxWorkdir(
        root=root,
        result=root / "result.json",
        stdout=root / "stdout.log",
        stderr=root / "stderr.log",
        pycache=cache,
        pgid=root / "pgid",
    )


def cleanup_workdir(root: Path) -> None:
    """Remove a worker directory; never raises, never touches siblings."""
    shutil.rmtree(root, ignore_errors=True)


def enter_worker_context(paths: SandboxWorkdir) -> None:
    """In-child hardening: minimal env, controlled cwd, captured stdio."""
    enforce_worker_environ()
    os.chdir(paths.root)
    try:
        with open(paths.stdout, "w", encoding="utf-8", errors="replace") as out:
            os.dup2(out.fileno(), 1)
        with open(paths.stderr, "w", encoding="utf-8", errors="replace") as err:
            os.dup2(err.fileno(), 2)
    except OSError:
        pass


@contextlib.contextmanager
def guarded_spawn(
    target: Callable[..., Any], args: tuple[Any, ...], *, environ: Mapping[str, str], cwd: Path
) -> Iterator[SpawnProcess]:
    """Spawn a worker that starts with a minimal env and controlled cwd.

    The parent's environment and cwd are restored immediately after the
    child execs. Spawning is main-thread-only: process-global swaps are
    unsafe under concurrency, and no supported caller is threaded.
    Yields the live process; supervision and cleanup stay with the caller.
    Nested use is refused: an inner call would restore its caller's mutated
    state at the wrong time.
    """
    if threading.current_thread() is not threading.main_thread():
        raise SandboxError("worker spawning is only supported from the main thread")
    if getattr(_SPAWN_GUARD_STATE, "active", False):
        raise SandboxError("nested worker spawning is not supported")
    _SPAWN_GUARD_STATE.active = True
    try:
        saved_env = dict(os.environ)
        saved_cwd = os.getcwd()
        ctx = multiprocessing.get_context("spawn")
        proc = ctx.Process(target=target, args=args, daemon=True)
        try:
            os.environ.clear()
            os.environ.update(environ)
            os.chdir(cwd)
            proc.start()
        finally:
            try:
                os.chdir(saved_cwd)
            finally:
                os.environ.clear()
                os.environ.update(saved_env)
        try:
            yield proc
        finally:
            if proc.is_alive():
                proc.kill()
                proc.join(TERMINATE_GRACE_SECONDS)
    finally:
        _SPAWN_GUARD_STATE.active = False


def capture_tail(path: Path) -> str:
    """Bounded diagnostic tail of a worker capture file ("" when absent/empty).

    Only regular files are read (lstat, never following symlinks), so a
    worker-left FIFO, socket, device, or directory cannot block or crash
    the parent. A path swapped after this check needs a post-exit writer
    outside the supervised tree — see security-model.md.
    """
    try:
        lstat = os.lstat(path)
    except OSError:
        return ""
    if not stat.S_ISREG(lstat.st_mode):
        return "[output unreadable: not a regular file]"
    size = lstat.st_size
    if size <= 0:
        return ""
    try:
        with open(path, "rb") as handle:
            handle.seek(max(0, size - MAX_CAPTURE_BYTES))
            decoded = handle.read(MAX_CAPTURE_BYTES + 1).decode("utf-8", errors="replace")
    except OSError:
        # A concurrently removed or replaced capture file degrades to empty
        # diagnostics (verified-empty tree postmortem); never crash the parent.
        return ""
    if size > MAX_CAPTURE_BYTES or len(decoded) > CAPTURE_TAIL_CHARS:
        return "[output truncated]\n" + decoded[-CAPTURE_TAIL_CHARS:]
    return decoded


def failure_suffix(paths: SandboxWorkdir) -> str:
    """Explicitly-marked diagnostic tails for infrastructure-failure details."""
    parts = ""
    err = capture_tail(paths.stderr)
    out = capture_tail(paths.stdout)
    if err:
        parts += f"\n[worker stderr]\n{err}"
    if out:
        parts += f"\n[worker stdout]\n{out}"
    return parts


def register_cleanup(root: Path) -> None:
    """Best-effort workdir removal if the parent exits without cleaning up."""
    atexit.register(cleanup_workdir, root)
