"""Contained runner: namespaces, mounts, then checks (Linux only).

Executed fresh via ``python -I -c`` with argv ``[snapshot_src, result_fd,
stage_dir]`` and the pickled check callable on stdin. Top-level imports
are stdlib plus the side-effect-free namespace bindings. The runner
forks a grandchild that unshares user+mount+PID namespaces together
(maps are written parent-side: self-mapping is rejected on hardened
kernels, as is lone PID unsharing), then forks again: that init
builds the private root, scrubs the environment, applies rlimits,
repoints imports at the in-namespace snapshot, self-checks origins,
runs checks, and writes one result envelope to the inherited result
fd. When init exits, the kernel SIGKILLs every remaining descendant.
The runner itself never enters a namespace and relays only the
grandchild's exit status.

Never imported on Windows; never imported pre-setup anywhere else.
"""

from __future__ import annotations

import contextlib
import os
import pickle
import resource
import signal
import sys
from pathlib import Path

from attest_core.ns_setup import RunnerError, run_mapped_child
from attest_core.nsmounts import build_root

MAX_PICKLE_BYTES = 1048576

RLIMIT_AS_BYTES = 1 << 30
RLIMIT_FSIZE_BYTES = 64 << 20
RLIMIT_NOFILE = 256

_NS_ENV = {
    "PATH": "/venv/bin:/usr/bin:/bin",
    "HOME": "/scratch",
    "TMPDIR": "/scratch/tmp",
    "LC_ALL": "C.UTF-8",
    "PYTHONPYCACHEPREFIX": "/scratch/pycache",
    "ATTEST_CONTAINED": "1",
}
"""Exact post-setup environment; nothing is inherited past this point."""


def _read_stdin_bounded() -> bytes:
    data = sys.stdin.buffer.read(MAX_PICKLE_BYTES + 1)
    if len(data) > MAX_PICKLE_BYTES:
        raise RunnerError("runner payload exceeds size bound")
    if not data:
        raise RunnerError("runner received no payload")
    return data


def _fix_sys_path() -> None:
    """Point imports at the in-namespace snapshot, stdlib, and venv."""
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    site = f"/venv/lib/python{version}/site-packages"
    if not os.path.isdir(site):
        raise RunnerError(f"venv site-packages missing in namespace: {site}")
    stdlib = [p for p in sys.path if p.startswith(("/usr/local/lib", "/usr/lib"))]
    sys.path[:] = ["/snapshot/src", site, *stdlib]
    # Evict the bootstrap generation: the runner, ns_setup, and package
    # shell were necessarily loaded from host paths pre-setup. Running
    # frames keep working (they hold their own references); every later
    # first-party import resolves fresh inside /snapshot, which the
    # origin self-check then proves. Eviction is prefix-based so no
    # pre-setup first-party module — including attest_spec or a
    # startup-preloaded submodule — can survive the transition.
    stale = [
        name for name in sys.modules if name.partition(".")[0] in ("attest_core", "attest_spec")
    ]
    for _mod in stale:
        sys.modules.pop(_mod, None)
    import importlib

    importlib.invalidate_caches()


def _scrub_env() -> None:
    """Replace the environment with exactly the namespace allowlist."""
    os.environ.clear()
    os.environ.update(_NS_ENV)


def _apply_rlimits() -> None:
    """Per-process floor: address space, file size, fd count.

    Deliberately not CPU time (the parent's wall-clock deadline owns
    attempt bounding; a blind CPU cap could kill slow-legit checks)
    and not process count (RLIMIT_NPROC counts host-wide per UID, so a
    low cap misfires on busy hosts). cgroup quotas are M3 work.
    """
    try:
        resource.setrlimit(resource.RLIMIT_AS, (RLIMIT_AS_BYTES, RLIMIT_AS_BYTES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (RLIMIT_FSIZE_BYTES, RLIMIT_FSIZE_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (RLIMIT_NOFILE, RLIMIT_NOFILE))
    except OSError as exc:
        raise RunnerError(f"rlimit setup failed: {exc}") from exc


def _clip(text: str, maximum: int) -> str:
    """Bound runner-side text (mirrors bounds._clip without importing it)."""
    if len(text) > maximum:
        return text[:maximum] + "[truncated]"
    return text


def _write_result(fd: int, envelope: str, limit: int) -> None:
    data = envelope.encode("utf-8")
    if len(data) > limit:
        raise RunnerError("contained result exceeds size bound")
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _on_sigterm(signum: int, frame: object) -> None:
    """PID-1 init ignores SIGTERM by default; map it to prompt failure."""
    raise RunnerError("received SIGTERM")


def _contained_main(payload: bytes, snapshot_root: str, result_fd: int, stage: str) -> int:
    """Grandchild body: boundary first, then imports, checks, one write."""
    signal.signal(signal.SIGTERM, _on_sigterm)
    build_root(snapshot_root, stage)
    _scrub_env()
    _apply_rlimits()
    _fix_sys_path()
    from attest_core.envelope import (
        MAX_DETAIL_CHARS,
        MAX_RESULT_BYTES,
        encode_attempt_report,
        encode_error,
    )
    from attest_core.origin import check_origins, report_worker_origins

    try:
        check_origins(report_worker_origins(), Path("/snapshot"), actor="contained worker")
    except Exception as exc:
        _write_result(result_fd, encode_error(f"origin self-check failed: {exc}"), MAX_RESULT_BYTES)
        return 0
    try:
        func = pickle.loads(payload)
        if not callable(func):
            raise RunnerError("payload is not callable")
        report = func()
        envelope = encode_attempt_report(report)
    except Exception as exc:
        envelope = encode_error(_clip(f"{type(exc).__name__}: {exc}", MAX_DETAIL_CHARS))
    _write_result(result_fd, envelope, MAX_RESULT_BYTES)
    return 0


def main(argv: list[str]) -> int:
    """Read the payload, run it mapped and contained, relay the status."""
    if len(argv) != 3:
        print("usage: contained_runner <snapshot_src> <result_fd> <stage>", file=sys.stderr)
        return 2
    snapshot_src, result_fd_text, stage_dir = argv
    try:
        result_fd = int(result_fd_text)
    except ValueError:
        print("result fd is not an integer", file=sys.stderr)
        return 2
    snapshot_root = os.path.dirname(os.path.abspath(snapshot_src))
    try:
        payload = _read_stdin_bounded()
        return run_mapped_child(
            lambda: _contained_main(payload, snapshot_root, result_fd, stage_dir),
            parent_close=(result_fd,),
        )
    except RunnerError as exc:
        print(f"contained setup failed: {exc}", file=sys.stderr)
        return 2
    finally:
        with contextlib.suppress(OSError):
            os.close(result_fd)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
