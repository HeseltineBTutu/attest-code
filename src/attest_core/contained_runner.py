"""Contained runner: namespaces, mounts, checks (Linux only).

Fresh ``python -I -c`` with argv ``[src, result_fd, stage, scope?, seccomp?]``
and the pickled check on stdin. The runner forks init via :func:`run_mapped_child`
(user+mount+PID+network, parent-written maps), never entering a namespace itself.
Init builds the private root, scrubs the environment, applies rlimits (+seccomp
when requested), repoints imports at the snapshot, self-checks origins, runs
checks, and writes one result envelope; its exit SIGKILLs every descendant, and
the runner relays only the exit status.

Never imported on Windows; never imported pre-setup anywhere else.
"""

from __future__ import annotations

import contextlib
import os
import pickle
import resource
import signal
import sys
import time
from pathlib import Path

from attest_core.ns_setup import RunnerError, run_mapped_child
from attest_core.nsmounts import build_root
from attest_core.scope_enter import ScopeError, verify_self_in_scope
from attest_core.seccomp import install_denylist

MAX_PICKLE_BYTES = 1048576
RUNNER_PROTOCOL_VERSION = 2  # wire contract; the parent probes this value

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
    # first-party import resolves fresh inside /snapshot, which the origin
    # self-check then proves. Prefix-based eviction leaves no pre-setup
    # module — including attest_spec or startup-preloaded ones — behind.
    stale = [n for n in sys.modules if n.partition(".")[0] in ("attest_core", "attest_spec")]
    for _mod in stale:
        sys.modules.pop(_mod, None)
    import importlib

    importlib.invalidate_caches()


def _scrub_env() -> None:
    """Replace the environment with exactly the namespace allowlist."""
    os.environ.clear()
    os.environ.update(_NS_ENV)


def _apply_rlimits() -> None:
    """Per-process floor: address space, file size, fd count, no core dumps.

    CPU time and process count stay unbounded here (wall-clock deadline
    owns bounding; NPROC is host-wide per UID); cgroups own quotas (M3-A).
    """
    try:
        resource.setrlimit(resource.RLIMIT_AS, (RLIMIT_AS_BYTES, RLIMIT_AS_BYTES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (RLIMIT_FSIZE_BYTES, RLIMIT_FSIZE_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (RLIMIT_NOFILE, RLIMIT_NOFILE))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
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


def _contained_main(
    payload: bytes, snapshot_root: str, result_fd: int, stage: str, seccomp_on: bool
) -> int:
    """Grandchild body: boundary first, then imports, checks, one write."""
    signal.signal(signal.SIGTERM, _on_sigterm)
    build_root(snapshot_root, stage)
    _scrub_env()
    _apply_rlimits()
    if seccomp_on:
        install_denylist()
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
    if len(argv) not in (3, 4, 5):
        print("usage: contained_runner <src> <fd> <stage> [scope] [seccomp]", file=sys.stderr)
        return 2
    snapshot_src, result_fd_text, stage_dir = argv[:3]
    scope_unit = argv[3] if len(argv) >= 4 and argv[3] else None
    if len(argv) == 5 and argv[4] not in ("", "1"):
        print("seccomp flag must be '' or '1'", file=sys.stderr)
        return 2
    seccomp_on = len(argv) == 5 and argv[4] == "1"
    try:
        result_fd = int(result_fd_text)
    except ValueError:
        print("result fd is not an integer", file=sys.stderr)
        return 2
    snapshot_root = os.path.dirname(os.path.abspath(snapshot_src))
    try:
        payload = _read_stdin_bounded()
        if scope_unit is not None:
            verify_self_in_scope(scope_unit)
            first = os.fork()
            if first == 0:
                if os.fork() == 0:
                    os.setsid()
                    os.closerange(0, 4096)
                    time.sleep(300)
                os._exit(0)
            os.waitpid(first, 0)
        return run_mapped_child(
            lambda: _contained_main(payload, snapshot_root, result_fd, stage_dir, seccomp_on),
            parent_close=(result_fd,),
        )
    except (RunnerError, ScopeError) as exc:
        print(f"contained setup failed: {exc}", file=sys.stderr)
        return 2
    finally:
        with contextlib.suppress(OSError):
            os.close(result_fd)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
