"""M1 Linux filesystem isolation: outer orchestration (trusted side).

The outer worker (existing S1/S2 identity: process-group leader, timeout
target) launches a contained runner over pipes and relays its result
into the existing file protocol. The runner executes checks inside
user, mount, and PID namespaces; this module never enters a namespace
and never runs check code. Parent-side supervision, capture bounds,
and result validation are unchanged.

Containment is explicit opt-in (``run_bounded(..., contained=True)``):
check callables must be importable from the snapshot inside the fresh
namespace, which test-local functions are not. Flipping the default
is a later rollout decision requiring CI validation.
"""

from __future__ import annotations

import functools
import os
import subprocess
import sys
import threading
from pathlib import Path

from attest_core.envelope import MAX_RESULT_BYTES
from attest_core.ns_setup import die_with_parent, run_mapped_child
from attest_core.sandbox import MAX_CAPTURE_BYTES, SandboxWorkdir

MAX_PICKLE_BYTES = 1048576
"""Largest outer-to-runner payload; production partials are tiny."""

_BOOTSTRAP = (
    "import sys; snapshot_src = sys.argv[1]\n"
    "stale = [m for m in sys.modules if m.partition('.')[0] in ('attest_core', 'attest_spec')]\n"
    "import sysconfig; _stdlib = sysconfig.get_path('stdlib')\n"
    "_platstdlib = sysconfig.get_path('platstdlib')\n"
    "sys.path[:] = [snapshot_src] + [p for p in sys.path if p in (_stdlib, _platstdlib) or\n"
    "    p.startswith((_stdlib + '/', _platstdlib + '/')) or\n"
    "    (p.startswith(sys.base_prefix + '/') and p.endswith('.zip'))]\n"
    "for _name in stale:\n"
    "    del sys.modules[_name]\n"
    "del stale; import importlib, os; importlib.invalidate_caches()\n"
    "if not os.path.isdir(os.path.join(snapshot_src, 'attest_core')):\n"
    "    print(f'snapshot incomplete: no attest_core in {snapshot_src}', file=sys.stderr)\n"
    "    raise SystemExit(2)\n"
    "from attest_core.contained_runner import main; raise SystemExit(main(sys.argv[1:]))\n"
)
"""Snapshot-pinned bootstrap: scrub, pin, verify, then import.

The runner starts as a fresh interpreter whose path may carry
interpreter- or venv-configured entries: ``site`` still processes
``.pth`` files under ``-I``, so an editable install's live ``src``
is importable unless removed. Before importing any first-party
module, evict preloaded target modules, rebuild ``sys.path`` as
exactly the snapshot plus the stdlib, refuse an incomplete
snapshot, and only then import the runner. The launcher also
passes ``-S`` (see below), so site initialization never runs and
``.pth``/``sitecustomize`` code is unreachable by construction;
the scrub still defends the import itself.
"""


class ContainedError(Exception):
    """Contained execution failed; the caller maps this to INFRA_FAILURE."""


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


def _drain_bounded(fd: int, limit: int, sink: list[bytes]) -> None:
    """Drain one pipe to EOF, keeping only the first limit+1 bytes.

    Excess is discarded (never buffered unboundedly), but draining
    continues so a chatty writer can always reach EOF and exit; the
    caller reaps afterwards. Runs in a subscriber thread per pipe.
    """
    kept: list[bytes] = []
    remaining = limit + 1
    while True:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        if remaining > 0:
            kept.append(chunk[:remaining])
            remaining -= len(chunk)
    sink.append(b"".join(kept))


def _tail(data: bytes, limit: int = 2048) -> str:
    """Bounded diagnostic tail; callers must not pass secret material."""
    return data[-limit:].decode("utf-8", errors="replace")


def run_contained(*, payload: bytes, snapshot_root: Path | None, paths: SandboxWorkdir) -> None:
    """Run checks contained; relay result and captures into the workdir.

    Spawns the contained runner with the pickled callable on stdin and
    a dedicated result fd. A snapshot without first-party sources is
    refused before spawning. Pipes are drained by bounded subscriber
    threads before reaping, so a chatty runner cannot deadlock the
    relay. Timeout enforcement stays with the parent's S2 supervision;
    this function blocks until the runner exits. Capture files are
    always written (bounded); any failure raises ContainedError for
    the caller to map to INFRA_FAILURE.
    """
    if snapshot_root is None:
        raise ContainedError("contained execution requires a snapshot")
    if not (snapshot_root / "src" / "attest_core").is_dir():
        raise ContainedError(f"snapshot incomplete: no attest_core in {snapshot_root / 'src'}")
    if len(payload) > MAX_PICKLE_BYTES:
        raise ContainedError(f"contained payload exceeds {MAX_PICKLE_BYTES} bytes")
    result_r, result_w = os.pipe()
    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                _BOOTSTRAP,
                str(snapshot_root / "src"),
                str(result_w),
                str(paths.root),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(result_w,),
            preexec_fn=die_with_parent,
            cwd=paths.root,
            env={"LC_ALL": "C.UTF-8"},
        )
    except BaseException:
        # Spawn failed: no child or reader owns result_r; release it.
        os.close(result_r)
        raise
    finally:
        os.close(result_w)
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    try:
        proc.stdin.write(payload)
        proc.stdin.close()
    except (BrokenPipeError, OSError) as exc:
        proc.wait()
        os.close(result_r)
        raise ContainedError(f"contained runner refused input: {exc}") from exc
    sinks: dict[str, list[bytes]] = {"result": [], "out": [], "err": []}
    jobs = [
        threading.Thread(target=_drain_bounded, args=(result_r, MAX_RESULT_BYTES, sinks["result"])),
        threading.Thread(
            target=_drain_bounded,
            args=(proc.stdout.fileno(), MAX_CAPTURE_BYTES, sinks["out"]),
        ),
        threading.Thread(
            target=_drain_bounded,
            args=(proc.stderr.fileno(), MAX_CAPTURE_BYTES, sinks["err"]),
        ),
    ]
    for job in jobs:
        job.daemon = True
        job.start()
    for job in jobs:
        job.join()
    os.close(result_r)
    exitcode = proc.wait()
    paths.stdout.write_bytes(b"".join(sinks["out"]))
    paths.stderr.write_bytes(b"".join(sinks["err"]))
    result = b"".join(sinks["result"])
    if exitcode != 0:
        raise ContainedError(f"contained runner exited {exitcode}: {_tail(b''.join(sinks['err']))}")
    if not result:
        raise ContainedError("contained runner produced no result")
    if len(result) > MAX_RESULT_BYTES:
        raise ContainedError(f"contained result exceeds {MAX_RESULT_BYTES} bytes")
    paths.result.write_bytes(result)
