"""M2 lifecycle probes: PID-namespace init semantics and teardown.

Each probe exercises one descendant-lifecycle behavior and reports PASS
only when the operating system enforces it. Probes run inside the
contained runner via ``run_bounded(..., contained=True)``; they are
imported there from the snapshot, so they must stay top-level and
picklable by reference. Shared fixture markers come from
:mod:`attest_core.contain_probes`, the M1 filesystem-probe module.
"""

from __future__ import annotations

import contextlib
import os
import select
import sys
import time

from attest_core.contain_probes import mark_allowed, require_ns
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome

_BEAT_READY = b"R"
_BEAT_BEAT = b"."
_BEATS_REQUIRED = 3
_BEAT_DELAY = 0.05
_HANDSHAKE_TIMEOUT = 5.0
"""Handshake bytes only a running process can write; zombies write nothing."""


def probe_pid() -> AttemptReport:
    """Report this process's PID; PID-namespace init observes 1."""
    if (missing := require_ns()) is not None:
        return missing
    return AttemptReport(AttemptOutcome.PASS, (), f"pid:{os.getpid()}")


def _read_exact(fd: int, count: int, timeout: float) -> bytes:
    """Read exactly count bytes before timeout; short reads raise."""
    deadline = time.monotonic() + timeout
    data = b""
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], max(remaining, 0))[0]:
            raise RuntimeError(f"sleeper handshake timeout ({len(data)}/{count} bytes)")
        chunk = os.read(fd, count - len(data))
        if not chunk:
            raise RuntimeError(f"sleeper handshake EOF ({len(data)}/{count} bytes)")
        data += chunk
    return data


def _spawn_fork_sleeper(sabotage: bool = False) -> int:
    """Double-fork + setsid a fork-only sleeper; return its namespace PID.

    No exec: the private root has no ELF loader, so the sleeper naps
    in already-loaded Python instead. Liveness is proven by bytes a
    zombie cannot produce — READY plus sustained heartbeats — read
    here with a deadline. EOF or timeout raises; a silent child can
    never look alive. With sabotage the Grandchild exits unannounced
    so tests can prove the handshake rejects it.
    """
    pid_r, pid_w = os.pipe()
    beat_r, beat_w = os.pipe()
    middle = os.fork()
    if middle != 0:
        os.close(pid_w)
        os.close(beat_w)
        pid_text = b""
        while not pid_text.endswith(b"\n"):
            pid_text += _read_exact(pid_r, 1, _HANDSHAKE_TIMEOUT)
        os.close(pid_r)
        os.waitpid(middle, 0)
        beats = _read_exact(beat_r, 1 + _BEATS_REQUIRED, _HANDSHAKE_TIMEOUT)
        os.close(beat_r)
        if beats != _BEAT_READY + _BEAT_BEAT * _BEATS_REQUIRED:
            raise RuntimeError(f"sleeper handshake garbled: {beats!r}")
        return int(pid_text.decode("ascii").strip())
    try:
        os.close(pid_r)
        os.close(beat_r)
        os.setsid()
        sleeper = os.fork()
        if sleeper != 0:
            os.write(pid_w, f"{sleeper}\n".encode("ascii"))
            os.close(pid_w)
            os.close(beat_w)
            os._exit(0)
        os.close(pid_w)
        if sabotage:
            os.close(beat_w)
            os._exit(0)
        devnull = os.open("/dev/null", os.O_RDWR)
        for target in (0, 1, 2):
            os.dup2(devnull, target)
        for fd in range(3, 1024):
            if fd != beat_w:
                with contextlib.suppress(OSError):
                    os.close(fd)
        os.write(beat_w, _BEAT_READY)
        for _ in range(_BEATS_REQUIRED):
            time.sleep(_BEAT_DELAY)
            os.write(beat_w, _BEAT_BEAT)
        os.close(beat_w)
        time.sleep(300)
        os._exit(0)
    except BaseException:
        os._exit(127)
    os._exit(127)


def _argv_has_token(token: str) -> bool:
    """Whether the runner stage argv carries this test's token.

    Runner, init, and every fork descendant share one command line,
    so the token in the stage path is what makes the sleeper
    host-identifiable. Absence fails loudly; the post-teardown
    absence scan must never pass for lack of a marker.
    """
    return len(sys.argv) > 3 and token in sys.argv[3]


def probe_detached_sleeper(token: str) -> AttemptReport:
    """Spawn a fork-only sleeper, prove it ran, exit normally."""
    if (missing := require_ns()) is not None:
        return missing
    if not _argv_has_token(token):
        return mark_allowed("stage-token-missing")
    try:
        _spawn_fork_sleeper()
    except RuntimeError as exc:
        return AttemptReport(AttemptOutcome.INFRA_FAILURE, (), f"sleeper-handshake-failed:{exc}")
    return AttemptReport(AttemptOutcome.PASS, (), f"sleeper-alive:{token}")


def probe_sleeper_handshake_negative() -> AttemptReport:
    """Prove the handshake rejects a child that never announces.

    The saboteur exits silently (the zombie case the old kill-0
    check accepted); PASS only when the handshake layer reports
    failure instead of mistaking it for a live sleeper.
    """
    if (missing := require_ns()) is not None:
        return missing
    try:
        _spawn_fork_sleeper(sabotage=True)
    except RuntimeError:
        return AttemptReport(AttemptOutcome.PASS, (), "handshake-failure-detected")
    return mark_allowed("handshake-accepted-silent-child")


def probe_crash_sleeper(token: str) -> AttemptReport:
    """Spawn a fork-only sleeper, announce it, then die as init."""
    if (missing := require_ns()) is not None:
        return missing
    if not _argv_has_token(token):
        print("STAGE_TOKEN_MISSING", file=sys.stderr, flush=True)
        os._exit(2)
    try:
        _spawn_fork_sleeper()
    except RuntimeError as exc:
        print(f"HANDSHAKE_FAILED:{exc}", file=sys.stderr, flush=True)
        os._exit(2)
    print(f"SLEEPER_ALIVE:{token}", file=sys.stderr, flush=True)
    os._exit(1)


def probe_hang() -> AttemptReport:
    """Sleep past any test timeout (the supervisor must kill us)."""
    if (missing := require_ns()) is not None:
        return missing
    time.sleep(120)
    return mark_allowed("hang-survived")


def probe_exit(code: int) -> AttemptReport:
    """Exit immediately with the given status (crash mapping probe)."""
    if (missing := require_ns()) is not None:
        return missing
    os._exit(code)


def probe_module_origins() -> AttemptReport:
    """Report where target modules loaded from (snapshot-first proof)."""
    if (missing := require_ns()) is not None:
        return missing
    core = getattr(sys.modules.get("attest_core.verification"), "__file__", None)
    spec = getattr(sys.modules.get("attest_spec"), "__file__", None)
    if not isinstance(core, str) or not isinstance(spec, str):
        return mark_allowed("origins-missing")
    return AttemptReport(AttemptOutcome.PASS, (), f"origins:{core},{spec}")
