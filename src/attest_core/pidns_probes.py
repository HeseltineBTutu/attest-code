"""M2 lifecycle probes: PID-namespace init semantics and teardown.

Each probe exercises one descendant-lifecycle behavior and reports PASS
only when the operating system enforces it. Probes run inside the
contained runner via ``run_bounded(..., contained=True)``; they are
imported there from the snapshot, so they must stay top-level and
picklable by reference. Shared fixture markers come from
:mod:`attest_core.contain_probes`, the M1 filesystem-probe module.
"""

from __future__ import annotations

import os
import sys
import time

from attest_core.contain_probes import mark_allowed, require_ns
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome


def probe_pid() -> AttemptReport:
    """Report this process's PID; PID-namespace init observes 1."""
    if (missing := require_ns()) is not None:
        return missing
    return AttemptReport(AttemptOutcome.PASS, (), f"pid:{os.getpid()}")


def _spawn_detached_sleeper(token: str) -> int:
    """Double-fork + setsid a sleeper; return its namespace PID.

    The middle process exits at once (reaped here); the sleeper
    detaches into a new session, drops inherited fds, and execs a
    token-marked sleep identifiable from the host by command line.
    """
    ready_r, ready_w = os.pipe()
    middle = os.fork()
    if middle != 0:
        os.close(ready_w)
        pid_text = b""
        while not pid_text.endswith(b"\n"):
            chunk = os.read(ready_r, 32)
            if not chunk:
                raise RuntimeError("detached spawn handshake failed")
            pid_text += chunk
        os.close(ready_r)
        os.waitpid(middle, 0)
        return int(pid_text.decode("ascii").strip())
    try:
        os.close(ready_r)
        os.setsid()
        sleeper = os.fork()
        if sleeper != 0:
            os.write(ready_w, f"{sleeper}\n".encode("ascii"))
            os.close(ready_w)
            os._exit(0)
        os.close(ready_w)
        devnull = os.open("/dev/null", os.O_RDWR)
        for target in (0, 1, 2):
            os.dup2(devnull, target)
        os.closerange(3, 1024)
        os.execv("/venv/bin/python", ["python", "-c", f"import time; time.sleep(300)  # {token}"])
    except BaseException:
        os._exit(127)
    os._exit(127)


def _sleeper_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def probe_detached_sleeper(token: str) -> AttemptReport:
    """Spawn a detached sleeper, prove it lived, exit normally."""
    if (missing := require_ns()) is not None:
        return missing
    pid = _spawn_detached_sleeper(token)
    if not _sleeper_alive(pid):
        return mark_allowed("sleeper-never-lived")
    return AttemptReport(AttemptOutcome.PASS, (), f"sleeper-alive:{token}")


def probe_crash_sleeper(token: str) -> AttemptReport:
    """Spawn a detached sleeper, announce it, then die as init."""
    if (missing := require_ns()) is not None:
        return missing
    pid = _spawn_detached_sleeper(token)
    if not _sleeper_alive(pid):
        return mark_allowed("sleeper-never-lived")
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
