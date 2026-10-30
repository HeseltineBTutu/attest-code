"""M3-A quota probes: resource-enforcement adversarial fixtures.

Each probe exercises one cgroup quota and reports PASS only when the
operating system enforces it; unexpected success yields VIOLATION with
an ALLOWED marker. Probes run inside the contained runner via
``run_bounded(..., contained=True, quotas=True)``; they are imported
there from the snapshot, so they must stay top-level and picklable
by reference. Shared markers come from :mod:`attest_core.contain_probes`.
"""

from __future__ import annotations

import os
import signal
import time

from attest_core.contain_probes import mark_allowed, require_ns
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome

_CHUNK_MB = 50
_CHUNK_PAGES = (_CHUNK_MB << 20) // 4096


def probe_no_cgroupfs() -> AttemptReport:
    """cgroupfs and proc must stay invisible to checks (no escape interface)."""
    if (missing := require_ns()) is not None:
        return missing
    if os.path.exists("/sys/fs/cgroup") or os.path.exists("/proc/self/cgroup"):
        return mark_allowed("cgroup-interface-visible")
    return AttemptReport(AttemptOutcome.PASS, (), "no-cgroup-interface")


def _burn(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pass


def probe_burn_cpu() -> AttemptReport:
    """Burn 4x2 CPU-seconds over forked children; quota throttles, not kills."""
    if (missing := require_ns()) is not None:
        return missing
    kids: list[int] = []
    for _ in range(3):
        pid = os.fork()
        if pid == 0:
            _burn(2.0)
            os._exit(0)
        kids.append(pid)
    _burn(2.0)
    for pid in kids:
        _, status = os.waitpid(pid, 0)
        if status != 0:
            return mark_allowed("burner-died")
    return AttemptReport(AttemptOutcome.PASS, (), "burned:4x2s")


def probe_hog_memory() -> AttemptReport:
    """Grow touched RSS past the 512M scope cap; the kernel must OOM-kill us."""
    if (missing := require_ns()) is not None:
        return missing
    held: list[bytearray] = []
    for _ in range(30):
        chunk = bytearray(_CHUNK_MB << 20)
        chunk[0::4096] = b"\x01" * _CHUNK_PAGES
        held.append(chunk)
    return mark_allowed("oom-survived")


def probe_fork_many() -> AttemptReport:
    """Fork 70 concurrent sleepers; the 64-task scope must deny some."""
    if (missing := require_ns()) is not None:
        return missing
    kids: list[int] = []
    denied = 0
    for _ in range(70):
        try:
            pid = os.fork()
        except OSError:
            denied += 1
            continue
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        kids.append(pid)
    for pid in kids:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    if denied == 0:
        return mark_allowed("tasks-uncapped")
    return AttemptReport(AttemptOutcome.PASS, (), f"forks-capped:{len(kids)}")
