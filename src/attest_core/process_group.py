"""Unix process-group establishment, validation, and signalling (S2).

Each worker establishes its own group as its first action and records
the group id in a handshake file. The parent signals only a verified
group — handshake must name exactly the child's pid and never a
protected id — so handshake tampering cannot redirect signals.
Numeric PGID reuse after the worker is reaped remains a same-UID
availability residual (see security-model.md). Best-effort delivery:
verification, not delivery, decides cleanup success.
"""

from __future__ import annotations

import contextlib
import os
import signal
from multiprocessing.context import SpawnProcess

from attest_core.sandbox import SandboxWorkdir

_HANDSHAKE_MAX_BYTES = 32


def supports_process_groups() -> bool:
    """Whether group supervision is available (POSIX with session control)."""
    return os.name == "posix" and hasattr(os, "killpg") and hasattr(os, "setsid")


def establish_worker_group(paths: SandboxWorkdir) -> None:
    """In-child first action: new process group plus recorded handshake.

    Runs before any check code, so descendants can only exist under the
    recorded group. Any failure propagates and the worker exits before
    running checks. No-op where groups are unsupported (single-process
    supervision then applies by construction).
    """
    if not supports_process_groups():
        return
    try:
        os.setsid()
    except OSError:
        os.setpgid(0, 0)
    paths.pgid.write_text(str(os.getpgrp()), encoding="ascii")


def verified_pgid(paths: SandboxWorkdir, proc: SpawnProcess) -> int | None:
    """Return the group id only if fully verified, else None (never signal).

    Verified means: a short ASCII handshake naming exactly the child's
    own pid, and never pid 1, our own pid, or our own process group.
    """
    try:
        with open(paths.pgid, "rb") as handle:
            text = handle.read(_HANDSHAKE_MAX_BYTES + 1).decode("ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not text.isdigit():
        return None
    pgid = int(text)
    if proc.pid is None or pgid != proc.pid:
        return None
    if pgid <= 1 or pgid == os.getpid() or pgid == os.getpgrp():
        return None
    return pgid


def signal_group(pgid: int, signum: signal.Signals) -> None:
    """Best-effort signal to an already-verified group; never raises."""
    with contextlib.suppress(OSError):
        os.killpg(pgid, signum)
