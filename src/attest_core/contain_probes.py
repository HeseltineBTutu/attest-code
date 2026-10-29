"""M1 containment probes: verifier-owned adversarial fixtures.

Each probe attempts one hostile action and reports PASS only when the
operating system denies it (or the channel preserves it, for integrity
probes). Unexpected success yields VIOLATION with an ``ALLOWED`` marker
— never confused with infrastructure failure. Probes run inside the
contained runner via ``run_bounded(..., contained=True)``; they are
imported there from the snapshot, so they must stay top-level and
picklable by reference.

Probes never return secret contents: denial is reported by marker and
basename only. Each probe also detects a missing namespace (``/scratch``
or ``/snapshot`` absent) and reports VIOLATION rather than a false
denial, so running outside containment fails loudly, never green.

M2 lifecycle probes live in :mod:`attest_core.pidns_probes` and reuse
the ``require_ns`` / ``mark_allowed`` markers defined here.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sys

from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome


def mark_denied(what: str) -> AttemptReport:
    return AttemptReport(AttemptOutcome.PASS, (), f"denied:{what}")


def mark_allowed(what: str) -> AttemptReport:
    return AttemptReport(AttemptOutcome.VIOLATION, (), f"ALLOWED:{what}")


def require_ns() -> AttemptReport | None:
    """VIOLATION marker when the namespace layout is absent, else None."""
    if not os.path.isdir("/snapshot") or not os.path.isdir("/scratch"):
        return mark_allowed("not-contained")
    return None


def probe_snapshot_write() -> AttemptReport:
    """Snapshot must be read-only: a write attempt must fail."""
    if (missing := require_ns()) is not None:
        return missing
    try:
        with open("/snapshot/pwned", "w", encoding="utf-8") as handle:
            handle.write("x")
    except OSError:
        return mark_denied("snapshot-write")
    with contextlib.suppress(OSError):
        os.unlink("/snapshot/pwned")
    return mark_allowed("snapshot-write")


def probe_escape_write(path: str) -> AttemptReport:
    """Host paths outside scratch must be unreachable for writing."""
    if (missing := require_ns()) is not None:
        return missing
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("escaped")
    except OSError:
        return mark_denied(f"escape-write:{os.path.basename(path)}")
    return mark_allowed(f"escape-write:{os.path.basename(path)}")


def probe_secret_read(path: str) -> AttemptReport:
    """Operator-only files must be unreadable; contents never reported."""
    if (missing := require_ns()) is not None:
        return missing
    name = os.path.basename(path)
    try:
        with open(path, encoding="utf-8") as handle:
            handle.read()
    except OSError:
        return mark_denied(f"secret-read:{name}")
    return mark_allowed(f"secret-read:{name}")


def probe_scratch_fill() -> AttemptReport:
    """Scratch beyond its tmpfs capacity must fail; small writes work."""
    if (missing := require_ns()) is not None:
        return missing
    try:
        with open("/scratch/ok", "w", encoding="utf-8") as handle:
            handle.write("small")
        with open("/scratch/ok", encoding="utf-8") as handle:
            if handle.read() != "small":
                return mark_allowed("scratch-unusable")
    except OSError:
        return mark_allowed("scratch-unusable")
    try:
        with open("/scratch/fill", "wb") as handle:
            handle.write(b"f" * (70 * 1024 * 1024))
            handle.flush()
    except OSError:
        return mark_denied("scratch-overflow")
    return mark_allowed("scratch-overflow")


def probe_exec_scratch() -> AttemptReport:
    """Scratch is noexec: a copied binary must refuse to execute."""
    if (missing := require_ns()) is not None:
        return missing
    target = "/scratch/notreally"
    try:
        shutil.copy("/venv/bin/python", target)
        os.execv(target, [target, "-c", "pass"])
    except OSError:
        return mark_denied("scratch-exec")
    return mark_allowed("scratch-exec")


def probe_environ() -> AttemptReport:
    """Report the exact environment key set (keys only, never values)."""
    if (missing := require_ns()) is not None:
        return missing
    return AttemptReport(AttemptOutcome.PASS, (), "env:" + ",".join(sorted(os.environ)))


def probe_big_detail() -> AttemptReport:
    """Oversized evidence must be clipped, relayed, and decodable."""
    if (missing := require_ns()) is not None:
        return missing
    return AttemptReport(AttemptOutcome.PASS, (), "D" * 20000)


def probe_python_version() -> AttemptReport:
    """Sanity: the contained interpreter resolves (version string only)."""
    if (missing := require_ns()) is not None:
        return missing
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    return AttemptReport(AttemptOutcome.PASS, (), f"python:{version}")
