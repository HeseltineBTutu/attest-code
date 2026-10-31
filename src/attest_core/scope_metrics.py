"""Per-attempt scope metrics: peaks and usage from cgroup v2 files.

Each hardened attempt runs in its own transient scope; this module
reads that scope's high-water marks while it is still alive (the
caller collects before teardown). Metrics describe exactly the
attempt whose scope is named — never host-wide counters.

Semantics (source file, unit, kind):

- ``memory.peak`` -> ``mem_peak``: bytes, high-water mark of RAM use.
- ``pids.peak`` -> ``pids_peak``: count, high-water mark of tasks.
- ``cpu.stat`` ``usage_usec`` -> ``cpu_usec``: microseconds, cumulative
  CPU time consumed. Event counters (oom, oom_kill, pids_max,
  throttled_usec) stay in :func:`scopes.read_scope_events`.

Collection is all-or-nothing with the event counters: peaks and
events come from the same live scope, so a scope readable for one
controller is readable for all. A scope removed mid-collection, a
missing file, or a malformed value raises :class:`ScopeError`,
which the caller renders as an explicit ``unavailable(...)``
marker — never a fabricated zero.
"""

from __future__ import annotations

from attest_core.scopes import ScopeError

_PEAK_FILES = {"mem_peak": "memory.peak", "pids_peak": "pids.peak"}
"""Metric name to single-value cgroup file holding it."""


def _read_int(path: str) -> int:
    """Read one integer from a cgroup file; anything else is ScopeError."""
    try:
        with open(path, encoding="ascii") as handle:
            text = handle.read().strip()
    except OSError as exc:
        raise ScopeError(f"cannot read {path}: {exc}") from exc
    try:
        return int(text)
    except ValueError:
        raise ScopeError(f"malformed counter in {path}: {text!r}") from None


def _stat_field(path: str, key: str) -> int:
    """Read one ``key value`` field from a cgroup stat file."""
    try:
        with open(path, encoding="ascii") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        raise ScopeError(f"cannot read {path}: {exc}") from exc
    for line in lines:
        if line.startswith(key + " "):
            try:
                return int(line.split()[1])
            except (ValueError, IndexError):
                break
    raise ScopeError(f"malformed counter {key!r} in {path}")


def read_peaks(scope_path: str) -> dict[str, int]:
    """Peak memory/tasks and cumulative CPU for one live scope.

    All values are non-negative by kernel construction; a scope
    removed before collection raises ScopeError.
    """
    peaks = {name: _read_int(f"{scope_path}/{leaf}") for name, leaf in _PEAK_FILES.items()}
    peaks["cpu_usec"] = _stat_field(f"{scope_path}/cpu.stat", "usage_usec")
    return peaks
