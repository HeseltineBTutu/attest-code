"""Child-side scope placement proof for M3-A quotas (Linux-only, os-only).

Minimal import surface for the -S runner self-verify: no subprocess,
no bus. Failures raise ScopeError."""

from __future__ import annotations

from attest_core.scopes import ScopeError as ScopeError


def verify_self_in_scope(unit: str) -> None:
    """This process must already be inside the named scope; else ScopeError."""
    try:
        with open("/proc/self/cgroup", encoding="ascii") as handle:
            line = handle.read().strip()
    except OSError as exc:
        raise ScopeError(f"cannot read own cgroup: {exc}") from exc
    if not unit or unit not in line:
        raise ScopeError(f"runner misplaced: in {line or 'no cgroup'}")
