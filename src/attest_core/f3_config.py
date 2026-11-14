"""F3 warm-up/measured configuration match within a series (W2, §6.3).

Each warm-up invocation must match each measured invocation of
its series on (profile, timeout_s, git_revision,
pyproject_digest, uv_lock_digest): profile and timeout from
the invocation's attempt records (unanimous within the
invocation), revision and lock digests from its environment
record. Markers compare by exact equality — an unavailable
field cannot establish a match (exact match, no waiver, D7).
Target and workload legs are P3's R-ID9/R-ID11, not repeated.
"""

from __future__ import annotations

from typing import Any

from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records import AttemptRecord
from attest_core.f3_records_env import EnvRecord
from attest_core.f3_series import Series

_FIELDS = ("profile", "timeout_s", "git_revision", "pyproject_digest", "uv_lock_digest")


def check_series_config(
    series: Series,
    attempts_by_inv: dict[str, list[tuple[str, AttemptRecord]]],
    envs_by_inv: dict[str, list[tuple[str, EnvRecord]]],
) -> tuple[Finding, ...]:
    """W2 for one series: every warm-up matches every measured invocation."""
    out: list[Finding] = []
    tuples: dict[str, tuple[Any, ...]] = {}
    for member in series.members:
        held_a = attempts_by_inv.get(member.invocation_id, [])
        held_e = envs_by_inv.get(member.invocation_id, [])
        if not held_a or len(held_e) != 1:
            continue
        unanimous, derivation = _invocation_tuple(held_a, held_e[0])
        out.extend(derivation)
        if unanimous is not None:
            tuples[member.invocation_id] = unanimous
    warmups = [m for m in series.members if m.sample_class == "warmup"]
    measured = [m for m in series.members if m.sample_class == "measured"]
    for left in warmups:
        for right in measured:
            if left.invocation_id in tuples and right.invocation_id in tuples:
                out.extend(_compare(series, left.invocation_id, right.invocation_id, tuples))
    return tuple(out)


def _invocation_tuple(
    attempts: list[tuple[str, AttemptRecord]], env: tuple[str, EnvRecord]
) -> tuple[tuple[Any, ...] | None, list[Finding]]:
    """Derive one invocation's config tuple; split attempts fail loudly."""
    out: list[Finding] = []
    profiles = {record.profile for _, record in attempts}
    timeouts = {record.timeout_s for _, record in attempts}
    if len(profiles) > 1:
        detail = "; ".join(f"{label}={record.profile}" for label, record in attempts)
        out.append(
            Finding(
                severity="INVALID",
                rule="W2",
                location=attempts[1][0],
                reason=f"profile disagreement within invocation: {detail}",
            )
        )
    if len(timeouts) > 1:
        detail = "; ".join(f"{label}={record.timeout_s}" for label, record in attempts)
        out.append(
            Finding(
                severity="INVALID",
                rule="W2",
                location=attempts[1][0],
                reason=f"timeout_s disagreement within invocation: {detail}",
            )
        )
    if out:
        return None, out
    record = env[1]
    return (
        (
            attempts[0][1].profile,
            attempts[0][1].timeout_s,
            record.git_revision,
            record.pyproject_digest,
            record.uv_lock_digest,
        ),
        out,
    )


def _compare(
    series: Series, warmup: str, measured: str, tuples: dict[str, tuple[Any, ...]]
) -> list[Finding]:
    """One warm-up/measured pair: exact tuple match or INVALID naming fields."""
    left, right = tuples[warmup], tuples[measured]
    differing = [name for name, old, new in zip(_FIELDS, left, right, strict=True) if old != new]
    if not differing:
        return []
    detail = "; ".join(
        f"{name}: {left[i]!r} != {right[i]!r}"
        for i, name in enumerate(_FIELDS)
        if name in differing
    )
    where = f"$.campaign.invocations[{_entry_of(series, warmup)}]"
    return [
        Finding(
            severity="INVALID",
            rule="W2",
            location=where,
            reason=(
                f"warmup {warmup} config differs from measured {measured} "
                f"(series {series.ordinal}; {', '.join(differing)}): {detail}"
            ),
        )
    ]


def _entry_of(series: Series, invocation_id: str) -> int:
    """Entry index of a series member."""
    return next(m.entry_index for m in series.members if m.invocation_id == invocation_id)
