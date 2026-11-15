"""F3 performance quorum evaluated once per W3 series (Q1, §10.6).

Eligibility: measurement-complete AND measured AND M1 in
{CLEAN, VIOLATION} AND evidence-verified. Shortfall is a
complete package with met:false, never incompleteness.
Quorum assumes P3 reported no INVALID (P8 gates on that);
it emits counts, never findings.

AQ-1 resolved by owner decision (2026-11-15; see
docs/decisions/f3-p6-policy-decisions.md): reproducible,
complete, uncensored MEASUREMENT_VIOLATION repetitions
count toward successful-sample quorum under the existing
eligibility conjuncts. Measurement eligibility does not
imply verifier success.
"""

from __future__ import annotations

import dataclasses

from attest_core.f3_measure import (
    MEASUREMENT_CLEAN,
    MEASUREMENT_VIOLATION,
    InvocationMeasurement,
)
from attest_core.f3_series import Series

# AQ-1: the design counts completed violations as successful
# samples. If the policy owner rejects that reading, set this
# to False (CLEAN only) — no other change required.
VIOLATION_COUNTS_AS_SUCCESSFUL = True


@dataclasses.dataclass(frozen=True)
class QuorumResult:
    """One quorum evaluation for one series (validation-report object)."""

    series_key: tuple[str, str, str, str, int]
    eligible: tuple[str, ...]
    eligible_count: int
    required_successful: int
    met: bool
    excluded: tuple[tuple[str, str], ...]


def _successful(m1: str | None) -> bool:
    """M1 conjunct of eligibility (AQ-1 isolated here)."""
    if m1 == MEASUREMENT_CLEAN:
        return True
    return VIOLATION_COUNTS_AS_SUCCESSFUL and m1 == MEASUREMENT_VIOLATION


def evaluate_quorum(
    *,
    series: Series,
    measurements: dict[str, InvocationMeasurement],
    evidence_ok: set[str],
    required_successful: int,
) -> QuorumResult:
    """Q1 over one series in member (run) order; deterministic output."""
    eligible: list[str] = []
    excluded: list[tuple[str, str]] = []
    for member in series.members:
        inv = member.invocation_id
        seen = measurements.get(inv)
        if seen is None or not seen.complete:
            excluded.append((inv, "incomplete"))
        elif member.sample_class != "measured":
            excluded.append((inv, "warmup"))
        elif not _successful(seen.m1):
            excluded.append((inv, "measurement-inconclusive"))
        elif inv not in evidence_ok:
            excluded.append((inv, "evidence-missing"))
        else:
            eligible.append(inv)
    met = len(eligible) >= required_successful
    return QuorumResult(
        series_key=series.key,
        eligible=tuple(eligible),
        eligible_count=len(eligible),
        required_successful=required_successful,
        met=met,
        excluded=tuple(excluded),
    )
