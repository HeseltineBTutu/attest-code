"""F3 measurement classification (M1, §10.6).

Derives exactly one class per measurement-complete invocation
from the bound attempt records only. Structurally incomplete
sets receive no classification (None), which is not a
verdict: P3 owns INVALID/INCOMPLETE severity. M1 classes are
measurement semantics, never verifier verdicts — outputs
never consult the stored verdict field and never emit
PASSED/FAILED or bare INCONCLUSIVE.
"""

from __future__ import annotations

import dataclasses

from attest_core.f3_records import AttemptRecord, TotalRecord

MEASUREMENT_CLEAN = "MEASUREMENT_CLEAN"
MEASUREMENT_VIOLATION = "MEASUREMENT_VIOLATION"
MEASUREMENT_INCONCLUSIVE = "MEASUREMENT_INCONCLUSIVE"


@dataclasses.dataclass(frozen=True)
class InvocationMeasurement:
    """Completeness plus M1 class for one invocation (P8 feeds Q1)."""

    invocation_id: str
    complete: bool
    m1: str | None


def classify_measurement(total: TotalRecord | None, attempts: list[AttemptRecord]) -> str | None:
    """M1 over bound attempts; None when the set is structurally incomplete."""
    if total is None or not attempts:
        return None
    expected = total.attempts_total
    numbers = sorted(record.attempt for record in attempts)
    if numbers != list(range(1, expected + 1)):
        return None
    censored = any(record.censored for record in attempts)
    outcomes = {record.outcome for record in attempts}
    if not censored and outcomes == {"PASS"}:
        return MEASUREMENT_CLEAN
    if not censored and outcomes == {"VIOLATION"}:
        return MEASUREMENT_VIOLATION
    return MEASUREMENT_INCONCLUSIVE


def measure_invocation(
    invocation_id: str,
    attempts: list[AttemptRecord],
    totals: list[TotalRecord],
    env_count: int,
) -> InvocationMeasurement:
    """Completeness (total+env+exact set) plus M1 for Q1 eligibility."""
    total = totals[0] if len(totals) == 1 else None
    m1 = classify_measurement(total, attempts)
    complete = m1 is not None and env_count == 1
    return InvocationMeasurement(invocation_id=invocation_id, complete=complete, m1=m1)
