"""F3 count legs, N-chain, and total consistency (V-B7, V-B8, V-B12, T1, T2).

Pure validation over typed records: no filesystem, no verdict
imports. T1/T2 run only over complete attempt sets — judging a
total's full-run claims against a partial set would misclassify
gaps (INCOMPLETE) as contradictions (INVALID).
"""

from __future__ import annotations

from collections import Counter
from decimal import Decimal

from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records import AttemptRecord, TotalRecord

ENGINE_ATTEMPTS = 3  # REQUIRED_ATTEMPTS, verdicts.py:21 (read-only; never imported)


def check_engine(protocol_n: int) -> Finding | None:
    """V-B8: declared attempts_per_invocation must equal the engine constant."""
    if protocol_n != ENGINE_ATTEMPTS:
        return Finding(
            severity="INVALID",
            rule="V-B8",
            location="$.campaign.protocol.attempts_per_invocation",
            reason=(
                "engine drift — conscious update required: "
                f"protocol declares {protocol_n}, engine requires {ENGINE_ATTEMPTS}"
            ),
        )
    return None


def check_invocation(
    *,
    entry_index: int,
    attempts: list[tuple[str, AttemptRecord]],
    totals: list[tuple[str, TotalRecord]],
    protocol_n: int,
) -> list[Finding]:
    """V-B7, V-B12, T1, T2 for one declared invocation with records."""
    out: list[Finding] = []
    if not totals:
        out.append(
            Finding(
                severity="INCOMPLETE",
                rule="V-B7",
                location=f"$.campaign.invocations[{entry_index}]",
                reason="no total record: attempt count unverifiable, never assumed",
            )
        )
        return out
    if len(totals) > 1:
        return out  # V-B10 owns duplicate totals; no single N to check against.
    label, total = totals[0]
    numbers = [record.attempt for _, record in attempts]
    if len(numbers) > total.attempts_total:
        out.append(
            Finding(
                severity="INVALID",
                rule="V-B7",
                location=label,
                reason=(
                    f"attempt count {len(numbers)} exceeds "
                    f"total.attempts_total {total.attempts_total} (injection)"
                ),
            )
        )
    elif len(numbers) < total.attempts_total:
        out.append(
            Finding(
                severity="INCOMPLETE",
                rule="V-B7",
                location=label,
                reason=(
                    f"attempt count {len(numbers)} short of "
                    f"total.attempts_total {total.attempts_total}"
                ),
            )
        )
    if total.attempts_total != protocol_n:
        out.append(
            Finding(
                severity="INVALID",
                rule="V-B12",
                location=label,
                reason=(
                    "N-chain break: total.attempts_total "
                    f"{total.attempts_total} != protocol.attempts_per_invocation "
                    f"{protocol_n}"
                ),
            )
        )
    if total.attempts_completed > total.attempts_total:
        out.append(
            Finding(
                severity="INVALID",
                rule="V-B12",
                location=f"{label}.attempts_completed",
                reason=(
                    f"attempts_completed {total.attempts_completed} exceeds "
                    f"attempts_total {total.attempts_total}"
                ),
            )
        )
    elif total.attempts_completed < total.attempts_total:
        out.append(
            Finding(
                severity="INCOMPLETE",
                rule="V-B12",
                location=label,
                reason=(
                    f"partial run: attempts_completed {total.attempts_completed} "
                    f"< attempts_total {total.attempts_total} (retained)"
                ),
            )
        )
    if _complete_set(numbers, total.attempts_total):
        out.extend(_check_t2(label, total, attempts))
        out.extend(_check_t1(label, total, attempts))
    return out


def _complete_set(numbers: list[int], expected: int) -> bool:
    """Exactly one record per number 1..N (implies no dup pairs)."""
    return len(numbers) == expected and set(numbers) == set(range(1, expected + 1))


def _check_t2(
    label: str, total: TotalRecord, attempts: list[tuple[str, AttemptRecord]]
) -> list[Finding]:
    """T2: outcome map must equal the recount over the bound set."""
    recounted = dict(Counter(record.outcome for _, record in attempts))
    if recounted != total.attempt_outcomes:
        return [
            Finding(
                severity="INVALID",
                rule="T2",
                location=label,
                reason=(
                    f"attempt_outcomes {total.attempt_outcomes!r} "
                    f"!= recount {recounted!r} over bound attempts"
                ),
            )
        ]
    return []


def _check_t1(
    label: str, total: TotalRecord, attempts: list[tuple[str, AttemptRecord]]
) -> list[Finding]:
    """T1: a completed invocation's total span covers its attempts."""
    elapsed = sum((Decimal(record.elapsed_s) for _, record in attempts), Decimal(0))
    if Decimal(total.elapsed_s) < elapsed:
        return [
            Finding(
                severity="INVALID",
                rule="T1",
                location=label,
                reason=(
                    f"total_elapsed_s {total.elapsed_s} < "
                    f"sum of attempts {elapsed} (clock corruption or tampering)"
                ),
            )
        ]
    return []
