"""F3 echo agreement: records must match each other and the declaration.

R-ID9 (target), R-ID11 (workload triple), and W1 (sample_class
echo, §7.2) are identity-level agreement checks. W1's series
role stays in P5; only the echo leg lives here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records import AttemptRecord, TotalRecord
from attest_core.f3_records_env import EnvRecord

InvRecord = AttemptRecord | TotalRecord | EnvRecord


def check_agreement(
    entry_index: int,
    entry: dict[str, Any],
    members: list[tuple[str, InvRecord]],
    targets: list[str],
) -> list[Finding]:
    """Agreement within one invocation plus conformance to its declaration."""
    out: list[Finding] = []
    workload = entry["workload"]
    declared_triple = (
        workload["workload_class"],
        workload["workload_id"],
        workload["input_digest"],
    )
    checks: list[tuple[Callable[[InvRecord], Any], Any, str, str]] = [
        (lambda record: record.target, entry["target"], "target", "R-ID9"),
        (
            lambda record: (
                record.workload_class,
                record.workload_id,
                record.input_digest,
            ),
            declared_triple,
            "workload triple",
            "R-ID11",
        ),
        (
            lambda record: record.sample_class,
            entry["sample_class"],
            "sample_class",
            "W1",
        ),
    ]
    where = f"$.campaign.invocations[{entry_index}]"
    for get, declared, what, rule in checks:
        seen = {get(record) for _, record in members}
        if len(seen) > 1:
            detail = "; ".join(f"{label}={get(record)!r}" for label, record in members)
            out.append(
                Finding(
                    severity="INVALID",
                    rule=rule,
                    location=where,
                    reason=f"{what} disagreement within invocation: {detail}",
                )
            )
        for label, record in members:
            if get(record) != declared:
                out.append(
                    Finding(
                        severity="INVALID",
                        rule=rule,
                        location=label,
                        reason=f"{what} {get(record)!r} != declared {declared!r}",
                    )
                )
    for label, record in members:
        if record.target not in targets:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="R-ID9",
                    location=label,
                    reason=f"target {record.target!r} not in protocol.targets",
                )
            )
    return out
