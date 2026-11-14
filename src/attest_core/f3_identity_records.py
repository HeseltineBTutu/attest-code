"""F3 per-invocation identity and cardinality (V-B2, V-B10, V-B11).

Campaign echo (V-B2), kind cardinality (V-B10), and attempt
identity (V-B11) for declared invocations, plus undeclared
records and declaration-free pair checks for packages whose
campaign root is missing or ambiguous.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from attest_core import f3_identity_agree as agree
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records import AttemptRecord, TotalRecord
from attest_core.f3_records_env import EnvRecord

InvRecord = AttemptRecord | TotalRecord | EnvRecord


def check_invocation(
    *,
    entry_index: int,
    entry: dict[str, Any],
    attempts: list[tuple[str, AttemptRecord]],
    totals: list[tuple[str, TotalRecord]],
    envs: list[tuple[str, EnvRecord]],
    campaign_id: str,
    targets: list[str],
) -> list[Finding]:
    """Identity and kind checks for one declared invocation with records."""
    out: list[Finding] = []
    members: list[tuple[str, InvRecord]] = []
    members.extend(attempts)
    members.extend(totals)
    members.extend(envs)
    for label, record in members:
        echo = _campaign_echo(label, record, campaign_id)
        if echo is not None:
            out.append(echo)
    out.extend(_cardinality(entry_index, entry, totals, "invocation_total"))
    out.extend(_cardinality(entry_index, entry, envs, "environment"))
    out.extend(agree.check_agreement(entry_index, entry, members, [str(item) for item in targets]))
    expected = totals[0][1].attempts_total if len(totals) == 1 else None
    out.extend(_attempt_identity(entry_index, attempts, expected))
    return out


def _cardinality(
    entry_index: int,
    entry: dict[str, Any],
    items: Sequence[tuple[str, InvRecord]],
    kind: str,
) -> list[Finding]:
    """V-B10: exactly one total and one environment per declared invocation."""
    location = f"$.campaign.invocations[{entry_index}]"
    if not items:
        return [
            Finding(
                severity="INCOMPLETE",
                rule="V-B10",
                location=location,
                reason=f"missing {kind} record for invocation {entry['invocation_id']!r}",
            )
        ]
    if len(items) > 1:
        labels = ", ".join(label for label, _ in items)
        return [
            Finding(
                severity="INVALID",
                rule="V-B10",
                location=items[1][0],
                reason=f"duplicate {kind} delivery: {labels}",
            )
        ]
    return []


def _attempt_identity(
    entry_index: int,
    attempts: list[tuple[str, AttemptRecord]],
    expected: int | None,
) -> list[Finding]:
    """V-B11: unique pairs; exact 1..N, strict prefix, or contradiction."""
    out: list[Finding] = []
    by_number: dict[int, list[str]] = {}
    for label, record in attempts:
        by_number.setdefault(record.attempt, []).append(label)
    for labels in (by_number[n] for n in sorted(by_number)):
        if len(labels) > 1:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B11",
                    location=labels[1],
                    reason=f"duplicate pair: {', '.join(labels)}",
                )
            )
    if expected is None:
        return out  # No single total: N is unverifiable, never assumed.
    found = set(by_number)
    want = set(range(1, expected + 1))
    if found == want:
        return out
    where = f"$.campaign.invocations[{entry_index}]"
    if found == set(range(1, len(found) + 1)) and len(found) < expected:
        missing = sorted(want - found)
        out.append(
            Finding(
                severity="INCOMPLETE",
                rule="V-B11",
                location=where,
                reason=f"consistent attempt prefix; missing numbers {missing}",
            )
        )
        return out
    outside = sorted(n for n in found if n < 1 or n > expected)
    if outside:
        out.append(
            Finding(
                severity="INVALID",
                rule="V-B11",
                location=where,
                reason=f"attempt numbers {outside} outside declared 1..{expected}",
            )
        )
        return out
    missing = sorted(want - found)
    out.append(
        Finding(
            severity="INVALID",
            rule="V-B11",
            location=where,
            reason=(
                "gapped attempt numbers contradict prefix-only interruption; "
                f"observed {sorted(found)}, missing {missing}"
            ),
        )
    )
    return out


def check_undeclared(
    members: list[tuple[str, InvRecord]],
    declared: set[str],
    campaign_id: str,
) -> list[Finding]:
    """V-B2: records citing invocations the campaign never declared."""
    out: list[Finding] = []
    for label, record in members:
        if record.invocation_id not in declared:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B2",
                    location=label,
                    reason=f"undeclared invocation_id {record.invocation_id!r}",
                )
            )
        echo = _campaign_echo(label, record, campaign_id)
        if echo is not None:
            out.append(echo)
    return out


def _campaign_echo(label: str, record: InvRecord, campaign_id: str) -> Finding | None:
    """V-B2: every record echoes its campaign's id."""
    if record.campaign_id != campaign_id:
        return Finding(
            severity="INVALID",
            rule="V-B2",
            location=label,
            reason=f"campaign_id {record.campaign_id!r} != campaign {campaign_id!r}",
        )
    return None


def check_observed_pairs(attempts: list[tuple[str, AttemptRecord]]) -> list[Finding]:
    """V-B11 duplicate-pair leg without any declaration (no/ambiguous campaign)."""
    out: list[Finding] = []
    seen: dict[tuple[str, int], str] = {}
    for label, record in attempts:
        pair = (record.invocation_id, record.attempt)
        if pair in seen:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B11",
                    location=label,
                    reason=f"duplicate pair (also at {seen[pair]})",
                )
            )
        else:
            seen[pair] = label
    return out
