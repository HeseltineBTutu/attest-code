"""F3 package summary composition over P3–P6 reports (§10.4, §10.6, §13).

Refuses INVALID packages (§13), composes per-series summaries via
`f3_summary`, and carries P6 content alongside them (I9). Stored
verdicts ride opaquely (M2); gaps/diagnostics carried verbatim.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from attest_core import f3_summary as summary_mod
from attest_core.f3_compare_attrs import InvAttributes
from attest_core.f3_errors import F3Error
from attest_core.f3_identity import IdentityReport, PackageRecords
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_measure import InvocationMeasurement
from attest_core.f3_quorum import QuorumResult
from attest_core.f3_records import AttemptRecord, TotalRecord
from attest_core.f3_records_summary import SummaryRecord
from attest_core.f3_series import Diagnostic, Series, SeriesReport


@dataclasses.dataclass(frozen=True)
class SeriesComposition:
    """One series' composed content: summary plus carried P6 reports.

    `stored_verdicts` pairs each member with its single stored total
    verdict, else None (M2: opaque). Member tuples run in member
    order. Quorum/measurements/attributes carried verbatim (I9).
    """

    series_key: tuple[str, str, str, str, int]
    summary: SummaryRecord | None
    absent_reason: str | None
    quorum: QuorumResult
    measurements: tuple[InvocationMeasurement, ...]
    attributes: tuple[InvAttributes, ...]
    stored_verdicts: tuple[tuple[str, str | None], ...]

    def __post_init__(self) -> None:
        if (self.summary is None) == (self.absent_reason is None):
            raise ValueError("exactly one of summary/absent_reason must be set")


@dataclasses.dataclass(frozen=True)
class SummaryComposition:
    """Package composition: per-series content plus carried P3–P5 reports.

    INVALID findings impossible (refused); diagnostics never fail (§13).
    """

    campaign_id: str | None
    series: tuple[SeriesComposition, ...]
    findings: tuple[Finding, ...]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def severity(self) -> str:
        """Worst finding wins; clean packages are VALID."""
        if any(item.severity == "INVALID" for item in self.findings):
            return "INVALID"
        if any(item.severity == "INCOMPLETE" for item in self.findings):
            return "INCOMPLETE"
        return "VALID"

    @property
    def ok(self) -> bool:
        """True only when no finding of any severity exists."""
        return not self.findings


def _refuse_invalid(findings: tuple[Finding, ...]) -> None:
    """Refuse composition when any upstream report is INVALID (§13)."""
    blocking = [item for item in findings if item.severity == "INVALID"]
    if blocking:
        detail = "; ".join(f"{item.rule}@{item.location}: {item.reason}" for item in blocking)
        raise F3Error(
            rule="COMPOSE",
            section="13",
            location="$",
            reason=f"INVALID package: nothing downstream consumes it ({detail})",
        )


def _check_coverage(have: set[Any], want: set[Any], what: str, section: str) -> None:
    """Refuse missing or surplus upstream keys (fail closed, deterministic)."""
    cases = (
        (f"missing upstream {what} for", want - have),
        (f"incompatible {what} outside the composed package", have - want),
    )
    for message, gap in cases:
        keys = sorted(gap, key=repr)
        if keys:
            detail = ", ".join(repr(key) for key in keys)
            raise F3Error(
                rule="COMPOSE", section=section, location="$", reason=f"{message}: {detail}"
            )


def _stored_verdict(totals: list[TotalRecord]) -> str | None:
    """Single total's verdict verbatim, else None (M2: never interpreted)."""
    return totals[0].verdict if len(totals) == 1 else None


def compose_package(
    *,
    package: PackageRecords,
    identity: IdentityReport,
    workload_findings: tuple[Finding, ...],
    series_report: SeriesReport,
    measurements: dict[str, InvocationMeasurement],
    quorums: dict[tuple[str, str, str, str, int], QuorumResult],
    attributes: dict[str, InvAttributes],
    record_ids: dict[tuple[str, str, str, str, int], str],
    context: dict[str, str] | None = None,
) -> SummaryComposition:
    """Compose per-series summaries over the P3–P6 reports.

    `record_ids` covers every series key (unused ids allowed);
    `context` echoes verbatim into every summary. Attempts outside
    every series are refused, never silently dropped (I2).
    """
    carried = (*identity.findings, *workload_findings, *series_report.findings)
    notes = series_report.diagnostics
    _refuse_invalid(carried)
    ordered: list[Series] = sorted(series_report.series, key=lambda item: item.ordinal)
    if len(package.campaigns) != 1:
        if ordered or len(package.campaigns) > 1:
            raise F3Error(
                rule="COMPOSE",
                section="10.4",
                location="$",
                reason="no single campaign identity for the composed summaries",
            )
        dropped = len(package.attempts) + len(package.totals) + len(package.envs)
        if dropped:
            raise F3Error(
                rule="COMPOSE",
                section="10.4",
                location="$",
                reason=f"{dropped} records without a declaring campaign (I2: never dropped)",
            )
        return SummaryComposition(campaign_id=None, series=(), findings=carried, diagnostics=notes)
    campaign_id = package.campaigns[0].campaign_id
    keys = {item.key for item in ordered}
    members = {member.invocation_id for item in ordered for member in item.members}
    _check_coverage(set(quorums), keys, "quorum", "10.6")
    _check_coverage(set(record_ids), keys, "record_id", "7.5")
    _check_coverage(set(measurements), members, "measurement", "10.6")
    _check_coverage(set(attributes), members, "attributes", "10.7")
    stray = sorted({r.record_id for r in package.attempts if r.invocation_id not in members})
    if stray:
        raise F3Error(
            rule="COMPOSE",
            section="10.4",
            location="$",
            reason=(
                "attempt records outside every composed series "
                f"(silently dropping them would violate I2): {', '.join(stray)}"
            ),
        )
    attempts_by_inv: dict[str, list[AttemptRecord]] = {}
    for attempt in package.attempts:
        attempts_by_inv.setdefault(attempt.invocation_id, []).append(attempt)
    totals_by_inv: dict[str, list[TotalRecord]] = {}
    for total in package.totals:
        totals_by_inv.setdefault(total.invocation_id, []).append(total)
    composed: list[SeriesComposition] = []
    for item in ordered:
        owned = frozenset(member.invocation_id for member in item.members)
        bound = [r for m in item.members for r in attempts_by_inv.get(m.invocation_id, [])]
        outcome = summary_mod.compose_summary(
            bound,
            series_key=item.key,
            member_invocations=owned,
            campaign_id=campaign_id,
            record_id=record_ids[item.key],
            context=context,
        )
        composed.append(
            SeriesComposition(
                series_key=item.key,
                summary=outcome.summary,
                absent_reason=outcome.absent_reason,
                quorum=quorums[item.key],
                measurements=tuple(measurements[m.invocation_id] for m in item.members),
                attributes=tuple(attributes[m.invocation_id] for m in item.members),
                stored_verdicts=tuple(
                    (m.invocation_id, _stored_verdict(totals_by_inv.get(m.invocation_id, [])))
                    for m in item.members
                ),
            )
        )
    return SummaryComposition(
        campaign_id=campaign_id, series=tuple(composed), findings=carried, diagnostics=notes
    )
