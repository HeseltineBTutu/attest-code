"""F3 validation report: schema, inventory, severity (§9, §13).

ValidationReport is the single-package validator's output: status
(validated | refused | infrastructure-failure), worst-wins severity
over carried findings, per-invocation record inventory with evidence
flags (§9 present reporting; missing/surplus stay P3's findings),
P6 measurement/quorum/comparability content, and P7 per-series
content. No ok flag by design: status plus severity is the complete
determination, so an infrastructure failure with no findings never
reads as success.
"""

from __future__ import annotations

import dataclasses

from attest_core import f3_assemble as asm
from attest_core.f3_compare_attrs import InvAttributes
from attest_core.f3_compose import SeriesComposition
from attest_core.f3_identity import PackageRecords
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_measure import InvocationMeasurement
from attest_core.f3_quorum import QuorumResult
from attest_core.f3_series import Diagnostic

STATUS_VALIDATED = "validated"
STATUS_REFUSED = "refused"
STATUS_INFRA = "infrastructure-failure"
_STATUSES = frozenset({STATUS_VALIDATED, STATUS_REFUSED, STATUS_INFRA})


@dataclasses.dataclass(frozen=True)
class InvInventory:
    """Per-invocation bound records plus evidence status (§9 present)."""

    invocation_id: str
    attempts: tuple[str, ...]
    totals: tuple[str, ...]
    envs: tuple[str, ...]
    evidence_verified: bool


@dataclasses.dataclass(frozen=True)
class ValidationReport:
    """Single-package validation outcome with carried stage content.

    `findings` concatenates stage findings in execution order,
    verbatim, each exactly once; `diagnostics` carries P5 notes.
    `composition` holds P7 per-series content only, since the
    report-level tuples already carry P7's identical findings and
    diagnostics objects.
    """

    status: str
    campaign_id: str | None
    findings: tuple[Finding, ...]
    diagnostics: tuple[Diagnostic, ...]
    inventory: tuple[InvInventory, ...]
    measurements: tuple[InvocationMeasurement, ...]
    attributes: tuple[InvAttributes, ...]
    quorums: tuple[QuorumResult, ...]
    composition: tuple[SeriesComposition, ...]

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ValueError(f"unknown validation status: {self.status!r}")

    @property
    def severity(self) -> str | None:
        """Worst finding wins (§13); None only when nothing was validated."""
        if self.status == STATUS_INFRA and not self.findings:
            return None
        if any(item.severity == "INVALID" for item in self.findings):
            return "INVALID"
        if any(item.severity == "INCOMPLETE" for item in self.findings):
            return "INCOMPLETE"
        return "VALID"


def build_report(
    *,
    status: str,
    package: PackageRecords,
    evidence_ok: set[str],
    findings: tuple[Finding, ...],
    diagnostics: tuple[Diagnostic, ...] = (),
    measurements: tuple[InvocationMeasurement, ...] = (),
    attributes: tuple[InvAttributes, ...] = (),
    quorums: tuple[QuorumResult, ...] = (),
    composition: tuple[SeriesComposition, ...] = (),
) -> ValidationReport:
    """Assemble a report from sequenced stage outputs (caller orders inputs)."""
    campaign_id = package.campaigns[0].campaign_id if len(package.campaigns) == 1 else None
    return ValidationReport(
        status=status,
        campaign_id=campaign_id,
        findings=findings,
        diagnostics=diagnostics,
        inventory=_inventory(package, evidence_ok),
        measurements=measurements,
        attributes=attributes,
        quorums=quorums,
        composition=composition,
    )


def _inventory(package: PackageRecords, evidence_ok: set[str]) -> tuple[InvInventory, ...]:
    """Record ids per invocation over declared-plus-observed ids, sorted."""
    attempts: dict[str, list[str]] = {}
    for attempt in package.attempts:
        attempts.setdefault(attempt.invocation_id, []).append(attempt.record_id)
    totals: dict[str, list[str]] = {}
    for total in package.totals:
        totals.setdefault(total.invocation_id, []).append(total.record_id)
    envs: dict[str, list[str]] = {}
    for env in package.envs:
        envs.setdefault(env.invocation_id, []).append(env.record_id)
    declared = asm.declared_ids(package)
    return tuple(
        InvInventory(
            invocation_id=inv,
            attempts=tuple(sorted(attempts.get(inv, []))),
            totals=tuple(sorted(totals.get(inv, []))),
            envs=tuple(sorted(envs.get(inv, []))),
            evidence_verified=inv in evidence_ok,
        )
        for inv in sorted(declared | set(attempts) | set(totals) | set(envs))
    )
