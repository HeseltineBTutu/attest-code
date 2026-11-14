"""F3 identity and cardinality validation (P3: R-ID, V-B7, V-B10–V-B12, T1, T2).

Pure validation over typed records plus manifest label binding.
Single-package scope: R-ID5 (immutability) is P2's digest
domain; R-ID7/R-ID8 need cross-run history (multi-package
mode, P8); retry lineage has no P0 schema fields. R-ID10
(filename opacity) holds structurally: no path input exists.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from attest_core import f3_identity_records as inv
from attest_core import f3_identity_totals as chain
from attest_core.f3_identity_binding import check_manifest_binding
from attest_core.f3_identity_decl import check_declarations
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records import AttemptRecord, TotalRecord
from attest_core.f3_records_campaign import CampaignRecord
from attest_core.f3_records_env import EnvRecord

__all__ = ["PackageRecords", "IdentityReport", "check_identity", "check_manifest_binding"]


@dataclasses.dataclass(frozen=True)
class PackageRecords:
    """Typed record view of one package (P2 EntryResult payloads, validated)."""

    campaigns: tuple[CampaignRecord, ...] = ()
    attempts: tuple[AttemptRecord, ...] = ()
    totals: tuple[TotalRecord, ...] = ()
    envs: tuple[EnvRecord, ...] = ()


@dataclasses.dataclass(frozen=True)
class IdentityReport:
    """Collected identity findings; worst severity wins."""

    findings: tuple[Finding, ...]

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


def check_identity(package: PackageRecords) -> IdentityReport:
    """Validate the package identity graph, collecting every finding."""
    campaigns = [(f"campaign[{i}]", record) for i, record in enumerate(package.campaigns)]
    attempts = [(f"attempt[{i}]", record) for i, record in enumerate(package.attempts)]
    totals = [(f"total[{i}]", record) for i, record in enumerate(package.totals)]
    envs = [(f"env[{i}]", record) for i, record in enumerate(package.envs)]
    findings: list[Finding] = _dup_record_ids([*campaigns, *attempts, *totals, *envs])
    if not campaigns:
        findings.append(
            Finding(
                severity="INCOMPLETE",
                rule="V-B2",
                location="$.campaign",
                reason="no campaign record: declared set unverifiable",
            )
        )
        findings.extend(inv.check_observed_pairs(attempts))
        return IdentityReport(findings=tuple(findings))
    if len(campaigns) > 1:
        labels = ", ".join(label for label, _ in campaigns)
        findings.append(
            Finding(
                severity="INVALID",
                rule="R-ID2",
                location=campaigns[1][0],
                reason=f"multiple campaign declarations in one package: {labels}",
            )
        )
        findings.extend(inv.check_observed_pairs(attempts))
        return IdentityReport(findings=tuple(findings))
    campaign = campaigns[0][1]
    findings.extend(check_declarations(campaign))
    declared = {str(item["invocation_id"]) for item in campaign.invocations}
    members: list[tuple[str, AttemptRecord | TotalRecord | EnvRecord]] = []
    members.extend(attempts)
    members.extend(totals)
    members.extend(envs)
    groups: dict[str, dict[str, list[Any]]] = {}
    for label, record in members:
        slot = groups.setdefault(record.invocation_id, {"a": [], "t": [], "e": []})
        if isinstance(record, AttemptRecord):
            slot["a"].append((label, record))
        elif isinstance(record, TotalRecord):
            slot["t"].append((label, record))
        else:
            slot["e"].append((label, record))
    targets = [str(item) for item in campaign.protocol["targets"]]
    protocol_n = int(campaign.protocol["attempts_per_invocation"])
    for index, entry in enumerate(campaign.invocations):
        key = str(entry["invocation_id"])
        slot = groups.get(key, {"a": [], "t": [], "e": []})
        if not (slot["a"] or slot["t"] or slot["e"]):
            findings.append(
                Finding(
                    severity="INCOMPLETE",
                    rule="V-B10",
                    location=f"$.campaign.invocations[{index}]",
                    reason=f"invocation {key!r}: no records (interrupted early)",
                )
            )
            continue
        findings.extend(
            inv.check_invocation(
                entry_index=index,
                entry=entry,
                attempts=slot["a"],
                totals=slot["t"],
                envs=slot["e"],
                campaign_id=campaign.campaign_id,
                targets=targets,
            )
        )
        findings.extend(
            chain.check_invocation(
                entry_index=index,
                attempts=slot["a"],
                totals=slot["t"],
                protocol_n=protocol_n,
            )
        )
    stray = [(label, record) for label, record in members if record.invocation_id not in declared]
    findings.extend(inv.check_undeclared(stray, declared, campaign.campaign_id))
    return IdentityReport(findings=tuple(findings))


def _dup_record_ids(
    labeled: list[tuple[str, Any]],
) -> list[Finding]:
    """R-ID1: record_id uniqueness across the package, every repeat named."""
    out: list[Finding] = []
    seen: dict[str, str] = {}
    for label, record in labeled:
        if record.record_id in seen:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="R-ID1",
                    location=label,
                    reason=(
                        f"duplicate record_id {record.record_id!r} "
                        f"(also at {seen[record.record_id]})"
                    ),
                )
            )
        else:
            seen[record.record_id] = label
    return out
