"""F3 stage-input derivation from verified P2 outputs (§8.2, §8.3, V-B5).

Interprets ManifestReport content into typed downstream inputs:
assembled records, the verified-evidence set, pin acceptance, the
P2 finding stream, and invocation groupings. Pure derivation only:
every check belongs to the phase that owns it. P2 already ran the
P0 schema validators during digest verification, so assembly type
conversion cannot fail on surviving payloads; the unknown-kind
branch is fail-closed defense mirroring `f3_parse`.
"""

from __future__ import annotations

from typing import Any, TypeVar

from attest_core import f3_records_campaign, f3_records_env
from attest_core.f3_digest import require_canonicalizer, require_projection
from attest_core.f3_errors import F3Error, F3SchemaError
from attest_core.f3_identity import PackageRecords
from attest_core.f3_manifest import ManifestReport
from attest_core.f3_manifest_entries import EntryResult, Finding
from attest_core.f3_records import AttemptRecord, TotalRecord, validate_attempt, validate_total
from attest_core.f3_records_env import EnvRecord

_R = TypeVar("_R", AttemptRecord, TotalRecord, EnvRecord)


def assemble_package(entries: tuple[EntryResult, ...]) -> PackageRecords:
    """Typed records from digest-verified payloads, in manifest order.

    Stored summaries are bound and digest-verified by P2 but consumed
    by no stage: recomputation is the auditor's right (I8), and the
    design states no runtime diff semantics for the validator.
    """
    campaigns = []
    attempts = []
    totals = []
    envs = []
    for entry in entries:
        if entry.source != "records" or entry.record is None:
            continue
        kind = entry.record.get("record_kind")
        if kind == "attempt":
            attempts.append(validate_attempt(entry.record))
        elif kind == "invocation_total":
            totals.append(validate_total(entry.record))
        elif kind == "environment":
            envs.append(f3_records_env.validate_environment(entry.record))
        elif kind == "campaign":
            campaigns.append(f3_records_campaign.validate_campaign(entry.record))
        elif kind == "summary":
            continue
        else:
            raise F3SchemaError(
                rule="V-B6",
                section="7",
                location="$.record_kind",
                reason=f"unknown record_kind: {kind!r}",
            )
    return PackageRecords(
        campaigns=tuple(campaigns), attempts=tuple(attempts), totals=tuple(totals), envs=tuple(envs)
    )


def verified_evidence(report: ManifestReport) -> set[str]:
    """Invocations with a present, verified s3-report entry (V-B5 quiet rule).

    Entries with any finding (shape, digest, confinement, duplicate)
    never qualify; missing entries are quietly absent. Invocation ids
    come from the manifest lists by entry index, never from parsing.
    """
    if report.manifest is None:
        return set()
    declared = report.manifest.get("evidence")
    if not isinstance(declared, list):
        return set()
    ok: set[str] = set()
    for entry in report.entries:
        if entry.source != "evidence" or entry.findings:
            continue
        raw = declared[entry.index] if entry.index < len(declared) else None
        inv = raw.get("invocation_id") if isinstance(raw, dict) else None
        if isinstance(inv, str):
            ok.add(inv)
    return ok


def pins_accepted(manifest: dict[str, Any]) -> bool:
    """True unless a version pin refuses exactly (§8.2 refuse rule)."""
    try:
        require_canonicalizer(manifest.get("canonicalization"), "8.3", "$.canonicalization")
        require_projection(manifest.get("digest_projection"), "8.3", "$.digest_projection")
    except F3Error:
        return False
    return True


def p2_findings(report: ManifestReport) -> tuple[Finding, ...]:
    """Manifest findings plus per-entry findings in manifest order."""
    out = list(report.manifest_findings)
    for entry in report.entries:
        out.extend(entry.findings)
    return tuple(out)


def declared_ids(package: PackageRecords) -> set[str]:
    """Invocation ids declared across all campaign records."""
    return {
        str(entry["invocation_id"])
        for campaign in package.campaigns
        for entry in campaign.invocations
    }


def grouped(records: tuple[_R, ...]) -> dict[str, list[_R]]:
    """Group typed records by invocation id (manifest order preserved)."""
    out: dict[str, list[_R]] = {}
    for record in records:
        out.setdefault(record.invocation_id, []).append(record)
    return out


def single(records: list[_R]) -> _R | None:
    """The single record, else None (counts belong to P3, never inferred)."""
    return records[0] if len(records) == 1 else None
