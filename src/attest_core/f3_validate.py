"""F3 validator orchestration: normative stage order and gating (§8.2, §9).

Runs P2 manifest verification, typed assembly, P3 identity, P4
workload inputs, P5 series, the P6 measurement block, and P7
composition in design order with enforced preconditions: pin
refusal stops everything (refused); quorum needs P3-clean input;
P7 needs quorums plus clean P3/P4/P5. Infrastructure failure
aborts the run with partial results preserved. Pure
orchestration: every check belongs to the phase that owns it.
"""

from __future__ import annotations

import os
from typing import Any

from attest_core import f3_assemble as asm
from attest_core import f3_paths as paths
from attest_core import f3_summary as summary_mod
from attest_core.f3_compare_attrs import derive_attributes
from attest_core.f3_compose import SeriesComposition, compose_package
from attest_core.f3_fields import DIGEST64_RE
from attest_core.f3_identity import PackageRecords, check_identity
from attest_core.f3_input_digest import verify_workload
from attest_core.f3_manifest import verify_manifest
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_measure import measure_invocation
from attest_core.f3_quorum import QuorumResult, evaluate_quorum
from attest_core.f3_report import (
    STATUS_INFRA,
    STATUS_REFUSED,
    STATUS_VALIDATED,
    ValidationReport,
    build_report,
)
from attest_core.f3_series_check import check_package_series


def _verify_workloads(
    package: PackageRecords, *, root_fd: int, root: str, canonical_pin: Any
) -> tuple[Finding, ...]:
    """V-B13 per declared invocation entry, in campaign/entry order."""
    out: list[Finding] = []
    single = len(package.campaigns) == 1
    for ci, campaign in enumerate(package.campaigns):
        for j, entry in enumerate(campaign.invocations):
            if single:
                location = f"$.campaign.invocations[{j}].workload"
            else:
                location = f"campaign[{ci}].invocations[{j}].workload"
            out.extend(
                verify_workload(
                    entry["workload"],
                    root_fd=root_fd,
                    root=root,
                    location=location,
                    canonical_pin=canonical_pin,
                )
            )
    return tuple(out)


def validate_package(
    root: str | os.PathLike[str],
    *,
    manifest_digest: str | None = None,
    record_ids: dict[tuple[str, str, str, str, int], str] | None = None,
    context: dict[str, str] | None = None,
) -> ValidationReport:
    """Validate one campaign package directory end to end.

    `record_ids` overrides minted per-series summary ids, enabling
    byte-exact recomputation runs; `context` echoes into every
    summary. Caller errors raise: ValueError for byte paths and
    malformed digest hex; F3Error for malformed record_ids/context
    (via P7's §7.5 contract) or unreachable internal inconsistency.
    """
    path = os.fspath(root)
    if isinstance(path, bytes):
        raise ValueError("byte paths unsupported")
    if manifest_digest is not None and (
        not isinstance(manifest_digest, str) or DIGEST64_RE.fullmatch(manifest_digest) is None
    ):
        raise ValueError(f"explicit manifest digest must be SHA-256 hex: {manifest_digest!r}")
    try:
        manifest = verify_manifest(path, manifest_digest=manifest_digest)
    except ValueError:
        empty = PackageRecords()
        return build_report(status=STATUS_INFRA, package=empty, evidence_ok=set(), findings=())
    p2 = asm.p2_findings(manifest)
    if manifest.manifest is not None and not asm.pins_accepted(manifest.manifest):
        empty = PackageRecords()
        return build_report(status=STATUS_REFUSED, package=empty, evidence_ok=set(), findings=p2)
    package = asm.assemble_package(manifest.entries)
    identity = check_identity(package)
    verified = asm.verified_evidence(manifest)
    workload_findings: tuple[Finding, ...] = ()
    if package.campaigns and manifest.manifest is not None:
        # Campaigns imply a parsed, pin-accepted manifest; the None arm
        # below it is unreachable defense for the type checker.
        pin = manifest.manifest["canonicalization"]
        try:
            root_fd = paths.open_root(path)
        except ValueError:
            return build_report(
                status=STATUS_INFRA,
                package=package,
                evidence_ok=verified,
                findings=(*p2, *identity.findings),
            )
        try:
            workload_findings = _verify_workloads(
                package, root_fd=root_fd, root=os.path.realpath(path), canonical_pin=pin
            )
        finally:
            os.close(root_fd)
    series = check_package_series(package)
    attempts = asm.grouped(package.attempts)
    totals = asm.grouped(package.totals)
    envs = asm.grouped(package.envs)
    declared = asm.declared_ids(package)
    keyed = sorted(declared | set(attempts) | set(totals) | set(envs))
    measurements = {
        inv: measure_invocation(
            inv, attempts.get(inv, []), totals.get(inv, []), len(envs.get(inv, []))
        )
        for inv in keyed
    }
    attributes = {
        inv: derive_attributes(inv, attempts.get(inv, []), asm.single(envs.get(inv, [])))
        for inv in keyed
    }
    p3_clean = identity.severity != "INVALID"
    quorums: dict[tuple[str, str, str, str, int], QuorumResult] = {}
    if p3_clean and len(package.campaigns) == 1:
        required = package.campaigns[0].protocol["required_successful"]
        for item in series.series:
            quorums[item.key] = evaluate_quorum(
                series=item,
                measurements=measurements,
                evidence_ok=verified,
                required_successful=required,
            )
    composition: tuple[SeriesComposition, ...] = ()
    dirty = any(f.severity == "INVALID" for f in (*workload_findings, *series.findings))
    if p3_clean and not dirty and series.series:
        minted = (
            record_ids
            if record_ids is not None
            else {item.key: summary_mod.mint_record_id() for item in series.series}
        )
        composed = compose_package(
            package=package,
            identity=identity,
            workload_findings=workload_findings,
            series_report=series,
            measurements=measurements,
            quorums=quorums,
            attributes=attributes,
            record_ids=minted,
            context=context,
        )
        composition = composed.series
    ordered = tuple(sorted(quorums.values(), key=lambda item: item.series_key[4]))
    return build_report(
        status=STATUS_VALIDATED,
        package=package,
        evidence_ok=verified,
        findings=(*p2, *identity.findings, *workload_findings, *series.findings),
        diagnostics=series.diagnostics,
        measurements=tuple(measurements[inv] for inv in keyed),
        attributes=tuple(attributes[inv] for inv in keyed),
        quorums=ordered,
        composition=composition,
    )
