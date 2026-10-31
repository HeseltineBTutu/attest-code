"""Focused verification orchestration: three genuine attempts, one verdict.

The orchestrator records the source revision and configuration digest, then
re-executes the provided checks once per attempt. It reuses
:mod:`attest_core.verdicts` for classification and
:mod:`attest_core.evidence` for records; it duplicates neither.

Limits of the three-attempt policy: separate worker executions on
one machine catch flaky results without proving determinism.
Isolation follows the selected profile (standard shares the host;
see security-model.md). Only verifier-owned check code runs,
never model-provided code.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping

from attest_core.evidence import (
    ATTESTATION_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    Attestation,
    EvidenceRecord,
    canonical_bytes,
    sha256_hex,
)
from attest_core.invariants import invariant_content_digest, is_approval_valid
from attest_core.verdicts import REQUIRED_ATTEMPTS, VerificationAttempt, classify_with_reason
from attest_spec import ApprovalRecord, AttemptOutcome, Invariant, Verdict

ATTEMPT_SUMMARY_CHECK_ID = "attempt-summary"
"""Check id of the per-attempt summary evidence record."""


class VerificationError(Exception):
    """Raised when verification is invoked with an invalid configuration."""


@dataclasses.dataclass(frozen=True)
class CheckEvidence:
    """One check observation within an attempt."""

    check_id: str
    target: str
    passed: bool
    detail: str


@dataclasses.dataclass(frozen=True)
class AttemptReport:
    """Outcome of a single fresh execution of the checks.

    ``detail`` is the worker's result verbatim; ``resources`` carries
    parent-collected evidence (quota counters), never worker output.
    """

    outcome: AttemptOutcome
    checks: tuple[CheckEvidence, ...]
    detail: str
    resources: str = ""


@dataclasses.dataclass(frozen=True)
class VerificationReport:
    """Verdict plus the attempts, evidence, and attestation behind it."""

    verdict: Verdict
    reason: str
    revision: str
    config_digest: str
    attempts: tuple[VerificationAttempt, ...]
    evidence: tuple[EvidenceRecord, ...]
    attestation: Attestation


def run_verification(
    *,
    invariant: Invariant,
    approval: ApprovalRecord,
    revision: str,
    settings: Mapping[str, str],
    run_checks: Callable[[], AttemptReport],
) -> VerificationReport:
    """Verify a target against one approved invariant.

    The approval must bind to the exact invariant content; otherwise this
    raises instead of producing any verdict. PASSED here means verified
    under the policy (clean attempts with scope coverage); the Phase 1
    verdict names are preserved unchanged.
    """
    if not is_approval_valid(invariant, approval):
        raise VerificationError("approval does not match invariant content")
    config_digest = sha256_hex(canonical_bytes(dict(settings)))
    evidence: list[EvidenceRecord] = []
    attempts: list[VerificationAttempt] = []
    for attempt_no in range(1, REQUIRED_ATTEMPTS + 1):
        try:
            report = run_checks()
            outcome = report.outcome
            checks = tuple(report.checks)
            detail = report.detail
            resources = report.resources
        except Exception as exc:
            outcome = AttemptOutcome.INFRA_FAILURE
            checks = ()
            detail = f"attempt raised {type(exc).__name__}: {exc}"
            resources = ""
        for check in checks:
            evidence.append(
                EvidenceRecord(
                    schema_version=EVIDENCE_SCHEMA_VERSION,
                    check_id=check.check_id,
                    target=check.target,
                    outcome="PASS" if check.passed else outcome.value,
                    detail=check.detail,
                    revision=revision,
                    config_digest=config_digest,
                    attempt=attempt_no,
                )
            )
        summary = EvidenceRecord(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            check_id=ATTEMPT_SUMMARY_CHECK_ID,
            target=invariant.invariant_id,
            outcome=outcome.value,
            detail=detail,
            resources=resources,
            revision=revision,
            config_digest=config_digest,
            attempt=attempt_no,
        )
        evidence.append(summary)
        attempts.append(
            VerificationAttempt(
                revision=revision,
                config_digest=config_digest,
                outcome=outcome,
                evidence_hash=summary.digest(),
            )
        )
    verdict, reason = classify_with_reason(attempts)
    attestation = Attestation(
        schema_version=ATTESTATION_SCHEMA_VERSION,
        verdict=verdict.value,
        invariant_id=invariant.invariant_id,
        invariant_version=invariant.version,
        content_digest=invariant_content_digest(invariant),
        evidence_hashes=tuple(item.digest() for item in evidence),
        statement=reason,
    )
    return VerificationReport(
        verdict=verdict,
        reason=reason,
        revision=revision,
        config_digest=config_digest,
        attempts=tuple(attempts),
        evidence=tuple(evidence),
        attestation=attestation,
    )
