"""Parent-owned verification orchestration (§§9-10, §14).

Refusal gates run before any execution; the three-attempt loop
collects verifier observations through the observation gate; only
the engine classifies the verdict via the reused verdict policy.
attest_core imports stay lazy so SDK import never touches legacy.
"""

from __future__ import annotations

import copy
import dataclasses
from typing import TYPE_CHECKING, Any

from attest_sdk import canonical, documents
from attest_sdk.documents import Invariant
from attest_sdk.errors import StaleApprovalError, VerifierParameterError
from attest_sdk.registry import Policy, Registry
from attest_sdk.requests import VerificationRequest
from attest_sdk.verifiers import Verifier, VerifierRef, match_pin, validate_observation
from attest_spec import AttemptOutcome, Verdict

if TYPE_CHECKING:
    from attest_core.evidence import EvidenceRecord
    from attest_core.verdicts import VerificationAttempt


@dataclasses.dataclass(frozen=True)
class Report:
    """Engine-classified verification outcome plus its evidence trail."""

    verdict: Verdict
    reason: str
    invariant_id: str
    invariant_version: int
    content_digest: str
    approval_event_id: str
    lifecycle_state: str
    revision: str
    config_digest: str
    execution_profile: str
    warnings: tuple[str, ...]
    attempts: tuple[VerificationAttempt, ...]
    evidence: tuple[EvidenceRecord, ...]
    verifier_ref: VerifierRef


def _config_payload(
    request: VerificationRequest, invariant: Invariant, policy: Policy
) -> dict[str, Any]:
    """Execution configuration covered by the config digest."""
    artifact = request.verifier_ref.artifact
    if artifact.available:
        artifact_payload: dict[str, Any] = {
            "status": "available",
            "algorithm": artifact.algorithm,
            "value": artifact.value,
        }
    else:
        artifact_payload = {"status": "unavailable", "reason": artifact.reason}
    config: dict[str, Any] = {
        "execution_profile": request.execution_profile,
        "parameters": invariant.parameters if invariant.parameters is not None else {},
        "policy": {
            "strict_deprecated": policy.strict_deprecated,
            "require_artifact_digest": policy.require_artifact_digest,
        },
        "verifier": {
            "type": request.verifier_ref.type,
            "implementation": request.verifier_ref.implementation,
            "version": request.verifier_ref.version,
            "artifact": artifact_payload,
        },
    }
    if request.target_selector is not None:
        config["target_selector"] = request.target_selector
    if request.timeout is not None:
        config["timeout"] = request.timeout
    return config


def _run_attempt(
    verifier: Verifier,
    scope: tuple[str, ...],
    target: str | None,
    params: dict[str, Any],
    attempt_no: int,
) -> tuple[AttemptOutcome, tuple[Any, ...], str]:
    """Run one attempt; crashes become infrastructure observations."""
    try:
        observation = verifier.run(scope, target, copy.deepcopy(params))
    except Exception as exc:
        detail = f"attempt {attempt_no} raised {type(exc).__name__}: {exc}"
        return AttemptOutcome.INFRA_FAILURE, (), detail
    return validate_observation(observation, scope, attempt_no)


def verify(
    request: VerificationRequest,
    invariant: Invariant,
    verifier: Verifier,
    registry: Registry,
) -> Report:
    """Validate bindings, run three attempts, classify the verdict.

    Every refusal below raises before the verifier runs once.
    The invariant MUST come from documents.load_invariant; the
    verifier object is untrusted and validated at every step.
    """
    from attest_core.evidence import EVIDENCE_SCHEMA_VERSION, EvidenceRecord
    from attest_core.verdicts import REQUIRED_ATTEMPTS, VerificationAttempt, classify_with_reason
    from attest_core.verification import ATTEMPT_SUMMARY_CHECK_ID

    policy = request.policy if request.policy is not None else Policy()
    definition_digest = documents.invariant_digest(invariant)
    if definition_digest != request.expected_content_digest:
        raise StaleApprovalError("request digest mismatch", reason_class="content-digest-mismatch")
    documents.ensure_known_verification_type(invariant)
    match_pin(
        request.verifier_ref,
        verification_type=invariant.verification_type,
        spec_version=request.spec_version,
        verifier=verifier,
        policy=policy,
    )
    params = invariant.parameters if invariant.parameters is not None else {}
    if params != {}:
        raise VerifierParameterError(
            f"parameters must be {{}} for {invariant.verification_type}",
            reason_class="parameter-schema",
        )
    eligibility = registry.check_eligible(
        request.invariant_id, request.invariant_version, definition_digest, policy
    )
    if eligibility.approval_event_id != request.approval_ref:
        raise StaleApprovalError(
            "approval_ref is not effective", reason_class="approval-ref-mismatch"
        )
    config_digest = canonical.digest_of(_config_payload(request, invariant, policy))
    scope = tuple(sorted(set(invariant.scope)))

    def _record(cid: str, target: str, result: str, detail: str, num: int) -> EvidenceRecord:
        return EvidenceRecord(
            EVIDENCE_SCHEMA_VERSION,
            cid,
            target,
            result,
            detail,
            request.revision,
            config_digest,
            num,
        )

    evidence: list[EvidenceRecord] = []
    attempts: list[VerificationAttempt] = []
    for attempt_no in range(1, REQUIRED_ATTEMPTS + 1):
        outcome, checks, detail = _run_attempt(
            verifier, scope, request.target_selector, params, attempt_no
        )
        for check in checks:
            evidence.append(
                _record(
                    check.check_id,
                    check.target,
                    "PASS" if check.passed else outcome.value,
                    check.detail,
                    attempt_no,
                )
            )
        summary = _record(
            ATTEMPT_SUMMARY_CHECK_ID, request.invariant_id, outcome.value, detail, attempt_no
        )
        evidence.append(summary)
        attempts.append(
            VerificationAttempt(request.revision, config_digest, outcome, summary.digest())
        )
    verdict, reason = classify_with_reason(attempts)
    return Report(
        verdict=verdict,
        reason=reason,
        invariant_id=request.invariant_id,
        invariant_version=request.invariant_version,
        content_digest=definition_digest,
        approval_event_id=eligibility.approval_event_id,
        lifecycle_state=eligibility.lifecycle_state,
        revision=request.revision,
        config_digest=config_digest,
        execution_profile=request.execution_profile,
        warnings=eligibility.warnings,
        attempts=tuple(attempts),
        evidence=tuple(evidence),
        verifier_ref=request.verifier_ref,
    )
