"""Orchestration: attempt execution, failure classification, evidence."""

from __future__ import annotations

from collections.abc import Callable

from apps.verify import SNAPSHOT_CHANGED_REASON, apply_snapshot_override
from attest_core.evidence import verify_attestation
from attest_core.invariants import create_approval, invariant_content_digest
from attest_core.verification import (
    AttemptReport,
    CheckEvidence,
    VerificationReport,
    run_verification,
)
from attest_spec import ApprovalRecord, AttemptOutcome, Invariant, Verdict

REVISION = "stub-target-v1"
SETTINGS = {"checks": "stub", "client": "stub"}


def _invariant() -> Invariant:
    return Invariant(
        invariant_id="AUTH-ADMIN-001",
        version=1,
        title="stub",
        requirement="stub requirement",
        scope=("/admin/users",),
    )


def _approval(invariant: Invariant) -> ApprovalRecord:
    return create_approval(
        invariant, approver="operator", approved_at="2026-10-27T00:00:00Z", method="stub"
    )


def _report(outcome: AttemptOutcome, passed: bool = True) -> AttemptReport:
    check = CheckEvidence("stub-check", "stub-target", passed, "stub detail")
    return AttemptReport(outcome, (check,), f"stub {outcome.value}")


def _verify(
    run_checks: Callable[[], AttemptReport], revision: str = REVISION
) -> VerificationReport:
    invariant = _invariant()
    return run_verification(
        invariant=invariant,
        approval=_approval(invariant),
        revision=revision,
        settings=SETTINGS,
        run_checks=run_checks,
    )


def _scripted(
    outcomes: list[AttemptOutcome],
) -> tuple[Callable[[], AttemptReport], list[int]]:
    calls: list[int] = []

    def run_checks() -> AttemptReport:
        calls.append(1)
        return _report(outcomes[len(calls) - 1])

    return run_checks, calls


def test_checks_execute_three_times() -> None:
    run_checks, calls = _scripted([AttemptOutcome.PASS] * 3)
    report = _verify(run_checks)
    assert len(calls) == 3
    assert {record.attempt for record in report.evidence} == {1, 2, 3}


def test_all_pass_yields_passed() -> None:
    run_checks, _ = _scripted([AttemptOutcome.PASS] * 3)
    assert _verify(run_checks).verdict == Verdict.PASSED


def test_all_violation_yields_failed() -> None:
    run_checks, _ = _scripted([AttemptOutcome.VIOLATION] * 3)
    assert _verify(run_checks).verdict == Verdict.FAILED


def test_snapshot_override_discards_verdict_but_keeps_evidence() -> None:
    run_checks, _ = _scripted([AttemptOutcome.PASS] * 3)
    invariant = _invariant()
    original = run_verification(
        invariant=invariant,
        approval=_approval(invariant),
        revision=REVISION,
        settings=SETTINGS,
        run_checks=run_checks,
    )
    assert original.verdict == Verdict.PASSED
    overridden = apply_snapshot_override(original, invariant)
    assert overridden.verdict == Verdict.INCONCLUSIVE
    assert overridden.reason == SNAPSHOT_CHANGED_REASON
    assert overridden.evidence == original.evidence
    assert overridden.attempts == original.attempts
    assert overridden.attestation.statement == SNAPSHOT_CHANGED_REASON
    assert overridden.attestation.verdict == Verdict.INCONCLUSIVE.value


def test_crash_yields_inconclusive() -> None:
    def crash() -> AttemptReport:
        raise RuntimeError("simulated verifier crash")

    report = _verify(crash)
    assert report.verdict == Verdict.INCONCLUSIVE
    assert all(attempt.outcome == AttemptOutcome.INFRA_FAILURE for attempt in report.attempts)
    assert any("RuntimeError" in record.detail for record in report.evidence)


def test_timeout_yields_inconclusive() -> None:
    def timeout() -> AttemptReport:
        raise TimeoutError("simulated timeout")

    report = _verify(timeout)
    assert report.verdict == Verdict.INCONCLUSIVE


def test_non_reproducible_violation_is_inconclusive() -> None:
    run_checks, _ = _scripted(
        [AttemptOutcome.VIOLATION, AttemptOutcome.VIOLATION, AttemptOutcome.PASS]
    )
    assert _verify(run_checks).verdict == Verdict.INCONCLUSIVE


def test_infra_flake_is_inconclusive() -> None:
    run_checks, _ = _scripted(
        [AttemptOutcome.PASS, AttemptOutcome.INFRA_FAILURE, AttemptOutcome.PASS]
    )
    assert _verify(run_checks).verdict == Verdict.INCONCLUSIVE


def test_evidence_records_revision_config_and_attempts() -> None:
    run_checks, _ = _scripted([AttemptOutcome.PASS] * 3)
    report = _verify(run_checks)
    assert report.revision == REVISION
    assert all(record.revision == REVISION for record in report.evidence)
    assert all(record.config_digest == report.config_digest for record in report.evidence)
    assert report.attestation.evidence_hashes == tuple(
        record.digest() for record in report.evidence
    )
    assert report.attestation.digest() == report.attestation.digest()


def test_empty_revision_is_inconclusive() -> None:
    run_checks, _ = _scripted([AttemptOutcome.PASS] * 3)
    assert _verify(run_checks, revision="").verdict == Verdict.INCONCLUSIVE


def test_emitted_attestation_validates_against_verified_content() -> None:
    run_checks, _ = _scripted([AttemptOutcome.PASS] * 3)
    invariant = _invariant()
    report = run_verification(
        invariant=invariant,
        approval=_approval(invariant),
        revision=REVISION,
        settings=SETTINGS,
        run_checks=run_checks,
    )
    assert report.attestation.content_digest == invariant_content_digest(invariant)
    checked = verify_attestation(
        report.attestation.to_payload(),
        invariant,
        report.attestation.digest(),
        report.evidence,
    )
    assert checked == report.attestation
