"""Verdict classification: reproducible results vs inconclusive evidence."""

from __future__ import annotations

from attest_core.verdicts import VerificationAttempt, classify_verdict
from attest_spec import AttemptOutcome, Verdict


def _attempt(outcome: AttemptOutcome, evidence: str | None = "hash") -> VerificationAttempt:
    return VerificationAttempt(
        revision="rev-1", config_digest="cfg-1", outcome=outcome, evidence_hash=evidence
    )


def test_three_violations_yield_failed() -> None:
    attempts = [_attempt(AttemptOutcome.VIOLATION) for _ in range(3)]
    assert classify_verdict(attempts) == Verdict.FAILED


def test_three_passes_yield_passed() -> None:
    attempts = [_attempt(AttemptOutcome.PASS) for _ in range(3)]
    assert classify_verdict(attempts) == Verdict.PASSED


def test_infra_failures_are_inconclusive_not_failed() -> None:
    attempts = [_attempt(AttemptOutcome.INFRA_FAILURE) for _ in range(3)]
    assert classify_verdict(attempts) == Verdict.INCONCLUSIVE


def test_mixed_results_are_inconclusive() -> None:
    attempts = [
        _attempt(AttemptOutcome.VIOLATION),
        _attempt(AttemptOutcome.VIOLATION),
        _attempt(AttemptOutcome.PASS),
    ]
    assert classify_verdict(attempts) == Verdict.INCONCLUSIVE


def test_missing_evidence_is_inconclusive() -> None:
    attempts = [_attempt(AttemptOutcome.VIOLATION, evidence=None) for _ in range(3)]
    assert classify_verdict(attempts) == Verdict.INCONCLUSIVE


def test_revision_mismatch_is_inconclusive() -> None:
    attempts = [
        _attempt(AttemptOutcome.VIOLATION),
        _attempt(AttemptOutcome.VIOLATION),
        VerificationAttempt(
            revision="rev-2",
            config_digest="cfg-1",
            outcome=AttemptOutcome.VIOLATION,
            evidence_hash="hash",
        ),
    ]
    assert classify_verdict(attempts) == Verdict.INCONCLUSIVE


def test_fewer_than_three_attempts_is_inconclusive() -> None:
    attempts = [_attempt(AttemptOutcome.VIOLATION) for _ in range(2)]
    assert classify_verdict(attempts) == Verdict.INCONCLUSIVE
