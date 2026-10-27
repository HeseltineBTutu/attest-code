"""Deterministic verdict policy.

Initial policy:
- FAILED requires a reproducible invariant violation across three
  independent attempts under the same recorded revision and configuration.
- PASSED requires three independent clean passes under the same recorded
  revision and configuration, each with evidence.
- Anything else (timeouts, crashes, missing evidence, mixed or
  non-reproducible results) is INCONCLUSIVE.

Infrastructure failures never produce FAILED on their own.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence

from attest_spec import AttemptOutcome, Verdict

REQUIRED_ATTEMPTS = 3


@dataclasses.dataclass(frozen=True)
class VerificationAttempt:
    """One independent verification attempt with recorded context."""

    revision: str
    config_digest: str
    outcome: AttemptOutcome
    evidence_hash: str | None


def _complete(attempt: VerificationAttempt) -> bool:
    return bool(attempt.revision) and bool(attempt.config_digest)


def _has_evidence(attempt: VerificationAttempt) -> bool:
    return attempt.evidence_hash is not None and bool(attempt.evidence_hash.strip())


def classify_verdict(attempts: Sequence[VerificationAttempt]) -> Verdict:
    """Classify attempts into PASSED, FAILED, or INCONCLUSIVE."""
    verdict, _ = classify_with_reason(attempts)
    return verdict


def classify_with_reason(attempts: Sequence[VerificationAttempt]) -> tuple[Verdict, str]:
    """Classify attempts and explain precisely what was checked."""
    items = list(attempts)
    checked = (
        f"checked {len(items)} attempt(s); "
        f"policy requires {REQUIRED_ATTEMPTS} independent attempts "
        "under the same revision and configuration with evidence"
    )
    if len(items) < REQUIRED_ATTEMPTS:
        return Verdict.INCONCLUSIVE, f"{checked}: insufficient attempts"
    if any(not _complete(item) for item in items):
        return Verdict.INCONCLUSIVE, f"{checked}: incomplete attempt context"
    revisions = {item.revision for item in items}
    configs = {item.config_digest for item in items}
    if len(revisions) != 1 or len(configs) != 1:
        return Verdict.INCONCLUSIVE, f"{checked}: revision or config mismatch"
    if any(not _has_evidence(item) for item in items):
        return Verdict.INCONCLUSIVE, f"{checked}: missing evidence"
    outcomes = {item.outcome for item in items}
    if outcomes == {AttemptOutcome.VIOLATION}:
        return Verdict.FAILED, f"{checked}: reproducible violation"
    if outcomes == {AttemptOutcome.PASS}:
        return Verdict.PASSED, f"{checked}: reproducible clean result"
    return Verdict.INCONCLUSIVE, f"{checked}: mixed or infrastructure failure"
