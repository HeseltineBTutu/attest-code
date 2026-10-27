"""Evidence integrity: canonical digests and attestation references."""

from __future__ import annotations

from attest_core.evidence import (
    ATTESTATION_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    Attestation,
    EvidenceRecord,
)


def _evidence() -> EvidenceRecord:
    return EvidenceRecord(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        check_id="unauthenticated-access",
        target="/admin/users",
        outcome="VIOLATION",
        detail="returned 200 without credentials",
        revision="rev-1",
        config_digest="cfg-1",
        attempt=1,
    )


def test_evidence_digest_is_deterministic() -> None:
    assert _evidence().digest() == _evidence().digest()


def test_evidence_digest_changes_with_content() -> None:
    original = _evidence().digest()
    altered = EvidenceRecord(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        check_id="unauthenticated-access",
        target="/admin/users",
        outcome="PASS",
        detail="returned 401 without credentials",
        revision="rev-1",
        config_digest="cfg-1",
        attempt=1,
    )
    assert altered.digest() != original


def test_attestation_references_evidence_and_has_own_digest() -> None:
    evidence_hash = _evidence().digest()
    attestation = Attestation(
        schema_version=ATTESTATION_SCHEMA_VERSION,
        verdict="FAILED",
        invariant_id="AUTH-ADMIN-001",
        invariant_version=1,
        evidence_hashes=(evidence_hash,),
        statement="reproducible violation across three attempts",
    )
    assert attestation.evidence_hashes == (evidence_hash,)
    assert attestation.digest() == attestation.digest()
    assert len(attestation.digest()) == 64
