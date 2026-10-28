"""Evidence integrity: canonical digests and attestation references."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from attest_core.evidence import (
    ATTESTATION_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    Attestation,
    AttestationError,
    EvidenceRecord,
    verify_attestation,
)
from attest_core.invariants import invariant_content_digest
from attest_spec import Invariant


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
        content_digest="0" * 64,
        evidence_hashes=(evidence_hash,),
        statement="reproducible violation across three attempts",
    )
    assert attestation.evidence_hashes == (evidence_hash,)
    assert attestation.digest() == attestation.digest()
    assert len(attestation.digest()) == 64


def _invariant() -> Invariant:
    return Invariant(
        invariant_id="AUTH-ADMIN-001",
        version=1,
        title="Admin endpoints require admin role",
        requirement="Every endpoint in scope must reject unauthenticated requests.",
        scope=("/admin/users", "/admin/settings"),
    )


def _attestation(
    invariant: Invariant | None = None, **overrides: Any
) -> tuple[Attestation, Invariant]:
    invariant = invariant if invariant is not None else _invariant()
    base: dict[str, Any] = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "verdict": "PASSED",
        "invariant_id": invariant.invariant_id,
        "invariant_version": invariant.version,
        "content_digest": invariant_content_digest(invariant),
        "evidence_hashes": (_evidence().digest(),),
        "statement": "reproducible clean result",
    }
    base.update(overrides)
    return (
        Attestation(
            schema_version=base["schema_version"],
            verdict=base["verdict"],
            invariant_id=base["invariant_id"],
            invariant_version=base["invariant_version"],
            content_digest=base["content_digest"],
            evidence_hashes=tuple(base["evidence_hashes"]),
            statement=base["statement"],
        ),
        invariant,
    )


def test_valid_attestation_verifies() -> None:
    attestation, invariant = _attestation()
    checked = verify_attestation(
        attestation.to_payload(), invariant, attestation.digest(), [_evidence()]
    )
    assert checked == attestation


def test_changed_content_same_id_version_is_detected() -> None:
    attestation, _ = _attestation()
    weakened = dataclasses.replace(_invariant(), requirement="weakened")
    assert weakened.invariant_id == attestation.invariant_id
    assert weakened.version == attestation.invariant_version
    with pytest.raises(AttestationError, match="content digest"):
        verify_attestation(attestation.to_payload(), weakened, attestation.digest())


def test_changed_content_digest_is_detected() -> None:
    attestation, invariant = _attestation()
    payload = attestation.to_payload()
    payload["content_digest"] = "1" * 64
    with pytest.raises(AttestationError, match="digest mismatch"):
        verify_attestation(payload, invariant, attestation.digest())


def test_mutated_evidence_record_is_detected() -> None:
    attestation, invariant = _attestation()
    tampered = dataclasses.replace(_evidence(), outcome="PASS")
    assert tampered.digest() != _evidence().digest()
    with pytest.raises(AttestationError, match="evidence hashes"):
        verify_attestation(attestation.to_payload(), invariant, attestation.digest(), [tampered])


def test_mutated_revision_or_config_is_detected() -> None:
    attestation, invariant = _attestation()
    drifted = dataclasses.replace(_evidence(), revision="rev-2", config_digest="cfg-2")
    with pytest.raises(AttestationError, match="evidence hashes"):
        verify_attestation(attestation.to_payload(), invariant, attestation.digest(), [drifted])


def test_mutated_verdict_is_detected() -> None:
    attestation, invariant = _attestation()
    payload = attestation.to_payload()
    payload["verdict"] = "FAILED"
    with pytest.raises(AttestationError, match="digest mismatch"):
        verify_attestation(payload, invariant, attestation.digest())


def test_removed_evidence_hash_is_detected() -> None:
    attestation, invariant = _attestation()
    payload = attestation.to_payload()
    payload["evidence_hashes"] = []
    with pytest.raises(AttestationError, match="evidence_hashes"):
        verify_attestation(payload, invariant, attestation.digest())


@pytest.mark.parametrize(
    "key",
    [
        "schema_version",
        "verdict",
        "invariant_id",
        "invariant_version",
        "content_digest",
        "evidence_hashes",
        "statement",
    ],
)
def test_missing_field_fails_closed(key: str) -> None:
    attestation, invariant = _attestation()
    payload = attestation.to_payload()
    del payload[key]
    with pytest.raises(AttestationError, match="missing required field"):
        verify_attestation(payload, invariant, attestation.digest())


def test_non_mapping_payload_fails_closed() -> None:
    _, invariant = _attestation()
    with pytest.raises(AttestationError, match="must be a mapping"):
        verify_attestation(["not", "a", "mapping"], invariant, "0" * 64)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [None, "not-an-invariant", 42])
def test_non_invariant_argument_fails_closed(bad: Any) -> None:
    attestation, _ = _attestation()
    with pytest.raises(AttestationError, match="must be an Invariant instance"):
        verify_attestation(attestation.to_payload(), bad, attestation.digest())


def test_serialization_round_trip_is_stable() -> None:
    attestation, invariant = _attestation()
    first = json.loads(json.dumps(attestation.to_payload()))
    checked = verify_attestation(first, invariant, attestation.digest())
    assert checked.digest() == attestation.digest()
    second = json.loads(json.dumps(checked.to_payload()))
    assert second == first


def test_v1_payload_is_rejected() -> None:
    assert ATTESTATION_SCHEMA_VERSION == 2
    attestation, invariant = _attestation()
    legacy = attestation.to_payload()
    legacy["schema_version"] = 1
    del legacy["content_digest"]
    with pytest.raises(AttestationError, match="unsupported attestation schema"):
        verify_attestation(legacy, invariant, attestation.digest())


def test_wrong_expected_digest_is_detected() -> None:
    attestation, invariant = _attestation()
    with pytest.raises(AttestationError, match="digest mismatch"):
        verify_attestation(attestation.to_payload(), invariant, "0" * 64)
