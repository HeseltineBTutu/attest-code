"""P4 tests: v3 full-payload digest coverage and evidence integrity."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, cast

import pytest
from p3_fixtures import load_auth_invariant
from p4_fixtures import passing_attestation

from attest_sdk.errors import AttestationError, UnsupportedSpecVersionError
from attest_sdk.history import verify_v3

_MUTATIONS: tuple[tuple[str, Any], ...] = (
    ("verdict", "FAILED"),
    ("invariant_id", "OTHER-001"),
    ("invariant_version", 2),
    ("content_digest", "0" * 64),
    ("statement", "altered"),
    ("approval_event_id", "1" * 64),
    ("verification_type", "other/9"),
    ("revision", "f" * 40),
    ("execution_profile", "hardened"),
    ("lifecycle_state", "revoked"),
)


def test_full_payload_digest_mutation_matrix(tmp_path: Path) -> None:
    _, payload, digest = passing_attestation(tmp_path / "reg")
    invariant = load_auth_invariant()
    for field, value in _MUTATIONS:
        mutated = dict(payload)
        mutated[field] = value
        with pytest.raises(AttestationError, match="digest mismatch"):
            verify_v3(mutated, invariant, digest)
    bad_spec = dict(payload)
    bad_spec["spec_version"] = 2
    with pytest.raises(UnsupportedSpecVersionError):
        verify_v3(bad_spec, invariant, digest)


def test_nested_mutations_break_digest(tmp_path: Path) -> None:
    _, payload, digest = passing_attestation(tmp_path / "reg")
    invariant = load_auth_invariant()
    nested = dict(payload)
    nested["registry_commit"] = {"vcs": "git", "commit": "f" * 40}
    with pytest.raises(AttestationError, match="digest mismatch"):
        verify_v3(nested, invariant, digest)
    verifier = dict(payload)
    inner = dict(verifier["verifier"])
    inner["version"] = "9.9.9"
    verifier["verifier"] = inner
    with pytest.raises(AttestationError, match="digest mismatch"):
        verify_v3(verifier, invariant, digest)
    hashes = dict(payload)
    tampered = list(hashes["evidence_hashes"])
    tampered[0] = "0" * 64
    hashes["evidence_hashes"] = tampered
    with pytest.raises(AttestationError, match="digest mismatch"):
        verify_v3(hashes, invariant, digest)


def test_tampered_and_reordered_evidence_refused(tmp_path: Path) -> None:
    report, payload, digest = passing_attestation(tmp_path / "reg")
    invariant = load_auth_invariant()
    assert verify_v3(payload, invariant, digest, report.evidence).verdict == "PASSED"
    tampered = dataclasses.replace(report.evidence[0], detail="forged detail")
    with pytest.raises(AttestationError, match="evidence hashes"):
        verify_v3(payload, invariant, digest, [tampered, *report.evidence[1:]])
    with pytest.raises(AttestationError, match="evidence hashes"):
        verify_v3(payload, invariant, digest, list(reversed(report.evidence)))
    with pytest.raises(AttestationError, match="EvidenceRecord"):
        verify_v3(payload, invariant, digest, cast(Any, [{"no": "record"}]))
