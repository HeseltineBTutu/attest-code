"""P4 tests: v3 issuance and integrity verification."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, cast

import pytest
from p3_fixtures import (
    DIGEST,
    FakeVerifier,
    load_auth_invariant,
    make_obs,
    make_request,
)
from p4_fixtures import COMMIT_A, eligible_registry, issued, passing_attestation, passing_report

from attest_sdk import canonical, verify
from attest_sdk.attestations import AttestationV3
from attest_sdk.commits import RegistryCommit
from attest_sdk.documents import invariant_digest
from attest_sdk.errors import AttestationError, UnsupportedSpecVersionError
from attest_sdk.history import verify_v3
from attest_sdk.issuance import issue_attestation
from attest_spec import AttemptOutcome, Verdict


def test_issue_verify_roundtrip(tmp_path: Path) -> None:
    report, payload, digest = passing_attestation(tmp_path / "reg")
    assert report.verdict is Verdict.PASSED
    record = verify_v3(payload, load_auth_invariant(), digest)
    assert isinstance(record, AttestationV3)
    assert record.schema_version == 3
    assert record.verdict == "PASSED"
    assert record.content_digest == DIGEST
    assert record.spec_version == 1
    assert record.registry_commit == RegistryCommit("git", COMMIT_A)
    assert record.verifier_implementation == "fake"
    assert record.lifecycle_state == "active"


def test_issue_is_deterministic(tmp_path: Path) -> None:
    report = passing_report(eligible_registry(tmp_path / "reg"))
    first = issued(report)
    second = issued(report)
    assert first[0] == second[0]
    assert first[1] == second[1]
    assert len(first[1]) == 64


def test_issue_requires_git_and_supported_spec(tmp_path: Path) -> None:
    report = passing_report(eligible_registry(tmp_path / "reg"))
    with pytest.raises(AttestationError, match="git"):
        issue_attestation(
            report,
            spec_version=1,
            registry_commit=RegistryCommit("hg", COMMIT_A),
            statement="s",
        )
    with pytest.raises(UnsupportedSpecVersionError):
        issue_attestation(
            report,
            spec_version=2,
            registry_commit=RegistryCommit("git", COMMIT_A),
            statement="s",
        )
    with pytest.raises(AttestationError, match="statement"):
        issue_attestation(
            report,
            spec_version=1,
            registry_commit=RegistryCommit("git", COMMIT_A),
            statement=cast(Any, None),
        )


def test_issue_refuses_malformed_reports(tmp_path: Path) -> None:
    report = passing_report(eligible_registry(tmp_path / "reg"))
    commit = RegistryCommit("git", COMMIT_A)
    empty = dataclasses.replace(report, evidence=())
    with pytest.raises(AttestationError, match="no evidence"):
        issue_attestation(empty, spec_version=1, registry_commit=commit, statement="s")
    bad_verdict = dataclasses.replace(report, verdict=cast(Any, "BOGUS"))
    with pytest.raises(AttestationError, match="verdict"):
        issue_attestation(bad_verdict, spec_version=1, registry_commit=commit, statement="s")
    bad_evidence = dataclasses.replace(report, evidence=(cast(Any, object()),))
    with pytest.raises(AttestationError, match="evidence"):
        issue_attestation(bad_evidence, spec_version=1, registry_commit=commit, statement="s")


def test_available_artifact_roundtrip(tmp_path: Path) -> None:
    """M2: the normative available-artifact shape round-trips through v3."""
    pin = {
        "type": "http-auth-probe/1",
        "implementation": "fake",
        "version": "1.0.0",
        "artifact": {"status": "available", "algorithm": "sha256", "value": "ab" * 32},
    }
    request = make_request(verifier_ref=pin)
    script = [make_obs(AttemptOutcome.PASS) for _ in range(3)]
    registry = eligible_registry(tmp_path / "reg")
    report = verify(request, load_auth_invariant(), FakeVerifier(script), registry)
    payload, digest = issued(report)
    assert payload["verifier"]["artifact"] == pin["artifact"]
    record = verify_v3(payload, load_auth_invariant(), digest, report.evidence)
    assert record.artifact.available is True
    assert record.artifact.algorithm == "sha256"
    assert record.artifact.value == "ab" * 32
    mutated = dict(payload)
    inner = dict(mutated["verifier"])
    artifact = dict(inner["artifact"])
    artifact["value"] = "00" * 32
    inner["artifact"] = artifact
    mutated["verifier"] = inner
    with pytest.raises(AttestationError, match="digest mismatch"):
        verify_v3(mutated, load_auth_invariant(), digest)


def test_wrong_bindings_refused(tmp_path: Path) -> None:
    _, payload, _ = passing_attestation(tmp_path / "reg")
    invariant = load_auth_invariant()
    other_doc = dict(payload)
    other_doc["invariant_id"] = "OTHER-001"
    resealed = canonical.digest_of(other_doc)
    with pytest.raises(AttestationError, match="different invariant"):
        verify_v3(other_doc, invariant, resealed)
    wrong_content = dict(payload)
    wrong_content["content_digest"] = "0" * 64
    with pytest.raises(AttestationError, match="content digest"):
        verify_v3(wrong_content, invariant, canonical.digest_of(wrong_content))
    wrong_type = dict(payload)
    wrong_type["verification_type"] = "other/9"
    with pytest.raises(AttestationError, match="verification_type"):
        verify_v3(wrong_type, invariant, canonical.digest_of(wrong_type))
    future = dataclasses.replace(invariant, spec_version=2)
    evolved = dict(payload)
    evolved["content_digest"] = invariant_digest(future)
    with pytest.raises(AttestationError, match="spec_version"):
        verify_v3(evolved, future, canonical.digest_of(evolved))


def test_unknown_claims_preserved_not_refused(tmp_path: Path) -> None:
    _, payload, _ = passing_attestation(tmp_path / "reg")
    invariant = load_auth_invariant()
    future = dataclasses.replace(invariant, verification_type="future/9")
    evolved = dict(payload)
    evolved["verification_type"] = "future/9"
    evolved["content_digest"] = invariant_digest(future)
    evolved["execution_profile"] = "tomorrow"
    record = verify_v3(evolved, future, canonical.digest_of(evolved))
    assert record.verification_type == "future/9"
    assert record.execution_profile == "tomorrow"


def test_malformed_payloads_refused(tmp_path: Path) -> None:
    _, payload, digest = passing_attestation(tmp_path / "reg")
    invariant = load_auth_invariant()
    with pytest.raises(AttestationError, match="mapping"):
        verify_v3(["not", "a", "mapping"], invariant, digest)
    missing = dict(payload)
    del missing["statement"]
    with pytest.raises(AttestationError, match="missing required"):
        verify_v3(missing, invariant, digest)
    extra = dict(payload)
    extra["x-extra"] = 1
    with pytest.raises(AttestationError, match="unknown attestation field"):
        verify_v3(extra, invariant, digest)
    bad_version = dict(payload)
    bad_version["schema_version"] = 4
    with pytest.raises(AttestationError, match="schema_version"):
        verify_v3(bad_version, invariant, digest)
    bad_spec = dict(payload)
    bad_spec["spec_version"] = 9
    with pytest.raises(UnsupportedSpecVersionError):
        verify_v3(bad_spec, invariant, digest)
    bad_hashes = dict(payload)
    bad_hashes["evidence_hashes"] = []
    with pytest.raises(AttestationError, match="evidence_hashes"):
        verify_v3(bad_hashes, invariant, digest)
