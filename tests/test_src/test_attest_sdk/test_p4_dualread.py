"""P4 tests: v2 dual-read, version routing, registry-commit wire rules."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, cast

import pytest
from p3_fixtures import load_auth_invariant
from p4_fixtures import COMMIT_A, eligible_registry, issued, legacy_setup, passing_report

from attest_sdk.commits import RegistryCommit
from attest_sdk.errors import AttestationError, HistoryUnavailableError
from attest_sdk.history import schema_version_of, verify_historical, verify_v2, verify_v3


def test_schema_version_routing() -> None:
    assert schema_version_of({"schema_version": 2}) == 2
    assert schema_version_of({"schema_version": 3}) == 3
    with pytest.raises(AttestationError, match="mapping"):
        schema_version_of(["v2"])
    with pytest.raises(AttestationError, match="schema_version"):
        schema_version_of({})
    with pytest.raises(AttestationError, match="schema_version"):
        schema_version_of({"schema_version": "3"})
    with pytest.raises(AttestationError, match="schema_version"):
        schema_version_of({"schema_version": True})


def test_verify_v2_roundtrip() -> None:
    payload, digest, invariant, evidence = legacy_setup()
    record = verify_v2(payload, invariant, digest, evidence)
    assert record.verdict == "FAILED"
    assert record.schema_version == 2
    assert verify_v2(payload, invariant, digest).digest() == digest


def test_verify_v2_refusals_match_legacy() -> None:
    payload, digest, invariant, evidence = legacy_setup()
    tampered = dict(payload)
    tampered["verdict"] = "PASSED"
    with pytest.raises(AttestationError, match="digest mismatch"):
        verify_v2(tampered, invariant, digest)
    with pytest.raises(AttestationError, match="mapping"):
        verify_v2(cast(Any, None), invariant, digest)
    with pytest.raises(AttestationError, match="EvidenceRecord"):
        verify_v2(payload, invariant, digest, cast(Any, ["nope"]))
    other = dataclasses.replace(invariant, version=2)
    with pytest.raises(AttestationError, match="different invariant"):
        verify_v2(payload, other, digest)
    forged = dataclasses.replace(evidence[0], detail="forged")
    with pytest.raises(AttestationError, match="evidence hashes"):
        verify_v2(payload, invariant, digest, [forged])
    future = dict(payload)
    future["schema_version"] = 3
    with pytest.raises(AttestationError, match="unsupported attestation schema"):
        verify_v2(future, invariant, digest)


def test_verify_v2_error_chains_legacy() -> None:
    payload, _, invariant, _ = legacy_setup()
    with pytest.raises(AttestationError) as caught:
        verify_v2(payload, invariant, "0" * 64)
    assert caught.value.__cause__ is not None
    assert type(caught.value.__cause__).__name__ == "AttestationError"
    assert "attest_core" in type(caught.value.__cause__).__module__


def test_historical_replay_needs_v3() -> None:
    payload, digest, invariant, _ = legacy_setup()
    with pytest.raises(HistoryUnavailableError, match="requires a v3"):
        verify_historical(payload, cast(Any, invariant), digest, cast(Any, None))


def test_registry_commit_wire_rules() -> None:
    commit = RegistryCommit.from_wire({"vcs": "git", "commit": COMMIT_A})
    assert commit.to_wire() == {"vcs": "git", "commit": COMMIT_A}
    hinted = RegistryCommit.from_wire({"vcs": "git", "commit": COMMIT_A, "ref": "main"})
    assert hinted.ref == "main"
    assert hinted.to_wire()["ref"] == "main"
    foreign = RegistryCommit.from_wire({"vcs": "hg", "commit": COMMIT_A})
    assert foreign.vcs == "hg"
    for bad in ("abc123", "A" * 40, "z" * 40, "main", ""):
        with pytest.raises(AttestationError, match="commit"):
            RegistryCommit.from_wire({"vcs": "git", "commit": bad})
    with pytest.raises(AttestationError, match="unknown registry_commit field"):
        RegistryCommit.from_wire({"vcs": "git", "commit": COMMIT_A, "tag": "v1"})
    with pytest.raises(AttestationError, match="missing field"):
        RegistryCommit.from_wire({"vcs": "git"})
    with pytest.raises(AttestationError, match="object"):
        RegistryCommit.from_wire("git:main")


def test_64_hex_commit_roundtrip(tmp_path: Path) -> None:
    """M3: a full 64-hex SHA-256 commit verifies end to end."""
    commit64 = "d" * 64
    parsed = RegistryCommit.from_wire({"vcs": "git", "commit": commit64})
    assert parsed.to_wire() == {"vcs": "git", "commit": commit64}
    root = tmp_path / "reg"
    report = passing_report(eligible_registry(root))
    payload, digest = issued(report, commit64)
    invariant = load_auth_invariant()
    assert verify_v3(payload, invariant, digest, report.evidence).verdict == "PASSED"

    def resolve(commit: RegistryCommit) -> Path:
        assert commit.commit == commit64
        return root

    result = verify_historical(payload, invariant, digest, resolve)
    assert result.registry_commit.commit == commit64
    assert result.lifecycle_state == "active"
